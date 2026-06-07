"""
Phase 7-PF4 tests for core/foundry/challenges.py.

The Challenge Bus is the novel core: it routes an anti-bot wall to the
human and resumes automation when they respond. Tests pin:

  * submit() blocks until resolve() is called, then returns the
    resolution (the round-trip handoff).
  * verification challenges carry the human's extracted_value back.
  * timeout: an unanswered challenge resolves as unresolved (bounded
    wait — the engine never hangs forever).
  * pending_challenges surfaces what's awaiting a human.
  * the notifier fires on submit; a broken notifier doesn't break the
    handoff.
  * resolve() on an unknown/already-resolved id returns False.
  * end-to-end: the bus.as_handler() drives a real RecipeReplayer run,
    with a "human" resolving concurrently.
"""
from __future__ import annotations

import asyncio
from typing import List

import pytest

from core.foundry.challenges import (
    ChallengeBus,
    _reset_bus_for_tests,
    get_challenge_bus,
)
from core.foundry.recipe import (
    ChallengeKind,
    RecipeStep,
    SignupRecipe,
    StepKind,
)
from core.foundry.replay import Challenge, ChallengeResolution, RecipeReplayer
from core.foundry.vault import ResearchPersona


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_bus_for_tests()
    yield
    _reset_bus_for_tests()


def _challenge(cid="c1", kind=ChallengeKind.CAPTCHA, needs_value_for=None):
    return Challenge(
        challenge_id=cid, kind=kind, prompt="Solve it",
        context_url="https://staging.airtable.com/signup",
        recipe_id="r1", persona_id="p1", service_handle="airtable",
        needs_value_for=needs_value_for,
    )


# ───────────────────────── round-trip handoff ─────────────────────────


class TestHandoffRoundTrip:
    def test_submit_blocks_until_resolve(self):
        bus = ChallengeBus(default_timeout_s=5.0)

        async def scenario():
            ch = _challenge()
            # Start submit (awaits). Concurrently resolve after a beat.
            async def resolve_soon():
                await asyncio.sleep(0.05)
                # The challenge must be pending while submit awaits.
                assert any(c.challenge_id == "c1" for c in bus.pending_challenges())
                ok = bus.resolve("c1", resolved=True)
                assert ok is True
            res, _ = await asyncio.gather(bus.submit(ch), resolve_soon())
            return res

        resolution = _run(scenario())
        assert resolution.resolved is True
        assert resolution.challenge_id == "c1"

    def test_verification_value_round_trips(self):
        bus = ChallengeBus(default_timeout_s=5.0)

        async def scenario():
            ch = _challenge(
                cid="c-email", kind=ChallengeKind.EMAIL_CODE,
                needs_value_for="verification:email_code",
            )
            async def resolve_soon():
                await asyncio.sleep(0.05)
                bus.resolve("c-email", resolved=True, extracted_value="999111")
            res, _ = await asyncio.gather(bus.submit(ch), resolve_soon())
            return res

        resolution = _run(scenario())
        assert resolution.resolved is True
        assert resolution.extracted_value == "999111"

    def test_unresolved_resolution(self):
        bus = ChallengeBus(default_timeout_s=5.0)

        async def scenario():
            ch = _challenge()
            async def reject_soon():
                await asyncio.sleep(0.05)
                bus.resolve("c1", resolved=False, note="operator declined")
            res, _ = await asyncio.gather(bus.submit(ch), reject_soon())
            return res

        resolution = _run(scenario())
        assert resolution.resolved is False
        assert "declined" in resolution.note


# ───────────────────────── bounded wait ─────────────────────────


class TestTimeout:
    def test_unanswered_challenge_times_out(self):
        # Very short timeout — nobody resolves it.
        bus = ChallengeBus(default_timeout_s=0.1)

        async def scenario():
            return await bus.submit(_challenge())

        resolution = _run(scenario())
        assert resolution.resolved is False
        assert "timed out" in resolution.note
        # And it's no longer pending.
        assert bus.pending_challenges() == []


# ───────────────────────── notifier ─────────────────────────


class TestNotifier:
    def test_notifier_fires_on_submit(self):
        seen: List[Challenge] = []
        bus = ChallengeBus(notifier=lambda ch: seen.append(ch), default_timeout_s=0.1)

        async def scenario():
            await bus.submit(_challenge())

        _run(scenario())
        assert len(seen) == 1
        assert seen[0].challenge_id == "c1"

    def test_broken_notifier_does_not_break_handoff(self):
        def boom(ch):
            raise RuntimeError("notifier exploded")
        bus = ChallengeBus(notifier=boom, default_timeout_s=5.0)

        async def scenario():
            ch = _challenge()
            async def resolve_soon():
                await asyncio.sleep(0.05)
                bus.resolve("c1", resolved=True)
            res, _ = await asyncio.gather(bus.submit(ch), resolve_soon())
            return res

        # Despite the broken notifier, the handoff still completes.
        resolution = _run(scenario())
        assert resolution.resolved is True


# ───────────────────────── resolve edge cases ─────────────────────────


class TestResolveEdgeCases:
    def test_resolve_unknown_returns_false(self):
        bus = ChallengeBus()
        assert bus.resolve("never-existed") is False

    def test_double_resolve_second_returns_false(self):
        bus = ChallengeBus(default_timeout_s=5.0)

        async def scenario():
            ch = _challenge()
            results = {}
            async def resolve_twice():
                await asyncio.sleep(0.05)
                results["first"] = bus.resolve("c1", resolved=True)
                results["second"] = bus.resolve("c1", resolved=True)
            await asyncio.gather(bus.submit(ch), resolve_twice())
            return results

        results = _run(scenario())
        assert results["first"] is True
        assert results["second"] is False  # already resolved


# ───────────────────────── singleton ─────────────────────────


class TestSingleton:
    def test_get_challenge_bus_returns_same_instance(self):
        a = get_challenge_bus()
        b = get_challenge_bus()
        assert a is b

    def test_reset_gives_fresh(self):
        a = get_challenge_bus()
        _reset_bus_for_tests()
        b = get_challenge_bus()
        assert a is not b


# ───────────────────────── end-to-end with replayer ─────────────────────────


class TestEndToEndWithReplayer:
    """The whole point: bus.as_handler() drives a real replay, with a
    'human' resolving the challenge concurrently. This is the
    automate-the-boring-95%, hand-off-the-rare-5% loop end to end."""

    def test_replay_with_concurrent_human_resolution(self):
        from tests.unit.test_foundry_replay import MockDriver

        bus = ChallengeBus(default_timeout_s=5.0)
        persona = ResearchPersona(
            persona_id="p1", label="alice", email="alice@x",
            password="pw", first_name="A", last_name="B",
        )
        recipe = SignupRecipe(
            service_handle="airtable", name="signup",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/signup"),
                RecipeStep(
                    kind=StepKind.FILL,
                    selector={"by": "name", "value": "email"},
                    value_binding="persona:email",
                ),
                RecipeStep(
                    kind=StepKind.CHALLENGE, label="captcha",
                    challenge_kind=ChallengeKind.CAPTCHA,
                ),
                RecipeStep(
                    kind=StepKind.CLICK,
                    selector={"by": "css", "value": "button"},
                ),
            ],
        )

        async def scenario():
            replayer = RecipeReplayer(MockDriver())

            async def human():
                # Poll until the challenge is pending, then resolve it.
                for _ in range(100):
                    pending = bus.pending_challenges()
                    if pending:
                        bus.resolve(pending[0].challenge_id, resolved=True)
                        return
                    await asyncio.sleep(0.02)

            outcome, _ = await asyncio.gather(
                replayer.run(recipe, persona, challenge_handler=bus.as_handler()),
                human(),
            )
            return outcome

        outcome = _run(scenario())
        from core.foundry.replay import ReplayState
        assert outcome.state is ReplayState.COMPLETED
        assert outcome.challenges_encountered == 1
