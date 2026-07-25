"""
Phase 7-PF3 tests for core/foundry/replay.py.

The replay engine drives a recipe with a persona, handing anti-bot
walls to a challenge_handler. Tests use a MockDriver (records calls,
returns scripted values) and scripted challenge handlers — no real
browser, no network.

Coverage:
  * Happy path: a recipe with FILL/CLICK/EXTRACT runs to COMPLETED,
    persona values + generated values land in the right fills.
  * CHALLENGE steps emit a Challenge and await the handler; resolved
    → continue, unresolved → ABORTED.
  * verification: FILL bindings emit a challenge and use the human's
    extracted_value as the fill.
  * Scope gate: NAVIGATE off-origin is refused (FAILED).
  * Persona missing a required field → fail-fast before any driver call.
  * Rate-limit gate: a vault at-cap refuses before any driver call.
  * Audit: success/aborted/failed recorded when a vault is present.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

from core.foundry.recipe import (
    ChallengeKind,
    RecipeStep,
    SignupRecipe,
    StepKind,
)
from core.foundry.replay import (
    Challenge,
    ChallengeResolution,
    RecipeReplayer,
    ReplayState,
)
from core.foundry.vault import PersonaVault, ResearchPersona


def _run(coro):
    return asyncio.run(coro)


# ───────────────────────── mock driver ─────────────────────────


class MockDriver:
    """Records every driver call; returns scripted extract values."""

    def __init__(self, extract_values: Optional[Dict[str, str]] = None,
                 current_url: str = "https://staging.airtable.com/signup"):
        self.calls: List[Dict[str, Any]] = []
        self._extracts = extract_values or {}
        self._url = current_url

    async def navigate(self, url):
        self.calls.append({"op": "navigate", "url": url})
        self._url = url

    async def fill(self, selector, value):
        self.calls.append({"op": "fill", "selector": selector, "value": value})

    async def click(self, selector):
        self.calls.append({"op": "click", "selector": selector})

    async def wait_for(self, selector, timeout_s):
        self.calls.append({"op": "wait_for", "selector": selector})

    async def extract(self, selector, mode):
        self.calls.append({"op": "extract", "selector": selector, "mode": mode})
        # Key extracts by the selector's value for scripting.
        key = selector.get("value", "")
        return self._extracts.get(key, "extracted-default")

    async def screenshot(self):
        return b"fake-png-bytes"

    async def current_url(self):
        return self._url

    def fills(self):
        return [c for c in self.calls if c["op"] == "fill"]


def _persona():
    return ResearchPersona(
        persona_id="p1", label="alice", email="alice@research.example",
        password="explicit-pw", first_name="Alice", last_name="R",
    )


def _recipe_simple():
    return SignupRecipe(
        service_handle="airtable", name="signup",
        origin="https://staging.airtable.com",
        steps=[
            RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/signup"),
            RecipeStep(
                kind=StepKind.FILL, label="email",
                selector={"by": "name", "value": "email"},
                value_binding="persona:email",
            ),
            RecipeStep(
                kind=StepKind.FILL, label="password",
                selector={"by": "name", "value": "password"},
                value_binding="generated:password",
            ),
            RecipeStep(
                kind=StepKind.CLICK, label="submit",
                selector={"by": "css", "value": "button[type=submit]"},
            ),
            RecipeStep(
                kind=StepKind.EXTRACT, label="token",
                selector={"by": "css", "value": ".api-token"},
                extract_as="api_token",
            ),
        ],
    )


async def _never_called_handler(challenge):
    raise AssertionError("challenge_handler should NOT be called for this recipe")


# ───────────────────────── happy path ─────────────────────────


class TestHappyPath:
    def test_simple_recipe_completes(self):
        driver = MockDriver(extract_values={".api-token": "tok-XYZ"})
        replayer = RecipeReplayer(driver)
        outcome = _run(replayer.run(
            _recipe_simple(), _persona(),
            challenge_handler=_never_called_handler,
        ))
        assert outcome.state is ReplayState.COMPLETED
        assert outcome.succeeded
        assert outcome.steps_executed == 5
        assert outcome.challenges_encountered == 0
        # The extracted token came through.
        assert outcome.extracted["api_token"] == "tok-XYZ"

    def test_persona_value_lands_in_fill(self):
        driver = MockDriver()
        replayer = RecipeReplayer(driver)
        _run(replayer.run(_recipe_simple(), _persona(),
                          challenge_handler=_never_called_handler))
        fills = driver.fills()
        # First fill is email → persona's email.
        assert fills[0]["value"] == "alice@research.example"
        # Second is generated password → 20 chars, not the persona's.
        assert len(fills[1]["value"]) == 20
        assert fills[1]["value"] != "explicit-pw"


# ───────────────────────── challenges ─────────────────────────


class TestChallenges:
    def test_challenge_emitted_and_resolved(self):
        recipe = _recipe_simple()
        # Insert a CAPTCHA challenge before submit.
        recipe.steps.insert(3, RecipeStep(
            kind=StepKind.CHALLENGE, label="captcha",
            challenge_kind=ChallengeKind.CAPTCHA,
        ))
        seen: List[Challenge] = []

        async def handler(ch):
            seen.append(ch)
            return ChallengeResolution(challenge_id=ch.challenge_id, resolved=True)

        driver = MockDriver()
        outcome = _run(RecipeReplayer(driver).run(
            recipe, _persona(), challenge_handler=handler,
        ))
        assert outcome.state is ReplayState.COMPLETED
        assert outcome.challenges_encountered == 1
        # The challenge carried context.
        assert len(seen) == 1
        assert seen[0].kind is ChallengeKind.CAPTCHA
        assert seen[0].screenshot_b64 is not None  # screenshot captured
        assert seen[0].service_handle == "airtable"

    def test_unresolved_challenge_aborts(self):
        recipe = _recipe_simple()
        recipe.steps.insert(3, RecipeStep(
            kind=StepKind.CHALLENGE, challenge_kind=ChallengeKind.CAPTCHA,
        ))

        async def handler(ch):
            return ChallengeResolution(challenge_id=ch.challenge_id, resolved=False)

        outcome = _run(RecipeReplayer(MockDriver()).run(
            recipe, _persona(), challenge_handler=handler,
        ))
        assert outcome.state is ReplayState.ABORTED
        assert not outcome.succeeded

    def test_verification_fill_uses_human_value(self):
        # A FILL bound to verification:email_code emits a challenge; the
        # human supplies the code, which becomes the fill value.
        recipe = SignupRecipe(
            service_handle="airtable", name="verify",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/v"),
                RecipeStep(
                    kind=StepKind.FILL, label="enter code",
                    selector={"by": "name", "value": "code"},
                    value_binding="verification:email_code",
                ),
            ],
        )

        async def handler(ch):
            assert ch.kind is ChallengeKind.EMAIL_CODE
            assert ch.needs_value_for == "verification:email_code"
            return ChallengeResolution(
                challenge_id=ch.challenge_id, resolved=True,
                extracted_value="123456",
            )

        driver = MockDriver()
        outcome = _run(RecipeReplayer(driver).run(
            recipe, _persona(), challenge_handler=handler,
        ))
        assert outcome.state is ReplayState.COMPLETED
        # The code the human supplied landed in the fill.
        assert driver.fills()[0]["value"] == "123456"

    def test_verification_fill_unresolved_aborts(self):
        recipe = SignupRecipe(
            service_handle="airtable", name="verify",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(
                    kind=StepKind.FILL,
                    selector={"by": "name", "value": "code"},
                    value_binding="verification:email_code",
                ),
            ],
        )

        async def handler(ch):
            return ChallengeResolution(challenge_id=ch.challenge_id, resolved=False)

        outcome = _run(RecipeReplayer(MockDriver()).run(
            recipe, _persona(), challenge_handler=handler,
        ))
        assert outcome.state is ReplayState.ABORTED


# ───────────────────────── scope gate ─────────────────────────


class TestScopeGate:
    def test_off_origin_navigate_fails(self):
        recipe = SignupRecipe(
            service_handle="airtable", name="evil",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(kind=StepKind.NAVIGATE, url="https://evil.example/x"),
            ],
        )
        outcome = _run(RecipeReplayer(MockDriver()).run(
            recipe, _persona(), challenge_handler=_never_called_handler,
        ))
        assert outcome.state is ReplayState.FAILED
        assert "off-origin" in (outcome.error or "")

    def test_extra_allowed_origin_permitted(self):
        recipe = SignupRecipe(
            service_handle="airtable", name="multi",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/a"),
                RecipeStep(kind=StepKind.NAVIGATE, url="https://accounts.staging.airtable.com/b"),
            ],
        )
        replayer = RecipeReplayer(
            MockDriver(),
            extra_allowed_origins=["https://accounts.staging.airtable.com"],
        )
        outcome = _run(replayer.run(
            recipe, _persona(), challenge_handler=_never_called_handler,
        ))
        assert outcome.state is ReplayState.COMPLETED


# ───────────────────────── fail-fast guards ─────────────────────────


class TestFailFast:
    def test_persona_missing_field_fails_before_driver(self):
        # Recipe needs persona:phone, persona has none.
        recipe = SignupRecipe(
            service_handle="airtable", name="needs-phone",
            origin="https://staging.airtable.com",
            steps=[
                RecipeStep(
                    kind=StepKind.FILL,
                    selector={"by": "name", "value": "phone"},
                    value_binding="persona:phone",
                ),
            ],
        )
        driver = MockDriver()
        outcome = _run(RecipeReplayer(driver).run(
            recipe, _persona(),  # no phone
            challenge_handler=_never_called_handler,
        ))
        assert outcome.state is ReplayState.FAILED
        assert "missing required fields" in (outcome.error or "")
        assert "phone" in (outcome.error or "")
        # Driver never touched.
        assert driver.calls == []

    def test_rate_limit_refuses_before_driver(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "v"))
        vault = PersonaVault(max_accounts_per_service=1)
        persona = vault.add_persona(
            label="alice", email="a@x", password="pw", first_name="A", last_name="B",
        )
        # Already at cap.
        vault.record_account_creation(
            persona_id=persona.persona_id, service_handle="airtable",
        )
        driver = MockDriver()
        outcome = _run(RecipeReplayer(driver, vault=vault).run(
            _recipe_simple(), persona,
            challenge_handler=_never_called_handler,
        ))
        assert outcome.state is ReplayState.FAILED
        assert "rate limit" in (outcome.error or "")
        # Refused before any driver action.
        assert driver.calls == []


# ───────────────────────── audit integration ─────────────────────────


class TestAuditIntegration:
    def test_success_records_audit(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "v"))
        vault = PersonaVault()
        persona = vault.add_persona(
            label="alice", email="a@x", password="pw", first_name="A", last_name="B",
        )
        outcome = _run(RecipeReplayer(MockDriver(), vault=vault).run(
            _recipe_simple(), persona,
            challenge_handler=_never_called_handler,
        ))
        assert outcome.succeeded
        records = vault.audit_records(persona_id=persona.persona_id)
        assert len(records) == 1
        assert records[0].outcome == "success"
        assert records[0].service_handle == "airtable"

    def test_abort_records_abandoned(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "v"))
        vault = PersonaVault()
        persona = vault.add_persona(
            label="alice", email="a@x", password="pw", first_name="A", last_name="B",
        )
        recipe = _recipe_simple()
        recipe.steps.insert(3, RecipeStep(
            kind=StepKind.CHALLENGE, challenge_kind=ChallengeKind.CAPTCHA,
        ))

        async def handler(ch):
            return ChallengeResolution(challenge_id=ch.challenge_id, resolved=False)

        outcome = _run(RecipeReplayer(MockDriver(), vault=vault).run(
            recipe, persona, challenge_handler=handler,
        ))
        assert outcome.state is ReplayState.ABORTED
        records = vault.audit_records(persona_id=persona.persona_id)
        assert records[0].outcome == "abandoned"
