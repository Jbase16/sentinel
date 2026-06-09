"""
Phase 7-PF9 tests for core/foundry/signup.py + the /signup endpoints.

The orchestrator runs a signup as a background task, bridging the
replayer to the challenge bus. Tests use a mock driver factory + a
real ChallengeBus, driving the full loop without a browser.

Coverage:
  * start() fails fast on missing recipe / persona / persona field.
  * a no-challenge recipe runs to COMPLETED in the background.
  * a recipe with a CHALLENGE runs, surfaces a pending challenge, and
    completes once the "human" resolves it — the whole /signup +
    /challenges + /resolve loop.
  * job dict redacts extracted secrets in the default (listing) view.
"""
from __future__ import annotations

import asyncio

import pytest

from core.foundry.challenges import ChallengeBus, _reset_bus_for_tests
from core.foundry.recipe import ChallengeKind, RecipeStep, SignupRecipe, StepKind
from core.foundry.recipe_store import save_recipe
from core.foundry.signup import (
    SignupJobState,
    _reset_orchestrator_for_tests,
)
from core.foundry.vault import PersonaVault


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    monkeypatch.setenv("SENTINELFORGE_RECIPE_STORE", str(tmp_path / "recipes"))
    _reset_bus_for_tests()
    yield
    _reset_bus_for_tests()


def _make_recipe(with_challenge=False, with_extract=False):
    steps = [
        RecipeStep(kind=StepKind.NAVIGATE, url="https://staging.airtable.com/signup"),
        RecipeStep(
            kind=StepKind.FILL,
            selector={"by": "name", "value": "email"},
            value_binding="persona:email",
        ),
    ]
    if with_challenge:
        steps.append(RecipeStep(
            kind=StepKind.CHALLENGE, challenge_kind=ChallengeKind.CAPTCHA,
        ))
    steps.append(RecipeStep(
        kind=StepKind.CLICK, selector={"by": "role", "value": "button"},
    ))
    if with_extract:
        steps.append(RecipeStep(
            kind=StepKind.EXTRACT,
            selector={"by": "css", "value": ".api-token"},
            extract_as="api_token",
        ))
    recipe = SignupRecipe(
        service_handle="airtable", name="signup",
        origin="https://staging.airtable.com", steps=steps,
    )
    save_recipe(recipe)
    return recipe


def _make_persona(vault):
    return vault.add_persona(
        label="alice", email="alice@research.example", password="pw",
        first_name="Alice", last_name="R",
    )


def _mock_driver_factory(extract_values=None):
    from tests.unit.test_foundry_replay import MockDriver

    async def factory():
        return MockDriver(extract_values=extract_values or {})
    return factory


# ───────────────────────── fail-fast ─────────────────────────


class TestStartFailFast:
    def test_unknown_recipe_raises(self):
        vault = PersonaVault()
        persona = _make_persona(vault)
        orch = _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(), vault=vault,
        )
        with pytest.raises(ValueError, match="recipe.*not found"):
            _run(orch.start("no-such-recipe", persona.persona_id))

    def test_unknown_persona_raises(self):
        recipe = _make_recipe()
        vault = PersonaVault()
        orch = _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(), vault=vault,
        )
        with pytest.raises(ValueError, match="persona.*not found"):
            _run(orch.start(recipe.recipe_id, "no-such-persona"))

    def test_persona_missing_field_raises(self):
        # Recipe needs persona:phone; persona has none.
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
        save_recipe(recipe)
        vault = PersonaVault()
        persona = _make_persona(vault)  # no phone
        orch = _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(), vault=vault,
        )
        with pytest.raises(ValueError, match="missing fields"):
            _run(orch.start(recipe.recipe_id, persona.persona_id))


# ───────────────────────── background run ─────────────────────────


class TestBackgroundRun:
    def test_no_challenge_recipe_completes(self):
        recipe = _make_recipe(with_extract=True)
        vault = PersonaVault()
        persona = _make_persona(vault)
        orch = _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(
                extract_values={".api-token": "tok-123"}),
            vault=vault,
        )

        async def scenario():
            job = await orch.start(recipe.recipe_id, persona.persona_id)
            # Wait for the background task to finish.
            for _ in range(200):
                if orch.get_job(job.job_id).state in (
                    SignupJobState.COMPLETED, SignupJobState.FAILED,
                    SignupJobState.ABORTED,
                ):
                    break
                await asyncio.sleep(0.01)
            return orch.get_job(job.job_id)

        job = _run(scenario())
        assert job.state is SignupJobState.COMPLETED
        # The extracted token is present internally...
        assert job._outcome.extracted["api_token"] == "tok-123"
        # ...but redacted in the public listing.
        d = job.to_dict()
        assert "extracted" not in d
        assert d["extracted_keys"]["api_token"] == "<7 chars>"

    def test_full_signup_with_challenge_handoff(self):
        """The whole loop: start a signup, the replay hits a CAPTCHA,
        the challenge surfaces, a 'human' resolves it, the signup
        completes."""
        recipe = _make_recipe(with_challenge=True)
        vault = PersonaVault()
        persona = _make_persona(vault)
        bus = ChallengeBus(default_timeout_s=5.0)
        orch = _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(), bus=bus, vault=vault,
        )

        async def scenario():
            job = await orch.start(recipe.recipe_id, persona.persona_id)

            # The "human": poll for the challenge, resolve it.
            async def human():
                for _ in range(200):
                    pending = bus.pending_challenges()
                    if pending:
                        bus.resolve(pending[0].challenge_id, resolved=True)
                        return
                    await asyncio.sleep(0.01)

            await human()
            # Wait for the job to finish.
            for _ in range(200):
                if orch.get_job(job.job_id).state in (
                    SignupJobState.COMPLETED, SignupJobState.FAILED,
                    SignupJobState.ABORTED,
                ):
                    break
                await asyncio.sleep(0.01)
            return orch.get_job(job.job_id)

        job = _run(scenario())
        assert job.state is SignupJobState.COMPLETED
        assert job._outcome.challenges_encountered == 1

    def test_aborted_when_challenge_declined(self):
        recipe = _make_recipe(with_challenge=True)
        vault = PersonaVault()
        persona = _make_persona(vault)
        bus = ChallengeBus(default_timeout_s=5.0)
        orch = _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(), bus=bus, vault=vault,
        )

        async def scenario():
            job = await orch.start(recipe.recipe_id, persona.persona_id)

            async def human():
                for _ in range(200):
                    pending = bus.pending_challenges()
                    if pending:
                        bus.resolve(pending[0].challenge_id, resolved=False)
                        return
                    await asyncio.sleep(0.01)

            await human()
            for _ in range(200):
                if orch.get_job(job.job_id).state in (
                    SignupJobState.COMPLETED, SignupJobState.FAILED,
                    SignupJobState.ABORTED,
                ):
                    break
                await asyncio.sleep(0.01)
            return orch.get_job(job.job_id)

        job = _run(scenario())
        assert job.state is SignupJobState.ABORTED


# ───────────────────────── endpoint wiring ─────────────────────────


class TestSignupEndpoints:
    def test_start_endpoint_unknown_recipe_400(self):
        from core.server.routers.foundry import (
            StartSignupRequest, start_signup_endpoint,
        )
        from fastapi import HTTPException

        vault = PersonaVault()
        persona = _make_persona(vault)
        _reset_orchestrator_for_tests(
            driver_factory=_mock_driver_factory(), vault=vault,
        )
        with pytest.raises(HTTPException) as ei:
            _run(start_signup_endpoint(
                StartSignupRequest(recipe_id="nope", persona_id=persona.persona_id),
                _=True,
            ))
        assert ei.value.status_code == 400

    def test_get_unknown_job_404(self):
        from core.server.routers.foundry import get_signup_job_endpoint
        from fastapi import HTTPException
        _reset_orchestrator_for_tests(driver_factory=_mock_driver_factory())
        with pytest.raises(HTTPException) as ei:
            _run(get_signup_job_endpoint("nope", _=True))
        assert ei.value.status_code == 404
