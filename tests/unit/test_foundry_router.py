"""
Phase 7-PF6 tests for core/server/routers/foundry.py + recipe_store.

Tested via direct route-handler calls (the project's pattern — no
FastAPI TestClient). Covers:
  * /plan returns the account topology.
  * persona CRUD never echoes the password.
  * recipe store round-trip + malformed-recipe rejection.
  * the challenge handoff loop: list pending + resolve completes the
    awaiting future (driven by a real ChallengeBus + a concurrent
    "replay" awaiting submit()).
"""
from __future__ import annotations

import asyncio

import pytest

from core.foundry.challenges import _reset_bus_for_tests, get_challenge_bus
from core.foundry.recipe import ChallengeKind, RecipeStep, SignupRecipe, StepKind
from core.foundry.replay import Challenge


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    monkeypatch.setenv("SENTINELFORGE_RECIPE_STORE", str(tmp_path / "recipes"))
    monkeypatch.setenv("SENTINELFORGE_AUTHZ_STORE", str(tmp_path / "authorizations"))
    monkeypatch.delenv("SENTINELFORGE_BEHAVIOR_PRIMARY", raising=False)
    _reset_bus_for_tests()
    yield
    _reset_bus_for_tests()


# ───────────────────────── plan ─────────────────────────


class TestPlanEndpoint:
    def test_plan_returns_topology(self):
        from core.server.routers.foundry import PlanRequest, plan_accounts_endpoint
        result = _run(plan_accounts_endpoint(
            PlanRequest(target_handle="airtable",
                        vuln_classes=["idor_cross_principal"]),
            _=True,
        ))
        assert result["target_handle"] == "airtable"
        assert result["account_count"] == 2
        assert result["tenant_count"] == 2

    def test_empty_vuln_classes_rejected(self):
        from core.server.routers.foundry import PlanRequest, plan_accounts_endpoint
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(plan_accounts_endpoint(
                PlanRequest(target_handle="airtable", vuln_classes=[]),
                _=True,
            ))
        assert ei.value.status_code == 400


# ───────────────────────── personas ─────────────────────────


class TestPersonaEndpoints:
    def test_add_persona_hides_password(self):
        from core.server.routers.foundry import (
            AddPersonaRequest, add_persona_endpoint,
        )
        result = _run(add_persona_endpoint(
            AddPersonaRequest(
                label="alice", email="alice@research.example",
                password="SUPER-SECRET", first_name="Alice",
            ),
            _=True,
        ))
        # Password NOT in the response.
        assert "password" not in result
        assert result["has_password"] is True
        assert result["email"] == "alice@research.example"

    def test_list_personas_hides_passwords(self):
        from core.server.routers.foundry import (
            AddPersonaRequest, add_persona_endpoint, list_personas_endpoint,
        )
        _run(add_persona_endpoint(
            AddPersonaRequest(label="a", email="a@x", password="pw"),
            _=True,
        ))
        listed = _run(list_personas_endpoint(_=True))
        assert len(listed) == 1
        assert "password" not in listed[0]
        assert listed[0]["has_password"] is True

    def test_persona_audit_endpoint(self):
        from core.server.routers.foundry import (
            AddPersonaRequest, add_persona_endpoint, persona_audit_endpoint,
        )
        from core.foundry.vault import PersonaVault
        persona = _run(add_persona_endpoint(
            AddPersonaRequest(label="a", email="a@x"), _=True,
        ))
        # Record an account creation directly.
        PersonaVault().record_account_creation(
            persona_id=persona["persona_id"], service_handle="airtable",
        )
        audit = _run(persona_audit_endpoint(persona["persona_id"], _=True))
        assert len(audit) == 1
        assert audit[0]["service_handle"] == "airtable"


# ───────────────── behavioral primary planner ─────────────────


class TestBehavioralAuthorizationEndpoint:
    ORIGIN = "https://api.example.test"
    SOURCE_ID = "RlLB9Tjpk7YfkTaBB0SpzA"
    PEER_ID = "9QsBs4y23m6HH4aB38ffkA"

    def _setup(self):
        import json

        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.foundry.vault import PersonaVault
        from core.server.routers.foundry import RunBehavioralAuthorizationRequest

        vault = PersonaVault()
        source_persona = vault.add_persona(label="source", email="source@research.example")
        peer_persona = vault.add_persona(label="peer", email="peer@research.example")
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[CONTROLLED_WORKFLOW],
            disclosure_attestation=True,
        )

        def record(persona_id, resource_id, private_marker):
            operation = "GetPrivateObject"
            return {
                "method": "POST",
                "url": f"{self.ORIGIN}/gql/batch",
                "request_headers": {
                    "content-type": "application/json",
                    "x-csrf-token": f"csrf-{persona_id}",
                },
                "request_body": json.dumps([{
                    "operationName": operation,
                    "query": (
                        "query GetPrivateObject($BizEncId: ID!) "
                        "{ privateObject(id: $BizEncId) { id } }"
                    ),
                    "variables": {"BizEncId": resource_id},
                }]),
                "response_body": json.dumps({"owner": private_marker}),
            }

        source_records = [record(source_persona.persona_id, self.SOURCE_ID, "SourcePrivateMarker")]
        peer_records = [record(peer_persona.persona_id, self.PEER_ID, "PeerPrivateMarker")]
        request = RunBehavioralAuthorizationRequest(
            target_origin=self.ORIGIN,
            envelope_id=envelope.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
            source_records=source_records,
            peer_records=peer_records,
        )
        return request, source_persona, peer_persona

    def test_disabled_endpoint_returns_plan_without_constructing_live_traffic(self, monkeypatch):
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import SNDReplayTransport

        request, _, _ = self._setup()

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("disabled primary planner must not reach SND")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "disabled"
        assert result["plan"]["selected_proposal_id"]
        assert result["execution"] is None

    def test_enabled_endpoint_executes_one_legacy_verified_experiment(self, monkeypatch):
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if persona == peer_persona.persona_id:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            if self.SOURCE_ID in (replay_request.body or ""):
                return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')
            return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert len(calls) == 3
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["finding"]["metadata"]["behavioral_primary_planner"]
        assert calls[0][1].headers["x-csrf-token"] == f"csrf-{peer_persona.persona_id}"
        assert calls[1][1].headers["x-csrf-token"] == f"csrf-{source_persona.persona_id}"


# ───────────────────────── recipes ─────────────────────────


def _valid_recipe_dict():
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
        ],
    )
    return recipe.to_dict()


class TestRecipeEndpoints:
    def test_add_and_get_recipe(self):
        from core.server.routers.foundry import (
            AddRecipeRequest, add_recipe_endpoint, get_recipe_endpoint,
        )
        added = _run(add_recipe_endpoint(
            AddRecipeRequest(recipe=_valid_recipe_dict()), _=True,
        ))
        rid = added["recipe_id"]
        assert added["required_persona_fields"] == ["email"]
        detail = _run(get_recipe_endpoint(rid, _=True))
        assert detail["service_handle"] == "airtable"
        assert len(detail["steps"]) == 2

    def test_malformed_recipe_rejected(self):
        from core.server.routers.foundry import AddRecipeRequest, add_recipe_endpoint
        from fastapi import HTTPException
        # A recipe with no steps is invalid.
        bad = {
            "service_handle": "airtable", "name": "x",
            "origin": "https://x", "steps": [],
        }
        with pytest.raises(HTTPException) as ei:
            _run(add_recipe_endpoint(AddRecipeRequest(recipe=bad), _=True))
        assert ei.value.status_code == 400

    def test_list_recipes(self):
        from core.server.routers.foundry import (
            AddRecipeRequest, add_recipe_endpoint, list_recipes_endpoint,
        )
        _run(add_recipe_endpoint(AddRecipeRequest(recipe=_valid_recipe_dict()), _=True))
        listed = _run(list_recipes_endpoint(_=True))
        assert len(listed) == 1
        assert listed[0]["service_handle"] == "airtable"

    def test_get_unknown_recipe_404(self):
        from core.server.routers.foundry import get_recipe_endpoint
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(get_recipe_endpoint("nope", _=True))
        assert ei.value.status_code == 404


# ───────────────────────── challenge handoff loop ─────────────────────────


class TestChallengeHandoffLoop:
    def test_list_and_resolve_completes_the_loop(self):
        """The cross-context handoff over HTTP: a 'replay' awaits
        bus.submit() while the human (the resolve endpoint) completes
        it. This is what the engine-awaits / human-resolves loop looks
        like through the router's two endpoints."""
        from core.server.routers.foundry import (
            ResolveChallengeRequest,
            list_challenges_endpoint,
            resolve_challenge_endpoint,
        )

        bus = get_challenge_bus()
        challenge = Challenge(
            challenge_id="cx", kind=ChallengeKind.CAPTCHA,
            prompt="Solve it", context_url="https://staging.airtable.com",
            recipe_id="r1", persona_id="p1", service_handle="airtable",
        )

        async def scenario():
            async def human():
                # Poll the LIST endpoint until the challenge shows up.
                for _ in range(100):
                    pending = await list_challenges_endpoint(_=True)
                    if pending:
                        cid = pending[0]["challenge_id"]
                        res = await resolve_challenge_endpoint(
                            cid, ResolveChallengeRequest(resolved=True), _=True,
                        )
                        return res
                    await asyncio.sleep(0.02)
                raise AssertionError("challenge never appeared in /challenges")

            resolution, human_result = await asyncio.gather(
                bus.submit(challenge), human(),
            )
            return resolution, human_result

        resolution, human_result = _run(scenario())
        assert resolution.resolved is True
        assert human_result["resolved"] is True

    def test_resolve_verification_passes_extracted_value(self):
        from core.server.routers.foundry import (
            ResolveChallengeRequest,
            list_challenges_endpoint,
            resolve_challenge_endpoint,
        )

        bus = get_challenge_bus()
        challenge = Challenge(
            challenge_id="cv", kind=ChallengeKind.EMAIL_CODE,
            prompt="Enter the code", context_url="https://x",
            recipe_id="r", persona_id="p", service_handle="airtable",
            needs_value_for="verification:email_code",
        )

        async def scenario():
            async def human():
                for _ in range(100):
                    pending = await list_challenges_endpoint(_=True)
                    if pending:
                        await resolve_challenge_endpoint(
                            pending[0]["challenge_id"],
                            ResolveChallengeRequest(
                                resolved=True, extracted_value="654321",
                            ),
                            _=True,
                        )
                        return
                    await asyncio.sleep(0.02)
            res, _ = await asyncio.gather(bus.submit(challenge), human())
            return res

        resolution = _run(scenario())
        assert resolution.extracted_value == "654321"

    def test_resolve_unknown_challenge_404(self):
        from core.server.routers.foundry import (
            ResolveChallengeRequest, resolve_challenge_endpoint,
        )
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            _run(resolve_challenge_endpoint(
                "never-existed", ResolveChallengeRequest(resolved=True), _=True,
            ))
        assert ei.value.status_code == 404
