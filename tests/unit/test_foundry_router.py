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
import json

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
    monkeypatch.setenv(
        "SENTINELFORGE_BEHAVIOR_RECEIPTS", str(tmp_path / "behavioral_receipts")
    )
    monkeypatch.setenv("SENTINELFORGE_CAPTURE_STORE", str(tmp_path / "captures"))
    monkeypatch.delenv("SENTINELFORGE_BEHAVIOR_PRIMARY", raising=False)
    monkeypatch.delenv(
        "SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION",
        raising=False,
    )
    monkeypatch.delenv(
        "SENTINELFORGE_BEHAVIOR_OMISSION_EXECUTION",
        raising=False,
    )
    monkeypatch.delenv(
        "SENTINELFORGE_BEHAVIOR_OMISSION_CONFIRMATION",
        raising=False,
    )
    monkeypatch.delenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", raising=False)
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


# ───────────────────────── authority-bound recording ─────────────────────────


class TestRecordRecipeEndpoint:
    ORIGIN = "https://app.sentinel-lab.test/signup"
    WORKFLOW = "sentinel-lab"

    def _authorized_request(self):
        from core.foundry.authorization import create_envelope
        from core.foundry.vault import PersonaVault
        from core.server.routers.foundry import RecordRecipeRequest

        persona = PersonaVault().add_persona(
            label="acceptance-alice",
            email="acceptance-alice@sentinel-lab.test",
            password="vault-only-password",
            first_name="Acceptance",
            last_name="Alice",
        )
        envelope = create_envelope(
            researcher_identity="operator",
            target_handle="sentinel-lab",
            authorized_origins=["https://app.sentinel-lab.test"],
            authorization_basis="isolated local acceptance lab",
            allowed_workflows=[self.WORKFLOW],
            disclosure_attestation=True,
        )
        return RecordRecipeRequest(
            service_handle=self.WORKFLOW,
            name="classic signup",
            origin=self.ORIGIN,
            envelope_id=envelope.envelope_id,
            persona_id=persona.persona_id,
            visual_variant="classic",
        )

    def test_missing_envelope_refuses_before_driver_launch(self, monkeypatch):
        from fastapi import HTTPException

        from core.foundry.driver_native import GhostNativeDriver
        from core.foundry.vault import PersonaVault
        from core.server.routers.foundry import (
            RecordRecipeRequest,
            record_recipe_endpoint,
        )

        persona = PersonaVault().add_persona(label="a", email="a@example.test")

        async def forbidden_launch(*_args, **_kwargs):
            raise AssertionError("authorization refusal must precede driver launch")

        monkeypatch.setattr(GhostNativeDriver, "launch", forbidden_launch)
        request = RecordRecipeRequest(
            service_handle=self.WORKFLOW,
            name="classic signup",
            origin=self.ORIGIN,
            envelope_id="0" * 32,
            persona_id=persona.persona_id,
            visual_variant="classic",
        )

        with pytest.raises(HTTPException) as exc:
            _run(record_recipe_endpoint(request, _=True))
        assert exc.value.status_code == 403

    def test_authorized_recording_persists_inspectable_provenance(
        self, monkeypatch
    ):
        from core.foundry.driver_native import GhostNativeDriver
        from core.foundry.recipe_store import load_recipe
        from core.server.routers import driver as driver_router
        from core.server.routers.foundry import record_recipe_endpoint

        request = self._authorized_request()

        class FakeDriver:
            session_id = "recording-session"

            async def start_recording(self):
                return None

            async def restrict_to_origins(self, origins):
                assert origins == ["https://app.sentinel-lab.test"]

            def emit(self, action):
                event = {
                    "event": "recorded_action",
                    "session_id": self.session_id,
                    "action": action,
                }
                for handler in list(driver_router.node_manager.event_handlers):
                    handler("recorded_action", event)

            async def navigate(self, url):
                self.emit({
                    "action": "navigate",
                    "url": "https://app.sentinel-lab.test/signup/classic",
                    "correlation_id": "lab:111111111111",
                })

            async def wait_for_close(self):
                self.emit({
                    "action": "fill",
                    "selector": {"by": "name", "value": "email"},
                    "field": {
                        "name": "email",
                        "type": "email",
                        "label": "Work email",
                    },
                })
                self.emit({
                    "action": "navigate",
                    "url": "https://app.sentinel-lab.test/verify",
                    "correlation_id": "lab:222222222222",
                })
                self.emit({
                    "action": "fill",
                    "selector": {"by": "name", "value": "code"},
                    "field": {"name": "code", "label": "Verification code"},
                })
                self.emit({
                    "action": "navigate",
                    "url": "https://app.sentinel-lab.test/app",
                    "correlation_id": "lab:333333333333",
                })

            async def close(self):
                return None

        fake = FakeDriver()

        async def launch(*_args, **_kwargs):
            return fake

        monkeypatch.setattr(GhostNativeDriver, "launch", launch)
        result = _run(record_recipe_endpoint(request, _=True))
        recipe = load_recipe(result["recipe_id"])

        assert recipe is not None
        assert recipe.visual_variant == "classic"
        assert recipe.secret_audit["status"] == "pass"
        assert recipe.provenance["correlation_ids"] == [
            "lab:111111111111",
            "lab:222222222222",
            "lab:333333333333",
        ]
        assert recipe.provenance["authorization"]["envelope_id"] == (
            request.envelope_id
        )
        assert recipe.challenge_steps()[0].challenge_kind.value == "email_code"
        assert all("vault-only-password" not in json.dumps(step.to_dict()) for step in recipe.steps)

    def test_recording_ending_on_http_error_is_not_persisted(
        self, monkeypatch
    ):
        from fastapi import HTTPException

        from core.foundry.driver_native import GhostNativeDriver
        from core.foundry.recipe_store import list_recipes
        from core.foundry.vault import PersonaVault
        from core.server.routers import driver as driver_router
        from core.server.routers.foundry import record_recipe_endpoint

        request = self._authorized_request()

        class FailedDriver:
            session_id = "failed-recording-session"
            close_count = 0

            async def start_recording(self):
                return None

            async def restrict_to_origins(self, origins):
                assert origins == ["https://app.sentinel-lab.test"]

            def emit(self, action):
                event = {
                    "event": "recorded_action",
                    "session_id": self.session_id,
                    "action": action,
                }
                for handler in list(driver_router.node_manager.event_handlers):
                    handler("recorded_action", event)

            async def navigate(self, url):
                self.emit({
                    "action": "navigate",
                    "url": url,
                    "response_status": 200,
                })

            async def wait_for_close(self):
                self.emit({
                    "action": "fill",
                    "selector": {"by": "name", "value": "email"},
                    "field": {"name": "email", "type": "email"},
                })
                self.emit({
                    "action": "click",
                    "selector": {"by": "role", "value": "button"},
                })
                self.emit({
                    "action": "navigate",
                    "url": "https://app.sentinel-lab.test/forbidden",
                    "response_status": 403,
                })

            async def close(self):
                self.close_count += 1

        failed = FailedDriver()

        async def launch(*_args, **_kwargs):
            return failed

        monkeypatch.setattr(GhostNativeDriver, "launch", launch)

        with pytest.raises(HTTPException) as exc:
            _run(record_recipe_endpoint(request, _=True))

        assert exc.value.status_code == 422
        assert "HTTP error (403)" in exc.value.detail
        assert list_recipes() == []
        assert failed.close_count == 1
        audit = PersonaVault().audit_records(
            persona_id=request.persona_id,
            service_handle=request.service_handle,
        )
        assert len(audit) == 1
        assert audit[0].outcome == "abandoned"


# ───────────────── behavioral primary planner ─────────────────


class TestBehavioralAuthorizationEndpoint:
    ORIGIN = "https://api.example.test"
    SOURCE_ID = "RlLB9Tjpk7YfkTaBB0SpzA"
    PEER_ID = "9QsBs4y23m6HH4aB38ffkA"

    def test_capture_budget_counts_utf8_bytes_across_both_personas(self):
        from core.server.routers.foundry import _behavioral_capture_bytes

        source = [{"value": "é"}]
        peer = [{"value": "é"}]

        assert _behavioral_capture_bytes(source, peer) == 28

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

    def _one_click_request(self):
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
        )

        request, source_persona, peer_persona = self._setup()
        return (
            RunBehavioralAuthorizationFromURLRequest(
                target_url=f"{self.ORIGIN}/app",
                envelope_id=request.envelope_id,
                source_persona_id=source_persona.persona_id,
                peer_persona_id=peer_persona.persona_id,
            ),
            request,
            source_persona,
            peer_persona,
        )

    def _omission_request(self):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.omission_confirmation import (
            FRESH_OMISSION_CONFIRMATION_WORKFLOW,
        )
        from core.behavior.omission_boundary import FRESH_OMISSION_WORKFLOW
        from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.foundry.vault import PersonaVault
        from core.server.routers.foundry import RunBehavioralAuthorizationRequest

        vault = PersonaVault()
        source_persona = vault.add_persona(
            label="source",
            email="source-omission@research.example",
        )
        peer_persona = vault.add_persona(
            label="peer",
            email="peer-omission@research.example",
        )
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                CONTROLLED_SEQUENCE_WORKFLOW,
                FRESH_OMISSION_WORKFLOW,
                FRESH_OMISSION_CONFIRMATION_WORKFLOW,
            ],
            disclosure_attestation=True,
        )
        captured_id = "workflow_7fa9f13a2b4c5d6e"
        captured_token = "token_4a5b6c7d8e9f0123"
        headers = {"x-csrf-token": f"csrf-{source_persona.persona_id}"}
        source_records = [
            {
                "persona_id": source_persona.persona_id,
                "method": "POST",
                "url": f"{self.ORIGIN}/api/workflows",
                "request_headers": headers,
                "request_body": '{"label":"controlled"}',
                "response_status": 201,
                "response_body": json.dumps({"workflowId": captured_id}),
            },
            {
                "persona_id": source_persona.persona_id,
                "method": "GET",
                "url": (
                    f"{self.ORIGIN}/api/workflows/{captured_id}/export-token"
                ),
                "request_headers": headers,
                "response_status": 200,
                "response_body": json.dumps(
                    {"exportToken": captured_token}
                ),
            },
            {
                "persona_id": source_persona.persona_id,
                "method": "GET",
                "url": (
                    f"{self.ORIGIN}/api/workflows/{captured_id}/export"
                    f"?format=json&exportToken={captured_token}"
                ),
                "request_headers": headers,
                "response_status": 200,
                "response_body": json.dumps(
                    {"status": "ready", "artifact": "controlled"}
                ),
            },
            {
                "persona_id": source_persona.persona_id,
                "method": "PATCH",
                "url": f"{self.ORIGIN}/api/workflows/{captured_id}",
                "request_headers": headers,
                "request_body": '{"archived":true}',
                "response_status": 200,
                "response_body": '{"archived":true}',
            },
        ]
        peer_records = [
            {
                "persona_id": peer_persona.persona_id,
                "method": "GET",
                "url": f"{self.ORIGIN}/api/status",
                "response_status": 200,
                "response_body": '{"status":"ok"}',
            }
        ]
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
        request.script_urls = [f"{self.ORIGIN}/assets/app.js"]
        request.interaction_page_url = f"{self.ORIGIN}/app"
        request.source_controls = [{
            "tag": "a",
            "role": "link",
            "input_type": "",
            "form_method": "none",
            "destination": "same_origin",
            "locator": [{"tag": "a", "sibling_index": 1}],
            "locator_truncated": False,
            "visible": True,
            "disabled": False,
            "content_editable": False,
            "aria_expanded": False,
            "aria_haspopup": False,
            "sensitive_form": False,
            "download": False,
            "scripted_handler": False,
            "submitter": False,
            "text": "must-not-be-retained",
        }]

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("disabled primary planner must not reach SND")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "disabled"
        assert result["plan"]["selected_proposal_id"]
        assert result["execution"] is None
        assert result["behavioral_shadow"]["status"] == "open"
        assert result["behavioral_shadow"]["executable"] is False
        assert result["behavioral_shadow"]["interactions"]["status"] == "ready"
        assert result["behavioral_shadow"]["interactions"]["executable"] is False
        assert result["behavioral_shadow"]["interaction_admission"]["status"] == (
            "no_open_acquisition_obligation"
        )
        assert result["behavioral_shadow"]["interaction_admission"]["admission"] is None
        assert result["behavioral_shadow"]["interaction_admission"]["executable"] is False
        assert "must-not-be-retained" not in str(
            result["behavioral_shadow"]["interactions"]
        )
        assert result["behavioral_shadow"]["selected"]["resolution_kind"] == (
            "authorization_proposal"
        )

    def test_invalid_envelope_blocks_resolver_traffic(self, monkeypatch):
        from fastapi import HTTPException

        from core.foundry import authorization as authorization_module
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import SNDReplayTransport

        request, _, _ = self._setup()
        request.script_urls = [f"{self.ORIGIN}/assets/app.js"]
        envelope = authorization_module.get_envelope(request.envelope_id)
        assert envelope is not None
        envelope.authorization_basis = "tampered after signing"
        monkeypatch.setattr(authorization_module, "get_envelope", lambda _envelope_id: envelope)
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("invalid envelope must block resolver transport")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "signature_mismatch" in error.value.detail

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
        assert result["plan"]["mode"] == "behavioral_closed_loop_resolver_v1"
        assert result["plan"]["selected_obligation_id"]
        assert result["finding"]["metadata"]["behavioral_primary_planner"]
        assert result["finding"]["metadata"]["behavioral_closed_loop_resolver"]
        assert result["behavioral_shadow"]["status"] == "finding"
        assert result["behavioral_shadow"]["closure"]["counts"]["violated"] == 1
        assert result["behavioral_shadow"]["receipt_feedback"]["status"] == "ready"
        assert result["behavioral_shadow"]["receipt_feedback"]["diagnostics"] == {
            "receipts_seen": 1,
            "dispositions_created": 1,
            "unbound_receipts": 0,
            "unsupported_receipts": 0,
        }
        assert calls[0][1].headers["x-csrf-token"] == f"csrf-{peer_persona.persona_id}"
        assert calls[1][1].headers["x-csrf-token"] == f"csrf-{source_persona.persona_id}"
        assert all(call[1].max_response_chars == 2 * 1024 * 1024 for call in calls)

    def test_adaptive_interaction_runs_bounded_chain_and_stops_at_four(
        self,
        monkeypatch,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.interaction_adaptive import (
            INTERACTION_ADAPTIVE_WORKFLOW,
        )
        from core.behavior.interaction_boundary import (
            INTERACTION_ACQUISITION_WORKFLOW,
        )
        from core.behavior.interaction_render import (
            INTERACTION_RENDER_WORKFLOW,
        )
        from core.foundry.authorization import create_envelope
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                INTERACTION_ACQUISITION_WORKFLOW,
                INTERACTION_RENDER_WORKFLOW,
                INTERACTION_ADAPTIVE_WORKFLOW,
            ],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id

        def mutation_record(persona_id, object_id):
            return {
                "persona_id": persona_id,
                "method": "POST",
                "url": f"{self.ORIGIN}/gql",
                "request_body": json.dumps(
                    {
                        "operationName": "UpdateThing",
                        "query": (
                            "mutation UpdateThing($id:ID!){"
                            "updateThing(id:$id){id}}"
                        ),
                        "variables": {"id": object_id},
                    }
                ),
                "response_status": 200,
                "response_body": "{}",
            }

        request.source_records = [
            mutation_record(source_persona.persona_id, "source-owned")
        ]
        request.peer_records = [
            mutation_record(peer_persona.persona_id, "peer-owned")
        ]
        request.interaction_page_url = f"{self.ORIGIN}/app"
        control = {
            "tag": "a",
            "role": "link",
            "input_type": "",
            "form_method": "none",
            "destination": "same_origin",
            "locator": [
                {"tag": "html", "sibling_index": 1},
                {"tag": "body", "sibling_index": 1},
                {"tag": "a", "sibling_index": 1},
            ],
            "locator_truncated": False,
            "visible": True,
            "disabled": False,
            "content_editable": False,
            "aria_expanded": False,
            "aria_haspopup": False,
            "sensitive_form": False,
            "download": False,
            "scripted_handler": False,
            "submitter": False,
        }
        request.source_controls = [control]
        request.peer_controls = []
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ADAPTIVE",
        ):
            monkeypatch.setenv(name, "1")
        monkeypatch.delenv(
            "SENTINELFORGE_BEHAVIOR_INTERACTION_SECOND_TRANSITION",
            raising=False,
        )

        sent = []

        async def fake_send(_transport, persona, replay_request):
            sent.append((persona, replay_request))
            return ReplayResponse(
                200,
                '<html><body><a href="/next">Next</a></body></html>',
            )

        async def resolve_live(persona_id, locator, peer_persona_id=None):
            return {
                "current_url": request.interaction_page_url,
                "destination_url": f"{self.ORIGIN}/step-1",
                "control": control,
                "catalog_controls": [control],
                "peer_catalog_controls": (),
            }

        async def resolve_response(
            persona_id,
            locator,
            *,
            base_url,
            html,
        ):
            step = int(base_url.rsplit("-", 1)[1])
            return {
                "current_url": base_url,
                "destination_url": f"{self.ORIGIN}/step-{step + 1}",
                "control": control,
                "catalog_controls": [control],
                "peer_catalog_controls": (),
            }

        async def inspect_response(persona_id, *, base_url, html):
            return {
                "base_url": base_url,
                "controls": [control],
                "scanned_nodes": 1,
                "controls_truncated": False,
                "bytes_inspected": len(html.encode()),
                "target_requests_sent": 0,
            }

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        monkeypatch.setattr(
            driver,
            "resolve_interaction_navigation",
            resolve_live,
        )
        monkeypatch.setattr(
            driver,
            "resolve_interaction_response_navigation",
            resolve_response,
        )
        monkeypatch.setattr(
            driver,
            "inspect_interaction_response",
            inspect_response,
        )

        result = _run(
            run_behavioral_authorization_endpoint(request, _=True)
        )

        adaptive = result["interaction_acquisition"]["adaptive_chain"]
        assert adaptive["status"] == "completed"
        assert adaptive["transition_count"] == 4
        assert adaptive["target_requests_sent"] == 3
        assert [item["step_index"] for item in adaptive["steps"]] == [
            2,
            3,
            4,
        ]
        assert "transition_limit" in adaptive["stop_reasons"]
        assert [item[1].url for item in sent] == [
            f"{self.ORIGIN}/step-1",
            f"{self.ORIGIN}/step-2",
            f"{self.ORIGIN}/step-3",
            f"{self.ORIGIN}/step-4",
        ]

    def test_adaptive_chain_seals_new_proof_and_receipt_binding(
        self,
        monkeypatch,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.interaction_adaptive import (
            INTERACTION_ADAPTIVE_WORKFLOW,
        )
        from core.behavior.interaction_boundary import (
            INTERACTION_ACQUISITION_WORKFLOW,
        )
        from core.behavior.interaction_render import (
            INTERACTION_RENDER_WORKFLOW,
        )
        from core.behavior.receipts import BehavioralReceiptStore
        from core.foundry.authorization import create_envelope
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                INTERACTION_ACQUISITION_WORKFLOW,
                INTERACTION_RENDER_WORKFLOW,
                INTERACTION_ADAPTIVE_WORKFLOW,
            ],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id

        def mutation_record(persona_id, object_id):
            return {
                "persona_id": persona_id,
                "method": "POST",
                "url": f"{self.ORIGIN}/gql",
                "request_body": json.dumps(
                    {
                        "operationName": "UpdateThing",
                        "query": (
                            "mutation UpdateThing($id:ID!){"
                            "updateThing(id:$id){id}}"
                        ),
                        "variables": {"id": object_id},
                    }
                ),
                "response_status": 200,
                "response_body": "{}",
            }

        request.source_records = [
            mutation_record(source_persona.persona_id, "source-owned")
        ]
        request.peer_records = [
            mutation_record(peer_persona.persona_id, "peer-owned"),
            {
                "persona_id": peer_persona.persona_id,
                "method": "GET",
                "url": f"{self.ORIGIN}/api/documents/{self.PEER_ID}",
                "response_status": 200,
                "response_body": '{"owner":"PeerPrivateMarker"}',
            },
        ]
        request.interaction_page_url = f"{self.ORIGIN}/app"
        control = {
            "tag": "a",
            "role": "link",
            "input_type": "",
            "form_method": "none",
            "destination": "same_origin",
            "locator": [
                {"tag": "html", "sibling_index": 1},
                {"tag": "body", "sibling_index": 1},
                {"tag": "a", "sibling_index": 1},
            ],
            "locator_truncated": False,
            "visible": True,
            "disabled": False,
            "content_editable": False,
            "aria_expanded": False,
            "aria_haspopup": False,
            "sensitive_form": False,
            "download": False,
            "scripted_handler": False,
            "submitter": False,
        }
        request.source_controls = [control]
        request.peer_controls = []
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ADAPTIVE",
        ):
            monkeypatch.setenv(name, "1")
        monkeypatch.delenv(
            "SENTINELFORGE_BEHAVIOR_INTERACTION_SECOND_TRANSITION",
            raising=False,
        )

        sent = []

        async def fake_send(_transport, persona, replay_request):
            sent.append((persona, replay_request))
            if replay_request.url.endswith("/discovery"):
                return ReplayResponse(
                    200,
                    (
                        "<html><body><a href="
                        f'"/api/documents/{self.SOURCE_ID}">Document</a>'
                        "</body></html>"
                    ),
                )
            if persona == peer_persona.persona_id:
                return ReplayResponse(
                    200,
                    '{"owner":"PeerPrivateMarker"}',
                )
            if self.SOURCE_ID in replay_request.url:
                return ReplayResponse(
                    200,
                    '{"owner":"SourcePrivateMarker"}',
                )
            return ReplayResponse(
                200,
                '{"owner":"PeerPrivateMarker"}',
            )

        async def resolve_live(persona_id, locator, peer_persona_id=None):
            return {
                "current_url": request.interaction_page_url,
                "destination_url": f"{self.ORIGIN}/discovery",
                "control": control,
                "catalog_controls": [control],
                "peer_catalog_controls": (),
            }

        async def resolve_response(
            persona_id,
            locator,
            *,
            base_url,
            html,
        ):
            return {
                "current_url": base_url,
                "destination_url": (
                    f"{self.ORIGIN}/api/documents/{self.SOURCE_ID}"
                ),
                "control": control,
                "catalog_controls": [control],
                "peer_catalog_controls": (),
            }

        async def inspect_response(persona_id, *, base_url, html):
            return {
                "base_url": base_url,
                "controls": [control],
                "scanned_nodes": 1,
                "controls_truncated": False,
                "bytes_inspected": len(html.encode()),
                "target_requests_sent": 0,
            }

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        monkeypatch.setattr(
            driver,
            "resolve_interaction_navigation",
            resolve_live,
        )
        monkeypatch.setattr(
            driver,
            "resolve_interaction_response_navigation",
            resolve_response,
        )
        monkeypatch.setattr(
            driver,
            "inspect_interaction_response",
            inspect_response,
        )

        result = _run(
            run_behavioral_authorization_endpoint(request, _=True)
        )

        handoff = result["adaptive_proof_handoff"]
        assert handoff["status"] == "ready"
        assert handoff["target_requests_sent"] == 0
        assert handoff["resolution_kind"] == "authorization_proposal"
        assert handoff["obligation_id"] == (
            result["plan"]["selected_obligation_id"]
        )
        assert handoff["resolution_ref"] == (
            result["plan"]["selected_proposal_id"]
        )
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["finding"] is not None
        metadata = result["finding"]["metadata"]
        assert metadata["behavioral_adaptive_proof_handoff"] == handoff
        assert metadata["behavioral_adaptive_proof_receipt"] == {
            "handoff_id": handoff["handoff_id"],
            "receipt_id": result["receipt"]["receipt_id"],
        }
        feedback = result["behavioral_shadow"]["receipt_feedback"]
        assert handoff["handoff_id"] in (
            feedback["dispositions"][0]["evidence_refs"]
        )
        stored = BehavioralReceiptStore().load(
            result["receipt"]["receipt_id"].removeprefix("behavioral-")
        )
        assert stored is not None and stored.outcome is not None
        assert stored.outcome["adaptive_proof_handoff"] == handoff
        assert len(sent) == 6
        assert [item[1].redirect_mode for item in sent[:3]] == [
            "manual",
            "manual",
            "manual",
        ]
        assert [item[1].redirect_mode for item in sent[3:]] == [
            "follow",
            "follow",
            "follow",
        ]

    def test_foundry_executes_reports_and_deduplicates_exact_omission_proof(
        self,
        monkeypatch,
        tmp_path,
    ):
        from urllib.parse import urlsplit

        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._omission_request()
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_CONFIRMATION",
        ):
            monkeypatch.setenv(name, "1")

        baseline_id = "workflow_fresh_baseline_8b9c0d1e2f3a"
        omission_id = "workflow_fresh_omission_5b6c7d8e9f0a"
        control_id = "workflow_fresh_control_2c3d4e5f6a7b"
        baseline_token = "token_fresh_baseline_12345678"
        fresh_ids = iter((baseline_id, omission_id, control_id))
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            assert persona == source_persona.persona_id
            path = urlsplit(replay_request.url).path
            if replay_request.method == "POST":
                return ReplayResponse(
                    201,
                    json.dumps({"workflowId": next(fresh_ids)}),
                )
            if replay_request.method == "PATCH":
                return ReplayResponse(200, '{"archived":true}')
            if path.endswith("/export-token"):
                return ReplayResponse(
                    200,
                    json.dumps({"exportToken": baseline_token}),
                )
            if control_id in path:
                return ReplayResponse(403, '{"error":"wrong workflow"}')
            return ReplayResponse(
                200,
                '{"status":"ready","artifact":"controlled"}',
            )

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))
        duplicate = _run(
            run_behavioral_authorization_endpoint(request, _=True)
        )

        assert result["status"] == "completed"
        assert result["plan"]["selected"]["resolution_kind"] == (
            "omission_experiment"
        )
        assert result["execution"]["reused"] is False
        proof = result["execution"]["execution"]
        assert proof["kind"] == "fresh_omission_confirmation"
        assert proof["confirmation_status"] == "confirmed_fail_open"
        assert proof["requests_sent"] == 10
        assert proof["creates_completed"] == 3
        assert proof["cleanup_steps_completed"] == 3
        assert proof["finding_authority"] is True
        assert result["finding"]["id"] == proof["finding_ref"]
        assert result["finding"]["metadata"]["subtype"] == (
            "prerequisite_omission_fail_open"
        )
        assert result["behavioral_shadow"]["status"] == "finding"
        assert result["behavioral_shadow"]["receipt_feedback"]["status"] == (
            "ready"
        )
        assert result["behavioral_shadow"]["receipt_feedback"]["diagnostics"] == {
            "receipts_seen": 1,
            "dispositions_created": 1,
            "unbound_receipts": 0,
            "unsupported_receipts": 0,
        }
        assert duplicate["status"] == "already_executed"
        assert duplicate["kind"] == "fresh_omission_confirmation"
        assert duplicate["finding_ref"] == proof["finding_ref"]
        assert len(calls) == 10

        receipts = list(
            (tmp_path / "behavioral_receipts").glob("behavioral-*.json")
        )
        assert len(receipts) == 2
        persisted = "".join(path.read_text() for path in receipts)
        for raw in (
            self.ORIGIN,
            "workflow_7fa9f13a2b4c5d6e",
            "token_4a5b6c7d8e9f0123",
            baseline_id,
            omission_id,
            control_id,
            baseline_token,
            source_persona.persona_id,
            peer_persona.persona_id,
            "controlled",
        ):
            assert raw not in persisted

    def test_foundry_defers_omission_when_confirmation_gates_are_off(
        self,
        monkeypatch,
    ):
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        request, _source_persona, _peer_persona = self._omission_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError(
                "disabled omission confirmation must not reach transport"
            )

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "no_executable_candidate"
        assert result["execution"] is None
        omission = next(
            item
            for item in result["plan"]["ranked"]
            if item["resolution_kind"] == "omission_experiment"
        )
        assert omission["actionable"] is True
        assert result["plan"]["selected"] is None

    def test_foundry_omission_requires_signed_workflow_before_traffic(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.omission_confirmation import (
            FRESH_OMISSION_CONFIRMATION_WORKFLOW,
        )
        from core.behavior.omission_boundary import FRESH_OMISSION_WORKFLOW
        from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        request, _source_persona, _peer_persona = self._omission_request()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                CONTROLLED_SEQUENCE_WORKFLOW,
                FRESH_OMISSION_WORKFLOW,
            ],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_CONFIRMATION",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("missing workflow must block target traffic")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert FRESH_OMISSION_CONFIRMATION_WORKFLOW not in (
            envelope.allowed_workflows
        )
        assert not (tmp_path / "behavioral_receipts").exists()

    def test_foundry_revalidates_omission_binding_before_transport(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.behavior.omission_confirmation import (
            FreshOmissionConfirmationAdmission,
        )
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        request, _source_persona, _peer_persona = self._omission_request()
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_CONFIRMATION",
        ):
            monkeypatch.setenv(name, "1")
        fingerprints = iter(("a" * 64, "a" * 64, "b" * 64))

        def changed_binding(_admission):
            return next(fingerprints)

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("changed binding must block target traffic")

        monkeypatch.setattr(
            FreshOmissionConfirmationAdmission,
            "validate_preflight",
            changed_binding,
        )
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 500
        assert "binding_changed_after_selection" in error.value.detail
        receipts = list(
            (tmp_path / "behavioral_receipts").glob("behavioral-*.json")
        )
        assert len(receipts) == 1
        stored = json.loads(receipts[0].read_text())
        assert stored["state"] == "aborted"
        assert stored["abort_reason"] == "closed_loop_resolver_error"

    def test_bounded_continuation_runs_second_progressing_obligation_and_stops(
        self,
        monkeypatch,
        tmp_path,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.continuation import CONTINUATION_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[CONTROLLED_WORKFLOW, CONTINUATION_WORKFLOW],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id

        def record(persona_id, noun, resource_id, marker):
            return {
                "persona_id": persona_id,
                "method": "GET",
                "url": f"{self.ORIGIN}/api/{noun}/{resource_id}",
                "request_headers": {"x-csrf-token": f"csrf-{persona_id}"},
                "response_status": 200,
                "response_body": json.dumps({"owner": marker}),
            }

        request.source_records = [
            record(
                source_persona.persona_id,
                "documents",
                "doc_source_7fa9f13a2b4c",
                "source-private-marker",
            ),
            record(
                source_persona.persona_id,
                "invoices",
                "invoice_source_7fa9f13a2b4c",
                "source-private-marker",
            ),
        ]
        request.peer_records = [
            record(
                peer_persona.persona_id,
                "documents",
                "doc_peer_4a5b6c7d8e9f0",
                "peer-private-marker",
            ),
            record(
                peer_persona.persona_id,
                "invoices",
                "invoice_peer_4a5b6c7d8e9f0",
                "peer-private-marker",
            ),
        ]
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            position = (len(calls) - 1) % 3
            round_index = (len(calls) - 1) // 3
            if position == 0:
                return ReplayResponse(200, '{"owner":"peer-private-marker"}')
            if position == 1:
                return ReplayResponse(200, '{"owner":"source-private-marker"}')
            if round_index == 0:
                return ReplayResponse(403, '{"error":"forbidden"}')
            return ReplayResponse(200, '{"owner":"peer-private-marker"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))
        duplicate = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["continuation"]["stop_reason"] == "finding_confirmed"
        assert result["continuation"]["total_requests_sent"] == 6
        assert [
            item["legacy_verdict"] for item in result["continuation"]["rounds"]
        ] == ["DENIED", "BOLA_CONFIRMED"]
        assert len(
            {
                item["obligation_id"]
                for item in result["continuation"]["rounds"]
            }
        ) == 2
        assert result["behavioral_shadow"]["status"] == "finding"
        assert duplicate["status"] == "already_executed"
        assert duplicate["continuation"]["stop_reason"] == "finding_confirmed"
        assert len(calls) == 6
        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 3
        persisted = "".join(path.read_text() for path in receipts)
        for raw in (
            self.ORIGIN,
            "doc_source_7fa9f13a2b4c",
            "invoice_peer_4a5b6c7d8e9f0",
            "source-private-marker",
            "peer-private-marker",
        ):
            assert raw not in persisted

    def test_bounded_continuation_requires_separate_workflow_before_traffic(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import SNDReplayTransport

        request, _, _ = self._setup()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("missing continuation workflow must block traffic")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "bounded_continuation_authorization_denied" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()

    def test_bounded_continuation_stops_immediately_after_first_finding(
        self,
        monkeypatch,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.continuation import CONTINUATION_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[CONTROLLED_WORKFLOW, CONTINUATION_WORKFLOW],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")
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

        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["continuation"]["stop_reason"] == "finding_confirmed"
        assert len(result["continuation"]["rounds"]) == 1
        assert len(calls) == 3

    def test_invalid_continuation_result_aborts_root_after_terminal_round(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.continuation import (
            CONTINUATION_WORKFLOW,
            BoundedContinuationController,
            BoundedContinuationDenied,
        )
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[CONTROLLED_WORKFLOW, CONTINUATION_WORKFLOW],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if persona == peer_persona.persona_id:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            if self.SOURCE_ID in (replay_request.body or ""):
                return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')
            return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')

        def invalid_finish(*_args, **_kwargs):
            raise BoundedContinuationDenied("invalid test transcript")

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        monkeypatch.setattr(BoundedContinuationController, "finish", invalid_finish)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 500
        assert "result was invalid" in error.value.detail
        assert len(calls) == 3
        receipts = [
            json.loads(path.read_text())
            for path in (tmp_path / "behavioral_receipts").glob("*.json")
        ]
        assert sorted(receipt["state"] for receipt in receipts) == [
            "aborted",
            "completed",
        ]
        assert next(
            receipt for receipt in receipts if receipt["state"] == "aborted"
        )["abort_reason"] == "continuation_result_invalid"

    def test_frontier_defers_preparatory_setup_and_dispatches_exact_auth_obligation(
        self, monkeypatch
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[CONTROLLED_WORKFLOW, CONTROLLED_SEQUENCE_WORKFLOW],
            disclosure_attestation=True,
        )
        note_id = "note_7fa9f13a2b4c5d6e"
        request.envelope_id = envelope.envelope_id
        request.source_records = [
            {
                "persona_id": source_persona.persona_id,
                "method": "POST",
                "url": f"{self.ORIGIN}/api/notes",
                "request_body": '{"title":"controlled marker"}',
                "response_status": 201,
                "response_body": json.dumps({"noteId": note_id}),
            },
            {
                "persona_id": source_persona.persona_id,
                "method": "GET",
                "url": f"{self.ORIGIN}/api/notes/{note_id}",
                "response_status": 200,
                "response_body": '{"title":"controlled marker"}',
            },
            {
                "persona_id": source_persona.persona_id,
                "method": "PATCH",
                "url": f"{self.ORIGIN}/api/notes/{note_id}",
                "request_body": '{"archived":true}',
                "response_status": 200,
                "response_body": '{"archived":true}',
            },
            request.source_records[0],
        ]
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
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["plan"]["selected"]["frontier_index"] == 1
        assert result["plan"]["diagnostics"]["deferred_preparatory_items"] == 1
        assert result["plan"]["selected_obligation_id"] != (
            result["behavioral_shadow"].get("selected") or {}
        ).get("obligation_id")
        assert len(calls) == 3

    def test_fresh_owned_frontier_creates_proves_and_cleans_both_personas(
        self,
        monkeypatch,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[CONTROLLED_WORKFLOW, CONTROLLED_SEQUENCE_WORKFLOW],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id
        source_captured = "note_source_7fa9f13a2b4c"
        peer_captured = "note_peer_4a5b6c7d8e9f0"
        source_fresh = "note_fresh_source_8b9c0d1e2f3a4"
        peer_fresh = "note_fresh_peer_5b6c7d8e9f0a1"

        def lifecycle(persona_id, object_id, marker):
            headers = {"x-csrf-token": f"csrf-{persona_id}"}
            return [
                {
                    "persona_id": persona_id,
                    "method": "POST",
                    "url": f"{self.ORIGIN}/api/notes",
                    "request_headers": headers,
                    "request_body": '{"title":"controlled marker"}',
                    "response_status": 201,
                    "response_body": json.dumps({"noteId": object_id}),
                },
                {
                    "persona_id": persona_id,
                    "method": "GET",
                    "url": f"{self.ORIGIN}/api/notes/{object_id}",
                    "request_headers": headers,
                    "response_status": 200,
                    "response_body": json.dumps({"owner": marker}),
                },
                {
                    "persona_id": persona_id,
                    "method": "PATCH",
                    "url": f"{self.ORIGIN}/api/notes/{object_id}",
                    "request_headers": headers,
                    "request_body": '{"archived":true}',
                    "response_status": 200,
                    "response_body": '{"archived":true}',
                },
            ]

        request.source_records = lifecycle(
            source_persona.persona_id,
            source_captured,
            "source-captured-private",
        )
        request.peer_records = lifecycle(
            peer_persona.persona_id,
            peer_captured,
            "peer-captured-private",
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if replay_request.method == "POST":
                object_id = (
                    source_fresh
                    if persona == source_persona.persona_id
                    else peer_fresh
                )
                return ReplayResponse(201, json.dumps({"noteId": object_id}))
            if replay_request.method == "PATCH":
                return ReplayResponse(200, '{"archived":true}')
            if source_fresh in replay_request.url:
                return ReplayResponse(200, '{"owner":"source-fresh-private"}')
            return ReplayResponse(200, '{"owner":"peer-fresh-private"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert result["plan"]["selected"]["resolution_kind"] == "owned_experiment"
        assert result["plan"]["selected"]["frontier_index"] == 0
        assert result["execution"]["kind"] == "fresh_owned_boundary"
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["execution"]["requests_sent"] == 7
        assert result["execution"]["cleanup_steps_completed"] == 2
        assert result["finding"]["metadata"]["behavioral_fresh_owned_boundary"]
        assert result["behavioral_shadow"]["status"] == "finding"
        assert result["behavioral_shadow"]["receipt_feedback"]["status"] == "ready"
        assert [
            (persona, replay_request.method)
            for persona, replay_request in calls
        ] == [
            (source_persona.persona_id, "POST"),
            (peer_persona.persona_id, "POST"),
            (source_persona.persona_id, "GET"),
            (peer_persona.persona_id, "GET"),
            (peer_persona.persona_id, "GET"),
            (peer_persona.persona_id, "PATCH"),
            (source_persona.persona_id, "PATCH"),
        ]

    def test_enabled_route_refuses_execution_when_obligation_frontier_fails(
        self, monkeypatch, tmp_path
    ):
        from fastapi import HTTPException

        from core.behavior.orchestrator import BehavioralShadowOrchestrator
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import SNDReplayTransport

        request, _, _ = self._setup()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        def broken_frontier(*_args, **_kwargs):
            raise RuntimeError("frontier failed")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("a missing frontier must block target traffic")

        monkeypatch.setattr(BehavioralShadowOrchestrator, "run", broken_frontier)
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 500
        assert "frontier failed; execution refused" in error.value.detail
        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 1
        assert json.loads(receipts[0].read_text())["state"] == "aborted"

    def test_truncated_baseline_cannot_reach_counterfactual_or_confirm(self, monkeypatch):
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if persona == peer_persona.persona_id:
                return ReplayResponse(
                    200,
                    '{"owner":"PeerPrivateMarker"}',
                    body_truncated=True,
                )
            return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert result["execution"]["legacy_verdict"] == "AMBIGUOUS"
        assert result["execution"]["requests_attempted"] == 2
        assert result["execution"]["restraint"]["stopped_after_first_proof"] is False
        assert result["finding"] is None
        assert result["behavioral_shadow"]["status"] == "blocked"
        assert result["behavioral_shadow"]["closure"]["counts"]["blocked"] == 1
        assert result["behavioral_shadow"]["receipt_feedback"]["status"] == "ready"
        assert len(calls) == 2

    def test_top_level_url_records_execute_as_generic_rest_proof(self, monkeypatch):
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationRequest,
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        base_request, source_persona, peer_persona = self._setup()
        request = RunBehavioralAuthorizationRequest(
            **{
                **base_request.model_dump(),
                "source_records": [{
                    "type": "navigation",
                    "method": "GET",
                    "url": f"{self.ORIGIN}/v1/documents/{self.SOURCE_ID}",
                    "response_status": 200,
                    "response_body": '{"owner":"SourcePrivateMarker"}',
                }],
                "peer_records": [{
                    "type": "navigation",
                    "method": "GET",
                    "url": f"{self.ORIGIN}/v1/documents/{self.PEER_ID}",
                    "response_status": 200,
                    "response_body": '{"owner":"PeerPrivateMarker"}',
                }],
            }
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if persona == peer_persona.persona_id or self.PEER_ID in replay_request.url:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert len(calls) == 3
        assert calls[0][1].url.endswith(self.PEER_ID)
        assert calls[1][1].url.endswith(self.SOURCE_ID)
        assert calls[2][1].url.endswith(self.PEER_ID)

    def test_identical_enabled_request_reuses_receipt_without_target_traffic(
        self, monkeypatch
    ):
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
        first = _run(run_behavioral_authorization_endpoint(request, _=True))
        duplicate = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert first["status"] == "completed"
        assert first["receipt"]["state"] == "completed"
        assert first["receipt"]["reused"] is False
        assert duplicate["status"] == "already_executed"
        assert duplicate["receipt"]["receipt_id"] == first["receipt"]["receipt_id"]
        assert duplicate["receipt"]["reused"] is True
        assert duplicate["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert duplicate["finding"] is None
        assert duplicate["finding_confirmed"] is True
        assert len(calls) == 3

    def test_concurrent_enabled_request_is_blocked_while_receipt_is_reserved(
        self, monkeypatch
    ):
        from fastapi import HTTPException

        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, source_persona, peer_persona = self._setup()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        entered_transport = asyncio.Event()
        release_transport = asyncio.Event()
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if len(calls) == 1:
                entered_transport.set()
                await release_transport.wait()
            if persona == peer_persona.persona_id:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            if self.SOURCE_ID in (replay_request.body or ""):
                return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')
            return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)

        async def run_concurrently():
            first_task = asyncio.create_task(
                run_behavioral_authorization_endpoint(request, _=True)
            )
            await entered_transport.wait()
            try:
                with pytest.raises(HTTPException) as duplicate_error:
                    await run_behavioral_authorization_endpoint(request, _=True)
            finally:
                release_transport.set()
            return await first_task, duplicate_error.value

        first, duplicate_error = _run(run_concurrently())

        assert first["status"] == "completed"
        assert duplicate_error.status_code == 409
        assert "state=reserved" in duplicate_error.detail
        assert len(calls) == 3

    def test_enabled_endpoint_resolves_persisted_query_through_policy(self, monkeypatch):
        import hashlib
        import json

        from core.server.routers.foundry import (
            RunBehavioralAuthorizationRequest,
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        base_request, source_persona, peer_persona = self._setup()
        document = (
            "query GetPrivateObject($BizEncId: ID!) "
            "{ privateObject(id: $BizEncId) { id } }"
        )
        digest = hashlib.sha256(document.encode()).hexdigest()

        def persisted(resource_id, marker):
            return {
                "method": "POST",
                "url": f"{self.ORIGIN}/gql/batch",
                "request_headers": {"content-type": "application/json"},
                "request_body": json.dumps([{
                    "operationName": "GetPrivateObject",
                    "variables": {"BizEncId": resource_id},
                    "extensions": {
                        "persistedQuery": {"version": 1, "sha256Hash": digest}
                    },
                }]),
                "response_body": json.dumps({"owner": marker}),
            }

        request = RunBehavioralAuthorizationRequest(
            **{
                **base_request.model_dump(),
                "source_records": [persisted(self.SOURCE_ID, "SourcePrivateMarker")],
                "peer_records": [persisted(self.PEER_ID, "PeerPrivateMarker")],
                "script_urls": [f"{self.ORIGIN}/assets/app.js"],
            }
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        calls = []

        async def fake_send(_transport, persona, replay_request):
            calls.append((persona, replay_request))
            if replay_request.url.endswith("/assets/app.js"):
                return ReplayResponse(200, f"const operation = {json.dumps(document)};")
            if persona == peer_persona.persona_id:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            if self.SOURCE_ID in (replay_request.body or ""):
                return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')
            return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')

        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["graphql_resolution"]["assets"] == {
            "attempted": 1,
            "fetched": 1,
            "failed": 0,
            "documents_added": 1,
        }
        assert result["graphql_resolution"]["source"]["resolved_operations"] == 1
        assert len(calls) == 4
        assert calls[0][1].max_response_chars == 2 * 1024 * 1024

    def test_one_click_disabled_refuses_before_native_driver_or_receipt(
        self, monkeypatch, tmp_path
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("disabled one-click path must not reach SND")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "SENTINELFORGE_BEHAVIOR_PRIMARY=1" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_continuation_workflow_denial_precedes_native_capture(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("workflow denial must precede native capture")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "bounded_continuation_authorization_denied" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()

    def test_one_click_adaptive_workflow_denial_precedes_native_capture(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.interaction_adaptive import (
            INTERACTION_ADAPTIVE_WORKFLOW,
        )
        from core.behavior.interaction_boundary import (
            INTERACTION_ACQUISITION_WORKFLOW,
        )
        from core.behavior.interaction_render import (
            INTERACTION_RENDER_WORKFLOW,
        )
        from core.foundry.authorization import create_envelope
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                INTERACTION_ACQUISITION_WORKFLOW,
                INTERACTION_RENDER_WORKFLOW,
            ],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ADAPTIVE",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError(
                "adaptive workflow denial must precede native capture"
            )

        monkeypatch.setattr(driver, "ensure_capture_available", forbidden)
        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(
                run_behavioral_authorization_from_url_endpoint(
                    request,
                    _=True,
                )
            )

        assert error.value.status_code == 409
        assert INTERACTION_ADAPTIVE_WORKFLOW not in (
            envelope.allowed_workflows
        )
        assert "missing signed workflow" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_rejects_competing_interaction_controllers_before_capture(
        self,
        monkeypatch,
    ):
        from fastapi import HTTPException

        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.interaction_adaptive import (
            INTERACTION_ADAPTIVE_WORKFLOW,
        )
        from core.behavior.interaction_boundary import (
            INTERACTION_ACQUISITION_WORKFLOW,
        )
        from core.behavior.interaction_render import (
            INTERACTION_RENDER_WORKFLOW,
        )
        from core.behavior.interaction_second_transition import (
            INTERACTION_SECOND_TRANSITION_WORKFLOW,
        )
        from core.foundry.authorization import create_envelope
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="public bounty scope",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                INTERACTION_ACQUISITION_WORKFLOW,
                INTERACTION_RENDER_WORKFLOW,
                INTERACTION_SECOND_TRANSITION_WORKFLOW,
                INTERACTION_ADAPTIVE_WORKFLOW,
            ],
            disclosure_attestation=True,
        )
        request.envelope_id = envelope.envelope_id
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_SECOND_TRANSITION",
            "SENTINELFORGE_BEHAVIOR_INTERACTION_ADAPTIVE",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError(
                "competing interaction modes must fail before capture"
            )

        monkeypatch.setattr(driver, "ensure_capture_available", forbidden)
        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(
                run_behavioral_authorization_from_url_endpoint(
                    request,
                    _=True,
                )
            )

        assert error.value.status_code == 409
        assert "mutually exclusive" in error.value.detail

    def test_one_click_omission_workflow_denial_precedes_native_capture(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_COMPILED_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_EXECUTION",
            "SENTINELFORGE_BEHAVIOR_OMISSION_CONFIRMATION",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError(
                "missing omission workflows must block native capture"
            )

        monkeypatch.setattr(driver, "ensure_capture_available", forbidden)
        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        with pytest.raises(HTTPException) as error:
            _run(
                run_behavioral_authorization_from_url_endpoint(
                    request,
                    _=True,
                )
            )

        assert error.value.status_code == 409
        assert "missing signed workflows" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_tampered_envelope_refuses_before_native_driver(
        self, monkeypatch, tmp_path
    ):
        from fastapi import HTTPException

        from core.foundry import authorization as authorization_module
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        envelope = authorization_module.get_envelope(request.envelope_id)
        assert envelope is not None
        envelope.authorization_basis = "tampered after signing"
        monkeypatch.setattr(
            authorization_module,
            "get_envelope",
            lambda _envelope_id: envelope,
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("invalid envelope must not reach SND")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "signature_mismatch" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_out_of_scope_url_refuses_before_native_driver(
        self, monkeypatch, tmp_path
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        request.target_url = "https://out-of-scope.example.test/private"
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("out-of-scope URL must not reach SND")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "denied_execution" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_missing_persona_window_refuses_before_reservation(
        self, monkeypatch, tmp_path
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def missing(*_args, **_kwargs):
            raise driver.PersonaWindowUnavailable("peer window missing")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("missing window must prevent capture")

        monkeypatch.setattr(driver, "validate_persona_windows", missing)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "peer window missing" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_busy_capture_seam_refuses_before_window_check_or_receipt(
        self, monkeypatch, tmp_path
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, _, _, _ = self._one_click_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setattr(driver, "ACTIVE_CAPTURE_OWNER_ID", "manual:active")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("busy capture seam must fail before SND commands")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "already active" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()
        assert not (tmp_path / "captures").exists()

    def test_one_click_captures_once_executes_once_and_reuses_intent_receipt(
        self, monkeypatch, tmp_path
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, capture_request, source_persona, peer_persona = self._one_click_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        window_checks = 0
        captures = 0
        traffic = []

        async def validate_windows(persona_ids):
            nonlocal window_checks
            window_checks += 1
            assert tuple(persona_ids) == (
                source_persona.persona_id,
                peer_persona.persona_id,
            )

        async def capture_pair(**kwargs):
            nonlocal captures
            captures += 1
            assert kwargs == {
                "target_url": f"{self.ORIGIN}/app",
                "source_persona_id": source_persona.persona_id,
                "peer_persona_id": peer_persona.persona_id,
            }
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/source-capture.jsonl",
                    records=tuple(capture_request.source_records),
                    captured_bytes=123,
                    limit_reached=False,
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/peer-capture.jsonl",
                    records=tuple(capture_request.peer_records),
                    captured_bytes=456,
                    limit_reached=False,
                ),
                (),
            )

        async def fake_send(_transport, persona, replay_request):
            traffic.append((persona, replay_request))
            if persona == peer_persona.persona_id:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            if self.SOURCE_ID in (replay_request.body or ""):
                return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')
            return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)

        first = _run(run_behavioral_authorization_from_url_endpoint(request, _=True))
        duplicate = _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert first["status"] == "completed"
        assert first["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert first["capture_pair"] == {
            "source": {"records": 1, "bytes": 123, "limit_reached": False},
            "peer": {"records": 1, "bytes": 456, "limit_reached": False},
        }
        assert first["orchestration_receipt"]["reused"] is False
        assert "/private/" not in str(first)
        assert duplicate["status"] == "already_executed"
        assert duplicate["orchestration_receipt"] == {
            "receipt_id": first["orchestration_receipt"]["receipt_id"],
            "state": "completed",
            "reused": True,
        }
        assert duplicate["finding"] is None
        assert duplicate["finding_confirmed"] is True
        assert window_checks == 1
        assert captures == 1
        assert len(traffic) == 3
        assert len(list((tmp_path / "behavioral_receipts").glob("*.json"))) == 2

    def test_one_click_real_driver_discovers_hidden_read_then_proves_it(
        self, monkeypatch, tmp_path
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, _, source_persona, peer_persona = self._one_click_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setattr(driver.node_manager, "active_node", object())
        monkeypatch.setattr(driver, "ACTIVE_CAPTURE_PATH", None)
        monkeypatch.setattr(driver, "ACTIVE_CAPTURE_PERSONA_ID", None)
        monkeypatch.setattr(driver, "ACTIVE_CAPTURE_OWNER_ID", None)
        monkeypatch.setattr(driver, "ACTIVE_CAPTURE_SESSION_ID", None)
        monkeypatch.setattr(driver, "_CAPTURE_MIN_SETTLE_SECONDS", 0.0)
        monkeypatch.setattr(driver, "_CAPTURE_QUIET_SECONDS", 0.0)
        monkeypatch.setattr(driver, "_CAPTURE_MAX_SETTLE_SECONDS", 0.2)
        driver._reset_capture_counters()
        commands = []
        traffic = []
        source_url = f"{self.ORIGIN}/api/documents/{self.SOURCE_ID}"
        peer_url = f"{self.ORIGIN}/api/documents/{self.PEER_ID}"
        records_by_persona = {
            source_persona.persona_id: {
                "method": "GET",
                "url": request.target_url,
                "response_status": 200,
                "response_body": json.dumps({"owned_document_url": source_url}),
            },
            peer_persona.persona_id: {
                "method": "GET",
                "url": request.target_url,
                "response_status": 200,
                "response_body": json.dumps({"owned_document_url": peer_url}),
            },
        }

        async def send_command(payload, timeout=30.0):
            commands.append((payload, timeout))
            if payload["command"] == "navigate":
                persona_id = payload["args"]["persona"]
                record = records_by_persona[persona_id]
                driver._handle_node_event(
                    "recorded_action",
                    {
                        "action": {
                            "action": "network_capture",
                            "persona_id": persona_id,
                            "capture_session": driver.ACTIVE_CAPTURE_SESSION_ID,
                            "type": "fetch",
                            **record,
                        }
                    },
                )
            if payload["command"] == "script_resource_urls":
                return []
            if payload["command"] == "interaction_controls":
                return []
            if payload["command"] == "current_url":
                return request.target_url
            return "ok"

        async def fake_send(_transport, persona, replay_request):
            traffic.append((persona, replay_request))
            if persona == peer_persona.persona_id or self.PEER_ID in replay_request.url:
                return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')
            if self.SOURCE_ID in replay_request.url:
                return ReplayResponse(200, '{"owner":"SourcePrivateMarker"}')
            return ReplayResponse(200, '{"owner":"PeerPrivateMarker"}')

        monkeypatch.setattr(driver.node_manager, "send_command", send_command)
        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)

        result = _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert result["status"] == "completed"
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["read_exploration"]["pairs_completed"] == 1
        assert result["read_exploration"]["selected_after_pair"] == 1
        assert result["capture_pair"]["source"]["records"] == 1
        assert result["capture_pair"]["peer"]["records"] == 1
        assert [payload["command"] for payload, _ in commands] == [
            "validate_persona_windows",
            "validate_persona_windows",
            "start_network_capture",
            "navigate",
            "stop_network_capture",
            "interaction_controls",
            "current_url",
            "start_network_capture",
            "navigate",
            "stop_network_capture",
            "interaction_controls",
            "current_url",
            "script_resource_urls",
        ]
        assert len(traffic) == 5
        assert traffic[0][1].url == source_url
        assert traffic[1][1].url == peer_url
        assert len(list((tmp_path / "captures").glob("*.jsonl"))) == 2
        assert driver.ACTIVE_CAPTURE_OWNER_ID is None
        assert driver.ACTIVE_CAPTURE_SESSION_ID is None


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
