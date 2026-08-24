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
    monkeypatch.delenv(
        "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_ADMISSION",
        raising=False,
    )
    monkeypatch.delenv(
        "SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION",
        raising=False,
    )
    for name in (
        "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK",
        "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM",
        "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE",
        "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION",
    ):
        monkeypatch.delenv(name, raising=False)
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

    def _setup(self, *, graph_bound=False):
        import json

        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.prerequisite_contracts import (
            GRAPH_BOUND_PREREQUISITE_WORKFLOW,
        )
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
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                *(
                    [GRAPH_BOUND_PREREQUISITE_WORKFLOW]
                    if graph_bound
                    else []
                ),
            ],
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
                "response_status": 200,
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
            prior_source_records=(list(source_records) if graph_bound else None),
            prior_peer_records=(list(peer_records) if graph_bound else None),
        )
        return request, source_persona, peer_persona

    def _one_click_request(self, *, graph_bound=False):
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
        )

        request, source_persona, peer_persona = self._setup(
            graph_bound=graph_bound
        )
        return (
            RunBehavioralAuthorizationFromURLRequest(
                target_url=f"{self.ORIGIN}/app",
                envelope_id=request.envelope_id,
                source_persona_id=source_persona.persona_id,
                peer_persona_id=peer_persona.persona_id,
                prior_source_records=(
                    list(request.source_records) if graph_bound else None
                ),
                prior_peer_records=(
                    list(request.peer_records) if graph_bound else None
                ),
            ),
            request,
            source_persona,
            peer_persona,
        )

    def _role_one_click_request(self, *, signed_role_workflow=True):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.normalize import stable_hash
        from core.behavior.role_monotonicity import ROLE_MONOTONICITY_WORKFLOW
        from core.foundry.authorization import create_envelope
        from core.foundry.vault import PersonaVault
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
        )

        vault = PersonaVault()
        higher = vault.add_persona(
            label="role-higher",
            email="role-higher@research.example",
        )
        lower = vault.add_persona(
            label="role-lower",
            email="role-lower@research.example",
        )
        envelope = create_envelope(
            researcher_identity="researcher",
            target_handle="role-example",
            authorized_origins=[self.ORIGIN],
            authorization_basis="owned role monotonicity test",
            allowed_workflows=[
                CONTROLLED_WORKFLOW,
                *(
                    [ROLE_MONOTONICITY_WORKFLOW]
                    if signed_role_workflow
                    else []
                ),
            ],
            disclosure_attestation=True,
        )
        higher_role_ref = stable_hash("experiment_role", "higher-role")
        lower_role_ref = stable_hash("experiment_role", "lower-role")
        tenant_id = "tenant_role_one_click"
        membership_collection = (
            f"{self.ORIGIN}/api/tenants/{tenant_id}/memberships"
        )
        membership_item = f"{membership_collection}/{lower.persona_id}"
        probe = f"{self.ORIGIN}/api/tenants/{tenant_id}/admin-effect"
        witness = (
            f"{self.ORIGIN}/api/tenants/{tenant_id}/authoritative-effect"
        )
        role_specification = {
            "schema_version": 1,
            "run_id": "ordinary-role-run-001",
            "tenant_id": tenant_id,
            "higher_role_ref": higher_role_ref,
            "lower_role_ref": lower_role_ref,
            "higher_session_id": "higher-role-session",
            "active_lower_session_id": "active-lower-role-session",
            "revoked_lower_session_id": "revoked-lower-role-session",
            "active_membership_generation": 11,
            "revoked_membership_generation": 12,
            "actions": {
                "setup": {
                    "url": membership_collection,
                    "body": {
                        "member_id": lower.persona_id,
                        "role_assignment": lower_role_ref,
                    },
                },
                "higher_baseline": {"url": f"{probe}?state=baseline"},
                "active_lower_probe": {"url": f"{probe}?state=active"},
                "active_effect_witness": {
                    "url": f"{witness}?state=active"
                },
                "revocation": {
                    "url": membership_item,
                    "body": {"state": "revoked"},
                },
                "revocation_verification": {"url": membership_item},
                "revoked_lower_probe": {"url": f"{probe}?state=revoked"},
                "revoked_effect_witness": {
                    "url": f"{witness}?state=revoked"
                },
            },
            "membership_pointers": {
                "tenant": "/tenant_id",
                "subject": "/member_id",
                "role": "/role_assignment",
                "state": "/state",
                "generation": "/generation",
            },
            "effect_pointers": {
                "probe_authorized": "/authorized",
                "probe_effect": "/effect",
                "witness_effect": "/effect",
            },
        }
        source_record = {
            "id": "role-operation",
            "persona_id": higher.persona_id,
            "method": "POST",
            "url": f"{self.ORIGIN}/api/admin/role/permission",
            "request_body": "{}",
            "response_status": 200,
            "response_body": '{"ok":true}',
        }
        peer_record = {
            **source_record,
            "id": "peer-role-operation",
            "persona_id": lower.persona_id,
        }
        return (
            RunBehavioralAuthorizationFromURLRequest(
                target_url=f"{self.ORIGIN}/app",
                envelope_id=envelope.envelope_id,
                source_persona_id=higher.persona_id,
                peer_persona_id=lower.persona_id,
                role_monotonicity=role_specification,
            ),
            (source_record,),
            (peer_record,),
            higher,
            lower,
            role_specification,
        )

    def _omission_request(
        self,
        *,
        graph_bound=False,
        continuation=False,
        legacy_omission=True,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.continuation import CONTINUATION_WORKFLOW
        from core.behavior.omission_confirmation import (
            FRESH_OMISSION_CONFIRMATION_WORKFLOW,
        )
        from core.behavior.omission_boundary import FRESH_OMISSION_WORKFLOW
        from core.behavior.runtime import CONTROLLED_SEQUENCE_WORKFLOW
        from core.behavior.prerequisite_admission import (
            GRAPH_BOUND_PREREQUISITE_WORKFLOW,
        )
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
                *(
                    [
                        CONTROLLED_SEQUENCE_WORKFLOW,
                        FRESH_OMISSION_WORKFLOW,
                        FRESH_OMISSION_CONFIRMATION_WORKFLOW,
                    ]
                    if legacy_omission
                    else []
                ),
                *(
                    [GRAPH_BOUND_PREREQUISITE_WORKFLOW]
                    if graph_bound
                    else []
                ),
                *([CONTINUATION_WORKFLOW] if continuation else []),
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
            prior_source_records=(list(source_records) if graph_bound else None),
            prior_peer_records=(list(peer_records) if graph_bound else None),
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
        # Browser Fetch cannot expose every intermediate redirect for scope
        # admission, so the bridge must keep every proof request manual.
        assert [item[1].redirect_mode for item in sent[3:]] == [
            "manual",
            "manual",
            "manual",
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

    def test_frontier_dispatches_the_payout_goal_bound_auth_obligation(
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
        assert result["plan"]["selected"]["frontier_index"] == 0
        assert result["plan"]["diagnostics"]["deferred_preparatory_items"] == 0
        assert result["plan"]["selected_obligation_id"]
        assert result["behavioral_shadow"].get("selected") is None
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
                # Typed admission requires observed success before replay is executable.
                "response_status": 200,
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

    def test_one_click_refuses_continuation_and_graph_workflow_before_capture(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )

        capture_request, source, peer = self._omission_request(
            graph_bound=True,
            continuation=True,
        )
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{self.ORIGIN}/app",
            envelope_id=capture_request.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_CONTINUATION",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("execution mode conflict must precede capture")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "mutually exclusive" in error.value.detail
        assert not (tmp_path / "behavioral_receipts").exists()

    def test_direct_refuses_continuation_and_graph_workflow_before_receipt(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        request, _source, _peer = self._omission_request(
            graph_bound=True,
            continuation=True,
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_CONTINUATION", "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("execution mode conflict reached target transport")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "mutually exclusive" in error.value.detail
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

    def test_one_click_graph_denial_replays_outer_receipt_without_capture(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.behavior.normalize import stable_hash
        from core.server.routers import driver
        import core.server.routers.foundry as foundry_module
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, capture_request, source_persona, peer_persona = (
            self._one_click_request(graph_bound=True)
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        graph_receipt_id = f"behavioral-{'1' * 64}"
        cleanup = {
            "status": "uncertain",
            "cleanup_steps_attempted": 1,
            "cleanup_steps_completed": 1,
            "cleanup_verifications_attempted": 1,
            "cleanup_verifications_completed": 0,
            "ownership_grants_removed": 0,
            "cleanup_evidence_refs": [
                f"graph_bound_cleanup_evidence:{'2' * 64}",
                f"graph_bound_cleanup_evidence:{'3' * 64}",
            ],
            "orphaned_owned_state_possible": True,
        }
        denial_payload = {
            "kind": "graph_bound_prerequisite_execution_denial",
            "status": "denied",
            "graph_receipt_id": graph_receipt_id,
            "reason_code": "graph_bound_runtime_value_extraction_failed",
            "category": "lineage",
            "claim_contract_id": (
                f"graph_bound_execution_claim_contract:{'4' * 64}"
            ),
            "capture_freshness_ref": (
                f"graph_bound_capture_freshness:{'7' * 64}"
            ),
            "plan_id": f"graph_bound_prepared_request_plan:{'5' * 64}",
            "family": "omission",
            "cleanup": cleanup,
            "finding_confirmed": False,
            "promotion_authority": False,
            "finding_authority": False,
            "retry_authority": False,
        }
        denial = {
            "schema_version": 1,
            "denial_evidence_ref": stable_hash(
                "graph_bound_prerequisite_denial_evidence",
                denial_payload,
            ),
            **denial_payload,
        }
        inner_detail = {
            "schema_version": 1,
            "kind": "graph_bound_prerequisite_execution_denial",
            "status": "denied",
            "reused": False,
            "graph_receipt": {
                "receipt_id": graph_receipt_id,
                "state": "aborted",
            },
            "orchestration_receipt": {
                "receipt_id": f"behavioral-{'6' * 64}",
                "state": "aborted",
            },
            "denial": denial,
            "debug": {"exportToken": "raw-runtime-secret"},
        }
        window_checks = 0
        captures = 0
        executions = 0

        async def validate_windows(persona_ids):
            nonlocal window_checks
            window_checks += 1
            assert tuple(persona_ids) == (
                source_persona.persona_id,
                peer_persona.persona_id,
            )

        async def capture_pair(**_kwargs):
            nonlocal captures
            captures += 1
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

        async def deny_execution(*_args, **_kwargs):
            nonlocal executions
            executions += 1
            raise HTTPException(status_code=409, detail=inner_detail)

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(
            foundry_module,
            "run_behavioral_authorization_endpoint",
            deny_execution,
        )

        with pytest.raises(HTTPException) as first_error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))
        with pytest.raises(HTTPException) as duplicate_error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        first = first_error.value.detail
        duplicate = duplicate_error.value.detail
        assert first_error.value.status_code == 409
        assert duplicate_error.value.status_code == 409
        assert first["reused"] is False
        assert duplicate["reused"] is True
        assert duplicate["denial"] == first["denial"] == denial
        assert duplicate["graph_receipt"] == first["graph_receipt"]
        assert duplicate["orchestration_receipt"] == (
            first["orchestration_receipt"]
        )
        assert first["orchestration_receipt"] != inner_detail[
            "orchestration_receipt"
        ]
        assert window_checks == captures == executions == 1

        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 1
        stored = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert stored["state"] == "aborted"
        assert stored["terminal_evidence"] == denial
        encoded = json.dumps([first, duplicate, stored], sort_keys=True)
        assert "exportToken" not in encoded
        assert "raw-runtime-secret" not in encoded

    def test_graph_bound_one_click_requires_signed_workflow_before_capture(
        self,
        monkeypatch,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )

        capture_request, source_persona, peer_persona = self._omission_request()
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{self.ORIGIN}/app",
            envelope_id=capture_request.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
            prior_source_records=list(capture_request.source_records),
            prior_peer_records=list(capture_request.peer_records),
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden_windows(*_args, **_kwargs):
            raise AssertionError("workflow denial must precede window access")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden_windows)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "graph-bound prerequisite" in error.value.detail
        assert "missing signed workflow" in error.value.detail

    def test_role_one_click_requires_signed_workflow_before_capture(
        self,
        monkeypatch,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )

        request, *_rest = self._role_one_click_request(
            signed_role_workflow=False
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK",
            "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE",
            "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden_windows(*_args, **_kwargs):
            raise AssertionError("role workflow denial must precede windows")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden_windows)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "role monotonicity" in error.value.detail
        assert "missing signed workflow" in error.value.detail

    def test_role_one_click_executes_once_and_reuses_outer_and_inner_receipts(
        self,
        monkeypatch,
    ):
        from urllib.parse import parse_qs, urlsplit

        from core.behavior.receipts import BehavioralReceiptStore
        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import (
            ReplayResponse,
            SNDReplayTransport,
            SessionBoundReplayResponse,
        )

        (
            request,
            source_records,
            peer_records,
            higher,
            lower,
            role_specification,
        ) = self._role_one_click_request()
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK",
            "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE",
            "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        captures = 0
        role_calls = []
        effect = {"capability": "owned-admin-export", "visible": True}

        async def validate_windows(persona_ids):
            assert tuple(persona_ids) == (higher.persona_id, lower.persona_id)

        async def capture_pair(**_kwargs):
            nonlocal captures
            captures += 1
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=higher.persona_id,
                    path="/private/role-source.jsonl",
                    records=source_records,
                    captured_bytes=128,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=lower.persona_id,
                    path="/private/role-peer.jsonl",
                    records=peer_records,
                    captured_bytes=128,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                (),
            )

        def membership(state, generation):
            return json.dumps(
                {
                    "tenant_id": role_specification["tenant_id"],
                    "member_id": lower.persona_id,
                    "role_assignment": role_specification["lower_role_ref"],
                    "state": state,
                    "generation": generation,
                },
                sort_keys=True,
            )

        async def fake_send_bound(
            _transport,
            persona_id,
            session_id,
            replay_request,
        ):
            role_calls.append((persona_id, session_id, replay_request))
            parsed = urlsplit(replay_request.url)
            state = parse_qs(parsed.query).get("state", [None])[0]
            if replay_request.method == "POST":
                response = ReplayResponse(200, membership("active", 11))
            elif replay_request.method == "PATCH":
                response = ReplayResponse(200, '{"accepted":true}')
            elif "/memberships/" in parsed.path:
                response = ReplayResponse(200, membership("revoked", 12))
            elif parsed.path.endswith("/admin-effect"):
                allowed = state in {"baseline", "active"}
                response = ReplayResponse(
                    200 if allowed else 403,
                    json.dumps(
                        {
                            "authorized": allowed,
                            "effect": effect if allowed else None,
                        },
                        sort_keys=True,
                    ),
                )
            elif parsed.path.endswith("/authoritative-effect"):
                response = ReplayResponse(
                    200,
                    json.dumps({"effect": effect}, sort_keys=True),
                )
            else:
                raise AssertionError(
                    f"unexpected role request: {replay_request.method} "
                    f"{replay_request.url}"
                )
            return SessionBoundReplayResponse(
                response=response,
                persona=persona_id,
                session_id=session_id,
            )

        async def forbidden_legacy_send(*_args, **_kwargs):
            raise AssertionError("selected role proof must block legacy fallback")

        monkeypatch.setattr(driver, "ensure_capture_available", lambda: None)
        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send_bound", fake_send_bound)
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden_legacy_send)

        result = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )
        duplicate = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )
        inner_duplicate = _run(
            run_behavioral_authorization_from_url_endpoint(
                RunBehavioralAuthorizationFromURLRequest(
                    **{
                        **request.model_dump(),
                        "target_url": f"{self.ORIGIN}/app?outer-retry=1",
                    }
                ),
                _=True,
            )
        )

        assert result["kind"] == "role_protected_effect_execution"
        assert result["status"] == "confirmed_active_escalation"
        assert result["finding_confirmed"] is True
        assert result["finding"]["tool"] == "behavioral_role_monotonicity"
        assert result["role_monotonicity_one_click"]["dispatched"] is True
        assert result["behavioral_shadow"]["receipt_feedback"]["status"] == (
            "unsupported"
        )
        assert duplicate["status"] == "already_executed"
        assert duplicate["orchestration_receipt"]["reused"] is True
        assert inner_duplicate["status"] == "already_executed"
        assert inner_duplicate["orchestration_receipt"]["reused"] is False
        assert captures == 2
        assert len(role_calls) == 8
        stored = BehavioralReceiptStore().load(
            inner_duplicate["orchestration_receipt"]["receipt_id"].removeprefix(
                "behavioral-"
            )
        )
        assert stored.outcome["selection_ref"] == result["selection_ref"]
        assert stored.outcome["finding_confirmed"] is True
        stored_text = json.dumps(stored.to_dict(), sort_keys=True)
        for private_value in (
            role_specification["run_id"],
            role_specification["tenant_id"],
            role_specification["higher_session_id"],
            role_specification["active_lower_session_id"],
            role_specification["revoked_lower_session_id"],
        ):
            assert private_value not in stored_text

    def test_role_one_click_default_off_stops_without_role_replay(
        self,
        monkeypatch,
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        (
            request,
            source_records,
            peer_records,
            higher,
            lower,
            _role_specification,
        ) = self._role_one_click_request()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def validate_windows(persona_ids):
            assert tuple(persona_ids) == (higher.persona_id, lower.persona_id)

        async def capture_pair(**_kwargs):
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=higher.persona_id,
                    path="/private/role-source.jsonl",
                    records=source_records,
                    captured_bytes=128,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=lower.persona_id,
                    path="/private/role-peer.jsonl",
                    records=peer_records,
                    captured_bytes=128,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                (),
            )

        async def forbidden_replay(*_args, **_kwargs):
            raise AssertionError("default-off role selection must not replay")

        monkeypatch.setattr(driver, "ensure_capture_available", lambda: None)
        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden_replay)
        monkeypatch.setattr(SNDReplayTransport, "send_bound", forbidden_replay)

        result = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )

        assert result["status"] == "no_executable_candidate"
        assert result["finding"] is None
        assert result["finding_confirmed"] is False
        assert result["role_monotonicity_one_click"]["status"] == (
            "selected_execution_disabled"
        )
        assert set(
            result["role_monotonicity_one_click"]["disabled_gates"]
        ) == {
            "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK",
            "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE",
            "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION",
        }
        assert result["orchestration_receipt"]["state"] == "completed"

    def test_graph_execution_requires_prior_capture_before_window_access(
        self,
        monkeypatch,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )

        capture_request, source_persona, peer_persona = self._omission_request(
            graph_bound=True,
            legacy_omission=False,
        )
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{self.ORIGIN}/app",
            envelope_id=capture_request.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("missing prior capture must fail before windows")

        monkeypatch.setattr(driver, "validate_persona_windows", forbidden)
        monkeypatch.setattr(driver, "capture_persona_pair", forbidden)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "requires an explicit prior paired capture" in error.value.detail

    def test_stale_prior_capture_refuses_graph_execution_and_replay_traffic(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        request, capture_request, source_persona, peer_persona = (
            self._one_click_request(graph_bound=True)
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        stale_source = [dict(item) for item in capture_request.source_records]
        stale_source[0] = {
            **stale_source[0],
            "response_status": 409,
            "response_body": '{"error":"workflow changed"}',
        }
        window_checks = 0
        captures = 0

        async def validate_windows(_persona_ids):
            nonlocal window_checks
            window_checks += 1

        async def capture_pair(**_kwargs):
            nonlocal captures
            captures += 1
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/current-source.jsonl",
                    records=tuple(stale_source),
                    captured_bytes=123,
                    limit_reached=False,
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/current-peer.jsonl",
                    records=tuple(capture_request.peer_records),
                    captured_bytes=123,
                    limit_reached=False,
                ),
                (),
            )

        async def forbidden_send(*_args, **_kwargs):
            raise AssertionError("stale capture must fail before graph traffic")

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden_send)

        with pytest.raises(HTTPException) as first_error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))
        with pytest.raises(HTTPException) as duplicate_error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert first_error.value.status_code == 409
        assert first_error.value.detail == "graph_bound_prior_capture_is_stale"
        assert duplicate_error.value.status_code == 409
        assert "already reserved or terminal" in duplicate_error.value.detail
        assert window_checks == captures == 1
        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 1
        stored = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert stored["state"] == "aborted"
        assert stored["terminal_evidence"] is None

    def test_changed_current_lineage_refuses_stale_graph_selection(
        self,
        monkeypatch,
    ):
        from fastapi import HTTPException

        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        capture_request, source_persona, peer_persona = self._omission_request(
            graph_bound=True,
            legacy_omission=False,
        )
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{self.ORIGIN}/app",
            envelope_id=capture_request.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
            prior_source_records=list(capture_request.source_records),
            prior_peer_records=list(capture_request.peer_records),
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        current_source = [dict(item) for item in capture_request.source_records]
        current_source[2] = {
            **current_source[2],
            "url": current_source[2]["url"].replace(
                "token_4a5b6c7d8e9f0123",
                "token_9a5b6c7d8e9f0123",
            ),
        }
        captures = 0

        async def validate_windows(_persona_ids):
            return None

        async def capture_pair(**_kwargs):
            nonlocal captures
            captures += 1
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/current-source-lineage.jsonl",
                    records=tuple(current_source),
                    captured_bytes=256,
                    limit_reached=False,
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/current-peer-lineage.jsonl",
                    records=tuple(capture_request.peer_records),
                    captured_bytes=64,
                    limit_reached=False,
                ),
                (),
            )

        async def forbidden_send(*_args, **_kwargs):
            raise AssertionError("changed lineage must fail before graph traffic")

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden_send)

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert error.value.detail == (
            "graph_bound_prior_capture_selection_is_stale"
        )
        assert captures == 1

    def test_selected_graph_plan_never_falls_through_to_generalized_execution(
        self,
        monkeypatch,
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.behavior.resolver import SingleStepObligationResolver
        from core.wraith.bola_replay import SNDReplayTransport

        capture_request, source_persona, peer_persona = self._omission_request(
            graph_bound=True,
        )
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{self.ORIGIN}/app",
            envelope_id=capture_request.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv(
            "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_ADMISSION",
            "1",
        )
        monkeypatch.setenv(
            "SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION",
            "1",
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.delenv(name, raising=False)

        async def validate_windows(_persona_ids):
            return None

        async def capture_pair(**_kwargs):
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/source-disabled-graph.jsonl",
                    records=tuple(capture_request.source_records),
                    captured_bytes=512,
                    limit_reached=False,
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/peer-disabled-graph.jsonl",
                    records=tuple(capture_request.peer_records),
                    captured_bytes=128,
                    limit_reached=False,
                ),
                (),
            )

        async def forbidden_send(*_args, **_kwargs):
            raise AssertionError("disabled selected graph plan sent target traffic")

        async def forbidden_legacy(*_args, **_kwargs):
            raise AssertionError("selected graph plan reached the legacy resolver")

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", forbidden_send)
        monkeypatch.setattr(
            SingleStepObligationResolver,
            "run",
            forbidden_legacy,
        )

        result = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )

        assert result["graph_bound_prerequisite_one_click"]["status"] == (
            "selected_execution_disabled"
        )
        assert "generalized_authorization_one_click" not in result
        assert result.get("finding") is None

    def test_graph_constructor_fault_aborts_claim_and_direct_receipts(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        import core.behavior.prerequisite_one_click as one_click_module
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )

        request, _source_persona, _peer_persona = self._omission_request(
            graph_bound=True
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        def fail_constructor(*_args, **_kwargs):
            raise ValueError("simulated graph coordinator constructor fault")

        monkeypatch.setattr(
            one_click_module,
            "GraphBoundPrerequisiteExperimentExecutor",
            fail_constructor,
        )

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 500
        assert error.value.detail == "behavioral execution failed closed"
        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 2
        assert {
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in receipts
        } == {"aborted"}

    def test_graph_execution_denial_returns_409_and_aborts_receipts(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        import core.behavior.prerequisite_one_click as one_click_module
        from core.behavior.prerequisite_execution import (
            GraphBoundPrerequisiteExecutionDenied,
        )
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )

        request, _source_persona, _peer_persona = self._omission_request(
            graph_bound=True
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        class DeniedExecution:
            def __init__(self, *_args, **_kwargs):
                pass

            async def execute(self):
                raise GraphBoundPrerequisiteExecutionDenied(
                    "simulated_graph_execution_denial"
                )

        monkeypatch.setattr(
            one_click_module,
            "GraphBoundPrerequisiteExperimentExecutor",
            DeniedExecution,
        )

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert error.value.detail == "simulated_graph_execution_denial"
        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 2
        assert {
            json.loads(path.read_text(encoding="utf-8"))["state"]
            for path in receipts
        } == {"aborted"}

    def test_graph_execution_denial_replays_durable_cleanup_evidence(
        self,
        monkeypatch,
        tmp_path,
    ):
        from fastapi import HTTPException

        import core.behavior.prerequisite_one_click as one_click_module
        from core.behavior.normalize import stable_hash
        from core.behavior.prerequisite_execution import (
            GraphBoundExperimentCleanupResult,
            GraphBoundPrerequisiteExecutionDenied,
        )
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )

        request, _source_persona, _peer_persona = self._omission_request(
            graph_bound=True
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        executions = 0

        class DeniedExecution:
            def __init__(self, claim, *_args, **_kwargs):
                self.claim = claim

            async def execute(self):
                nonlocal executions
                executions += 1
                authority = self.claim._begin_provisioning()
                cleanup = GraphBoundExperimentCleanupResult(
                    status="uncertain",
                    cleanup_steps_attempted=1,
                    cleanup_steps_completed=1,
                    cleanup_verifications_attempted=1,
                    cleanup_verifications_completed=0,
                    ownership_grants_removed=0,
                    cleanup_evidence_refs=(
                        f"graph_bound_cleanup_evidence:{'1' * 64}",
                        f"graph_bound_cleanup_evidence:{'2' * 64}",
                    ),
                    orphaned_owned_state_possible=True,
                )
                payload = {
                    "kind": "graph_bound_prerequisite_execution_denial",
                    "status": "denied",
                    "graph_receipt_id": authority.receipt_id,
                    "reason_code": (
                        "graph_bound_runtime_value_extraction_failed"
                    ),
                    "category": "lineage",
                    "claim_contract_id": self.claim.contract.contract_id,
                    "capture_freshness_ref": (
                        self.claim.contract.preview.capture_freshness_ref
                    ),
                    "plan_id": authority.runtime_plan.plan.plan_id,
                    "family": authority.runtime_plan.plan.family,
                    "cleanup": cleanup.to_dict(),
                    "finding_confirmed": False,
                    "promotion_authority": False,
                    "finding_authority": False,
                    "retry_authority": False,
                }
                evidence = {
                    "schema_version": 1,
                    "denial_evidence_ref": stable_hash(
                        "graph_bound_prerequisite_denial_evidence",
                        payload,
                    ),
                    **payload,
                }
                authority.abort(
                    expected_state=authority.state,
                    reason="graph_bound_experiment_orphan_risk",
                    terminal_evidence=evidence,
                )
                raise GraphBoundPrerequisiteExecutionDenied(
                    payload["reason_code"],
                    category="lineage",
                    cleanup=cleanup,
                    terminal_receipt=authority.terminal_receipt,
                )

        monkeypatch.setattr(
            one_click_module,
            "GraphBoundPrerequisiteExperimentExecutor",
            DeniedExecution,
        )

        with pytest.raises(HTTPException) as first_error:
            _run(run_behavioral_authorization_endpoint(request, _=True))
        with pytest.raises(HTTPException) as duplicate_error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert first_error.value.status_code == 409
        assert duplicate_error.value.status_code == 409
        first = first_error.value.detail
        duplicate = duplicate_error.value.detail
        assert first["kind"] == "graph_bound_prerequisite_execution_denial"
        assert first["status"] == "denied"
        assert first["reused"] is False
        assert duplicate["reused"] is True
        assert duplicate["denial"] == first["denial"]
        assert duplicate["graph_receipt"] == first["graph_receipt"]
        assert duplicate["orchestration_receipt"] == (
            first["orchestration_receipt"]
        )
        assert first["denial"]["retry_authority"] is False
        assert first["denial"]["finding_authority"] is False
        assert executions == 1

        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 2
        stored = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in receipts
        ]
        assert {item["state"] for item in stored} == {"aborted"}
        assert all(item["terminal_evidence"] is not None for item in stored)
        encoded = json.dumps(stored, sort_keys=True)
        assert "exportToken" not in encoded
        assert "runtime-workflow" not in encoded

    def test_direct_graph_execution_cannot_bypass_prior_capture_binding(
        self,
        monkeypatch,
    ):
        from fastapi import HTTPException

        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )

        request, _source_persona, _peer_persona = self._omission_request(
            graph_bound=True,
            legacy_omission=False,
        )
        request = request.model_copy(
            update={
                "prior_source_records": None,
                "prior_peer_records": None,
            }
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        with pytest.raises(HTTPException) as error:
            _run(run_behavioral_authorization_endpoint(request, _=True))

        assert error.value.status_code == 409
        assert "requires an explicit prior paired capture" in error.value.detail

    def test_generalized_cancellation_uses_neutral_receipt_reason(
        self,
        monkeypatch,
        tmp_path,
    ):
        import core.behavior.generalized_authorization_one_click as one_click_module
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )

        request, _source_persona, _peer_persona = self._setup()
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def cancel_dispatch(*_args, **_kwargs):
            raise asyncio.CancelledError

        monkeypatch.setattr(
            one_click_module.GeneralizedAuthorizationOneClickDispatcher,
            "run",
            cancel_dispatch,
        )

        with pytest.raises(asyncio.CancelledError):
            _run(run_behavioral_authorization_endpoint(request, _=True))

        receipts = list((tmp_path / "behavioral_receipts").glob("*.json"))
        assert len(receipts) == 1
        stored = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert stored["state"] == "aborted"
        assert stored["abort_reason"] == "behavioral_execution_cancelled"

    def test_pre_dispatch_cancellation_aborts_direct_and_outer_receipts(
        self,
        monkeypatch,
        tmp_path,
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import SNDReplayTransport

        request, capture_request, source_persona, peer_persona = (
            self._one_click_request()
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")

        async def validate_windows(_persona_ids):
            return None

        async def capture_pair(**_kwargs):
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/source-cancel.jsonl",
                    records=tuple(capture_request.source_records),
                    captured_bytes=512,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/peer-cancel.jsonl",
                    records=tuple(capture_request.peer_records),
                    captured_bytes=128,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                (f"{self.ORIGIN}/assets/app.js",),
            )

        async def cancel_send(*_args, **_kwargs):
            raise asyncio.CancelledError

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", cancel_send)

        with pytest.raises(asyncio.CancelledError):
            _run(run_behavioral_authorization_from_url_endpoint(request, _=True))

        receipts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in (tmp_path / "behavioral_receipts").glob("*.json")
        ]
        assert len(receipts) == 2
        assert {receipt["state"] for receipt in receipts} == {"aborted"}
        assert {receipt["abort_reason"] for receipt in receipts} == {
            "behavioral_execution_cancelled",
            "capture_orchestration_cancelled",
        }

    def test_continuation_cancellation_aborts_round_and_root_receipts(
        self,
        monkeypatch,
        tmp_path,
    ):
        from core.behavior.active import CONTROLLED_WORKFLOW
        from core.behavior.continuation import CONTINUATION_WORKFLOW
        from core.behavior.resolver import SingleStepObligationResolver
        from core.foundry.authorization import create_envelope
        from core.server.routers.foundry import (
            run_behavioral_authorization_endpoint,
        )

        request, _source_persona, _peer_persona = self._setup()
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

        async def cancel_round(*_args, **_kwargs):
            raise asyncio.CancelledError

        monkeypatch.setattr(SingleStepObligationResolver, "run", cancel_round)

        with pytest.raises(asyncio.CancelledError):
            _run(run_behavioral_authorization_endpoint(request, _=True))

        receipts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in (tmp_path / "behavioral_receipts").glob("*.json")
        ]
        assert len(receipts) == 2
        assert {receipt["state"] for receipt in receipts} == {"aborted"}
        assert {receipt["abort_reason"] for receipt in receipts} == {
            "behavioral_execution_cancelled"
        }

    @pytest.mark.parametrize(
        ("secure", "expected_verdict", "finding_expected"),
        ((False, "confirmed", True), (True, "refuted", False)),
    )
    def test_one_click_dispatches_graph_bound_prerequisite_twins_once(
        self,
        monkeypatch,
        secure,
        expected_verdict,
        finding_expected,
    ):
        from urllib.parse import parse_qsl, urlsplit

        from core.server.routers import driver
        from core.server.routers.foundry import (
            RunBehavioralAuthorizationFromURLRequest,
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport
        from core.behavior.prerequisite_one_click import (
            GraphBoundPrerequisiteOneClickDispatcher,
        )
        from core.behavior.receipts import BehavioralReceiptStore

        capture_request, source_persona, peer_persona = self._omission_request(
            graph_bound=True,
            legacy_omission=False,
        )
        request = RunBehavioralAuthorizationFromURLRequest(
            target_url=f"{self.ORIGIN}/app",
            envelope_id=capture_request.envelope_id,
            source_persona_id=source_persona.persona_id,
            peer_persona_id=peer_persona.persona_id,
            prior_source_records=list(capture_request.source_records),
            prior_peer_records=list(capture_request.peer_records),
        )
        for name in (
            "SENTINELFORGE_BEHAVIOR_PRIMARY",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_EXECUTION_CLAIM",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_FRESH_WORLD_PROVISIONING",
            "SENTINELFORGE_BEHAVIOR_GRAPH_BOUND_PREREQUISITE_EXECUTION",
        ):
            monkeypatch.setenv(name, "1")

        traffic = []
        worlds = {}
        graph_runs = []
        graph_dispatchers = []
        original_graph_run = GraphBoundPrerequisiteOneClickDispatcher.run
        current_source_encoded = json.dumps(capture_request.source_records)
        for prior, current in (
            ("workflow_7fa9f13a2b4c5d6e", "workflow_8fa9f13a2b4c5d6e"),
            ("token_4a5b6c7d8e9f0123", "token_5a5b6c7d8e9f0123"),
        ):
            current_source_encoded = current_source_encoded.replace(
                prior,
                current,
            )
        current_source_records = tuple(json.loads(current_source_encoded))

        async def capture_graph_run(dispatcher, *args, **kwargs):
            run = await original_graph_run(dispatcher, *args, **kwargs)
            graph_dispatchers.append(dispatcher)
            graph_runs.append(run)
            return run

        async def validate_windows(persona_ids):
            assert tuple(persona_ids) == (
                source_persona.persona_id,
                peer_persona.persona_id,
            )

        async def capture_pair(**_kwargs):
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/source-graph-capture.jsonl",
                    records=current_source_records,
                    captured_bytes=512,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/peer-graph-capture.jsonl",
                    records=tuple(capture_request.peer_records),
                    captured_bytes=128,
                    limit_reached=False,
                    page_url=f"{self.ORIGIN}/app",
                ),
                (),
            )

        async def fake_send(_transport, persona_id, replay_request):
            assert persona_id == source_persona.persona_id
            traffic.append(replay_request)
            parsed = urlsplit(replay_request.url)
            path = parsed.path
            if replay_request.method == "POST" and path == "/api/workflows":
                object_id = f"runtime-workflow-{len(worlds) + 1}"
                worlds[object_id] = {"archived": False}
                return ReplayResponse(201, json.dumps({"workflowId": object_id}))
            parts = path.strip("/").split("/")
            object_id = parts[2]
            world = worlds[object_id]
            token = f"runtime-export-token-{object_id}"
            if replay_request.method == "GET" and path.endswith("/export-token"):
                return ReplayResponse(200, json.dumps({"exportToken": token}))
            if replay_request.method == "GET" and path.endswith("/export"):
                if world["archived"]:
                    return ReplayResponse(404, '{"error":"not found"}')
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                capability = query.get("exportToken")
                if capability is not None and capability != token:
                    return ReplayResponse(403, '{"error":"object mismatch"}')
                if secure and capability is None:
                    return ReplayResponse(403, '{"error":"token required"}')
                return ReplayResponse(
                    200,
                    json.dumps({"status": "ready", "artifact": "controlled"}),
                )
            if replay_request.method == "PATCH" and len(parts) == 3:
                world["archived"] = True
                return ReplayResponse(200, '{"archived":true}')
            raise AssertionError(
                f"unexpected graph-bound request: {replay_request.method} "
                f"{replay_request.url}"
            )

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)
        monkeypatch.setattr(
            GraphBoundPrerequisiteOneClickDispatcher,
            "run",
            capture_graph_run,
        )

        result = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )
        shadow_result = result["behavioral_shadow"]
        assert len(graph_runs) == 1
        assert shadow_result["prerequisite_admission"]["status"] == (
            "ready_for_explicit_execution_boundary"
        )
        assert shadow_result["prerequisite_requests"]["status"] == (
            "ready_for_single_use_execution_claim"
        )
        assert shadow_result["payout_goal_plan"]["selected"]["backend"] == (
            "graph_bound_prerequisite"
        )
        assert graph_runs[0].dispatched is True, graph_runs[0]
        assert result["kind"] == "graph_bound_prerequisite_execution"
        assert result["capture_freshness_ref"].startswith(
            "graph_bound_capture_freshness:"
        )
        traffic_after_first_run = len(traffic)
        duplicate = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )
        inner_duplicate = _run(
            run_behavioral_authorization_from_url_endpoint(
                RunBehavioralAuthorizationFromURLRequest(
                    target_url=f"{self.ORIGIN}/app?outer-retry=1",
                    envelope_id=request.envelope_id,
                    source_persona_id=request.source_persona_id,
                    peer_persona_id=request.peer_persona_id,
                    prior_source_records=list(
                        request.prior_source_records or []
                    ),
                    prior_peer_records=list(
                        request.prior_peer_records or []
                    ),
                ),
                _=True,
            )
        )

        assert len(graph_dispatchers) == 1
        assert result["kind"] == "graph_bound_prerequisite_execution"
        assert result["status"] == expected_verdict, (
            graph_runs[0].execution.oracle.uncertainty_reasons
        )
        assert result["oracle_verdict"] == expected_verdict
        assert result["graph_bound_prerequisite_one_click"]["dispatched"] is True
        assert isinstance(result["finding"], dict) is finding_expected
        assert result["cleanup_status"] == "verified"
        assert result["orphaned_owned_state_possible"] is False
        assert result["behavioral_shadow"]["receipt_feedback"]["status"] == (
            "unsupported"
        )
        assert graph_dispatchers[0].executor.policy.budget.max_creates == 3
        assert len(worlds) == 3
        assert len(traffic) == result["target_requests_sent"] > 0
        assert all(world["archived"] for world in worlds.values())
        if finding_expected:
            assert result["finding"]["metadata"][
                "adversarial_triage_required"
            ] is True
            assert result["finding"]["metadata"]["submission_authority"] is False
        assert duplicate["status"] == "already_executed"
        assert inner_duplicate["status"] == "already_executed"
        assert inner_duplicate["orchestration_receipt"]["reused"] is False
        assert inner_duplicate["orchestration_receipt"]["receipt_id"] != (
            result["orchestration_receipt"]["receipt_id"]
        )
        normalized_outer = BehavioralReceiptStore().load(
            inner_duplicate["orchestration_receipt"]["receipt_id"].removeprefix(
                "behavioral-"
            )
        )
        assert normalized_outer is not None
        assert normalized_outer.outcome["status"] == expected_verdict
        assert normalized_outer.outcome["capture_freshness_ref"] == (
            result["capture_freshness_ref"]
        )
        assert len(traffic) == traffic_after_first_run

    def test_one_click_dispatches_generalized_owned_capture_without_manual_wiring(
        self,
        monkeypatch,
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, capture_request, source_persona, peer_persona = (
            self._one_click_request()
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv(
            "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_ADMISSION",
            "1",
        )
        monkeypatch.setenv(
            "SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION",
            "1",
        )

        def records(persona_id, object_id, marker):
            return (
                {
                    "persona_id": persona_id,
                    "method": "POST",
                    "url": f"{self.ORIGIN}/api/documents",
                    "request_body": json.dumps(
                        {"title": "controlled ownership marker"}
                    ),
                    "response_status": 201,
                    "response_body": json.dumps({"documentId": object_id}),
                },
                {
                    "persona_id": persona_id,
                    "method": "GET",
                    "url": f"{self.ORIGIN}/api/documents/{object_id}",
                    "response_status": 200,
                    "response_body": json.dumps(
                        {"documentId": object_id, "privateMarker": marker}
                    ),
                },
            )

        source_records = records(
            source_persona.persona_id,
            self.SOURCE_ID,
            "SourcePrivateMarker",
        )
        peer_records = records(
            peer_persona.persona_id,
            self.PEER_ID,
            "PeerPrivateMarker",
        )
        capture_request.source_records = list(source_records)
        capture_request.peer_records = list(peer_records)
        traffic = []

        async def validate_windows(persona_ids):
            assert tuple(persona_ids) == (
                source_persona.persona_id,
                peer_persona.persona_id,
            )

        async def capture_pair(**_kwargs):
            return (
                driver.PersonaCaptureArtifact(
                    persona_id=source_persona.persona_id,
                    path="/private/source-capture.jsonl",
                    records=source_records,
                    captured_bytes=321,
                    limit_reached=False,
                ),
                driver.PersonaCaptureArtifact(
                    persona_id=peer_persona.persona_id,
                    path="/private/peer-capture.jsonl",
                    records=peer_records,
                    captured_bytes=654,
                    limit_reached=False,
                ),
                (),
            )

        async def fake_send(_transport, persona, replay_request):
            traffic.append((persona, replay_request))
            if self.PEER_ID in replay_request.url:
                return ReplayResponse(
                    200,
                    json.dumps(
                        {
                            "documentId": self.PEER_ID,
                            "privateMarker": "PeerPrivateMarker",
                        }
                    ),
                )
            return ReplayResponse(
                200,
                json.dumps(
                    {
                        "documentId": self.SOURCE_ID,
                        "privateMarker": "SourcePrivateMarker",
                    }
                ),
            )

        monkeypatch.setattr(driver, "validate_persona_windows", validate_windows)
        monkeypatch.setattr(driver, "capture_persona_pair", capture_pair)
        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)

        result = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )

        assert result["kind"] == "proof_experiment_generalized_authorization"
        assert result["status"] == "completed"
        assert result["oracle_verdict"] == "confirmed"
        assert result["one_click_selection"]["dispatched"] is True
        assert "graph_bound_prerequisite_one_click" not in result
        assert result["finding"] is None
        assert result["finding_authority"] is False
        assert result["promotion_authority"] is False
        assert len(traffic) == 4
        assert [persona for persona, _ in traffic] == [
            peer_persona.persona_id,
            source_persona.persona_id,
            source_persona.persona_id,
            peer_persona.persona_id,
        ]

    def test_one_click_keeps_legacy_fallback_isolated_when_r5_has_no_lineage(
        self,
        monkeypatch,
    ):
        from core.server.routers import driver
        from core.server.routers.foundry import (
            run_behavioral_authorization_from_url_endpoint,
        )
        from core.wraith.bola_replay import ReplayResponse, SNDReplayTransport

        request, capture_request, source_persona, peer_persona = (
            self._one_click_request()
        )
        monkeypatch.setenv("SENTINELFORGE_BEHAVIOR_PRIMARY", "1")
        monkeypatch.setenv(
            "SENTINELFORGE_BEHAVIOR_PROOF_EXPERIMENT_ADMISSION",
            "1",
        )
        monkeypatch.setenv(
            "SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION",
            "1",
        )
        traffic = []

        async def validate_windows(_persona_ids):
            return None

        async def capture_pair(**_kwargs):
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

        result = _run(
            run_behavioral_authorization_from_url_endpoint(request, _=True)
        )

        assert result["status"] == "completed"
        assert result["execution"]["legacy_verdict"] == "BOLA_CONFIRMED"
        assert result["generalized_authorization_one_click"]["status"] == (
            "no_eligible_candidate"
        )
        assert len(traffic) == 3

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
            "current_url",
            "current_url",
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

    def test_cross_persona_navigation_requires_html_oracle_and_api_proof(
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
        from core.behavior.normalize import stable_hash
        from core.foundry.authorization import create_envelope
        from core.safety.ownership_registry import NativeOwnedCreationWitness
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
        request.source_records = [{
            "persona_id": source_persona.persona_id,
            "method": "GET",
            "url": f"{self.ORIGIN}/documents",
            "response_status": 200,
            "response_body": "owner list",
        }]
        request.peer_records = [{
            "persona_id": peer_persona.persona_id,
            "method": "GET",
            "url": f"{self.ORIGIN}/documents",
            "response_status": 200,
            "response_body": "reader list",
        }]
        request.interaction_page_url = f"{self.ORIGIN}/documents"
        control = {
            "tag": "a",
            "role": "link",
            "input_type": "",
            "form_method": "none",
            "destination": "same_origin",
            "destination_ref": stable_hash(
                "interaction_destination",
                {"test": "owner-document"},
            ),
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
        peer_control = dict(control)
        peer_control["destination_ref"] = stable_hash(
            "interaction_destination",
            {"test": "reader-document"},
        )
        request.source_controls = [control]
        request.peer_controls = [peer_control]
        destination_ref = control["destination_ref"]
        witness = NativeOwnedCreationWitness(
            persona_id=source_persona.persona_id,
            create_ref=stable_hash("interaction_creation", {"test": 1}),
            destination_ref=destination_ref,
            proof_ref=stable_hash("native_ownership_witness", {"test": 1}),
        )
        owner_url = f"{self.ORIGIN}/documents/doc_owner"
        reader_url = f"{self.ORIGIN}/documents/doc_reader"

        async def resolve_live(persona_id, locator, peer_persona_id=None):
            if persona_id == source_persona.persona_id:
                return {
                    "current_url": request.interaction_page_url,
                    "destination_url": owner_url,
                    "control": control,
                    "catalog_controls": [control],
                    "peer_catalog_controls": [peer_control],
                    "ownership_witness": witness,
                }
            return {
                "current_url": request.interaction_page_url,
                "destination_url": reader_url,
                "control": peer_control,
                "catalog_controls": [peer_control],
                "peer_catalog_controls": [],
            }

        traffic = []

        async def fake_send(_transport, persona, replay_request):
            traffic.append((persona, replay_request.url))
            if replay_request.url.endswith("/api/documents/doc_owner"):
                return ReplayResponse(200, '{"body":"OwnerPrivateMarker"}')
            if replay_request.url.endswith("/documents/doc_owner"):
                return ReplayResponse(200, '{"body":"OwnerPrivateMarker"}')
            if replay_request.url.endswith("/documents/doc_reader"):
                return ReplayResponse(200, '{"body":"ReaderPrivateMarker"}')
            raise AssertionError(f"unexpected proof URL: {replay_request.url}")

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
        monkeypatch.setattr(driver, "resolve_interaction_navigation", resolve_live)
        monkeypatch.setattr(SNDReplayTransport, "send", fake_send)

        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "completed", result[
            "interaction_acquisition"
        ]
        assert result["finding"]["type"] == "cross_principal_object_access"
        metadata = result["finding"]["metadata"]
        assert metadata["owner_persona_id"] == source_persona.persona_id
        assert metadata["reader_persona_id"] == peer_persona.persona_id
        proof = metadata["behavioral_interaction_cross_persona_proof"]
        assert proof["finding_authority"] is True
        assert proof["matched_marker_count"] == 1
        assert traffic[-1] == (
            peer_persona.persona_id,
            f"{self.ORIGIN}/api/documents/doc_owner",
        )


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

    def test_empty_verification_value_is_rejected_without_settling_challenge(self):
        from core.server.routers.foundry import (
            ResolveChallengeRequest,
            resolve_challenge_endpoint,
        )
        from fastapi import HTTPException

        bus = get_challenge_bus()
        challenge = Challenge(
            challenge_id="cv-empty", kind=ChallengeKind.EMAIL_CODE,
            prompt="Enter the code", context_url="https://x",
            recipe_id="r", persona_id="p", service_handle="airtable",
            needs_value_for="verification:email_code",
        )

        async def scenario():
            async def human():
                for _ in range(100):
                    if bus.get_pending(challenge.challenge_id) is not None:
                        with pytest.raises(HTTPException) as exc_info:
                            await resolve_challenge_endpoint(
                                challenge.challenge_id,
                                ResolveChallengeRequest(
                                    resolved=True, extracted_value="   ",
                                ),
                                _=True,
                            )
                        assert exc_info.value.status_code == 422
                        assert bus.get_pending(challenge.challenge_id) is challenge
                        await resolve_challenge_endpoint(
                            challenge.challenge_id,
                            ResolveChallengeRequest(
                                resolved=True, extracted_value=" 654321 ",
                            ),
                            _=True,
                        )
                        return
                    await asyncio.sleep(0.02)
                raise AssertionError("challenge never became pending")

            resolution, _ = await asyncio.gather(bus.submit(challenge), human())
            return resolution

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
