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

    def test_disabled_endpoint_returns_plan_without_constructing_live_traffic(self, monkeypatch):
        from core.server.routers.foundry import run_behavioral_authorization_endpoint
        from core.wraith.bola_replay import SNDReplayTransport

        request, _, _ = self._setup()
        request.script_urls = [f"{self.ORIGIN}/assets/app.js"]

        async def forbidden(*_args, **_kwargs):
            raise AssertionError("disabled primary planner must not reach SND")

        monkeypatch.setattr(SNDReplayTransport, "send", forbidden)
        result = _run(run_behavioral_authorization_endpoint(request, _=True))

        assert result["status"] == "disabled"
        assert result["plan"]["selected_proposal_id"]
        assert result["execution"] is None
        assert result["behavioral_shadow"]["status"] == "open"
        assert result["behavioral_shadow"]["executable"] is False
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
        assert result["finding"]["metadata"]["behavioral_primary_planner"]
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
            "start_network_capture",
            "navigate",
            "stop_network_capture",
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
