from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from core.base import config as config_module
from core.base.config import SentinelConfig, StorageConfig, set_config
from core.base.task_router import TaskRouter
from core.behavior.normalize import stable_hash
from core.behavior.prerequisite_contracts import (
    GRAPH_BOUND_PREREQUISITE_WORKFLOW,
)
from core.behavior.prerequisite_one_click import (
    GraphBoundPrerequisiteFindingCandidate,
)
from core.behavior.receipts import (
    COMPLETED,
    BehavioralReceiptStore,
    redacted_receipt_context,
    request_fingerprint,
)
from core.epistemic.ledger import (
    ActiveProofCitation,
    Citation,
    ConfirmationLevel,
    EvidenceLedger,
)
from core.foundry.authorization import create_envelope
from core.foundry.vault import PersonaVault
from core.identity import (
    AssessmentIdentityContext,
    CredentialFreshness,
    scanner_evidence_context,
)
from core.server.routers.scans import (
    BehavioralOneClickProfile,
    ScanRequest,
    _run_behavioral_one_click_phase,
)
from core.verify.console import _reset_for_tests


ORIGIN = "https://owned.example.test"
PROVENANCE_ROOT = "c" * 64


class _NoopAI:
    async def process_tool_output(self, **_kwargs: Any) -> dict[str, Any]:
        return {"summary": "receipt relayed", "proposals": [], "next_steps": []}


class _FindingStore:
    def __init__(self) -> None:
        self.added: list[tuple[dict[str, Any], bool]] = []

    async def add_finding_async(
        self,
        finding: dict[str, Any],
        *,
        persist: bool,
    ) -> dict[str, Any]:
        self.added.append((finding, persist))
        return finding


class _ScanSession:
    def __init__(self, session_id: str) -> None:
        self.id = session_id
        self.knowledge: dict[str, Any] = {}
        self.findings = _FindingStore()
        self.logs: list[str] = []

    def log(self, message: str) -> None:
        self.logs.append(message)


class _ReceiptIndex:
    def __init__(self, receipts: dict[str, Any]) -> None:
        self.receipts = receipts

    def load(self, fingerprint: str) -> Any:
        return self.receipts.get(fingerprint)


@pytest.fixture
def isolated_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    previous_config = config_module._config
    previous_router = TaskRouter._instance
    data_dir = tmp_path / "sentinel-data"
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(data_dir))
    monkeypatch.setenv(
        "SENTINELFORGE_AUTHZ_STORE",
        str(data_dir / "authorizations"),
    )
    monkeypatch.setenv(
        "SENTINELFORGE_PERSONA_VAULT",
        str(data_dir / "personas"),
    )
    config = SentinelConfig(storage=StorageConfig(base_dir=data_dir))
    set_config(config)
    TaskRouter._instance = None
    _reset_for_tests()
    try:
        yield config
    finally:
        _reset_for_tests()
        TaskRouter._instance = previous_router
        config_module._config = previous_config


def _confirmed_outcome() -> dict[str, Any]:
    empty_resolution = {
        "resolved_operations": 0,
        "unresolved_operations": 0,
        "ambiguous_operations": 0,
    }
    return {
        "status": "completed",
        "plan": {
            "selected_proposal_id": f"authorization_proposal:{'b' * 64}",
        },
        "execution": {
            "status": "completed",
            "legacy_verdict": "BOLA_CONFIRMED",
            "finding_confirmed": True,
            "requests_attempted": 1,
            "requests_sent": 1,
            "policy_denials": 0,
            "provenance_root": PROVENANCE_ROOT,
        },
        "finding_confirmed": True,
        "finding": {"redacted": True},
        "graphql_resolution": {
            "catalog": {
                "artifacts": 0,
                "artifact_bytes": 0,
                "documents": 0,
                "operation_names": 0,
                "dropped": {
                    "artifacts": 0,
                    "artifact_bytes": 0,
                    "documents": 0,
                },
            },
            "assets": {
                "attempted": 0,
                "fetched": 0,
                "failed": 0,
                "documents_added": 0,
            },
            "source": empty_resolution,
            "peer": empty_resolution,
        },
    }


def _confirmed_graph_outcome() -> dict[str, Any]:
    terminal_refs = tuple(
        f"graph_bound_terminal_observation:{digit * 64}"
        for digit in ("1", "2", "3")
    )
    cleanup_refs = tuple(
        f"graph_bound_cleanup_evidence:{digit * 64}"
        for digit in ("4", "5", "6", "7", "8", "9")
    )
    oracle_requirement_id = (
        f"prerequisite_effect_oracle_requirement:{'a' * 64}"
    )
    plan_id = f"graph_bound_prepared_request_plan:{'b' * 64}"
    effect_witness_ref = (
        f"graph_bound_independent_effect_witness:{'c' * 64}"
    )
    selection = {
        "payout_goal_plan_id": f"payout_goal_plan:{'d' * 64}",
        "payout_candidate_id": f"payout_goal_candidate:{'e' * 64}",
        "payout_goal_id": f"security_witness_goal:{'f' * 64}",
        "payout_terminal_operation_id": f"action:{'1' * 64}",
        "specification_id": (
            f"graph_bound_prerequisite_experiment:{'2' * 64}"
        ),
        "plan_id": plan_id,
        "graph_target_ref": f"security_obligation_target:{'3' * 64}",
        "graph_digest": f"security_obligation_graph:{'4' * 64}",
    }
    candidate_ref = stable_hash(
        "graph_bound_prerequisite_candidate",
        {
            "oracle_requirement_id": oracle_requirement_id,
            "plan_id": plan_id,
            "family": "omission",
            "terminal_evidence_refs": list(terminal_refs),
            "effect_witness_ref": effect_witness_ref,
            "verdict": "confirmed",
        },
    )
    return {
        "schema_version": 1,
        "kind": "graph_bound_prerequisite_execution",
        "mode": "behavioral_graph_bound_prerequisite_execution_v1",
        "status": "confirmed",
        "receipt_state": "completed",
        "claim_contract_id": (
            f"graph_bound_execution_claim_contract:{'5' * 64}"
        ),
        "capture_freshness_ref": (
            f"graph_bound_capture_freshness:{'0' * 64}"
        ),
        "plan_id": plan_id,
        "family": "omission",
        "provisioning_id": (
            f"graph_bound_fresh_world_provisioning:{'6' * 64}"
        ),
        "oracle_requirement_id": oracle_requirement_id,
        "reference_state_id": f"state:{'7' * 64}",
        "oracle_evaluation_id": (
            f"graph_bound_prerequisite_oracle_evaluation:{'8' * 64}"
        ),
        "oracle_verdict": "confirmed",
        "effect_witness_ref": effect_witness_ref,
        "runtime_value_inequality_ref": (
            "graph_bound_runtime_value_inequality_attestation:"
            f"{'9' * 64}"
        ),
        "terminal_evidence_refs": list(terminal_refs),
        "cleanup_evidence_refs": list(cleanup_refs),
        "cleanup_status": "verified",
        "cleanup_steps_attempted": 3,
        "cleanup_steps_completed": 3,
        "cleanup_verifications_attempted": 3,
        "cleanup_verifications_completed": 3,
        "ownership_grants_removed": 3,
        "target_requests_sent": 14,
        "orphaned_owned_state_possible": False,
        "provenance_root": PROVENANCE_ROOT,
        "finding_candidate_ref": candidate_ref,
        "finding_confirmed": True,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
        **selection,
        "selection_ref": stable_hash(
            "graph_bound_one_click_selection",
            selection,
        ),
    }
def _identity(session_id: str, *, target_origin: str = ORIGIN) -> AssessmentIdentityContext:
    return AssessmentIdentityContext(
        session_id=session_id,
        authorization_envelope_id="envelope-proof-test",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target_origin=target_origin,
        target_reset_epoch=0,
        world_id="world-alice",
        persona_id="persona-alice",
        target_actor_id="actor-alice",
        tenant_id="tenant-owned",
        credential_source_ref="credential:alice",
        credential_epoch=1,
        credential_freshness=CredentialFreshness.FRESH,
        resource_id="resource:owned-note",
        representation_id="representation:http-json-v1",
    )


def _operation(session_id: str, *, target: str = f"{ORIGIN}/notes/1"):
    return scanner_evidence_context(
        session_id=session_id,
        authorization_envelope_id="envelope-proof-test",
        authorization_envelope_ref=f"authorization_envelope:{'a' * 64}",
        target=target,
        tool_name="proof-fixture",
        exec_id=stable_hash("exec", session_id),
        exit_code=0,
        world_id="world-alice",
    )


def _record_observation(
    ledger: EvidenceLedger,
    session_id: str,
    *,
    raw_output: bytes = b'{"id":"owned-note"}',
):
    operation = _operation(session_id)
    return ledger.record_canonical_observation(
        tool_name="proof-fixture",
        tool_args=["GET", "/notes/1"],
        target=f"{ORIGIN}/notes/1",
        raw_output=raw_output,
        identity=_identity(session_id),
        operation_family=operation.operation_family,
        operation_instance=operation.operation_instance,
    )


async def _post_verify_session(
    config: SentinelConfig,
    *,
    session_id: str,
    finding_id: str,
) -> httpx.Response:
    from core.server.api import app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {config.security.api_token}"},
    ) as client:
        return await client.post(
            "/v1/verify/sessions",
            json={"canonical_session_id": session_id, "finding_id": finding_id},
        )


@pytest.mark.asyncio
async def test_completed_behavioral_receipt_promotes_once_and_opens_verify(
    isolated_runtime: SentinelConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = create_envelope(
        researcher_identity="wo-a-operator",
        target_handle="owned-proof-target",
        authorized_origins=[ORIGIN],
        authorization_basis="operator-owned in-process proof target",
        allowed_workflows=["controlled_authorization"],
        disclosure_attestation=True,
    )
    vault = PersonaVault()
    source = vault.add_persona(label="Alice", email="alice@example.test")
    peer = vault.add_persona(label="Bob", email="bob@example.test")
    receipt_store = BehavioralReceiptStore()
    fingerprint = request_fingerprint(
        {"session_id": "session-wo-a", "proof": "cross-object-read"}
    )
    reservation = receipt_store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )
    completed = receipt_store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token or "",
        outcome=_confirmed_outcome(),
    )
    raw_finding = {
        "type": "Cross-object document read",
        "severity": "HIGH",
        "message": "The peer persona read the source persona's owned document.",
    }
    behavioral_response = _confirmed_outcome()
    behavioral_response["finding"] = raw_finding
    behavioral_response["orchestration_receipt"] = {
        "receipt_id": completed.receipt_id,
        "state": completed.state,
        "reused": False,
    }

    async def completed_endpoint(_request: Any, _: bool) -> dict[str, Any]:
        assert _ is True
        return behavioral_response

    from core.server.routers import foundry

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        completed_endpoint,
    )
    ledger = EvidenceLedger(isolated_runtime, receipt_store=receipt_store)
    TaskRouter._instance = TaskRouter(ai=_NoopAI(), ledger=ledger)
    session = _ScanSession("session-wo-a")
    request = ScanRequest(
        target=f"{ORIGIN}/notes/1",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )

    result = await _run_behavioral_one_click_phase(request, session=session)
    read_model = ledger.session_read_model(session.id)

    assert result is not None
    assert len(read_model.findings) == 1
    finding = read_model.findings[0]
    assert finding.session_id == session.id
    assert finding.active_proof == [
        ActiveProofCitation(
            observation_id=read_model.observations[0].id,
            receipt_id=completed.receipt_id,
            provenance_root=PROVENANCE_ROOT,
        )
    ]
    assert result["finding"]["id"] == finding.id
    assert session.findings.added[0][0]["id"] == finding.id

    response = await _post_verify_session(
        isolated_runtime,
        session_id=session.id,
        finding_id=finding.id,
    )
    assert response.status_code == 200, response.text
    assert response.json()["finding_id"] == finding.id


@pytest.mark.asyncio
async def test_graph_bound_receipt_promotes_only_its_exact_finding(
    isolated_runtime: SentinelConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = create_envelope(
        researcher_identity="graph-proof-operator",
        target_handle="owned-graph-proof-target",
        authorized_origins=[ORIGIN],
        authorization_basis="operator-owned graph proof target",
        allowed_workflows=[GRAPH_BOUND_PREREQUISITE_WORKFLOW],
        disclosure_attestation=True,
    )
    vault = PersonaVault()
    source = vault.add_persona(label="Alice", email="alice@example.test")
    peer = vault.add_persona(label="Bob", email="bob@example.test")
    outcome = _confirmed_graph_outcome()
    expected_finding = (
        GraphBoundPrerequisiteFindingCandidate.from_completed_outcome(
            outcome
        ).to_finding()
    )
    receipt_store = BehavioralReceiptStore()
    fingerprint = request_fingerprint(
        {"session_id": "session-graph-proof", "selection": outcome["selection_ref"]}
    )
    reservation = receipt_store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )
    completed = receipt_store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token or "",
        outcome=outcome,
    )
    behavioral_response = dict(completed.outcome or {})
    behavioral_response["finding"] = expected_finding
    behavioral_response["orchestration_receipt"] = {
        "receipt_id": completed.receipt_id,
        "state": completed.state,
        "reused": False,
    }

    async def completed_endpoint(_request: Any, _: bool) -> dict[str, Any]:
        assert _ is True
        return dict(behavioral_response)

    from core.server.routers import foundry

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        completed_endpoint,
    )
    ledger = EvidenceLedger(isolated_runtime, receipt_store=receipt_store)
    TaskRouter._instance = TaskRouter(ai=_NoopAI(), ledger=ledger)
    session = _ScanSession("session-graph-proof")
    request = ScanRequest(
        target=f"{ORIGIN}/workflows/owned/export",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )

    result = await _run_behavioral_one_click_phase(request, session=session)
    read_model = ledger.session_read_model(session.id)

    assert result is not None
    assert len(read_model.observations) == 1
    assert len(read_model.findings) == 1
    finding = read_model.findings[0]
    assert finding.active_proof == [
        ActiveProofCitation(
            observation_id=read_model.observations[0].id,
            receipt_id=completed.receipt_id,
            provenance_root=PROVENANCE_ROOT,
        )
    ]
    assert result["finding"]["id"] == finding.id
    assert result["finding"]["metadata"]["adversarial_triage_required"] is True
    assert result["finding"]["metadata"]["promotion_authority"] is False
    assert result["finding"]["metadata"]["submission_authority"] is False
    assert session.findings.added == [(result["finding"], True)]


@pytest.mark.asyncio
async def test_graph_bound_receipt_refuses_tampered_finding_before_promotion(
    isolated_runtime: SentinelConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = create_envelope(
        researcher_identity="graph-proof-operator",
        target_handle="owned-graph-proof-target",
        authorized_origins=[ORIGIN],
        authorization_basis="operator-owned graph proof target",
        allowed_workflows=[GRAPH_BOUND_PREREQUISITE_WORKFLOW],
        disclosure_attestation=True,
    )
    vault = PersonaVault()
    source = vault.add_persona(label="Alice", email="alice@example.test")
    peer = vault.add_persona(label="Bob", email="bob@example.test")
    outcome = _confirmed_graph_outcome()
    receipt_store = BehavioralReceiptStore()
    fingerprint = request_fingerprint(
        {"session_id": "session-graph-tamper", "selection": outcome["selection_ref"]}
    )
    reservation = receipt_store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )
    completed = receipt_store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token or "",
        outcome=outcome,
    )
    expected_finding = (
        GraphBoundPrerequisiteFindingCandidate.from_completed_outcome(
            completed.outcome or {}
        ).to_finding()
    )
    tampered_finding = {
        **expected_finding,
        "message": "tampered graph-bound claim",
    }
    behavioral_response = dict(completed.outcome or {})
    behavioral_response["finding"] = tampered_finding
    behavioral_response["orchestration_receipt"] = {
        "receipt_id": completed.receipt_id,
        "state": completed.state,
        "reused": False,
    }

    async def completed_endpoint(_request: Any, _: bool) -> dict[str, Any]:
        assert _ is True
        return dict(behavioral_response)

    from core.server.routers import foundry

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        completed_endpoint,
    )
    ledger = EvidenceLedger(isolated_runtime, receipt_store=receipt_store)
    TaskRouter._instance = TaskRouter(ai=_NoopAI(), ledger=ledger)
    session = _ScanSession("session-graph-tamper")
    request = ScanRequest(
        target=f"{ORIGIN}/workflows/owned/export",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )

    with pytest.raises(
        ValueError,
        match="graph-bound finding does not match its completed receipt",
    ):
        await _run_behavioral_one_click_phase(request, session=session)

    read_model = ledger.session_read_model(session.id)
    assert not read_model.observations
    assert not read_model.findings
    assert session.findings.added == []


@pytest.mark.parametrize(
    ("splice", "expected_error"),
    (
        (
            "legacy_kind",
            "behavioral finding result kind does not match completed receipt",
        ),
        (
            "peer_context",
            "behavioral finding receipt context does not match exact scan request",
        ),
    ),
)
@pytest.mark.asyncio
async def test_graph_bound_receipt_refuses_kind_or_peer_context_splice(
    isolated_runtime: SentinelConfig,
    monkeypatch: pytest.MonkeyPatch,
    splice: str,
    expected_error: str,
) -> None:
    envelope = create_envelope(
        researcher_identity="graph-splice-operator",
        target_handle="owned-graph-splice-target",
        authorized_origins=[ORIGIN],
        authorization_basis="operator-owned graph proof target",
        allowed_workflows=[GRAPH_BOUND_PREREQUISITE_WORKFLOW],
        disclosure_attestation=True,
    )
    vault = PersonaVault()
    source = vault.add_persona(label="Alice", email="alice@example.test")
    peer = vault.add_persona(label="Bob", email="bob@example.test")
    other_peer = vault.add_persona(label="Carol", email="carol@example.test")
    graph_outcome = _confirmed_graph_outcome()
    expected_finding = (
        GraphBoundPrerequisiteFindingCandidate.from_completed_outcome(
            graph_outcome
        ).to_finding()
    )
    receipt_store = BehavioralReceiptStore()
    fingerprint = request_fingerprint(
        {"session_id": f"session-graph-{splice}", "splice": splice}
    )
    reservation = receipt_store.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=(
                other_peer.persona_id if splice == "peer_context" else peer.persona_id
            ),
        ),
    )
    completed = receipt_store.complete(
        fingerprint,
        reservation_token=reservation.reservation_token or "",
        outcome=(
            _confirmed_outcome() if splice == "legacy_kind" else graph_outcome
        ),
    )
    behavioral_response = dict(graph_outcome)
    behavioral_response["finding"] = expected_finding
    behavioral_response["orchestration_receipt"] = {
        "receipt_id": completed.receipt_id,
        "state": completed.state,
        "reused": False,
    }

    async def completed_endpoint(_request: Any, _: bool) -> dict[str, Any]:
        assert _ is True
        return dict(behavioral_response)

    from core.server.routers import foundry

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        completed_endpoint,
    )
    ledger = EvidenceLedger(isolated_runtime, receipt_store=receipt_store)
    TaskRouter._instance = TaskRouter(ai=_NoopAI(), ledger=ledger)
    session = _ScanSession(f"session-graph-{splice}")
    request = ScanRequest(
        target=f"{ORIGIN}/workflows/owned/export",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=envelope.envelope_id,
            source_persona_id=source.persona_id,
            peer_persona_id=peer.persona_id,
        ),
    )

    with pytest.raises(ValueError, match=expected_error):
        await _run_behavioral_one_click_phase(request, session=session)

    read_model = ledger.session_read_model(session.id)
    assert not read_model.observations
    assert not read_model.findings
    assert session.findings.added == []


@pytest.mark.asyncio
async def test_passive_scanner_observation_stays_unpromoted_and_verify_refuses(
    isolated_runtime: SentinelConfig,
) -> None:
    ledger = EvidenceLedger(isolated_runtime)
    router = TaskRouter(ai=_NoopAI(), ledger=ledger)
    identity = _identity("session-passive")
    operation = _operation("session-passive")

    result = await router.handle_tool_output(
        tool_name="passive-scanner",
        stdout='{"candidate":"unverified"}',
        stderr="",
        rc=0,
        metadata={"target": f"{ORIGIN}/notes/1"},
        identity=identity,
        operation_family=operation.operation_family,
        operation_instance=operation.operation_instance,
        scanner_findings=(
            {
                "type": "Passive access-control candidate",
                "severity": "HIGH",
                "message": "Scanner-only classification.",
            },
        ),
    )

    assert result["findings"] == []
    assert ledger.session_read_model("session-passive").findings == ()
    response = await _post_verify_session(
        isolated_runtime,
        session_id="session-passive",
        finding_id="find-" + "0" * 64,
    )
    assert response.status_code == 400
    assert "requires a finding in the exact session" in response.text


@pytest.mark.parametrize(
    ("case", "expected_error"),
    (
        ("absent", "receipt is not completed"),
        ("identity_mismatch", "identity does not match evidence"),
        ("provenance_mismatch", "provenance is not committed"),
        ("oracle_refuted", "does not support an active finding"),
        ("oracle_inconclusive", "does not support an active finding"),
    ),
)
def test_fabricated_or_negative_active_proof_is_rejected_without_a_finding(
    isolated_runtime: SentinelConfig,
    case: str,
    expected_error: str,
) -> None:
    fingerprint = "1" * 64
    receipt_id = f"behavioral-{fingerprint}"
    context = redacted_receipt_context(
        target_origin=ORIGIN,
        envelope_id=_identity("session-negative").authorization_envelope_id,
        source_persona_id=_identity("session-negative").persona_id,
        peer_persona_id="persona-peer",
    )
    outcome = {
        "provenance_root": PROVENANCE_ROOT,
        "finding_confirmed": True,
        "oracle_verdict": "confirmed",
    }
    receipts: dict[str, Any] = {}
    if case != "absent":
        if case == "identity_mismatch":
            context = redacted_receipt_context(
                target_origin="https://different.example.test",
                envelope_id="different-envelope",
                source_persona_id="different-persona",
                peer_persona_id="different-peer",
            )
        if case == "provenance_mismatch":
            outcome["provenance_root"] = "d" * 64
        if case == "oracle_refuted":
            outcome["oracle_verdict"] = "refuted"
        if case == "oracle_inconclusive":
            outcome["oracle_verdict"] = "inconclusive"
        receipts[fingerprint] = SimpleNamespace(
            state=COMPLETED,
            outcome=outcome,
            context=context,
        )
    ledger = EvidenceLedger(
        isolated_runtime,
        receipt_store=_ReceiptIndex(receipts),
    )
    observation = _record_observation(ledger, "session-negative")

    with pytest.raises(ValueError, match=expected_error):
        ledger.promote_canonical_finding(
            title="Fabricated active claim",
            severity="HIGH",
            citations=[Citation(observation_id=observation.id)],
            description="Must fail closed.",
            confirmation_level=ConfirmationLevel.CONFIRMED.value,
            active_proof=[
                ActiveProofCitation(
                    observation_id=observation.id,
                    receipt_id=receipt_id,
                    provenance_root=PROVENANCE_ROOT,
                )
            ],
        )

    assert ledger.session_read_model("session-negative").findings == ()


def test_cross_session_active_proof_is_rejected(
    isolated_runtime: SentinelConfig,
) -> None:
    ledger = EvidenceLedger(isolated_runtime, receipt_store=_ReceiptIndex({}))
    first = _record_observation(ledger, "session-a", raw_output=b"first")
    second = _record_observation(ledger, "session-b", raw_output=b"second")

    with pytest.raises(
        ValueError,
        match="canonical finding cannot cross session identities",
    ):
        ledger.promote_canonical_finding(
            title="Cross-session claim",
            severity="HIGH",
            citations=[
                Citation(observation_id=first.id),
                Citation(observation_id=second.id),
            ],
            description="Session boundaries are immutable.",
            confirmation_level=ConfirmationLevel.CONFIRMED.value,
            active_proof=[
                ActiveProofCitation(
                    observation_id=first.id,
                    receipt_id="behavioral-" + "2" * 64,
                    provenance_root=PROVENANCE_ROOT,
                )
            ],
        )

    assert ledger.session_read_model("session-a").findings == ()
    assert ledger.session_read_model("session-b").findings == ()
