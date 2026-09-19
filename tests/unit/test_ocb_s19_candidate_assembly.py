"""OCB-S19: retained proof to draft, with real isolated receipt/ledger state.

Family-D setup reuses the frozen producer's controlled in-memory proof fixture.
Every assembly/read subsequently uses official persisted receipt, canonical
ledger, and workbench APIs. No live database or external target is involved.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi import HTTPException
import httpx
import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.behavior.capability_effect_evidence import evaluate_replay_leak
from core.behavior.capability_effect_promotion import CAPABILITY_FINDING_PROMOTION_ENV
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_receipt_context,
    request_fingerprint,
)
from core.epistemic.ledger import ActiveProofCitation, Citation, EvidenceLedger
from core.errors import SentinelError
from core.foundry.authorization import AuthorizationEnvelope
from core.ghost.canonical_evidence import GhostCanonicalEvidenceAdapter
from core.ghost.flow import FlowMapper, FlowStep
from core.identity import CredentialFreshness
from core.behavior.normalize import normalize_exchange
from core.reporting.submission_candidate import (
    build_submission_candidate,
    render_submission_candidate,
    resolve_submission_candidate,
)
from core.verify.workbench import CandidateWorkbenchStore
from tests.unit.test_active_finding_promotion_seam import (
    ORIGIN,
    PROVENANCE_ROOT,
    _confirmed_outcome,
)
from tests.unit.test_behavior_capability_effect_promotion import _completed_source


@dataclass
class _RetainedProof:
    config: SentinelConfig
    receipts: BehavioralReceiptStore
    session_id: str
    finding_id: str
    workbench_root: Path
    evidence: Any = None
    twin: Any = None
    captured: tuple[FlowStep, ...] = ()
    observation_ids: tuple[str, ...] = ()

    def ledger(self) -> EvidenceLedger:
        return EvidenceLedger(self.config, receipt_store=self.receipts)

    def read_model(self, session_id: str | None = None):
        return self.ledger().session_read_model(session_id or self.session_id)

    def store(self) -> CandidateWorkbenchStore:
        return CandidateWorkbenchStore(
            self.workbench_root,
            receipt_store=BehavioralReceiptStore(self.receipts.root),
            config=self.config,
        )


def _family_d(tmp_path: Path, monkeypatch, *, leak: bool = True) -> _RetainedProof:
    monkeypatch.setenv(CAPABILITY_FINDING_PROMOTION_ENV, "1")
    config, receipts, service, admission, receipt, evidence, twin = _completed_source(
        tmp_path, leak=leak
    )
    promoted = service.promote(receipt.receipt_id)
    assert promoted.promotion_state == ("promoted" if leak else "not_eligible")
    return _RetainedProof(
        config=config,
        receipts=receipts,
        session_id=admission.session_id,
        finding_id=promoted.canonical_finding_id or "find-" + "0" * 64,
        workbench_root=tmp_path / "workbenches",
        evidence=evidence,
        twin=twin,
    )


def _deny_target_requests(monkeypatch) -> None:
    from core.cortex.execution_policy import PolicyExecutor

    def denied(*_args, **_kwargs):
        raise AssertionError("OCB-S19 assembly must perform zero target requests")

    async def async_denied(*_args, **_kwargs):
        denied()

    monkeypatch.setattr(httpx.Client, "send", denied)
    monkeypatch.setattr(httpx.AsyncClient, "send", async_denied)
    monkeypatch.setattr(PolicyExecutor, "send_action", async_denied)
    monkeypatch.setattr(PolicyExecutor, "send_claimed_action", async_denied)


def _family_r(
    tmp_path: Path,
    monkeypatch,
    *,
    suffix: str = "primary",
    stale: bool = False,
    dependency: bool = False,
    request_body: str = "",
    request_content_type: str | None = None,
) -> _RetainedProof:
    from core.base import config as config_module

    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    monkeypatch.setattr(config_module, "_config", config)
    monkeypatch.setenv("SENTINELFORGE_FLOW_STORE", str(tmp_path / "captured-flows"))
    receipts = BehavioralReceiptStore(tmp_path / "receipts")
    session_id = "ocb-s19-captured-proof"
    ledger = EvidenceLedger(config, receipt_store=receipts)
    headers = {
        "Authorization": "Bearer ocb-operator-token",
        "Cookie": "sid=ocb-cookie-secret; csrf=ocb-csrf-secret",
        "X-Persona": "ocb-persona-session-value",
    }
    steps = []
    if dependency:
        producer = FlowStep("POST", f"{ORIGIN}/api/invoices", headers=headers)
        producer.set_response(
            status=201,
            body='{"invoiceId":"inv_7fa9f13a2b4c5d6e"}',
            content_type="application/json",
        )
        steps.append(producer)
    terminal = FlowStep(
        "POST" if request_body else "GET",
        f"{ORIGIN}/api/invoices/inv_7fa9f13a2b4c5d6e/export"
        if dependency
        else f"{ORIGIN}/api/documents/12345?token=ocb-query-secret",
        headers=headers,
        request_body=request_body,
        request_content_type=request_content_type,
    )
    terminal.set_response(
        status=200,
        body=(
            '{"privateNote":"ocb-response-secret",'
            '"sessionToken":"ocb-response-session-token"}'
        ),
        content_type="application/json",
    )
    steps.append(terminal)
    mapper = FlowMapper()
    flow_id = mapper.start_recording("OCB-S19 captured proof")
    for step in steps:
        step_id = mapper.record_request(
            flow_id,
            method=step.method,
            url=step.url,
            headers=step.headers,
            request_body=step.request_body,
            request_content_type=step.request_content_type,
        )
        assert step_id is not None
        assert mapper.finalize_step(
            step_id,
            status=step.response_status,
            body=step.response_body,
            content_type=step.response_content_type,
        )
    assert mapper.persist(flow_id) is not None
    flow = FlowMapper().load_persisted(flow_id)
    assert flow is not None
    envelope = AuthorizationEnvelope(
        envelope_id="ocb-s19-capture-envelope",
        researcher_identity="ocb-s19-researcher",
        target_handle="owned-fixture",
        authorized_origins=[ORIGIN],
        authorization_basis="owned in-memory test evidence",
        disclosure_attestation=True,
        created_at=1_700_000_000.0,
        expires_at=4_000_000_000.0,
    )
    envelope.sign()
    GhostCanonicalEvidenceAdapter(ledger).record_flow(
        flow, session_id=session_id, envelope=envelope
    )
    indexed = {
        item.operation_instance.source_ref: item
        for item in ledger.session_read_model(session_id).observations
    }
    observations = [
        indexed[
            normalize_exchange(
                step.to_dict(), source_id=f"{flow.id}:{step.id}", world_id=flow.id
            ).source_id
        ]
        for step in flow.steps
    ]
    if stale:
        observations = [
            ledger.record_canonical_observation(
                tool_name=item.tool.name,
                tool_args=list(item.tool.args),
                target=item.target,
                raw_output=ledger.cas.load(item.blob_hash),
                identity=replace(
                    item.identity, credential_freshness=CredentialFreshness.STALE
                ),
                operation_family=item.operation_family,
                operation_instance=item.operation_instance,
            )
            for item in observations
        ]
    identity = observations[0].identity
    fingerprint = request_fingerprint({"scenario": "OCB-S19", "lineage": suffix})
    reserved = receipts.reserve(
        fingerprint,
        context=redacted_receipt_context(
            target_origin=ORIGIN,
            envelope_id=identity.authorization_envelope_id,
            source_persona_id=identity.persona_id,
            peer_persona_id="persona-bob",
        ),
    )
    completed = receipts.complete(
        fingerprint,
        reservation_token=reserved.reservation_token,
        outcome=_confirmed_outcome(),
    )
    finding = ledger.promote_canonical_finding(
        title="Cross-account document exposure",
        severity="HIGH",
        citations=[Citation(observation_id=item.id) for item in observations],
        description="The receipt records access to the owned document from a peer.",
        remediation="Check document ownership before returning private data.",
        confirmation_level="confirmed",
        active_proof=[
            ActiveProofCitation(
                observation_id=item.id,
                receipt_id=completed.receipt_id,
                provenance_root=PROVENANCE_ROOT,
            )
            for item in observations
        ],
    )
    return _RetainedProof(
        config=config,
        receipts=receipts,
        session_id=session_id,
        finding_id=finding.id,
        workbench_root=tmp_path / "workbenches",
        captured=tuple(flow.steps),
        observation_ids=tuple(item.id for item in observations),
    )


def _select_captures(proof: _RetainedProof, *, duplicate: bool = False):
    model = proof.read_model()
    store = proof.store()
    workbench = store.open(model, finding_id=proof.finding_id)
    receipt_id = model.findings[0].active_proof[0].receipt_id
    exchanges = [
        (index, step, observation_id, receipt_id)
        for index, (step, observation_id) in enumerate(
            zip(proof.captured, proof.observation_ids)
        )
    ]
    captures = list(proof.captured)
    if duplicate:
        exchanges.append(
            (len(exchanges), proof.captured[-1], proof.observation_ids[-1], receipt_id)
        )
    noise = FlowStep("GET", f"{ORIGIN}/health")
    noise.id = "ocb-s19-unrelated-noise"
    noise.set_response(status=200, body="healthy", content_type="text/plain")
    captures.append(noise)
    return store.select_exchanges(
        workbench,
        exchanges=tuple(exchanges),
        read_model=model,
        capture_steps=tuple(captures),
    )


def _wire_surfaces(proof: _RetainedProof, monkeypatch):
    """Redirect runtime owners to tmp_path; canonical readers stay real/fresh."""

    from core.base import config as config_module
    from core.data import db as db_module
    from core.epistemic import ledger as ledger_module
    from core.reporting import submission_candidate as candidate_module
    from core.server.routers import ai, cortex
    from core.verify import console, workbench as workbench_module

    origin = (
        proof.evidence.target_origin
        if proof.evidence is not None
        else (proof.read_model().observations[0].identity.target_origin)
    )

    class _SessionIndex:
        async def init(self):
            return None

        async def get_session(self, _session_id):
            return {"target": origin}

    def fresh_read(session_id):
        return proof.read_model(session_id)

    monkeypatch.setattr(config_module, "_config", proof.config)
    monkeypatch.setattr(console, "_SESSIONS", {})
    monkeypatch.setattr(db_module.Database, "instance", staticmethod(_SessionIndex))
    monkeypatch.setattr(candidate_module, "CandidateWorkbenchStore", proof.store)
    monkeypatch.setattr(workbench_module, "CandidateWorkbenchStore", proof.store)
    monkeypatch.setattr(ledger_module, "load_canonical_session_read_model", fresh_read)
    monkeypatch.setattr(cortex, "load_canonical_session_read_model", fresh_read)
    monkeypatch.setattr(ai, "load_canonical_session_read_model", fresh_read)

    def no_model():
        raise AssertionError("OCB-S19 claims must not invoke an AI model")

    monkeypatch.setattr(ai.AIEngine, "instance", staticmethod(no_model))
    return origin


def _verify_shell(proof: _RetainedProof):
    from core.verify.console import create_session_from_workbench

    model = proof.read_model()
    workbench = proof.store().open(model, finding_id=proof.finding_id)
    session = create_session_from_workbench(
        workbench,
        target_url=model.observations[0].target,
        original_finding=next(
            item for item in model.finding_views() if item["id"] == proof.finding_id
        ),
    )
    session.candidate_workbench_store = proof.store()
    return session


async def _render_four(proof: _RetainedProof, session, origin: str):
    from core.server.routers import ai, cortex, scans, verify

    verified = await verify.get_submission_candidate(session.session_id, _=True)
    cortex_report = await cortex.generate_report(
        cortex.ReportGenerateRequest(
            target=origin,
            session_id=proof.session_id,
            finding_id=proof.finding_id,
            format="json",
        ),
        graph_analyzer=SimpleNamespace(),
    )
    ai_report = await ai.generate_report(
        session_id=proof.session_id,
        finding_id=proof.finding_id,
        report_type="technical",
        format="json",
    )
    scan_report = await scans.get_session_bounty_report(proof.session_id)
    return verified, cortex_report, ai_report, scan_report


async def _assert_four_refuse(proof: _RetainedProof, session, origin: str):
    from core.server.routers import ai, cortex, scans, verify

    with pytest.raises(HTTPException) as verify_refusal:
        await verify.get_submission_candidate(session.session_id, _=True)
    assert verify_refusal.value.status_code in {400, 409}
    with pytest.raises(HTTPException) as cortex_refusal:
        await cortex.generate_report(
            cortex.ReportGenerateRequest(
                target=origin,
                session_id=proof.session_id,
                finding_id=proof.finding_id,
            ),
            graph_analyzer=SimpleNamespace(),
        )
    assert cortex_refusal.value.status_code == 409
    with pytest.raises(SentinelError):
        await ai.generate_report(
            session_id=proof.session_id,
            finding_id=proof.finding_id,
            report_type="technical",
            format="json",
        )
    report = await scans.get_session_bounty_report(proof.session_id)
    assert report["reports"] == []
    assert report["candidate_digests"] == []
    assert report["count"] == 0


def test_ocb_s19_shape_a_refuted_oracle_retains_every_required_observation(
    tmp_path, monkeypatch
):
    proof = _family_d(tmp_path, monkeypatch)
    _deny_target_requests(monkeypatch)
    assert proof.evidence.oracle["verdict"] == "refuted"
    assert evaluate_replay_leak(proof.evidence).eligible
    calls_before = (len(proof.twin.calls), len(proof.twin.cleanup_calls))

    candidate = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    payload = candidate.to_dict()
    assert payload["reproduction_kind"] == "evidence_attestation"
    assert payload["replayable"] is False
    assert payload["steps"] == []
    assert len(payload["active_proof"]) == 1
    assert payload["active_proof"][0]["receipt_id"] == proof.evidence.source_receipt_id
    assert payload["active_proof"][0]["provenance_root"] == proof.evidence.evidence_root
    attestation_json = json.dumps(payload["attestation"], sort_keys=True)
    assert proof.evidence.evidence_root in attestation_json
    for observation in proof.evidence.observations:
        assert observation["observation_id"] in attestation_json
        assert observation["observation_kind"] in attestation_json
    assert "refuted" in attestation_json
    assert payload["effect_class"] == "capability_replay_leak_v1"
    assert payload["claims"]["severity"] == proof.read_model().findings[0].severity
    rendered = render_submission_candidate(candidate)
    assert "non-replayable" in rendered.markdown.lower()
    assert "curl " not in rendered.markdown
    assert rendered.steps_to_reproduce == ()
    assert (len(proof.twin.calls), len(proof.twin.cleanup_calls)) == calls_before


def test_ocb_s19_shape_a_same_digest_on_four_surfaces_and_restart(
    tmp_path, monkeypatch
):
    proof = _family_d(tmp_path, monkeypatch)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    session.persona_headers = {"Authorization": "Bearer ocb-attestation-operator-token"}
    session.persona_cookies = {"sid": "ocb-attestation-cookie"}
    expected = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    first = asyncio.run(_render_four(proof, session, origin))
    restarted_session = _verify_shell(proof)
    second = asyncio.run(_render_four(proof, restarted_session, origin))
    for verified, cortex_report, ai_report, scan_report in (first, second):
        assert verified.candidate_digest == expected.candidate_digest
        assert cortex_report.candidate_digest == expected.candidate_digest
        assert ai_report["candidate_digest"] == expected.candidate_digest
        assert scan_report["candidate_digests"] == [expected.candidate_digest]
        assert json.loads(cortex_report.content)["reproduction_kind"] == (
            "evidence_attestation"
        )
        assert json.loads(ai_report["content"])["replayable"] is False
        assert scan_report["reports"][0]["replayable"] is False
        assert verified.entry_count == 0
        serialized = json.dumps(
            {
                "verify": verified.model_dump(),
                "cortex": cortex_report.model_dump(),
                "ai": ai_report,
                "scans": scan_report,
            }
        )
        assert "ocb-attestation-operator-token" not in serialized
        assert "ocb-attestation-cookie" not in serialized
    assert len(list(proof.workbench_root.glob("*.json"))) == 1
    restarted = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    assert restarted.to_dict() == expected.to_dict()


@pytest.mark.parametrize("entity", ["finding", "observation"])
@pytest.mark.parametrize("shape", ["R", "A"])
def test_ocb_s19_invalidation_survives_restart_and_closes_every_surface(
    tmp_path, monkeypatch, entity, shape
):
    proof = (
        _family_d(tmp_path, monkeypatch)
        if shape == "A"
        else _family_r(tmp_path, monkeypatch)
    )
    if shape == "R":
        _select_captures(proof)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    asyncio.run(_render_four(proof, session, origin))
    ledger = proof.ledger()
    if entity == "finding":
        ledger.invalidate_finding(proof.finding_id, "OCB-S19 proof invalidated")
    else:
        ledger.invalidate_observation(
            proof.read_model().observations[0].id, "OCB-S19 source invalidated"
        )
    assert proof.read_model().findings == ()
    asyncio.run(_assert_four_refuse(proof, session, origin))


def test_ocb_s19_secure_family_d_source_never_becomes_an_attestation(
    tmp_path, monkeypatch
):
    proof = _family_d(tmp_path, monkeypatch, leak=False)
    _deny_target_requests(monkeypatch)
    assert not evaluate_replay_leak(proof.evidence).eligible
    assert proof.read_model().findings == ()
    with pytest.raises(ValueError):
        resolve_submission_candidate(proof.read_model(), workbench_store=proof.store())
    assert not proof.workbench_root.exists() or not list(
        proof.workbench_root.glob("*.json")
    )
    origin = _wire_surfaces(proof, monkeypatch)
    from core.verify.console import VerificationSession, _register

    session = VerificationSession(
        session_id="ocb-s19-secure-source-review",
        finding_id=proof.finding_id,
        target_url=origin,
        target_origin=origin,
        canonical_session_id=proof.session_id,
    )
    _register(session)
    asyncio.run(_assert_four_refuse(proof, session, origin))


@pytest.mark.parametrize("shape", ["R", "A"])
def test_ocb_s19_cross_session_cannot_render_existing_workbench(
    tmp_path, monkeypatch, shape
):
    proof = (
        _family_d(tmp_path, monkeypatch)
        if shape == "A"
        else _family_r(tmp_path, monkeypatch)
    )
    if shape == "R":
        _select_captures(proof)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    foreign = replace(proof, session_id="ocb-s19-other-assessment")
    from core.verify.console import _register

    foreign_session = replace(
        session,
        session_id="ocb-s19-cross-session-attempt",
        canonical_session_id=foreign.session_id,
    )
    _register(foreign_session)
    asyncio.run(_assert_four_refuse(foreign, foreign_session, origin))


def test_ocb_s19_shape_r_minimizes_duplicates_and_renders_identically_everywhere(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch)
    workbench = _select_captures(proof, duplicate=True)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    expected = build_submission_candidate(
        proof.read_model(),
        workbench_id=workbench.workbench_id,
        workbench_store=proof.store(),
    )
    payload = expected.to_dict()
    assert payload["reproduction_kind"] == "replayable_recipe"
    assert payload["replayable"] is True
    assert payload["attestation"] is None
    assert len(payload["steps"]) == 1
    assert payload["impact"] == "unknown"
    assert payload["effect_class"] == "unknown"
    reports = asyncio.run(_render_four(proof, session, origin))
    verified, cortex_report, ai_report, scan_report = reports
    assert verified.candidate_digest == expected.candidate_digest
    assert cortex_report.candidate_digest == expected.candidate_digest
    assert ai_report["candidate_digest"] == expected.candidate_digest
    assert scan_report["candidate_digests"] == [expected.candidate_digest]
    serialized = json.dumps(
        {
            "candidate": payload,
            "verify": verified.model_dump(),
            "cortex": cortex_report.model_dump(),
            "ai": ai_report,
            "scans": scan_report,
            "draft": workbench.to_dict(),
        },
        sort_keys=True,
    )
    for secret in (
        "ocb-query-secret",
        "ocb-operator-token",
        "ocb-cookie-secret",
        "ocb-csrf-secret",
        "ocb-persona-session-value",
        "ocb-response-secret",
        "ocb-response-session-token",
    ):
        assert secret not in serialized
    assert "/health" not in serialized
    assert "curl " in verified.submission_markdown
    restarted = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    assert restarted.to_dict() == payload
    with pytest.raises(ValueError, match="digest mismatch"):
        replace(expected, summary="An unsupported broader impact claim")


def test_ocb_s19_shape_r_preserves_required_producer_and_refuses_omission(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch, dependency=True)
    model = proof.read_model()
    store = proof.store()
    workbench = store.open(model, finding_id=proof.finding_id)
    receipt_id = model.findings[0].active_proof[0].receipt_id
    with pytest.raises(ValueError):
        store.select_exchanges(
            workbench,
            exchanges=((1, proof.captured[1], proof.observation_ids[1], receipt_id),),
            read_model=model,
            capture_steps=proof.captured,
        )
    selected = _select_captures(proof)
    candidate = build_submission_candidate(
        proof.read_model(),
        workbench_id=selected.workbench_id,
        workbench_store=proof.store(),
    )
    assert len(candidate.steps) == 2
    assert {item.proof.observation_id for item in candidate.steps} == set(
        proof.observation_ids
    )


@pytest.mark.parametrize("source_state", ["missing", "changed"])
def test_ocb_s19_recipe_refuses_missing_or_changed_retained_capture(
    tmp_path, monkeypatch, source_state
):
    proof = _family_r(tmp_path, monkeypatch)
    _select_captures(proof)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    asyncio.run(_render_four(proof, session, origin))
    if source_state == "missing":
        monkeypatch.setenv(
            "SENTINELFORGE_FLOW_STORE", str(tmp_path / "unavailable-capture-store")
        )
    else:
        flow_id = proof.read_model().observations[0].identity.world_id
        mapper = FlowMapper()
        flow = mapper.load_persisted(flow_id)
        assert flow is not None
        assert mapper.finalize_step(
            flow.steps[0].id,
            status=403,
            body='{"denied":true}',
            content_type="application/json",
        )
        assert mapper.persist(flow_id) is not None
    asyncio.run(_assert_four_refuse(proof, session, origin))


def test_ocb_s19_retained_flow_order_change_refuses_every_surface(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch, dependency=True)
    _select_captures(proof)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    asyncio.run(_render_four(proof, session, origin))
    original_model = proof.read_model()
    flow_id = original_model.observations[0].identity.world_id
    mapper = FlowMapper()
    flow = mapper.load_persisted(flow_id)
    assert flow is not None and len(flow.steps) == 2
    # Controlled source mutation uses the existing flow object/persistence API.
    # Canonical observations, findings, receipts, and their CAS blobs stay intact.
    flow.steps.reverse()
    assert mapper.persist(flow_id) is not None
    assert proof.read_model() == original_model
    with pytest.raises(ValueError, match="order changed"):
        resolve_submission_candidate(
            proof.read_model(),
            finding_id=proof.finding_id,
            workbench_store=proof.store(),
        )
    asyncio.run(_assert_four_refuse(proof, session, origin))


def test_ocb_s19_recipe_dependency_digest_ignores_unrelated_retained_capture(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch, dependency=True)
    first = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    flow_id = proof.read_model().observations[0].identity.world_id
    mapper = FlowMapper()
    assert mapper.load_persisted(flow_id) is not None
    step_id = mapper.record_request(flow_id, "GET", f"{ORIGIN}/health")
    assert step_id is not None
    assert mapper.finalize_step(step_id, status=200, body="healthy")
    assert mapper.persist(flow_id) is not None
    second = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    assert second.to_dict() == first.to_dict()
    assert len(second.steps) == 2


def test_ocb_s19_distinct_active_receipt_lineages_never_deduplicate(
    tmp_path, monkeypatch
):
    first = _family_r(tmp_path / "first", monkeypatch, suffix="first")
    first_workbench = _select_captures(first)
    first_candidate = build_submission_candidate(
        first.read_model(),
        workbench_id=first_workbench.workbench_id,
        workbench_store=first.store(),
    )
    second = _family_r(tmp_path / "second", monkeypatch, suffix="second")
    second_workbench = _select_captures(second)
    second_candidate = build_submission_candidate(
        second.read_model(),
        workbench_id=second_workbench.workbench_id,
        workbench_store=second.store(),
    )
    assert first_candidate.canonical_session_id == second_candidate.canonical_session_id
    assert first_candidate.title == second_candidate.title
    assert first_candidate.lineage_digest != second_candidate.lineage_digest
    assert first_candidate.candidate_digest != second_candidate.candidate_digest


def test_ocb_s19_canonical_claim_secrets_are_sanitized_after_restart_on_all_surfaces(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch)
    original = proof.read_model().findings[0]
    claim = proof.ledger().promote_canonical_finding(
        title="Document access with ocb-operator-token",
        severity=original.severity,
        citations=list(original.citations),
        description=(
            "Owned evidence contains ocb-cookie-secret and ocb-response-session-token."
        ),
        remediation="Rotate ocb-csrf-secret after fixing document ownership.",
        metadata={
            "impact": "Recorded private-document exposure for ocb-persona-session-value.",
        },
        confirmation_level=original.confirmation_level,
        active_proof=list(original.active_proof),
    )
    proof = replace(proof, finding_id=claim.id)
    _select_captures(proof)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    verified, cortex_report, ai_report, scan_report = asyncio.run(
        _render_four(proof, session, origin)
    )
    candidate = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    serialized = json.dumps(
        {
            "candidate": candidate.to_dict(),
            "verify": verified.model_dump(),
            "cortex": cortex_report.model_dump(),
            "ai": ai_report,
            "scans": scan_report,
        }
    )
    for secret in (
        "ocb-operator-token",
        "ocb-cookie-secret",
        "ocb-response-session-token",
        "ocb-csrf-secret",
        "ocb-persona-session-value",
    ):
        assert secret not in serialized
    assert candidate.impact.startswith("Recorded private-document exposure")
    assert candidate.effect_class == "unknown"
    assert candidate.candidate_digest == verified.candidate_digest


@pytest.mark.parametrize(
    "changed_field",
    ["method", "url", "headers", "request_body", "response_status", "response_body"],
)
def test_ocb_s19_recipe_must_match_its_recorded_canonical_exchange(
    tmp_path, monkeypatch, changed_field
):
    proof = _family_r(tmp_path, monkeypatch)
    model = proof.read_model()
    store = proof.store()
    workbench = store.open(model, finding_id=proof.finding_id)
    captured = FlowStep.from_dict(proof.captured[0].to_dict())
    substitutions = {
        "method": "DELETE",
        "url": f"{ORIGIN}/api/unrelated/98765",
        "headers": {"authorization": "Bearer ocb-substituted-persona-token"},
        "request_body": '{"unsupported":"request-body-substitution"}',
        "response_status": 403,
        "response_body": '{"unsupported":"ocb-response-substitution"}',
    }
    setattr(captured, changed_field, substitutions[changed_field])
    with pytest.raises(ValueError):
        store.select_exchanges(
            workbench,
            exchanges=(
                (
                    0,
                    captured,
                    proof.observation_ids[0],
                    model.findings[0].active_proof[0].receipt_id,
                ),
            ),
            read_model=model,
            capture_steps=(captured,),
        )
    assert proof.store().load(workbench.workbench_id, read_model=model).selections == ()


_AMBIGUOUS_REQUEST_BODIES = (
    (
        "application/json",
        '{"document":{"access":"read"}}',
        '{"document":{"access":"write","access":"read"}}',
    ),
    (
        "application/x-www-form-urlencoded",
        "scope=read",
        "sc%6fpe=write&scope=read",
    ),
)


@pytest.mark.parametrize(
    "content_type,original_body,ambiguous_body", _AMBIGUOUS_REQUEST_BODIES
)
def test_ocb_s19_ambiguous_body_cannot_exploit_equivalent_normalized_commitment(
    tmp_path, monkeypatch, content_type, original_body, ambiguous_body
):
    proof = _family_r(
        tmp_path,
        monkeypatch,
        request_body=original_body,
        request_content_type=content_type,
    )
    model = proof.read_model()
    observation = next(
        item for item in model.observations if item.id == proof.observation_ids[0]
    )
    captured = proof.captured[0]
    substituted = FlowStep.from_dict(captured.to_dict())
    substituted.request_body = ambiguous_body
    canonical_source = f"{observation.identity.world_id}:{captured.id}"
    before = normalize_exchange(
        captured.to_dict(),
        source_id=canonical_source,
        world_id=observation.identity.world_id,
    )
    after = normalize_exchange(
        substituted.to_dict(),
        source_id=canonical_source,
        world_id=observation.identity.world_id,
    )
    assert before.to_dict() == after.to_dict()
    store = proof.store()
    workbench = store.open(model, finding_id=proof.finding_id)
    with pytest.raises(ValueError, match="unambiguous request body"):
        store.select_exchanges(
            workbench,
            exchanges=(
                (
                    0,
                    substituted,
                    observation.id,
                    model.findings[0].active_proof[0].receipt_id,
                ),
            ),
            read_model=model,
            capture_steps=(substituted,),
        )
    assert store.load(workbench.workbench_id, read_model=model).selections == ()


@pytest.mark.parametrize(
    "content_type,_original_body,ambiguous_body", _AMBIGUOUS_REQUEST_BODIES
)
def test_ocb_s19_ambiguously_recorded_request_refuses_every_surface(
    tmp_path, monkeypatch, content_type, _original_body, ambiguous_body
):
    proof = _family_r(
        tmp_path,
        monkeypatch,
        request_body=ambiguous_body,
        request_content_type=content_type,
    )
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    with pytest.raises(ValueError, match="unambiguous request body"):
        resolve_submission_candidate(
            proof.read_model(),
            finding_id=proof.finding_id,
            workbench_store=proof.store(),
        )
    asyncio.run(_assert_four_refuse(proof, session, origin))


def test_ocb_s19_complete_citation_coverage_cannot_hide_missing_lineage_producer(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch, dependency=True)
    model = proof.read_model()
    original = model.findings[0]
    terminal_id = proof.observation_ids[-1]
    terminal_finding = proof.ledger().promote_canonical_finding(
        title=original.title,
        severity=original.severity,
        citations=[Citation(observation_id=terminal_id)],
        description=original.description,
        confirmation_level=original.confirmation_level,
        active_proof=[
            item for item in original.active_proof if item.observation_id == terminal_id
        ],
    )
    model = proof.read_model()
    store = proof.store()
    workbench = store.open(model, finding_id=terminal_finding.id)
    with pytest.raises(ValueError):
        store.select_exchanges(
            workbench,
            exchanges=(
                (
                    1,
                    proof.captured[1],
                    terminal_id,
                    terminal_finding.active_proof[0].receipt_id,
                ),
            ),
            read_model=model,
            capture_steps=proof.captured,
        )


def test_ocb_s19_explicitly_stale_recorded_identity_refuses_all_surfaces(
    tmp_path, monkeypatch
):
    proof = _family_r(tmp_path, monkeypatch, stale=True)
    with pytest.raises(ValueError, match="stale"):
        _select_captures(proof)
    origin = _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    asyncio.run(_assert_four_refuse(proof, session, origin))


def test_ocb_s19_owned_draft_cleanup_is_idempotent_and_preserves_evidence(
    tmp_path, monkeypatch
):
    proof = _family_d(tmp_path, monkeypatch)
    candidate = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    before = proof.read_model()
    removed = proof.store().discard(candidate.workbench_id)
    assert removed == {"status": "removed", "orphaned_owned_state_possible": False}
    assert proof.store().discard(candidate.workbench_id) == {
        "status": "absent",
        "orphaned_owned_state_possible": False,
    }
    assert proof.read_model() == before
    assert not list(proof.workbench_root.glob("*.json"))
    rebuilt = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    assert rebuilt.candidate_digest == candidate.candidate_digest


def test_ocb_s19_failed_owned_draft_cleanup_reports_orphan_risk(tmp_path, monkeypatch):
    proof = _family_d(tmp_path, monkeypatch)
    candidate = resolve_submission_candidate(
        proof.read_model(), finding_id=proof.finding_id, workbench_store=proof.store()
    )
    original_unlink = Path.unlink

    def cannot_remove_draft(path, *args, **kwargs):
        if path.parent == proof.workbench_root:
            raise OSError("ocb-cleanup-private-detail")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", cannot_remove_draft)
    result = proof.store().discard(candidate.workbench_id)
    assert result == {"status": "failed", "orphaned_owned_state_possible": True}
    assert "ocb-cleanup-private-detail" not in json.dumps(result)
    assert len(list(proof.workbench_root.glob("*.json"))) == 1


def test_ocb_s19_shape_a_verify_promote_accepts_empty_transcript(tmp_path, monkeypatch):
    from core.server.routers import verify

    proof = _family_d(tmp_path, monkeypatch)
    _wire_surfaces(proof, monkeypatch)
    _deny_target_requests(monkeypatch)
    session = _verify_shell(proof)
    assert session.transcript == []
    response = asyncio.run(
        verify.promote_to_repro(session.session_id, verify.PromoteRequest(), _=True)
    )
    assert response.reproduction_kind == "evidence_attestation"
    assert response.replayable is False
    assert response.steps_to_reproduce == []


@pytest.mark.parametrize("failure", [ValueError, OSError])
def test_ocb_s19_render_refusals_never_serialize_secret_exception_text(
    tmp_path, monkeypatch, failure
):
    proof = _family_d(tmp_path, monkeypatch)
    origin = _wire_surfaces(proof, monkeypatch)
    session = _verify_shell(proof)
    from core.epistemic import ledger as ledger_module
    from core.server.routers import ai, cortex, scans, verify

    def broken_read(_session_id):
        raise failure("ocb-diagnostic-operator-secret")

    monkeypatch.setattr(ledger_module, "load_canonical_session_read_model", broken_read)
    monkeypatch.setattr(ai, "load_canonical_session_read_model", broken_read)
    monkeypatch.setattr(cortex, "load_canonical_session_read_model", broken_read)
    calls = (
        lambda: verify.get_submission_candidate(session.session_id, _=True),
        lambda: cortex.generate_report(
            cortex.ReportGenerateRequest(target=origin, session_id=proof.session_id),
            graph_analyzer=SimpleNamespace(),
        ),
        lambda: ai.generate_report(
            session_id=proof.session_id,
            finding_id=proof.finding_id,
            report_type="technical",
            format="json",
        ),
        lambda: scans.get_session_bounty_report(proof.session_id),
    )
    for call in calls:
        with pytest.raises((HTTPException, SentinelError)) as refused:
            asyncio.run(call())
        assert "ocb-diagnostic-operator-secret" not in str(refused.value)
        assert "ocb-diagnostic-operator-secret" not in str(
            getattr(refused.value, "detail", "")
        )
