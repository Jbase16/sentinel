"""Controlled interaction acquisition tests."""

from __future__ import annotations

import json

import pytest

from core.behavior.interaction_admission import InteractionIntentSelector
from core.behavior.interaction_boundary import (
    INTERACTION_ACQUISITION_WORKFLOW,
    InteractionAcquisitionConfig,
    InteractionAcquisitionDenied,
    InteractionReadAcquisitionAdmission,
    InteractionReadAcquisitionBoundary,
)
from core.behavior.interactions import InteractionIntentMiner
from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    BehavioralReceiptStore,
    redacted_interaction_acquisition_outcome,
)
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.ownership_registry import (
    NativeOwnedCreationWitness,
    OwnershipRegistry,
)
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://example.test"
ALICE = "a" * 32
BOB = "b" * 32


def _control(index: int = 1, *, destination_ref: str = ""):
    control = {
        "tag": "a",
        "role": "link",
        "input_type": "",
        "form_method": "none",
        "destination": "same_origin",
        "locator": [
            {"tag": "html", "sibling_index": 1},
            {"tag": "body", "sibling_index": 1},
            {"tag": "a", "sibling_index": index},
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
    if destination_ref:
        control["destination_ref"] = destination_ref
    return control


def _frontier():
    return [{
        "obligation_id": stable_hash("security_obligation", {"index": 1}),
        "kind": "ownership_boundary",
        "risk_class": "read",
        "score": 500,
        "actionable": False,
        "resolution_kind": "unavailable",
        "resolution_ref": None,
        "signals": ["no_safe_resolution_path", "unresolved_frontier"],
    }]


def _envelope():
    envelope = AuthorizationEnvelope(
        envelope_id="c" * 32,
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="public bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=[INTERACTION_ACQUISITION_WORKFLOW],
    )
    envelope.sign()
    return envelope


def _policy(
    *,
    scope_filter=lambda url: url.startswith(ORIGIN),
    ownership_registry=None,
):
    return ExecutionPolicy(
        "bounty_safe",
        scope_filter=scope_filter,
        budget=ProofBudget(
            max_total_requests=7,
            max_requests_per_endpoint=5,
            max_cross_object_reads=1,
            max_privilege_mutations=0,
            max_creates=2,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
        ownership_registry=ownership_registry,
    )


def _admission(policy, *, destination_ref: str = ""):
    source_controls = [_control(destination_ref=destination_ref)]
    peer_controls = [_control(2)]
    catalog = InteractionIntentMiner().mine(
        source_controls,
        target_origin=ORIGIN,
        world_id=ALICE,
        peer_controls=peer_controls,
        peer_world_id=BOB,
        page_url=f"{ORIGIN}/app",
    )
    selected = InteractionIntentSelector().select(
        catalog,
        _frontier(),
        world_id=ALICE,
        policy_digest=policy.digest(),
        budget_snapshot=policy.budget.snapshot(),
        max_total_requests=policy.budget.max_total_requests,
    )
    assert selected.admission is not None
    return selected.admission, source_controls, peer_controls


def _resolver(
    source_controls,
    peer_controls,
    *,
    destinations=None,
    ownership_witness=None,
):
    calls = []
    destination_values = iter(destinations or [f"{ORIGIN}/details"] * 20)

    async def resolve(persona_id, locator, peer_persona_id):
        calls.append((persona_id, locator, peer_persona_id))
        result = {
            "current_url": f"{ORIGIN}/app",
            "destination_url": next(destination_values),
            "control": source_controls[0],
            "catalog_controls": source_controls,
            "peer_catalog_controls": peer_controls,
        }
        if ownership_witness is not None:
            result["ownership_witness"] = ownership_witness
        return result

    return resolve, calls


def _boundary(policy, raw_send, resolver, *, enabled=True):
    admission, _source, _peer = _admission(policy)
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    return InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=enabled),
    )


@pytest.mark.asyncio
async def test_boundary_resolves_twice_sends_one_get_and_persists_only_redacted_facts(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url, body, kwargs))
        return 200, '{"private":"response-body-must-not-enter-receipt"}'

    policy = _policy()
    admission, source_controls, peer_controls = _admission(policy)
    resolver, resolver_calls = _resolver(source_controls, peer_controls)
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )
    store = BehavioralReceiptStore(tmp_path)

    result = await InteractionReadAcquisitionAdmission(
        boundary,
        receipt_store=store,
    ).execute()

    assert result.status == "completed"
    assert result.reused is False
    assert result.record is not None
    assert result.record["url"] == f"{ORIGIN}/details"
    assert result.record["response_body"].startswith('{"private"')
    assert len(resolver_calls) == 2
    assert [(method, url, body) for method, url, body, _ in sent] == [
        ("GET", f"{ORIGIN}/details", None)
    ]
    assert sent[0][3]["_max_response_chars"] == 2 * 1024 * 1024
    assert sent[0][3]["_redirect_mode"] == "manual"
    receipt_text = next(tmp_path.glob("*.json")).read_text()
    assert f"{ORIGIN}/details" not in receipt_text
    assert "response-body-must-not-enter-receipt" not in receipt_text
    stored = json.loads(receipt_text)
    assert stored["outcome"]["kind"] == "interaction_read_acquisition"
    assert stored["outcome"]["requests_sent"] == 1
    assert stored["outcome"]["destination_page_ref"].startswith(
        "interaction_page:"
    )
    assert stored["outcome"]["operation_ref"].startswith("action:")
    legacy_outcome = dict(stored["outcome"])
    legacy_outcome.pop("destination_page_ref")
    legacy_outcome.pop("operation_ref")
    assert (
        redacted_interaction_acquisition_outcome(legacy_outcome)
        == legacy_outcome
    )


@pytest.mark.asyncio
async def test_cross_persona_probe_resolves_as_alice_and_sends_once_as_bob(
    tmp_path,
):
    registry = OwnershipRegistry()
    registry.register_created_value(
        f"{ORIGIN}/documents",
        "doc-owned",
        actor_persona=ALICE,
    )
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=ProofBudget(
            max_total_requests=1,
            max_requests_per_endpoint=1,
            max_cross_object_reads=1,
            max_privilege_mutations=0,
            max_creates=0,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
        ownership_registry=registry,
    )
    admission, source_controls, peer_controls = _admission(policy)
    resolver, resolver_calls = _resolver(
        source_controls,
        peer_controls,
        destinations=[f"{ORIGIN}/documents/doc-owned"] * 2,
    )
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url, body))
        return 200, '{"owner":"alice","private":"controlled"}'

    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        request_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )

    result = await InteractionReadAcquisitionAdmission(
        boundary,
        receipt_store=BehavioralReceiptStore(tmp_path),
    ).execute()

    assert resolver_calls == [
        (ALICE, admission.to_dict()["locator"], BOB),
        (ALICE, admission.to_dict()["locator"], BOB),
    ]
    assert sent == [("GET", f"{ORIGIN}/documents/doc-owned", None)]
    assert result.record is not None
    assert result.record["persona_id"] == BOB
    assert result.execution["budget_snapshot"]["cross_object_reads"] == 1


@pytest.mark.asyncio
async def test_cross_persona_probe_requires_creation_witness_before_traffic(
    tmp_path,
):
    destination_ref = "interaction_destination:" + "d" * 64
    registry = OwnershipRegistry()
    policy = _policy(ownership_registry=registry)
    admission, source_controls, peer_controls = _admission(
        policy,
        destination_ref=destination_ref,
    )
    resolver, _calls = _resolver(
        source_controls,
        peer_controls,
        destinations=[f"{ORIGIN}/documents/doc-owned"] * 2,
    )
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url))
        return 200, "must not run"

    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        request_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )

    with pytest.raises(
        InteractionAcquisitionDenied,
        match="interaction_cross_persona_ownership_proof_unavailable",
    ):
        await InteractionReadAcquisitionAdmission(
            boundary,
            receipt_store=BehavioralReceiptStore(tmp_path),
        ).execute()

    assert sent == []
    assert not registry.is_owned(
        f"{ORIGIN}/documents/doc-owned"
    )


@pytest.mark.asyncio
async def test_cross_persona_probe_accepts_bound_native_creation_witness(
    tmp_path,
):
    destination_ref = "interaction_destination:" + "d" * 64
    proof_ref = "native_ownership_witness:" + "e" * 64
    witness = NativeOwnedCreationWitness(
        persona_id=ALICE,
        create_ref="interaction_creation:" + "c" * 64,
        destination_ref=destination_ref,
        proof_ref=proof_ref,
    )
    registry = OwnershipRegistry()
    policy = _policy(ownership_registry=registry)
    admission, source_controls, peer_controls = _admission(
        policy,
        destination_ref=destination_ref,
    )
    resolver, _calls = _resolver(
        source_controls,
        peer_controls,
        destinations=[f"{ORIGIN}/documents/doc-owned"] * 2,
        ownership_witness=witness,
    )
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append((method, url, body))
        return 200, '{"owner":"alice","private":"controlled"}'

    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        request_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )

    result = await InteractionReadAcquisitionAdmission(
        boundary,
        receipt_store=BehavioralReceiptStore(tmp_path),
    ).execute()

    assert sent == [
        ("GET", f"{ORIGIN}/documents/doc-owned", None),
    ]
    assert result.execution["ownership_proof_ref"] == proof_ref
    assert registry.owner_of(
        f"{ORIGIN}/documents/doc-owned"
    ) == ALICE
    stored = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert stored["outcome"]["ownership_proof_ref"] == proof_ref


@pytest.mark.asyncio
async def test_terminal_receipt_is_reused_by_a_fresh_executor_without_target_traffic(
    tmp_path,
):
    first_sent = []

    async def first_raw(method, url, body=None, **kwargs):
        first_sent.append(url)
        return 200, "first"

    first_policy = _policy()
    admission, source_controls, peer_controls = _admission(first_policy)
    first_resolver, _calls = _resolver(source_controls, peer_controls)
    envelope = _envelope()
    first_provenance = ProvenanceSink()
    first_provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=first_policy.digest(),
    )
    first_boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=envelope,
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(
            first_raw,
            first_policy,
            provenance=first_provenance,
        ),
        resolver=first_resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )
    store = BehavioralReceiptStore(tmp_path)
    await InteractionReadAcquisitionAdmission(
        first_boundary,
        receipt_store=store,
    ).execute()

    retry_sent = []

    async def retry_raw(method, url, body=None, **kwargs):
        retry_sent.append(url)
        return 200, "must not run"

    retry_policy = _policy()
    retry_resolver, retry_calls = _resolver(source_controls, peer_controls)
    retry_provenance = ProvenanceSink()
    retry_provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=retry_policy.digest(),
    )
    retry_boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=envelope,
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(
            retry_raw,
            retry_policy,
            provenance=retry_provenance,
        ),
        resolver=retry_resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )

    reused = await InteractionReadAcquisitionAdmission(
        retry_boundary,
        receipt_store=store,
    ).execute()

    assert reused.status == "already_executed"
    assert reused.reused is True
    assert reused.record is None
    assert len(retry_calls) == 1
    assert retry_sent == []
    assert first_sent == [f"{ORIGIN}/details"]


@pytest.mark.asyncio
async def test_changed_destination_after_reservation_is_terminal_and_sends_nothing(
    tmp_path,
):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, "unexpected"

    policy = _policy()
    admission, source_controls, peer_controls = _admission(policy)
    resolver, calls = _resolver(
        source_controls,
        peer_controls,
        destinations=[f"{ORIGIN}/one", f"{ORIGIN}/two"],
    )
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )

    with pytest.raises(
        InteractionAcquisitionDenied,
        match="resolution_changed_before_send",
    ):
        await InteractionReadAcquisitionAdmission(
            boundary,
            receipt_store=BehavioralReceiptStore(tmp_path),
        ).execute()

    assert len(calls) == 2
    assert sent == []
    stored = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert stored["state"] == "aborted"
    assert stored["abort_reason"] == "interaction_acquisition_error"


@pytest.mark.asyncio
async def test_disabled_or_policy_denied_boundary_never_reaches_raw_transport(tmp_path):
    sent = []

    async def raw_send(method, url, body=None, **kwargs):
        sent.append(url)
        return 200, "unexpected"

    disabled_policy = _policy()
    admission, source_controls, peer_controls = _admission(disabled_policy)
    disabled_resolver, disabled_calls = _resolver(
        source_controls,
        peer_controls,
    )
    disabled_provenance = ProvenanceSink()
    disabled_provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=disabled_policy.digest(),
    )
    disabled = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(
            raw_send,
            disabled_policy,
            provenance=disabled_provenance,
        ),
        resolver=disabled_resolver,
        config=InteractionAcquisitionConfig(enabled=False),
    )
    with pytest.raises(InteractionAcquisitionDenied, match="is_disabled"):
        await disabled.validate_preflight()
    assert disabled_calls == []

    denied_policy = _policy(scope_filter=lambda _url: False)
    denied_admission, denied_source, denied_peer = _admission(denied_policy)
    denied_resolver, denied_calls = _resolver(denied_source, denied_peer)
    denied_provenance = ProvenanceSink()
    denied_provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=denied_policy.digest(),
    )
    denied = InteractionReadAcquisitionBoundary(
        admission=denied_admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(
            raw_send,
            denied_policy,
            provenance=denied_provenance,
        ),
        resolver=denied_resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )
    with pytest.raises(InteractionAcquisitionDenied, match="denied_by_policy"):
        await InteractionReadAcquisitionAdmission(
            denied,
            receipt_store=BehavioralReceiptStore(tmp_path / "denied"),
        ).execute()
    assert len(denied_calls) == 2
    assert sent == []


@pytest.mark.asyncio
async def test_transport_failure_reports_possible_single_request_and_aborts_receipt(
    tmp_path,
):
    attempts = 0

    async def raw_send(method, url, body=None, **kwargs):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("connection ended after dispatch")

    policy = _policy()
    admission, source_controls, peer_controls = _admission(policy)
    resolver, _calls = _resolver(source_controls, peer_controls)
    provenance = ProvenanceSink()
    provenance.record_context(
        target=ORIGIN,
        proof_mode="bounty_safe_shadow",
        policy_digest=policy.digest(),
    )
    boundary = InteractionReadAcquisitionBoundary(
        admission=admission,
        target_origin=ORIGIN,
        authorization=_envelope(),
        actor_persona_id=ALICE,
        peer_persona_id=BOB,
        executor=PolicyExecutor(raw_send, policy, provenance=provenance),
        resolver=resolver,
        config=InteractionAcquisitionConfig(enabled=True),
    )

    with pytest.raises(
        InteractionAcquisitionDenied,
        match="transport_failed",
    ) as error:
        await InteractionReadAcquisitionAdmission(
            boundary,
            receipt_store=BehavioralReceiptStore(tmp_path),
        ).execute()

    assert attempts == 1
    assert error.value.target_request_possible is True
    stored = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert stored["state"] == "aborted"
