"""R5D3 passive capability-consumption ledger and replay-refusal tests."""

from __future__ import annotations

import ast
from copy import copy
from dataclasses import fields, replace
import json
from pathlib import Path

import pytest

import core.behavior.capability_consumption_ledger as consumption_module
from core.behavior.capability_confinement_freshness import (
    ConfinedPresentationBinding,
    ConfinementOutcome,
    ConfinementPresentation,
    evaluate_confinement,
)
from core.behavior.capability_consumption_ledger import (
    CAPABILITY_CONSUMPTION_LEDGER_MODE,
    CapabilityConsumptionLedger,
    ConsumptionDecision,
    ConsumptionEntry,
    ConsumptionLedgerDenied,
    ConsumptionOutcome,
    ConsumptionResult,
    evaluate_consumption,
)
from core.behavior.capability_contract import (
    CapabilityDecision,
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash


ORIGIN = "https://api.example.test"
OTHER_ORIGIN = "https://other.example.test"
RAW_PRIOR_OBJECT = "r5d3-prior-object-0000"
RAW_PRIOR_TOKEN = "r5d3-prior-token-0000"
RAW_BOUND_OBJECT = "r5d3-bound-object-0000"
RAW_BOUND_TOKEN = "r5d3-bound-token-0000"


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"r5d3-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"r5d3-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"r5d3-{suffix}"),
    )


def _contract(
    *,
    suffix: str = "alice",
    max_uses: int = 1,
    revocation_state: CapabilityRevocationState = CapabilityRevocationState.ACTIVE,
) -> IssuedCapabilityContract:
    world = _owned_world(suffix)
    assert world.persona_ref is not None
    tenant_ref = stable_hash("owned_tenant", f"r5d3-{suffix}")
    tenant_ownership_ref = stable_hash(
        "ownership_proof",
        f"r5d3-{suffix}-tenant-owned",
    )
    return IssuedCapabilityContract.build(
        world=world,
        world_tenant_ref=tenant_ref,
        world_tenant_ownership_ref=tenant_ownership_ref,
        subject_ref=world.persona_ref,
        resource_ref=stable_hash("capability_resource", f"r5d3-{suffix}"),
        operation_ref=stable_hash("capability_operation", "download"),
        audience_ref=world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", "r5d3-service"),
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        source_evidence_ref=stable_hash("source_evidence", f"r5d3-{suffix}"),
        secret_digest=stable_hash(
            "capability_secret_digest",
            f"r5d3-ephemeral-secret-{suffix}",
        ),
        issued_at_index=10,
        expires_at_index=20,
        max_uses=max_uses,
        revocation_state=revocation_state,
    )


def _records(
    *,
    origin: str = ORIGIN,
    object_id: str = RAW_BOUND_OBJECT,
    token: str = RAW_BOUND_TOKEN,
    status: int = 200,
):
    return [
        {
            "method": "POST",
            "url": f"{origin}/api/exports",
            "request_body": '{"format":"json"}',
            "response_status": 201,
            "response_body": f'{{"id":"{object_id}","token":"{token}"}}',
        },
        {
            "method": "GET",
            "url": f"{origin}/api/exports/{object_id}",
            "headers": {"authorization": f"Bearer {token}"},
            "response_status": status,
            "response_body": '{"ready":true}',
        },
    ]


def _logical_presentation(
    contract: IssuedCapabilityContract,
    **overrides,
) -> CapabilityPresentation:
    values = {
        "resource_ref": contract.resource_ref,
        "account_ref": contract.subject_ref,
        "audience_ref": contract.audience_ref,
        "operation_ref": contract.operation_ref,
        "at_index": contract.issued_at_index,
        "use_index": 0,
    }
    values.update(overrides)
    return CapabilityPresentation.build(**values)


def _binding(contract: IssuedCapabilityContract) -> ConfinedPresentationBinding:
    return ConfinedPresentationBinding.build(
        contract=contract,
        capability_ref=contract.capability_id,
        confined_world=contract._owned_world,
        confined_tenant_ref=contract.tenant_ref,
        confined_tenant_ownership_ref=contract.tenant_ownership_ref,
        target_origin=ORIGIN,
        prior_presentation_records=_records(
            object_id=RAW_PRIOR_OBJECT,
            token=RAW_PRIOR_TOKEN,
        ),
        current_presentation_records=_records(),
    )


def _confinement_decision(
    contract: IssuedCapabilityContract,
    binding: ConfinedPresentationBinding,
    *,
    index: int = 0,
    origin: str = ORIGIN,
    status: int = 200,
):
    presentation = ConfinementPresentation.build(
        presented_world_ref=binding.confined_world_ref,
        presented_tenant_ref=binding.confined_tenant_ref,
        presented_tenant_ownership_ref=(binding.confined_tenant_ownership_ref),
        presented_target_origin=origin,
        current_capture_records=_records(
            origin=origin,
            object_id=f"r5d3-presentation-object-{index:04d}",
            token=f"r5d3-presentation-token-{index:04d}",
            status=status,
        ),
    )
    return evaluate_confinement(contract, binding, presentation)


def _admissible_context(
    *,
    suffix: str = "alice",
    max_uses: int = 1,
):
    contract = _contract(suffix=suffix, max_uses=max_uses)
    capability_decision = classify_presentation(
        contract,
        _logical_presentation(contract),
    )
    binding = _binding(contract)
    return contract, capability_decision, binding


def _consume(
    contract: IssuedCapabilityContract,
    capability_decision: CapabilityDecision,
    binding: ConfinedPresentationBinding,
    ledger: CapabilityConsumptionLedger,
    *,
    index: int = 0,
) -> ConsumptionResult:
    return evaluate_consumption(
        contract,
        capability_decision,
        _confinement_decision(contract, binding, index=index),
        ledger,
    )


def test_first_consumption_and_all_content_addresses_are_reproducible():
    contract, capability_decision, binding = _admissible_context()
    confinement_decision = _confinement_decision(contract, binding)
    genesis = CapabilityConsumptionLedger.build()

    first = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        genesis,
    )
    rebuilt_entry = ConsumptionEntry.build(
        contract=contract,
        capability_decision=capability_decision,
        confinement_decision=confinement_decision,
        use_slot=0,
    )
    rebuilt_ledger = CapabilityConsumptionLedger.build(entries=(rebuilt_entry,))
    rebuilt_decision = ConsumptionDecision.build(
        contract=contract,
        capability_decision=capability_decision,
        confinement_decision=confinement_decision,
        prior_ledger=genesis,
        next_ledger=rebuilt_ledger,
        outcome=ConsumptionOutcome.FIRST_CONSUMPTION,
    )

    assert first.decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
    assert first.decision.prior_ledger_ref == genesis.ledger_id
    assert first.decision.next_ledger_ref == first.ledger.ledger_id
    assert first.ledger is not genesis
    assert len(first.ledger.entries) == 1
    assert first.ledger.entries[0].use_slot == 0
    assert first.ledger.entries[0] == rebuilt_entry
    assert first.ledger == rebuilt_ledger
    assert first.decision == rebuilt_decision
    assert rebuilt_entry.entry_id == stable_hash(
        "capability_consumption_entry",
        {
            key: value
            for key, value in rebuilt_entry.to_dict().items()
            if key not in {"schema_version", "entry_id"}
        },
    )
    assert rebuilt_ledger.ledger_id == stable_hash(
        "capability_consumption_ledger",
        {"entry_ids": [rebuilt_entry.entry_id]},
    )
    assert rebuilt_decision.decision_id == stable_hash(
        "capability_consumption_decision",
        {
            key: value
            for key, value in rebuilt_decision.to_dict().items()
            if key not in {"schema_version", "decision_id"}
        },
    )


def test_empty_genesis_ledger_is_deterministic_and_passive():
    first = CapabilityConsumptionLedger.build()
    second = CapabilityConsumptionLedger.build(entries=())

    assert first == second
    assert first.entries == ()
    assert first.mode == CAPABILITY_CONSUMPTION_LEDGER_MODE
    assert first.ledger_id == stable_hash(
        "capability_consumption_ledger",
        {"entry_ids": []},
    )
    assert first.durable_persistence_authority is False
    assert first.target_io_authority is False
    assert first.backend_dispatch_authority is False
    assert first.receipt_authority is False
    assert first.finding_authority is False
    assert first.executable is False


def test_identical_presentation_is_replay_and_returns_same_ledger_object():
    contract, capability_decision, binding = _admissible_context()
    confinement_decision = _confinement_decision(contract, binding)
    first = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        CapabilityConsumptionLedger.build(),
    )

    replay = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        first.ledger,
    )

    assert replay.decision.outcome is ConsumptionOutcome.REPLAYED_PRESENTATION
    assert replay.ledger is first.ledger
    assert replay.decision.prior_ledger_ref == first.ledger.ledger_id
    assert replay.decision.next_ledger_ref == first.ledger.ledger_id
    assert replay.ledger.entries == first.ledger.entries


def test_single_use_distinct_presentation_is_capability_exhaustion():
    contract, capability_decision, binding = _admissible_context(max_uses=1)
    first = _consume(
        contract,
        capability_decision,
        binding,
        CapabilityConsumptionLedger.build(),
        index=0,
    )

    exhausted = _consume(
        contract,
        capability_decision,
        binding,
        first.ledger,
        index=1,
    )

    assert exhausted.decision.outcome is (
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
    )
    assert exhausted.decision.presentation_ref != (
        first.ledger.entries[0].presentation_ref
    )
    assert exhausted.ledger is first.ledger
    assert exhausted.ledger.entries == first.ledger.entries


def test_multi_use_budget_records_slots_then_refuses_n_plus_one():
    max_uses = 3
    contract, capability_decision, binding = _admissible_context(max_uses=max_uses)
    ledger = CapabilityConsumptionLedger.build()

    for index in range(max_uses):
        result = _consume(
            contract,
            capability_decision,
            binding,
            ledger,
            index=index,
        )
        assert result.decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
        assert result.ledger is not ledger
        ledger = result.ledger

    assert sorted(entry.use_slot for entry in ledger.entries) == [0, 1, 2]
    exhausted = _consume(
        contract,
        capability_decision,
        binding,
        ledger,
        index=max_uses,
    )
    assert exhausted.decision.outcome is (
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
    )
    assert exhausted.ledger is ledger


def test_replay_precedes_exhaustion_at_a_fully_consumed_budget():
    contract, capability_decision, binding = _admissible_context(max_uses=1)
    confinement_decision = _confinement_decision(contract, binding, index=0)
    first = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        CapabilityConsumptionLedger.build(),
    )

    replay = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        first.ledger,
    )

    assert len(first.ledger.entries) == contract.max_uses
    assert replay.decision.outcome is ConsumptionOutcome.REPLAYED_PRESENTATION
    assert replay.decision.outcome is not (
        ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
    )


def test_ledger_count_not_r5d1_use_index_is_authoritative():
    contract, _, binding = _admissible_context(max_uses=2)
    caller_supplied_first_slot = classify_presentation(
        contract,
        _logical_presentation(contract, use_index=0),
    )
    assert caller_supplied_first_slot.outcome is CapabilityOutcome.VALID

    first = _consume(
        contract,
        caller_supplied_first_slot,
        binding,
        CapabilityConsumptionLedger.build(),
        index=0,
    )
    second = _consume(
        contract,
        caller_supplied_first_slot,
        binding,
        first.ledger,
        index=1,
    )

    assert second.decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
    assert sorted(entry.use_slot for entry in second.ledger.entries) == [0, 1]


def test_one_ledger_tracks_multiple_capabilities_independently():
    contract_a, logical_a, binding_a = _admissible_context(suffix="alice")
    contract_b, logical_b, binding_b = _admissible_context(suffix="bob")
    genesis = CapabilityConsumptionLedger.build()
    first_a = _consume(contract_a, logical_a, binding_a, genesis)
    first_b = _consume(contract_b, logical_b, binding_b, first_a.ledger)

    assert len(first_b.ledger.entries) == 2
    by_capability = {
        entry.capability_ref: entry.use_slot for entry in first_b.ledger.entries
    }
    assert by_capability == {
        contract_a.capability_id: 0,
        contract_b.capability_id: 0,
    }


@pytest.mark.parametrize(
    "outcome",
    (
        CapabilityOutcome.WRONG_BINDING,
        CapabilityOutcome.EXPIRED,
        CapabilityOutcome.REVOKED,
        CapabilityOutcome.ALREADY_USED,
    ),
)
def test_every_inadmissible_r5d1_outcome_fails_closed(outcome):
    revocation = (
        CapabilityRevocationState.REVOKED
        if outcome is CapabilityOutcome.REVOKED
        else CapabilityRevocationState.ACTIVE
    )
    contract = _contract(revocation_state=revocation)
    overrides = {}
    if outcome is CapabilityOutcome.WRONG_BINDING:
        overrides["resource_ref"] = stable_hash("capability_resource", "wrong")
    elif outcome is CapabilityOutcome.EXPIRED:
        overrides["at_index"] = contract.expires_at_index
    elif outcome is CapabilityOutcome.ALREADY_USED:
        overrides["use_index"] = contract.max_uses
    capability_decision = classify_presentation(
        contract,
        _logical_presentation(contract, **overrides),
    )
    binding = _binding(contract)
    confinement_decision = _confinement_decision(contract, binding)
    assert capability_decision.outcome is outcome
    assert confinement_decision.outcome is ConfinementOutcome.CONFINED_FRESH

    with pytest.raises(
        ConsumptionLedgerDenied,
        match="capability_use_is_not_admissible",
    ):
        evaluate_consumption(
            contract,
            capability_decision,
            confinement_decision,
            CapabilityConsumptionLedger.build(),
        )


@pytest.mark.parametrize(
    "outcome",
    (
        ConfinementOutcome.ESCAPED_CONFINEMENT,
        ConfinementOutcome.STALE_CAPTURE,
    ),
)
def test_every_inadmissible_r5d2_outcome_fails_closed(outcome):
    contract, capability_decision, binding = _admissible_context()
    if outcome is ConfinementOutcome.ESCAPED_CONFINEMENT:
        confinement_decision = _confinement_decision(
            contract,
            binding,
            origin=OTHER_ORIGIN,
        )
    else:
        confinement_decision = _confinement_decision(
            contract,
            binding,
            status=409,
        )
    assert capability_decision.outcome is CapabilityOutcome.VALID
    assert confinement_decision.outcome is outcome

    with pytest.raises(
        ConsumptionLedgerDenied,
        match="capability_use_is_not_admissible",
    ):
        evaluate_consumption(
            contract,
            capability_decision,
            confinement_decision,
            CapabilityConsumptionLedger.build(),
        )


@pytest.mark.parametrize("mismatched_axis", ("logical", "confinement"))
def test_cross_capability_decision_mismatch_fails_closed(mismatched_axis):
    contract_a, logical_a, binding_a = _admissible_context(suffix="alice")
    contract_b, logical_b, binding_b = _admissible_context(suffix="bob")
    confinement_a = _confinement_decision(contract_a, binding_a)
    confinement_b = _confinement_decision(contract_b, binding_b)
    logical = logical_b if mismatched_axis == "logical" else logical_a
    confinement = confinement_b if mismatched_axis == "confinement" else confinement_a

    with pytest.raises(
        ConsumptionLedgerDenied,
        match="capability_use_is_not_admissible",
    ):
        evaluate_consumption(
            contract_a,
            logical,
            confinement,
            CapabilityConsumptionLedger.build(),
        )


@pytest.mark.parametrize("artifact", ("entry", "ledger", "decision"))
def test_content_addresses_cannot_be_replaced_with_forged_ids(artifact):
    contract, capability_decision, binding = _admissible_context()
    first = _consume(
        contract,
        capability_decision,
        binding,
        CapabilityConsumptionLedger.build(),
    )
    values = {
        "entry": (
            first.ledger.entries[0],
            "entry_id",
            stable_hash("capability_consumption_entry", "forged"),
            "consumption entry",
        ),
        "ledger": (
            first.ledger,
            "ledger_id",
            stable_hash("capability_consumption_ledger", "forged"),
            "consumption ledger",
        ),
        "decision": (
            first.decision,
            "decision_id",
            stable_hash("capability_consumption_decision", "forged"),
            "consumption decision",
        ),
    }
    value, field_name, forged_id, error = values[artifact]

    with pytest.raises(ValueError, match=error):
        replace(value, **{field_name: forged_id})


@pytest.mark.parametrize("artifact", ("logical", "confinement", "ledger"))
def test_evaluator_rederives_input_ids_before_deciding(artifact):
    contract, capability_decision, binding = _admissible_context()
    confinement_decision = _confinement_decision(contract, binding)
    ledger = CapabilityConsumptionLedger.build()
    if artifact == "logical":
        capability_decision = copy(capability_decision)
        object.__setattr__(
            capability_decision,
            "decision_id",
            stable_hash("capability_decision", "forged"),
        )
    elif artifact == "confinement":
        confinement_decision = copy(confinement_decision)
        object.__setattr__(
            confinement_decision,
            "decision_id",
            stable_hash("capability_confinement_decision", "forged"),
        )
    else:
        ledger = copy(ledger)
        object.__setattr__(
            ledger,
            "ledger_id",
            stable_hash("capability_consumption_ledger", "forged"),
        )

    with pytest.raises(
        ConsumptionLedgerDenied,
        match="capability_use_is_not_admissible",
    ):
        evaluate_consumption(
            contract,
            capability_decision,
            confinement_decision,
            ledger,
        )


@pytest.mark.parametrize(
    "flag",
    (
        "durable_persistence_authority",
        "target_io_authority",
        "backend_dispatch_authority",
        "receipt_authority",
        "finding_authority",
        "executable",
    ),
)
def test_passive_flags_cannot_be_enabled_in_build_or_replacement(flag):
    with pytest.raises(
        ConsumptionLedgerDenied,
        match="passive_boundary_violation",
    ):
        CapabilityConsumptionLedger.build(**{flag: True})

    with pytest.raises(ValueError, match="consumption ledger is invalid"):
        replace(CapabilityConsumptionLedger.build(), **{flag: True})


def test_private_context_and_raw_capture_values_are_not_publicly_exposed():
    contract, capability_decision, binding = _admissible_context()
    result = _consume(
        contract,
        capability_decision,
        binding,
        CapabilityConsumptionLedger.build(),
    )
    entry = result.ledger.entries[0]
    encoded = json.dumps(result.to_dict(), sort_keys=True)
    representations = f"{entry!r}{result.decision!r}{result.ledger!r}"

    for raw_value in (
        RAW_PRIOR_OBJECT,
        RAW_PRIOR_TOKEN,
        RAW_BOUND_OBJECT,
        RAW_BOUND_TOKEN,
        "r5d3-presentation-object-0000",
        "r5d3-presentation-token-0000",
    ):
        assert raw_value not in encoded
        assert raw_value not in representations
    assert all(not key.startswith("_") for key in entry.to_dict())
    assert all(not key.startswith("_") for key in result.decision.to_dict())
    for data_type in (ConsumptionEntry, ConsumptionDecision):
        private_fields = [
            item for item in fields(data_type) if item.name.startswith("_")
        ]
        assert private_fields
        assert all(item.repr is False for item in private_fields)
        assert all(item.compare is False for item in private_fields)


def test_module_imports_are_passive_and_do_not_reference_receipt_storage():
    source_path = Path(consumption_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_from = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }

    assert not {"os", "tempfile"} & imported_modules
    assert not any(name.endswith("receipts") for name in imported_from)
    assert not any(name in {"os", "tempfile"} for name in imported_from)


def test_ledger_identity_and_entry_order_are_order_independent():
    contract, capability_decision, binding = _admissible_context(max_uses=2)
    first = _consume(
        contract,
        capability_decision,
        binding,
        CapabilityConsumptionLedger.build(),
        index=0,
    )
    second = _consume(
        contract,
        capability_decision,
        binding,
        first.ledger,
        index=1,
    )
    forward = CapabilityConsumptionLedger.build(entries=second.ledger.entries)
    reverse = CapabilityConsumptionLedger.build(
        entries=tuple(reversed(second.ledger.entries))
    )

    assert forward == reverse
    assert forward.ledger_id == reverse.ledger_id
    assert forward.entries == reverse.entries
    assert [entry.entry_id for entry in forward.entries] == sorted(
        entry.entry_id for entry in forward.entries
    )


def test_duplicate_entry_and_invalid_entry_content_are_rejected():
    contract, capability_decision, binding = _admissible_context()
    first = _consume(
        contract,
        capability_decision,
        binding,
        CapabilityConsumptionLedger.build(),
    )
    entry = first.ledger.entries[0]

    with pytest.raises(ValueError, match="duplicate entries"):
        CapabilityConsumptionLedger.build(entries=(entry, entry))
    forged_entry = copy(entry)
    object.__setattr__(
        forged_entry,
        "entry_id",
        stable_hash("capability_consumption_entry", "forged"),
    )
    with pytest.raises(ValueError, match="ledger entry is invalid"):
        CapabilityConsumptionLedger.build(entries=(forged_entry,))


@pytest.mark.parametrize("use_slot", (False, -1, 1))
def test_entry_rejects_bool_negative_or_out_of_budget_use_slot(use_slot):
    contract, capability_decision, binding = _admissible_context(max_uses=1)

    with pytest.raises(ValueError, match="use slot is invalid"):
        ConsumptionEntry.build(
            contract=contract,
            capability_decision=capability_decision,
            confinement_decision=_confinement_decision(contract, binding),
            use_slot=use_slot,
        )


def test_decision_guard_rejects_changed_refusal_and_unchanged_first():
    contract, capability_decision, binding = _admissible_context()
    confinement_decision = _confinement_decision(contract, binding)
    genesis = CapabilityConsumptionLedger.build()
    first = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        genesis,
    )

    with pytest.raises(ValueError, match="decision is inconsistent"):
        ConsumptionDecision.build(
            contract=contract,
            capability_decision=capability_decision,
            confinement_decision=confinement_decision,
            prior_ledger=genesis,
            next_ledger=first.ledger,
            outcome=ConsumptionOutcome.REPLAYED_PRESENTATION,
        )
    with pytest.raises(ValueError, match="decision is inconsistent"):
        ConsumptionDecision.build(
            contract=contract,
            capability_decision=capability_decision,
            confinement_decision=confinement_decision,
            prior_ledger=genesis,
            next_ledger=genesis,
            outcome=ConsumptionOutcome.FIRST_CONSUMPTION,
        )


def test_decision_guard_independently_reasserts_replay_over_exhaustion():
    contract, capability_decision, binding = _admissible_context()
    confinement_decision = _confinement_decision(contract, binding)
    first = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        CapabilityConsumptionLedger.build(),
    )

    with pytest.raises(ValueError, match="decision is inconsistent"):
        ConsumptionDecision.build(
            contract=contract,
            capability_decision=capability_decision,
            confinement_decision=confinement_decision,
            prior_ledger=first.ledger,
            next_ledger=first.ledger,
            outcome=ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED,
        )


def test_valid_and_confined_fresh_axes_remain_independent_after_consumption():
    contract, capability_decision, binding = _admissible_context()
    confinement_decision = _confinement_decision(contract, binding)
    first = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        CapabilityConsumptionLedger.build(),
    )
    replay = evaluate_consumption(
        contract,
        capability_decision,
        confinement_decision,
        first.ledger,
    )

    assert capability_decision.outcome is CapabilityOutcome.VALID
    assert confinement_decision.outcome is ConfinementOutcome.CONFINED_FRESH
    assert replay.decision.outcome is ConsumptionOutcome.REPLAYED_PRESENTATION
    assert replay.ledger is first.ledger


@pytest.mark.parametrize(
    "position",
    ("contract", "capability_decision", "confinement_decision", "ledger"),
)
def test_evaluator_rejects_untyped_inputs(position):
    contract, capability_decision, binding = _admissible_context()
    values = {
        "contract": contract,
        "capability_decision": capability_decision,
        "confinement_decision": _confinement_decision(contract, binding),
        "ledger": CapabilityConsumptionLedger.build(),
    }
    values[position] = object()

    with pytest.raises(TypeError):
        evaluate_consumption(**values)
