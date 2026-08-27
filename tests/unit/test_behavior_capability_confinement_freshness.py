"""R5D2 confined-presentation freshness binding and evaluator tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from core.behavior.capability_confinement_freshness import (
    CAPABILITY_CONFINEMENT_FRESHNESS_MODE,
    ConfinedPresentationBinding,
    ConfinementDecision,
    ConfinementFreshnessDenied,
    ConfinementOutcome,
    ConfinementPresentation,
    evaluate_confinement,
)
from core.behavior.capability_contract import (
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from core.behavior.prerequisite_capture_freshness import (
    graph_bound_capture_artifact_ref,
)


ORIGIN = "https://api.example.test"
OTHER_ORIGIN = "https://other.example.test"
RAW_PRIOR_OBJECT = "prior-presentation-object"
RAW_PRIOR_TOKEN = "prior-presentation-token"
RAW_CURRENT_OBJECT = "current-presentation-object"
RAW_CURRENT_TOKEN = "current-presentation-token"
TENANT_REF = stable_hash("owned_tenant", "r5d2-tenant")
TENANT_OWNERSHIP_REF = stable_hash(
    "ownership_proof",
    "r5d2-tenant-owned-by-researcher",
)


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"r5d2-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"r5d2-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"r5d2-{suffix}"),
    )


def _contract(
    *,
    world: ExperimentWorldBinding | None = None,
) -> IssuedCapabilityContract:
    owned_world = world or _owned_world()
    assert owned_world.persona_ref is not None
    return IssuedCapabilityContract.build(
        world=owned_world,
        world_tenant_ref=TENANT_REF,
        world_tenant_ownership_ref=TENANT_OWNERSHIP_REF,
        subject_ref=owned_world.persona_ref,
        resource_ref=stable_hash("capability_resource", "r5d2-export"),
        operation_ref=stable_hash("capability_operation", "download"),
        audience_ref=owned_world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", "r5d2-service"),
        tenant_ref=TENANT_REF,
        tenant_ownership_ref=TENANT_OWNERSHIP_REF,
        source_evidence_ref=stable_hash("source_evidence", "r5d2-issued"),
        secret_digest=stable_hash(
            "capability_secret_digest",
            "r5d2-ephemeral-secret",
        ),
        issued_at_index=10,
        expires_at_index=20,
        max_uses=1,
        revocation_state=CapabilityRevocationState.ACTIVE,
    )


def _records(
    *,
    origin: str = ORIGIN,
    object_id: str = RAW_CURRENT_OBJECT,
    token: str = RAW_CURRENT_TOKEN,
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


def _binding(**overrides) -> ConfinedPresentationBinding:
    contract = overrides.pop("contract", _contract())
    world = overrides.pop("confined_world", contract._owned_world)
    values = {
        "contract": contract,
        "capability_ref": contract.capability_id,
        "confined_world": world,
        "confined_tenant_ref": TENANT_REF,
        "confined_tenant_ownership_ref": TENANT_OWNERSHIP_REF,
        "target_origin": ORIGIN,
        "prior_presentation_records": _records(
            object_id=RAW_PRIOR_OBJECT,
            token=RAW_PRIOR_TOKEN,
        ),
        "current_presentation_records": _records(),
    }
    values.update(overrides)
    return ConfinedPresentationBinding.build(**values)


def _presentation(
    binding: ConfinedPresentationBinding,
    **overrides,
) -> ConfinementPresentation:
    values = {
        "presented_world_ref": binding.confined_world_ref,
        "presented_tenant_ref": binding.confined_tenant_ref,
        "presented_tenant_ownership_ref": (
            binding.confined_tenant_ownership_ref
        ),
        "presented_target_origin": ORIGIN,
        "current_capture_records": _records(),
    }
    values.update(overrides)
    return ConfinementPresentation.build(**values)


def _logical_presentation(
    contract: IssuedCapabilityContract,
) -> CapabilityPresentation:
    return CapabilityPresentation.build(
        resource_ref=contract.resource_ref,
        account_ref=contract.subject_ref,
        audience_ref=contract.audience_ref,
        operation_ref=contract.operation_ref,
        at_index=contract.issued_at_index,
        use_index=0,
    )


def test_confined_fresh_binding_and_decision_are_deterministic_and_passive():
    first_binding = _binding()
    second_binding = _binding()
    first_presentation = _presentation(first_binding)
    second_presentation = _presentation(second_binding)

    first = evaluate_confinement(
        first_binding._contract,
        first_binding,
        first_presentation,
    )
    second = evaluate_confinement(
        second_binding._contract,
        second_binding,
        second_presentation,
    )

    assert first_binding == second_binding
    assert first_presentation == second_presentation
    assert first == second
    assert first.outcome is ConfinementOutcome.CONFINED_FRESH
    assert first_binding.mode == CAPABILITY_CONFINEMENT_FRESHNESS_MODE
    assert first_binding.current_capture_revalidated is True
    assert first_binding.target_requests_sent == 0
    assert first_binding.backend_dispatch_authority is False
    assert first_binding.promotion_authority is False
    assert first_binding.finding_authority is False
    assert first_binding.retry_authority is False
    assert first.capability_ref == first_binding._contract.capability_id
    assert first.binding_id == first_binding.binding_id
    assert first.presentation_id == first_presentation.presentation_id


def test_binding_and_decision_content_addresses_are_reproducible():
    binding = _binding()
    presentation = _presentation(binding)
    decision = evaluate_confinement(binding._contract, binding, presentation)

    binding_payload = binding.to_dict()
    for key in ("schema_version", "mode", "binding_id"):
        binding_payload.pop(key)
    decision_payload = decision.to_dict()
    for key in ("schema_version", "decision_id"):
        decision_payload.pop(key)

    assert binding.binding_id == stable_hash(
        "capability_confinement_freshness",
        binding_payload,
    )
    assert decision.decision_id == stable_hash(
        "capability_confinement_decision",
        decision_payload,
    )
    assert decision.reason_ref.startswith("capability_confinement_reason:")


def test_dynamic_capture_values_may_rotate_when_structure_is_current():
    binding = _binding()
    rotated_records = _records(
        object_id="rotated-presentation-object",
        token="rotated-presentation-token",
    )
    presentation = _presentation(
        binding,
        current_capture_records=rotated_records,
    )

    decision = evaluate_confinement(binding._contract, binding, presentation)

    assert decision.outcome is ConfinementOutcome.CONFINED_FRESH
    assert presentation.current_snapshot_ref == binding.presentation_snapshot_ref
    assert presentation.current_capture_ref != binding.presentation_capture_ref


def test_capture_origin_escape_is_classified_and_binding_build_denies_it():
    binding = _binding()
    escaped = _presentation(
        binding,
        presented_target_origin=OTHER_ORIGIN,
        current_capture_records=_records(origin=OTHER_ORIGIN),
    )

    decision = evaluate_confinement(binding._contract, binding, escaped)

    assert decision.outcome is ConfinementOutcome.ESCAPED_CONFINEMENT
    with pytest.raises(
        ConfinementFreshnessDenied,
        match="capture_escaped_confinement",
    ):
        _binding(
            current_presentation_records=_records(origin=OTHER_ORIGIN),
        )


@pytest.mark.parametrize(
    "presentation_overrides",
    (
        {
            "presented_world_ref": _owned_world("bob").binding_id,
        },
        {
            "presented_tenant_ref": stable_hash("owned_tenant", "other"),
        },
        {
            "presented_tenant_ownership_ref": stable_hash(
                "ownership_proof",
                "other",
            ),
        },
    ),
)
def test_cross_account_or_tenant_presentation_escapes_confinement(
    presentation_overrides,
):
    binding = _binding()
    presentation = _presentation(binding, **presentation_overrides)

    decision = evaluate_confinement(binding._contract, binding, presentation)

    assert decision.outcome is ConfinementOutcome.ESCAPED_CONFINEMENT


def test_stale_snapshot_is_classified_and_binding_build_denies_it():
    binding = _binding()
    stale_records = _records(status=409)
    stale = _presentation(binding, current_capture_records=stale_records)

    decision = evaluate_confinement(binding._contract, binding, stale)

    assert decision.outcome is ConfinementOutcome.STALE_CAPTURE
    with pytest.raises(
        ConfinementFreshnessDenied,
        match="capture_is_stale",
    ):
        _binding(current_presentation_records=stale_records)


def test_stale_record_count_is_classified_and_binding_build_denies_it():
    binding = _binding()
    extra_records = [*_records(), _records()[-1]]
    stale = _presentation(binding, current_capture_records=extra_records)

    decision = evaluate_confinement(binding._contract, binding, stale)

    assert decision.outcome is ConfinementOutcome.STALE_CAPTURE
    assert stale.current_record_count != binding.presentation_record_count
    with pytest.raises(
        ConfinementFreshnessDenied,
        match="capture_is_stale",
    ):
        _binding(current_presentation_records=extra_records)


def test_confinement_escape_precedes_stale_capture():
    binding = _binding()
    escaped_and_stale = _presentation(
        binding,
        presented_world_ref=_owned_world("bob").binding_id,
        current_capture_records=_records(status=409),
    )

    decision = evaluate_confinement(
        binding._contract,
        binding,
        escaped_and_stale,
    )

    assert decision.outcome is ConfinementOutcome.ESCAPED_CONFINEMENT


def test_binding_rejects_non_owned_or_role_qualified_world():
    anonymous = ExperimentWorldBinding.build(
        slot="anonymous",
        kind=ExperimentWorldKind.FRESH_ANONYMOUS,
        world_ref=stable_hash("world", "r5d2-anonymous"),
        fresh=True,
    )
    role_world = ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", "r5d2-role"),
        persona_ref=stable_hash("experiment_persona", "r5d2-role"),
        ownership_ref=stable_hash("ownership_proof", "r5d2-role"),
        role_ref=stable_hash("experiment_role", "r5d2-role"),
    )

    for world in (anonymous, role_world):
        with pytest.raises(
            ConfinementFreshnessDenied,
            match="requires_owned_account_world",
        ):
            _binding(confined_world=world)


def test_binding_rejects_contract_world_or_tenant_substitution():
    contract = _contract(world=_owned_world("alice"))

    with pytest.raises(
        ConfinementFreshnessDenied,
        match="contract_world_mismatch",
    ):
        _binding(contract=contract, confined_world=_owned_world("bob"))
    with pytest.raises(
        ConfinementFreshnessDenied,
        match="cross_tenant_world",
    ):
        _binding(
            contract=contract,
            confined_tenant_ref=stable_hash("owned_tenant", "other"),
        )
    with pytest.raises(
        ConfinementFreshnessDenied,
        match="cross_tenant_world",
    ):
        _binding(
            contract=contract,
            confined_tenant_ownership_ref=stable_hash(
                "ownership_proof",
                "other",
            ),
        )


@pytest.mark.parametrize(
    "capability_ref",
    (
        "raw-capability",
        stable_hash("issued_capability_contract", "other"),
    ),
)
def test_binding_rejects_malformed_or_unbound_capability_ref(capability_ref):
    error = (
        ValueError
        if capability_ref == "raw-capability"
        else ConfinementFreshnessDenied
    )
    with pytest.raises(error):
        _binding(capability_ref=capability_ref)


@pytest.mark.parametrize(
    "overrides",
    (
        {"target_requests_sent": 1},
        {"target_requests_sent": False},
        {"backend_dispatch_authority": True},
        {"promotion_authority": True},
        {"finding_authority": True},
        {"retry_authority": True},
    ),
)
def test_binding_build_rejects_any_passive_boundary_change(overrides):
    with pytest.raises(
        ConfinementFreshnessDenied,
        match="passive_boundary_violation",
    ):
        _binding(**overrides)


@pytest.mark.parametrize(
    "field,value",
    (
        ("capability_ref", stable_hash("issued_capability_contract", "forged")),
        ("confined_world_ref", stable_hash("experiment_world_binding", "forged")),
        ("confined_tenant_ref", stable_hash("owned_tenant", "forged")),
        (
            "confined_tenant_ownership_ref",
            stable_hash("ownership_proof", "forged"),
        ),
        ("target_origin_ref", stable_hash("behavioral_capture_target", "forged")),
        (
            "presentation_capture_ref",
            stable_hash("graph_bound_capture_artifact", "forged"),
        ),
        (
            "presentation_snapshot_ref",
            stable_hash("graph_bound_capture_snapshot", "forged"),
        ),
        ("presentation_record_count", 0),
        ("current_capture_revalidated", False),
        ("target_requests_sent", 1),
        ("backend_dispatch_authority", True),
        ("promotion_authority", True),
        ("finding_authority", True),
        ("retry_authority", True),
    ),
)
def test_binding_direct_construction_rechecks_identity_and_bounds(field, value):
    binding = _binding()

    with pytest.raises(
        ValueError,
        match="confinement freshness binding is invalid",
    ):
        replace(binding, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    (
        ("presented_world_ref", "raw-world"),
        ("presented_tenant_ref", "raw-tenant"),
        ("presented_tenant_ownership_ref", "raw-ownership"),
    ),
)
def test_presentation_rejects_malformed_typed_refs(field, value):
    binding = _binding()

    with pytest.raises(ValueError, match="confinement presentation is invalid"):
        _presentation(binding, **{field: value})


def test_raw_capture_values_are_never_stored_serialized_or_repr_exposed():
    binding = _binding()
    presentation = _presentation(binding)
    decision = evaluate_confinement(binding._contract, binding, presentation)
    encoded = json.dumps(
        {
            "binding": binding.to_dict(),
            "presentation": presentation.to_dict(),
            "decision": decision.to_dict(),
        },
        sort_keys=True,
    )
    representations = f"{binding!r}{presentation!r}{decision!r}"

    for raw_value in (
        RAW_PRIOR_OBJECT,
        RAW_PRIOR_TOKEN,
        RAW_CURRENT_OBJECT,
        RAW_CURRENT_TOKEN,
    ):
        assert raw_value not in encoded
        assert raw_value not in representations
        assert raw_value not in binding.__dict__.values()
        assert raw_value not in presentation.__dict__.values()


@pytest.mark.parametrize(
    "evidence_outcome,presentation_overrides",
    (
        (
            ConfinementOutcome.ESCAPED_CONFINEMENT,
            {"presented_world_ref": _owned_world("bob").binding_id},
        ),
        (
            ConfinementOutcome.STALE_CAPTURE,
            {"current_capture_records": _records(status=409)},
        ),
    ),
)
def test_r5d1_valid_can_still_fail_the_independent_evidence_axis(
    evidence_outcome,
    presentation_overrides,
):
    binding = _binding()
    contract = binding._contract
    logical = classify_presentation(contract, _logical_presentation(contract))
    evidence = evaluate_confinement(
        contract,
        binding,
        _presentation(binding, **presentation_overrides),
    )

    assert logical.outcome is CapabilityOutcome.VALID
    assert evidence.outcome is evidence_outcome


def test_decision_reason_rejects_outcome_mismatch_or_unordered_fields():
    binding = _binding()
    presentation = _presentation(binding)

    with pytest.raises(ValueError, match="decision reason is invalid"):
        ConfinementDecision.build(
            contract=binding._contract,
            binding=binding,
            presentation=presentation,
            outcome=ConfinementOutcome.CONFINED_FRESH,
            confinement_mismatches=("world",),
        )
    with pytest.raises(ValueError, match="decision reason is invalid"):
        ConfinementDecision.build(
            contract=binding._contract,
            binding=binding,
            presentation=presentation,
            outcome=ConfinementOutcome.ESCAPED_CONFINEMENT,
            confinement_mismatches=("origin", "world"),
        )


def test_forged_presentation_or_decision_content_address_is_rejected():
    binding = _binding()
    presentation = _presentation(binding)
    decision = evaluate_confinement(binding._contract, binding, presentation)

    with pytest.raises(ValueError, match="confinement presentation is invalid"):
        replace(
            presentation,
            presentation_id=stable_hash(
                "capability_confinement_presentation",
                "forged",
            ),
        )
    with pytest.raises(ValueError, match="confinement decision is invalid"):
        replace(
            decision,
            decision_id=stable_hash(
                "capability_confinement_decision",
                "forged",
            ),
        )


def test_capture_artifact_ref_is_the_revalidated_current_capture_only():
    binding = _binding()
    prior_ref = graph_bound_capture_artifact_ref(
        _records(object_id=RAW_PRIOR_OBJECT, token=RAW_PRIOR_TOKEN),
        target_origin=ORIGIN,
        world_id=binding.confined_world_ref,
    )
    current_ref = graph_bound_capture_artifact_ref(
        _records(),
        target_origin=ORIGIN,
        world_id=binding.confined_world_ref,
    )

    assert binding.presentation_capture_ref == current_ref
    assert binding.presentation_capture_ref != prior_ref


@pytest.mark.parametrize(
    "position",
    ("contract", "binding", "presentation"),
)
def test_evaluator_rejects_untyped_inputs(position):
    binding = _binding()
    values = {
        "contract": binding._contract,
        "binding": binding,
        "presentation": _presentation(binding),
    }
    values[position] = object()

    with pytest.raises(TypeError):
        evaluate_confinement(**values)
