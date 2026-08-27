"""R5D1 transport-free issued-capability contract tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from core.behavior.capability_contract import (
    CAPABILITY_CONTRACT_MODE,
    CapabilityDecision,
    CapabilityOutcome,
    CapabilityOwnedFixture,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    classify_presentation,
)
from core.behavior.experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import ProofTopology


RAW_SECRET = "r5d1-ephemeral-bearer-secret"
TENANT_REF = stable_hash("owned_tenant", "r5d1-tenant")
TENANT_OWNERSHIP_REF = stable_hash(
    "ownership_proof",
    "r5d1-tenant-owned-by-researcher",
)


def _owned_world(suffix: str = "alice") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", f"r5d1-{suffix}"),
        persona_ref=stable_hash("experiment_persona", f"r5d1-{suffix}"),
        ownership_ref=stable_hash("ownership_proof", f"r5d1-{suffix}"),
    )


def _callback_world(suffix: str = "receiver") -> ExperimentWorldBinding:
    return ExperimentWorldBinding.build(
        slot="callback",
        kind=ExperimentWorldKind.CALLBACK_RECEIVER,
        world_ref=stable_hash("world", f"r5d1-{suffix}"),
        callback_ref=stable_hash("callback_receiver", f"r5d1-{suffix}"),
    )


def _contract(**overrides) -> IssuedCapabilityContract:
    world = overrides.pop("world", _owned_world())
    values = {
        "world": world,
        "world_tenant_ref": TENANT_REF,
        "world_tenant_ownership_ref": TENANT_OWNERSHIP_REF,
        "subject_ref": (
            world.persona_ref
            if world.persona_ref is not None
            else stable_hash("experiment_persona", "r5d1-alice")
        ),
        "resource_ref": stable_hash("capability_resource", "r5d1-export"),
        "operation_ref": stable_hash("capability_operation", "download"),
        "audience_ref": (
            world.persona_ref
            if world.persona_ref is not None
            else stable_hash("experiment_persona", "r5d1-alice")
        ),
        "issuer_ref": stable_hash("capability_issuer", "r5d1-service"),
        "tenant_ref": TENANT_REF,
        "tenant_ownership_ref": TENANT_OWNERSHIP_REF,
        "source_evidence_ref": stable_hash("source_evidence", "r5d1-issued"),
        "secret_digest": stable_hash("capability_secret_digest", RAW_SECRET),
        "issued_at_index": 10,
        "expires_at_index": 20,
        "max_uses": 1,
        "revocation_state": CapabilityRevocationState.ACTIVE,
    }
    values.update(overrides)
    return IssuedCapabilityContract.build(**values)


def _presentation(
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


def test_contract_fixture_and_valid_decision_are_deterministic_and_passive():
    first = _contract()
    second = _contract()
    first_fixture = CapabilityOwnedFixture.build(
        world=first._owned_world,
        contract=first,
    )
    second_fixture = CapabilityOwnedFixture.build(
        world=second._owned_world,
        contract=second,
    )

    first_decision = classify_presentation(first, _presentation(first))
    second_decision = classify_presentation(second, _presentation(second))

    assert first == second
    assert first_fixture == second_fixture
    assert first_decision == second_decision
    assert first.mode == CAPABILITY_CONTRACT_MODE
    assert first_fixture.topology is ProofTopology.SINGLE_OWNED_ACCOUNT
    assert first_decision.outcome is CapabilityOutcome.VALID
    assert first_fixture.disposable is True
    assert first_fixture.reversible is True
    assert first_fixture.cleanup_required is False
    assert first_fixture.residue_created is False
    assert first_fixture.orphan_risk is False
    assert first_fixture.target_requests_sent == 0
    assert first_fixture.budget_reserved is False
    assert first_fixture.backend_dispatch_authority is False
    assert first_fixture.finding_authority is False
    assert first_fixture.executable is False

    public_payload = first.to_dict()
    expected_payload = {
        key: value
        for key, value in public_payload.items()
        if key not in {"schema_version", "capability_id"}
    }
    assert first.capability_id == stable_hash(
        "issued_capability_contract",
        expected_payload,
    )


@pytest.mark.parametrize(
    "field,prefix",
    (
        ("resource_ref", "capability_resource"),
        ("account_ref", "experiment_persona"),
        ("audience_ref", "experiment_persona"),
        ("operation_ref", "capability_operation"),
    ),
)
def test_wrong_resource_account_audience_or_operation_is_wrong_binding(field, prefix):
    contract = _contract()
    presentation = _presentation(
        contract,
        **{field: stable_hash(prefix, f"wrong-{field}")},
    )

    decision = classify_presentation(contract, presentation)

    assert decision.outcome is CapabilityOutcome.WRONG_BINDING


@pytest.mark.parametrize("at_index", (0, 9, 20, 21))
def test_before_issuance_and_at_or_after_expiry_are_expired(at_index):
    contract = _contract()

    decision = classify_presentation(
        contract,
        _presentation(contract, at_index=at_index),
    )

    assert decision.outcome is CapabilityOutcome.EXPIRED


def test_revoked_capability_is_rejected_even_when_the_presentation_otherwise_matches():
    contract = _contract(revocation_state=CapabilityRevocationState.REVOKED)

    decision = classify_presentation(contract, _presentation(contract))

    assert decision.outcome is CapabilityOutcome.REVOKED


def test_single_use_capability_rejects_the_second_zero_based_use_index():
    contract = _contract(max_uses=1)

    first = classify_presentation(contract, _presentation(contract, use_index=0))
    second = classify_presentation(contract, _presentation(contract, use_index=1))

    assert first.outcome is CapabilityOutcome.VALID
    assert second.outcome is CapabilityOutcome.ALREADY_USED


def test_revocation_precedes_expiry_wrong_binding_and_use_exhaustion():
    contract = _contract(revocation_state=CapabilityRevocationState.REVOKED)
    presentation = _presentation(
        contract,
        resource_ref=stable_hash("capability_resource", "wrong"),
        at_index=contract.expires_at_index,
        use_index=contract.max_uses,
    )

    decision = classify_presentation(contract, presentation)

    assert decision.outcome is CapabilityOutcome.REVOKED


def test_expiry_precedes_wrong_binding_and_use_exhaustion():
    contract = _contract()
    presentation = _presentation(
        contract,
        account_ref=stable_hash("experiment_persona", "wrong"),
        at_index=contract.expires_at_index,
        use_index=contract.max_uses,
    )

    decision = classify_presentation(contract, presentation)

    assert decision.outcome is CapabilityOutcome.EXPIRED


def test_wrong_binding_precedes_use_exhaustion():
    contract = _contract()
    presentation = _presentation(
        contract,
        operation_ref=stable_hash("capability_operation", "wrong"),
        use_index=contract.max_uses,
    )

    decision = classify_presentation(contract, presentation)

    assert decision.outcome is CapabilityOutcome.WRONG_BINDING


def test_machine_reason_and_decision_are_content_addressed():
    contract = _contract()
    presentation = _presentation(contract)

    first = classify_presentation(contract, presentation)
    second = classify_presentation(contract, presentation)
    rebuilt = CapabilityDecision.build(
        contract=contract,
        presentation=presentation,
        outcome=CapabilityOutcome.VALID,
    )

    assert first == second
    assert first == rebuilt
    assert first.reason_ref.startswith("capability_reason:")
    assert first.decision_id.startswith("capability_decision:")
    assert first.to_dict()["capability_id"] == contract.capability_id
    assert first.to_dict()["presentation_id"] == presentation.presentation_id
    with pytest.raises(ValueError, match="decision reason"):
        CapabilityDecision.build(
            contract=contract,
            presentation=presentation,
            outcome=CapabilityOutcome.VALID,
            binding_mismatches=("resource",),
        )


@pytest.mark.parametrize(
    "field",
    (
        "subject_ref",
        "resource_ref",
        "operation_ref",
        "audience_ref",
        "issuer_ref",
        "tenant_ref",
        "tenant_ownership_ref",
        "source_evidence_ref",
        "secret_digest",
    ),
)
def test_contract_rejects_malformed_or_raw_public_reference(field):
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(**{field: RAW_SECRET})


def test_contract_rejects_non_owned_and_role_qualified_worlds():
    anonymous = ExperimentWorldBinding.build(
        slot="anonymous",
        kind=ExperimentWorldKind.FRESH_ANONYMOUS,
        world_ref=stable_hash("world", "r5d1-anonymous"),
        fresh=True,
    )
    role_world = ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", "r5d1-role"),
        persona_ref=stable_hash("experiment_persona", "r5d1-role"),
        ownership_ref=stable_hash("ownership_proof", "r5d1-role"),
        role_ref=stable_hash("experiment_role", "r5d1-role"),
    )

    with pytest.raises(ValueError, match="one unqualified owned account"):
        _contract(world=anonymous)
    with pytest.raises(ValueError, match="one unqualified owned account"):
        _contract(world=role_world)


def test_contract_rejects_cross_tenant_world_context():
    with pytest.raises(ValueError, match="tenant binding"):
        _contract(
            world_tenant_ref=stable_hash("owned_tenant", "other"),
        )
    with pytest.raises(ValueError, match="tenant binding"):
        _contract(
            world_tenant_ownership_ref=stable_hash("ownership_proof", "other"),
        )


@pytest.mark.parametrize(
    "overrides",
    (
        {"max_uses": 0},
        {"max_uses": -1},
        {"max_uses": True},
        {"issued_at_index": -1},
        {"issued_at_index": True},
        {"expires_at_index": 10},
        {"expires_at_index": 9},
        {"expires_at_index": False},
    ),
)
def test_contract_rejects_invalid_logical_bounds(overrides):
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(**overrides)


def test_contract_requires_typed_revocation_state():
    with pytest.raises(TypeError, match="CapabilityRevocationState"):
        _contract(revocation_state="revoked")


def test_fixture_rejects_wrong_account_subject_or_audience():
    world = _owned_world()
    wrong_subject = stable_hash("experiment_persona", "wrong-subject")

    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(world=world, subject_ref=wrong_subject)
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(world=world, audience_ref=wrong_subject)


def test_fixture_rejects_substitution_to_another_owned_account():
    contract = _contract(world=_owned_world("alice"))

    with pytest.raises(ValueError, match="owned fixture world"):
        CapabilityOwnedFixture.build(
            world=_owned_world("bob"),
            contract=contract,
        )


def test_callback_reference_requires_controlled_callback_world_and_explicit_scope():
    callback_world = _callback_world()
    contract = _contract(
        callback_ref=callback_world.callback_ref,
        callback_scope_ref=stable_hash("capability_scope", "r5d1-callback"),
        callback_world=callback_world,
    )

    assert contract.callback_ref == callback_world.callback_ref
    assert contract.callback_scope_ref is not None
    assert contract.to_dict()["callback_ref"] == callback_world.callback_ref
    assert "callback_world" not in contract.to_dict()


def test_callback_reference_fails_closed_on_missing_scope_world_or_ref_match():
    callback_world = _callback_world()
    callback_ref = callback_world.callback_ref
    scope_ref = stable_hash("capability_scope", "r5d1-callback")

    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(callback_ref=callback_ref)
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(callback_scope_ref=scope_ref)
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(callback_ref=callback_ref, callback_scope_ref=scope_ref)
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(
            callback_ref=stable_hash("callback_receiver", "wrong"),
            callback_scope_ref=scope_ref,
            callback_world=callback_world,
        )
    with pytest.raises(ValueError, match="issued capability contract"):
        _contract(
            callback_ref=_owned_world().ownership_ref,
            callback_scope_ref=scope_ref,
            callback_world=_owned_world(),
        )


def test_raw_secret_is_never_stored_or_serialized():
    contract = _contract()
    fixture = CapabilityOwnedFixture.build(
        world=contract._owned_world,
        contract=contract,
    )

    contract_public = json.dumps(contract.to_dict(), sort_keys=True)
    fixture_public = json.dumps(fixture.to_dict(), sort_keys=True)

    assert contract.secret_digest == stable_hash(
        "capability_secret_digest",
        RAW_SECRET,
    )
    assert RAW_SECRET not in contract_public
    assert RAW_SECRET not in fixture_public
    assert RAW_SECRET not in repr(contract)
    assert RAW_SECRET not in contract.__dict__.values()


def test_content_addresses_and_passive_fixture_flags_cannot_be_forged():
    contract = _contract()
    fixture = CapabilityOwnedFixture.build(
        world=contract._owned_world,
        contract=contract,
    )

    with pytest.raises(ValueError, match="issued capability contract"):
        replace(
            contract,
            capability_id=stable_hash("issued_capability_contract", "forged"),
        )
    with pytest.raises(ValueError, match="capability owned fixture"):
        replace(
            fixture,
            fixture_id=stable_hash("capability_owned_fixture", "forged"),
        )
    with pytest.raises(ValueError, match="capability owned fixture"):
        replace(fixture, executable=True)


@pytest.mark.parametrize(
    "overrides",
    (
        {"resource_ref": RAW_SECRET},
        {"account_ref": RAW_SECRET},
        {"audience_ref": RAW_SECRET},
        {"operation_ref": RAW_SECRET},
        {"at_index": -1},
        {"at_index": True},
        {"use_index": -1},
        {"use_index": False},
    ),
)
def test_presentation_rejects_malformed_refs_or_indices(overrides):
    contract = _contract()

    with pytest.raises(ValueError, match="capability presentation"):
        _presentation(contract, **overrides)


def test_classifier_rejects_non_contract_or_non_presentation_inputs():
    contract = _contract()
    presentation = _presentation(contract)

    with pytest.raises(TypeError, match="IssuedCapabilityContract"):
        classify_presentation(object(), presentation)
    with pytest.raises(TypeError, match="CapabilityPresentation"):
        classify_presentation(contract, object())
