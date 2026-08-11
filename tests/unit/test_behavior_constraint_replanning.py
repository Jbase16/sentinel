"""Passive constraint-learning and deterministic-replanning contract tests."""

from __future__ import annotations

import json

import pytest

import core.behavior as behavior_package

from core.behavior.compiler import (
    Capability,
    CapabilityKind,
    CompilerLimits,
    OperationContract,
    OperationSafety,
)
from core.behavior.constraints import (
    ConstraintBasis,
    ConstraintExtractionLimits,
    ConstraintKind,
    ConstraintLedgerBuilder,
    ConstraintLedgerLimits,
    ConstraintSignal,
    ConstraintTruth,
    StructuredConstraintExtractor,
)
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import (
    PayoutSink,
    SecurityProperty,
    SecurityWitnessGoal,
)
from core.behavior.replanning import (
    CONSTRAINT_REPLANNER_MODE,
    ConstraintReplanLimits,
    ConstraintReplanner,
)


ROOT_EVIDENCE = stable_hash("semantic_source", {"capture": "s13"})
SUBMIT_OPERATION_ID = stable_hash(
    "action",
    {"method": "POST", "path": "/api/orders/submit"},
)
ADDRESS = Capability(CapabilityKind.VALUE, "address_id")
POSTAL_CODE = Capability(CapabilityKind.VALUE, "postal_code")


def _response_ref(value: object) -> str:
    return stable_hash("response_artifact", value)


def _operations(*, cyclic: bool = False):
    order_started = Capability(CapabilityKind.STATE, "order_started")
    create_requires = (order_started,) if cyclic else ()
    create = OperationContract(
        operation_id="create_address",
        label="Create controlled address",
        requires=create_requires,
        produces=(ADDRESS,),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    postal = OperationContract(
        operation_id="discover_postal_code",
        label="Read controlled postal code",
        requires=(),
        produces=(POSTAL_CODE,),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    submit = OperationContract(
        operation_id=SUBMIT_OPERATION_ID,
        label="Submit controlled order",
        requires=(),
        produces=(order_started,) if cyclic else (),
        safety=OperationSafety.READ_ONLY,
        observed_success=True,
    )
    return create, postal, submit


def _goal(submit: OperationContract) -> SecurityWitnessGoal:
    return SecurityWitnessGoal.build(
        operation=submit,
        sink=PayoutSink.FINANCIAL,
        security_property=SecurityProperty.PREREQUISITE_ENFORCEMENT,
        evidence_refs=(ROOT_EVIDENCE,),
    )


def _structured_address_signal():
    body = {
        "detail": [
            {
                "type": "missing",
                "loc": ["body", "address_id"],
                "msg": "Field required",
                "input": {},
            }
        ]
    }
    return StructuredConstraintExtractor().extract(
        operation_id=SUBMIT_OPERATION_ID,
        response_status=422,
        response_body=json.dumps(body),
        response_ref=_response_ref(body),
    )


def _typed_signal(*, capability: Capability, response_name: str):
    return ConstraintSignal.structured_failure(
        operation_id=SUBMIT_OPERATION_ID,
        kind=ConstraintKind.REQUIRED_FIELD,
        key="body.address_id",
        required_capability=capability,
        evidence_ref=_response_ref({"name": response_name}),
        response_status=409,
        schema_ref=stable_hash(
            "constraint_schema",
            {"adapter": "trusted_test_adapter", "version": 1},
        ),
    )


def test_structured_pydantic_failure_creates_a_redacted_deterministic_fact():
    first = _structured_address_signal()
    second = _structured_address_signal()

    assert first == second
    assert first.status == "observed"
    assert len(first.signals) == 1
    signal = first.signals[0]
    assert signal.kind is ConstraintKind.REQUIRED_FIELD
    assert signal.key == "body.address_id"
    assert signal.required_capability == ADDRESS

    ledger = ConstraintLedgerBuilder().build(extractions=(first,))
    assert ledger.status == "ready"
    assert len(ledger.facts) == 1
    assert ledger.facts[0].truth is ConstraintTruth.FACT
    assert ledger.facts[0].basis is ConstraintBasis.STRUCTURED_RESPONSE
    serialized = json.dumps(ledger.to_dict(), sort_keys=True)
    assert "Field required" not in serialized
    assert '"input":' not in serialized


def test_free_text_is_only_a_hypothesis_until_an_independent_control_succeeds():
    failure = ConstraintSignal.free_text_hint(
        operation_id=SUBMIT_OPERATION_ID,
        kind=ConstraintKind.REQUIRED_FIELD,
        key="body.address_id",
        required_capability=ADDRESS,
        evidence_ref=_response_ref("address is required"),
        response_status=400,
    )
    hypothesis_ledger = ConstraintLedgerBuilder().build((failure,))
    assert hypothesis_ledger.status == "hypotheses_only"
    assert hypothesis_ledger.facts == ()

    control = ConstraintSignal.successful_control(
        failure=failure,
        evidence_ref=_response_ref({"address_id": "controlled", "status": 201}),
        response_status=201,
    )
    proven_ledger = ConstraintLedgerBuilder().build((failure, control))
    assert proven_ledger.status == "ready"
    assert proven_ledger.facts[0].basis is ConstraintBasis.CORROBORATED_CONTROL
    assert proven_ledger.facts[0].signal_ids == tuple(
        sorted((failure.signal_id, control.signal_id))
    )


def test_s13_fail_learn_replan_to_a_controlled_prerequisite_path():
    create, postal, submit = _operations()
    goal = _goal(submit)
    replanner = ConstraintReplanner((submit, postal, create))
    empty = ConstraintLedgerBuilder().build()

    baseline = replanner.compile_witness(goal, ledger=empty)
    assert baseline.status == "ready"
    assert baseline.plan.step_ids == (SUBMIT_OPERATION_ID,)

    learned = ConstraintLedgerBuilder().build(
        extractions=(_structured_address_signal(),)
    )
    replanned = replanner.compile_witness(goal, ledger=learned, previous=baseline)

    assert replanned.status == "ready"
    assert replanned.mode == CONSTRAINT_REPLANNER_MODE
    assert replanned.executable is False
    assert replanned.plan.step_ids == ("create_address", SUBMIT_OPERATION_ID)
    assert replanned.generation == 1
    assert len(replanned.lineage) == 2
    assert len(replanned.disproved_assumptions) == 1
    assert replanned.disproved_assumptions[0].prior_plan_id == baseline.plan.plan_id
    assert replanned.root_evidence_refs == baseline.root_evidence_refs
    assert replanned.policy_digest == baseline.policy_digest
    assert replanned.compiler_limits_digest == baseline.compiler_limits_digest
    assert "analysis_only_no_execution_authority" in replanned.plan.execution_blockers


def test_hypothesis_only_replanning_cannot_change_or_repeat_the_plan():
    create, postal, submit = _operations()
    replanner = ConstraintReplanner((create, postal, submit))
    baseline = replanner.compile_witness(
        _goal(submit),
        ledger=ConstraintLedgerBuilder().build(),
    )
    hint = ConstraintSignal.free_text_hint(
        operation_id=SUBMIT_OPERATION_ID,
        kind=ConstraintKind.REQUIRED_FIELD,
        key="body.address_id",
        required_capability=ADDRESS,
        evidence_ref=_response_ref("maybe address"),
        response_status=400,
    )

    hint_ledger = ConstraintLedgerBuilder().build((hint,))
    result = replanner.compile_witness(
        _goal(submit),
        ledger=hint_ledger,
        previous=baseline,
    )

    assert result.status == "blocked"
    assert result.blockers == ("no_new_constraint_fact",)
    assert result.plan.plan_id == baseline.plan.plan_id
    assert result.lineage == baseline.lineage
    assert result.accepted_ledger_id == baseline.accepted_ledger_id
    assert result.observed_ledger_id == hint_ledger.ledger_id
    assert result.applied_constraint_ids == ()
    assert result.hypothesis_constraint_ids


def test_same_fact_cannot_trigger_an_identical_second_replan():
    create, postal, submit = _operations()
    replanner = ConstraintReplanner((create, postal, submit))
    goal = _goal(submit)
    baseline = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    learned = ConstraintLedgerBuilder().build(
        extractions=(_structured_address_signal(),)
    )
    first = replanner.compile_witness(goal, ledger=learned, previous=baseline)

    repeated = replanner.compile_witness(goal, ledger=learned, previous=first)

    assert repeated.status == "blocked"
    assert repeated.blockers == ("no_new_constraint_fact",)
    assert repeated.generation == first.generation
    assert repeated.lineage == first.lineage


def test_contradictory_fact_dimension_blocks_without_applying_either_value():
    address = _typed_signal(capability=ADDRESS, response_name="address")
    postal = _typed_signal(capability=POSTAL_CODE, response_name="postal")
    ledger = ConstraintLedgerBuilder().build((address, postal))

    assert ledger.status == "blocked"
    assert ledger.blockers == ("contradictory_constraints",)
    assert len(ledger.facts) == 2

    create, discover_postal, submit = _operations()
    result = ConstraintReplanner((create, discover_postal, submit)).compile_witness(
        _goal(submit),
        ledger=ledger,
    )
    assert result.status == "blocked"
    assert "constraint_ledger_blocked" in result.blockers
    assert result.applied_constraint_ids == ()


def test_learned_cycle_is_reported_as_an_honest_blocker():
    create, postal, submit = _operations(cyclic=True)
    replanner = ConstraintReplanner((create, postal, submit))
    goal = _goal(submit)
    baseline = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )

    result = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(
            extractions=(_structured_address_signal(),)
        ),
        previous=baseline,
    )

    assert result.status == "blocked"
    assert "constraint_cycle_or_unreachable" in result.blockers
    assert "replanned_goal_blocked" in result.blockers
    assert any(
        item.startswith("cyclic_or_unreachable:")
        for item in result.plan.execution_blockers
    )


def test_extraction_and_ledger_bounds_fail_closed():
    body = {
        "detail": [
            {"type": "missing", "loc": ["body", "address_id"]},
            {"type": "missing", "loc": ["body", "postal_code"]},
        ]
    }
    extraction = StructuredConstraintExtractor(
        ConstraintExtractionLimits(max_issues=1)
    ).extract(
        operation_id=SUBMIT_OPERATION_ID,
        response_status=422,
        response_body=body,
        response_ref=_response_ref(body),
    )
    assert extraction.status == "blocked"
    assert extraction.blockers == ("constraint_issue_limit_exceeded",)

    signal = _structured_address_signal().signals[0]
    other = _typed_signal(capability=POSTAL_CODE, response_name="bound")
    ledger = ConstraintLedgerBuilder(
        ConstraintLedgerLimits(max_signals=1)
    ).build((signal, other))
    assert ledger.status == "blocked"
    assert "constraint_signal_limit_exceeded" in ledger.blockers
    assert ledger.diagnostics.dropped_signals == 1

    deduplicated = ConstraintLedgerBuilder().build((signal, signal))
    assert deduplicated.status == "ready"
    assert deduplicated.diagnostics.input_signals == 2
    assert deduplicated.diagnostics.unique_signals == 1
    assert deduplicated.diagnostics.duplicate_signals == 1
    assert deduplicated.diagnostics.dropped_signals == 0


def test_compiler_search_bound_is_exposed_by_the_replanner():
    create, postal, submit = _operations()
    replanner = ConstraintReplanner(
        (create, postal, submit),
        compiler_limits=CompilerLimits(max_search_states=1),
    )
    goal = _goal(submit)
    baseline = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    assert baseline.status == "ready"

    bounded = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(
            extractions=(_structured_address_signal(),)
        ),
        previous=baseline,
    )

    assert bounded.status == "blocked"
    assert bounded.plan.search_exhausted is True
    assert "constraint_search_bound_exhausted" in bounded.blockers


def test_replan_generation_bound_preserves_the_last_valid_lineage():
    create, postal, submit = _operations()
    replanner = ConstraintReplanner(
        (create, postal, submit),
        replan_limits=ConstraintReplanLimits(max_generations=1),
    )
    goal = _goal(submit)
    baseline = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    address_signal = _structured_address_signal().signals[0]
    first_ledger = ConstraintLedgerBuilder().build((address_signal,))
    first = replanner.compile_witness(goal, ledger=first_ledger, previous=baseline)

    postal_signal = ConstraintSignal.structured_failure(
        operation_id=SUBMIT_OPERATION_ID,
        kind=ConstraintKind.REQUIRED_FIELD,
        key="body.postal_code",
        required_capability=POSTAL_CODE,
        evidence_ref=_response_ref({"missing": "postal_code"}),
        response_status=422,
        schema_ref=stable_hash(
            "constraint_schema",
            {"adapter": "test", "version": 1},
        ),
    )
    bounded = replanner.compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build((address_signal, postal_signal)),
        previous=first,
    )

    assert bounded.status == "blocked"
    assert "replan_generation_limit_exceeded" in bounded.blockers
    assert bounded.generation == first.generation
    assert bounded.lineage == first.lineage


def test_unstructured_error_never_becomes_a_fact_implicitly():
    result = StructuredConstraintExtractor().extract(
        operation_id=SUBMIT_OPERATION_ID,
        response_status=400,
        response_body="address_id is required",
        response_ref=_response_ref("address_id is required"),
    )
    ledger = ConstraintLedgerBuilder().build(extractions=(result,))

    assert result.status == "blocked"
    assert result.signals == ()
    assert result.blockers == ("untrusted_free_text_only",)
    assert ledger.facts == ()
    assert ledger.status == "blocked"


def test_constraint_kernel_is_not_implicitly_exported_or_network_capable():
    assert not hasattr(behavior_package, "ConstraintLedgerBuilder")
    assert not hasattr(behavior_package, "ConstraintReplanner")

    source = __import__(
        "core.behavior.constraints",
        fromlist=["StructuredConstraintExtractor"],
    )
    assert not hasattr(source, "requests")
    assert not hasattr(source, "httpx")


def test_invalid_control_and_context_drift_fail_closed():
    failure = ConstraintSignal.free_text_hint(
        operation_id=SUBMIT_OPERATION_ID,
        kind=ConstraintKind.REQUIRED_FIELD,
        key="body.address_id",
        required_capability=ADDRESS,
        evidence_ref=_response_ref("address"),
        response_status=400,
    )
    with pytest.raises(ValueError, match="constraint signal contract"):
        ConstraintSignal(
            **{
                **failure.__dict__,
                "response_status": 200,
            }
        )
    with pytest.raises(ValueError, match="distinct evidence"):
        ConstraintSignal.successful_control(
            failure=failure,
            evidence_ref=failure.evidence_ref,
            response_status=200,
        )

    create, postal, submit = _operations()
    goal = _goal(submit)
    previous = ConstraintReplanner((create, postal, submit)).compile_witness(
        goal,
        ledger=ConstraintLedgerBuilder().build(),
    )
    with pytest.raises(ValueError, match="planning context"):
        ConstraintReplanner(
            (create, postal, submit),
            replan_limits=ConstraintReplanLimits(max_generations=2),
        ).compile_witness(
            goal,
            ledger=ConstraintLedgerBuilder().build(
                extractions=(_structured_address_signal(),)
            ),
            previous=previous,
        )
