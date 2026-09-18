"""OCB-S18 passive search: real R1/R2/R3 derivation, no target requests."""

from dataclasses import FrozenInstanceError, replace
import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.behavior.compiler import CompilerLimits
from core.behavior.constraints import (
    ConstraintLedgerBuilder,
    StructuredConstraintExtractor,
)
from core.behavior.experiment_admission import (
    ExperimentRuntimeActionBinding,
    experiment_endpoint_ref,
)
from core.behavior.experiment_sdk import (
    ExistingBackendAdapter,
    ExperimentAction,
    ExperimentActionClass,
    ExperimentCleanupContract,
    ExperimentControl,
    ExperimentControlKind,
    ExperimentOracleContract,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
    ProofExperimentCompiler,
)
from core.behavior.normalize import stable_hash
from core.behavior.payout_goals import GoalPlanningContext, PayoutGoalTopologyPlanner
from core.behavior.search_stopping import (
    HighValueSinkLedger,
    MarginalValueScheduler,
    SearchBudget,
    SearchProof,
)
from core.behavior.semantic_catalog import TargetSemanticCatalogBuilder
from core.behavior.proposals import (
    AuthorizationExperimentProposal,
    MutationLocator,
    ProposalLeg,
)
from core.behavior.replanning import ConstraintReplanner
from core.cortex.execution_policy import CandidateAction
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import SAFE_READ
from core.safety.proof_budget import ProofBudget

ORIGIN = "https://search.example.test"
TARGET = stable_hash("security_obligation_target", ORIGIN)


def _ledger(
    names=("files", "documents", "role", "token"),
    *,
    authorized=True,
    world="alice",
    selected="alice",
    extra=(),
    records_override=None,
    state_machine=None,
):
    records = (
        records_override
        if records_override is not None
        else tuple(
            {
                "id": name,
                "persona_id": world,
                "method": "GET",
                "url": ORIGIN + "/api/" + name,
                "response_status": 200,
                "response_body": '{"data":{"ok":true}}',
            }
            for name in names
        )
    )
    catalog = TargetSemanticCatalogBuilder().build(
        (*records, *extra),
        target_ref=TARGET,
        target_origin=ORIGIN,
        world_id=world,
    )
    envelope = AuthorizationEnvelope(
        envelope_id="search-fixture",
        researcher_identity="researcher",
        target_handle="owned",
        authorized_origins=[ORIGIN],
        authorization_basis="owned fixture",
        disclosure_attestation=True,
        max_accounts_per_service=2,
        allowed_workflows=[
            "behavioral_object_authorization",
            "behavioral_role_membership_monotonicity",
            "behavioral_compiled_owned_sequence",
            "behavioral_state_machine_omission",
            "behavioral_state_machine_omission_confirmation",
        ],
        created_at=1780000000.0,
        expires_at=1900000000.0,
    )
    envelope.sign()
    context = GoalPlanningContext.build(
        target_ref=TARGET,
        target_origin=ORIGIN,
        authorization=envelope if authorized else None,
        selected_world_id=selected,
        owned_world_ids=("alice", "bob"),
        role_world_ids=("alice", "bob"),
        available_backends=(
            "object_authorization",
            "authority_monotonicity",
            "capability_confinement",
            "prerequisite_omission",
        ),
        lifecycle_available=True,
    )
    graph = SimpleNamespace(
        target_ref=TARGET,
        graph_digest=stable_hash("security_obligation_graph", "search"),
        obligations=(),
    )
    payout = PayoutGoalTopologyPlanner().plan(
        catalog.planner_operations(world_ref=stable_hash("world", world)),
        graph=graph,
        context=context,
        state_machine=state_machine,
    )
    return HighValueSinkLedger(payout, catalog)


def _proofs(ledger, *, method="GET"):
    """Compile complete existing R4 costs for A; C/D are honestly unbudgeted."""
    output = []
    for candidate in ledger.candidates:
        if candidate.backend != "object_authorization":
            continue
        operation = ledger.operations[candidate.goal.terminal_operation_id]
        proposal = AuthorizationExperimentProposal(
            proposal_id=stable_hash("authorization_proposal", operation.operation_id),
            action_id=operation.operation_id,
            operation_label=operation.label,
            source_ref=candidate.goal.evidence_refs[0],
            source_record_index=0,
            risk_class="safe_read",
            mutations=(
                MutationLocator(
                    location_kind="request_path",
                    pointer="/document_id",
                    semantic_key="document_id",
                    source_value_hash=stable_hash("mutation_value", "alice-document"),
                    replacement_value_hash=stable_hash(
                        "mutation_value", "bob-document"
                    ),
                ),
            ),
            legs=(
                ProposalLeg(
                    "peer_baseline", stable_hash("world", "bob"), "peer_observed_value"
                ),
                ProposalLeg(
                    "source_baseline",
                    stable_hash("world", "alice"),
                    "source_observed_value",
                ),
                ProposalLeg(
                    "counterfactual",
                    stable_hash("world", "alice"),
                    "peer_observed_value",
                ),
            ),
        )
        worlds = tuple(
            ExperimentWorldBinding.build(
                slot=slot,
                kind=ExperimentWorldKind.OWNED_ACCOUNT,
                world_ref=stable_hash("world", name),
                persona_ref=stable_hash("experiment_persona", name),
                ownership_ref=stable_hash("ownership_proof", name),
            )
            for slot, name in (("actor", "alice"), ("peer", "bob"))
        )
        # Existing action identity remains opaque. These owned fixture endpoints
        # are bound by the SDK's own runtime binding constructor, without dispatch.
        url = ORIGIN + "/api/" + operation.label.rsplit(".", 1)[-1]
        actions, bindings = [], []
        for ordinal, (phase, world, action_class) in enumerate(
            (
                (ExperimentPhase.CONTROL, worlds[0], ExperimentActionClass.SAFE_READ),
                (ExperimentPhase.CONTROL, worlds[1], ExperimentActionClass.SAFE_READ),
                (
                    ExperimentPhase.TREATMENT,
                    worlds[0],
                    ExperimentActionClass.CROSS_OBJECT_READ,
                ),
                (ExperimentPhase.WITNESS, worlds[1], ExperimentActionClass.SAFE_READ),
            )
        ):
            action = ExperimentAction.build(
                ordinal=ordinal,
                phase=phase,
                operation_id=operation.operation_id,
                world_binding_id=world.binding_id,
                action_class=action_class,
                endpoint_ref=experiment_endpoint_ref(method, url),
                mutation=MutationExpectation.NONE,
                evidence_refs=candidate.goal.evidence_refs,
            )
            runtime = CandidateAction(
                method,
                url,
                hint=action_class.value,
                actor_persona_id="alice" if world == worlds[0] else "bob",
                target_owner_persona_id="bob" if ordinal == 2 else None,
                target_is_researcher_owned=True,
                expected_side_effect="none",
                proof_goal="owned_object_counterfactual",
            )
            bindings.append(
                ExperimentRuntimeActionBinding.bind(
                    action=action,
                    candidate=runtime,
                    target_origin=ORIGIN,
                    runtime_worlds={
                        worlds[0].binding_id: (
                            "alice",
                            ExperimentWorldKind.OWNED_ACCOUNT,
                        ),
                        worlds[1].binding_id: (
                            "bob",
                            ExperimentWorldKind.OWNED_ACCOUNT,
                        ),
                    },
                )
            )
            actions.append(action)
        controls = tuple(
            ExperimentControl.build(
                kind=kind,
                action_ids=(actions[index].action_id,),
                world_binding_ids=(worlds[index].binding_id,),
            )
            for index, kind in enumerate(
                (
                    ExperimentControlKind.OWNER_BASELINE,
                    ExperimentControlKind.PEER_BASELINE,
                )
            )
        )
        replan = ConstraintReplanner(tuple(ledger.operations.values())).compile_witness(
            candidate.goal,
            ledger=ConstraintLedgerBuilder().build(),
        )
        manifest = ProofExperimentCompiler().compile(
            candidate=candidate,
            replan=replan,
            world_manifest=ExperimentWorldManifest.build(
                requirement=candidate.world_requirement, bindings=worlds
            ),
            backend=ExistingBackendAdapter.authorization(proposal),
            actions=actions,
            controls=controls,
            oracle=ExperimentOracleContract.build(
                goal=candidate.goal,
                control_ids=tuple(x.control_id for x in controls),
                treatment_action_ids=(actions[2].action_id,),
                witness_action_ids=(actions[3].action_id,),
                comparison_kind="owned_object_counterfactual",
            ),
            cleanup=ExperimentCleanupContract.build(),
            target_ref=TARGET,
            authority_context_ref=stable_hash(
                "experiment_authority_context", "fixture"
            ),
            provenance_refs=(stable_hash("provenance", "fixture"),),
        )
        output.append(SearchProof(manifest, tuple(bindings)))
    return tuple(output)


def _plan(ledger=None, budget=None, constraints=None, **kwargs):
    ledger = ledger or _ledger()
    proofs = kwargs.pop("proofs") if "proofs" in kwargs else _proofs(ledger)
    return MarginalValueScheduler().plan(
        ledger=ledger,
        proofs=proofs,
        constraints=constraints or ConstraintLedgerBuilder().build(),
        budget=SearchBudget.capture(
            budget
            or ProofBudget(
                max_total_requests=20,
                max_cross_object_reads=5,
                max_requests_per_endpoint=20,
            )
        ),
        enabled=kwargs.pop("enabled", True),
        **kwargs,
    )


def _blocked(ledger, candidate_id):
    candidate = ledger.require_candidate(candidate_id)
    body = {
        "detail": [
            {"type": "missing", "loc": ["body", "missing_key"], "msg": "required"}
        ]
    }
    extraction = StructuredConstraintExtractor().extract(
        operation_id=candidate.goal.terminal_operation_id,
        response_status=422,
        response_body=json.dumps(body),
        response_ref=stable_hash("response_artifact", body),
    )
    return ConstraintLedgerBuilder().build(extractions=(extraction,))


def test_ocb_s18_order_replan_coverage_and_honest_stop(tmp_path):
    ledger = _ledger()
    budget = ProofBudget(
        max_total_requests=20, max_cross_object_reads=5, max_requests_per_endpoint=20
    )
    before = SearchBudget.capture(budget)
    first = _plan(ledger, budget)
    assert len(first.ordering) == 2
    assert {x.family for x in first.entries} == {"A", "C", "D"}
    assert first == _plan(_ledger(), budget)
    blocked_id = first.ordering[0]
    constraints = _blocked(ledger, blocked_id)
    second = _plan(ledger, budget, constraints, previous=first)
    assert blocked_id not in second.ordering
    assert set(second.ordering) == set(first.ordering) - {blocked_id}
    assert (
        next(x for x in second.entries if x.candidate_id == blocked_id).status
        == "blocked"
    )
    assert second.ledger.ledger_id == first.ledger.ledger_id
    assert SearchBudget.capture(budget) == before
    # Actual budget accounting, no transport: charge existing ordinary read slots.
    for _ in range(20):
        budget.record(SAFE_READ, "owned-fixture")
    final = _plan(ledger, budget, constraints, previous=second)
    certificate = final.certificate()
    body = certificate.to_dict()
    assert final.ordering == ()
    assert body["stop_reason"] == "proof_budget_unavailable"
    assert body["budget_consumed_requests"] == 20
    assert body["planner_requests_sent"] == 0
    assert body["families"]["B"] == dict.fromkeys(
        ("proved", "blocked", "exhausted", "never_explored"), []
    )
    assert sum(len(row["blocked"]) for row in body["families"].values()) == 1
    assert sum(len(row["never_explored"]) for row in body["families"].values()) == 3
    assert sum(len(row["proved"]) for row in body["families"].values()) == 0
    assert sorted(
        x for row in body["families"].values() for ids in row.values() for x in ids
    ) == list(ledger.candidate_ids)
    assert certificate.verify(final)
    (tmp_path / "ocb-s18-certificate.json").write_text(
        json.dumps(body, indent=2) + "\n"
    )
    (tmp_path / "ocb-s18-inputs.json").write_text(
        json.dumps(final.input_dict(), indent=2) + "\n"
    )


def test_tie_break_is_ascending_candidate_id_and_input_order_does_not_matter():
    ledger = _ledger(("files", "documents"))
    reverse = _ledger(("documents", "files"))
    one, two = _plan(ledger), _plan(reverse)
    assert len(one.ordering) == 2
    assert one.entries[0].signals == one.entries[1].signals
    assert one.ordering == tuple(sorted(one.ordering)) == two.ordering
    assert one.certificate() == two.certificate()


def test_default_off_never_invokes_replanner(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("disabled planner invoked R3")

    monkeypatch.setattr(
        "core.behavior.search_stopping.ConstraintReplanner.compile_witness", forbidden
    )
    plan = _plan(enabled=False, proofs=())
    assert plan.ordering == ()
    assert plan.certificate().to_dict()["stop_reason"] == "planning_disabled"
    assert all(x.status == "never_explored" for x in plan.entries)


@pytest.mark.parametrize(
    "authorized,world,selected", [(False, "alice", "alice"), (True, "bob", "alice")]
)
def test_only_r1_admitted_and_selected_world_r2_candidates(authorized, world, selected):
    ledger = _ledger(authorized=authorized, world=world, selected=selected)
    assert ledger.candidate_ids == ()
    with pytest.raises(ValueError, match="non-admitted"):
        ledger.require_candidate(stable_hash("payout_goal_candidate", "invented"))
    assert _plan(ledger).ordering == ()


def test_empty_frontier_has_no_fabricated_coverage():
    plan = _plan(_ledger(()))
    cert = plan.certificate().to_dict()
    assert plan.ordering == ()
    assert cert["stop_reason"] == "frontier_exhausted"
    assert cert["entries"] == cert["admitted_candidate_ids"] == []
    assert all(not ids for row in cert["families"].values() for ids in row.values())


def test_outstanding_reservations_bound_plan_and_budget_is_unchanged():
    budget = ProofBudget(
        max_total_requests=6, max_requests_per_endpoint=10, max_cross_object_reads=3
    )
    reservation, reason = budget.try_reserve(((SAFE_READ, "owned-fixture"),) * 2)
    assert reservation and reason == "ok"
    before = SearchBudget.capture(budget)
    plan = _plan(budget=budget)
    assert len(plan.ordering) == 1
    assert plan.certificate().to_dict()["planned_cost_units"] <= before.remaining == 4
    assert SearchBudget.capture(budget) == before
    assert budget.reservation_remaining(reservation) == 2
    budget.release_reservation(reservation)
    with pytest.raises(ValueError, match="raise budget"):
        _plan(plan.ledger, budget, previous=plan)


@pytest.mark.parametrize("change", ["limit", "permissions", "spent", "authority"])
def test_replanning_cannot_raise_budget_or_change_authority(change):
    ledger = _ledger()
    budget = ProofBudget(max_total_requests=5, allow_real_user_data_access=False)
    budget.record(SAFE_READ, "owned-fixture")
    first = _plan(ledger, budget)
    if change == "limit":
        budget.max_total_requests += 1
    elif change == "permissions":
        budget.allow_real_user_data_access = True
    elif change == "spent":
        budget = ProofBudget(max_total_requests=5, allow_real_user_data_access=False)
    else:
        ledger = _ledger(("attachments",))
    with pytest.raises(ValueError, match="budget|authority"):
        _plan(ledger, budget, previous=first)


def test_stale_or_invalidated_constraints_cannot_reopen_frontier():
    ledger = _ledger()
    initial = _plan(ledger)
    constraints = _blocked(ledger, initial.ordering[0])
    learned = _plan(ledger, constraints=constraints, previous=initial)
    with pytest.raises(ValueError, match="stale constraints"):
        _plan(ledger, previous=learned)
    invalidated = _plan(
        ledger, constraints=constraints, constraints_valid=False, previous=learned
    )
    assert invalidated.ordering == ()
    assert all(x.status == "blocked" for x in invalidated.entries)
    with pytest.raises(ValueError, match="invalidated constraints"):
        _plan(ledger, constraints=constraints, previous=invalidated)


def test_certificate_is_immutable_detached_and_rejects_rehashed_lies():
    plan = _plan()
    certificate = plan.certificate()
    with pytest.raises(FrozenInstanceError):
        certificate.certificate_id = "invented"
    exported = certificate.to_dict()
    exported["entries"].clear()
    assert len(certificate.to_dict()["entries"]) == 4
    payload = json.loads(certificate.payload_json)
    payload["families"]["A"]["proved"].append("fabricated")
    with pytest.raises(ValueError, match="content address"):
        replace(
            certificate,
            payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
    # Even if content is rehashed, the input-bound verifier refuses the claim.
    with pytest.raises(ValueError, match="claims do not match"):
        replace(
            certificate,
            payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            certificate_id=stable_hash("search_stop_certificate", payload),
        )


def test_no_live_caller_transport_or_persistence_surface():
    import core.behavior as package
    import core.behavior.search_stopping as module

    assert not hasattr(package, "MarginalValueScheduler")
    tree = ast.parse(Path(module.__file__).read_text())
    roots = {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    roots |= {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not roots & {
        "httpx",
        "requests",
        "socket",
        "os",
        "pathlib",
        "sqlite3",
        "subprocess",
    }
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not calls & {
        "execute",
        "send",
        "request",
        "try_reserve",
        "record",
        "write_text",
        "complete",
    }


def test_r3_search_exhaustion_reorders_without_fabricating_execution():
    from core.behavior.constraints import ConstraintKind, ConstraintSignal

    ledger = _ledger()
    first = _plan(ledger, compiler_limits=CompilerLimits(max_search_states=1))
    candidate = ledger.require_candidate(first.ordering[0])
    produced = ledger.operations[candidate.goal.terminal_operation_id].produces[0]
    signal = ConstraintSignal.structured_failure(
        operation_id=candidate.goal.terminal_operation_id,
        kind=ConstraintKind.LIFECYCLE_STATE,
        key="required_state",
        required_capability=produced,
        evidence_ref=stable_hash("response_artifact", "missing_observed_state"),
        response_status=409,
        schema_ref=stable_hash("constraint_schema", "owned_fixture"),
    )
    constraints = ConstraintLedgerBuilder().build((signal,))
    second = _plan(
        ledger,
        constraints=constraints,
        previous=first,
        compiler_limits=CompilerLimits(max_search_states=1),
    )
    entry = next(x for x in second.entries if x.candidate_id == candidate.candidate_id)
    assert entry.status == "exhausted" and entry.reason == "r3_search_exhausted"
    assert candidate.candidate_id not in second.ordering
    assert set(second.ordering) == set(first.ordering) - {candidate.candidate_id}
    assert second.certificate().to_dict()["budget_consumed_requests"] == 0
    assert (
        candidate.candidate_id
        in second.certificate().to_dict()["families"]["A"]["exhausted"]
    )
    with pytest.raises(ValueError, match="widen proof or search budget"):
        _plan(ledger, constraints=constraints, previous=second)


@pytest.mark.parametrize(
    "limits",
    [
        {"max_total_requests": 3},
        {"max_requests_per_endpoint": 3},
        {"max_cross_object_reads": 0},
    ],
)
def test_complete_four_leg_proof_respects_each_applicable_budget(limits):
    ledger = _ledger(("files",))
    budget = ProofBudget(**limits)
    plan = _plan(ledger, budget)
    assert plan.entries[0].signals.proof_cost == 4
    assert plan.ordering == ()
    assert plan.entries[0].status == "never_explored"
    assert plan.certificate().to_dict()["stop_reason"] == "budget_exhausted"
    assert budget.snapshot()["total_requests"] == 0


def test_cross_object_budget_is_shared_across_entire_order():
    plan = _plan(_ledger(("files", "documents")), ProofBudget(max_cross_object_reads=1))
    assert len(plan.ordering) == 1
    assert plan.certificate().to_dict()["planned_cost_units"] == 4


def test_existing_endpoint_usage_and_reservations_are_not_reset():
    budget = ProofBudget(max_requests_per_endpoint=4, max_cross_object_reads=2)
    budget.record(SAFE_READ, "search.example.test/api/files")
    plan = _plan(_ledger(("files",)), budget)
    assert plan.ordering == ()
    assert plan.certificate().to_dict()["budget_consumed_requests"] == 1


def test_missing_full_proof_cost_is_explicitly_never_explored():
    plan = _plan(proofs=())
    assert plan.ordering == ()
    assert all(
        x.status == "never_explored" and x.reason == "proof_budget_unavailable"
        for x in plan.entries
    )
    assert plan.certificate().to_dict()["stop_reason"] == "proof_budget_unavailable"


def test_non_admitted_proof_is_refused_before_scheduling():
    proof = _proofs(_ledger(("files",)))[0]
    with pytest.raises(ValueError, match="non-admitted"):
        _plan(_ledger(("documents",)), proofs=(proof,))


def test_bound_proof_set_cannot_expand_during_replanning():
    ledger = _ledger()
    first = _plan(ledger, proofs=())
    with pytest.raises(ValueError, match="widen proof"):
        _plan(ledger, previous=first)


def test_every_signal_is_recorded_and_exact_score_responds_to_each():
    from core.behavior.search_stopping import SearchSignals

    base = SearchSignals(80, 2, 4, 4, 20, 1)
    for signal in (
        "payout_relevance",
        "reachability_gain",
        "information_gain",
        "remaining_budget",
    ):
        assert (
            replace(base, **{signal: getattr(base, signal) + 1}).marginal_value
            > base.marginal_value
        )
    for signal in ("proof_cost", "cleanup_risk"):
        assert (
            replace(base, **{signal: getattr(base, signal) + 1}).marginal_value
            < base.marginal_value
        )
    assert set(base.to_dict()) == {*vars(base), "marginal_value"}


def test_family_b_coverage_comes_from_actual_r1_and_r2_state_machine_inputs():
    import importlib.util
    from core.behavior.state_machine import StateMachineLegalityMiner

    spec = importlib.util.spec_from_file_location(
        "_search_omission_fixture",
        Path(__file__).with_name("test_behavior_experiment_sdk.py"),
    )
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    records = tuple(
        {**record, "url": record["url"].replace(fixture.OMISSION_ORIGIN, ORIGIN)}
        for record in fixture._omission_records()
    )
    machine = StateMachineLegalityMiner().mine(records, world_id="alice")
    assert machine.candidates
    ledger = _ledger(records_override=records, state_machine=machine)
    plan = _plan(ledger, proofs=())
    family_b = [entry for entry in plan.entries if entry.family == "B"]
    assert family_b
    assert all(entry.status in {"blocked", "never_explored"} for entry in family_b)
    cert = plan.certificate().to_dict()
    assert sorted(x for ids in cert["families"]["B"].values() for x in ids) == sorted(
        entry.candidate_id for entry in family_b
    )
    assert cert["families"]["B"]["proved"] == []


def test_proof_for_another_origin_is_rejected(monkeypatch):
    ledger = _ledger(("files",))
    monkeypatch.setitem(_proofs.__globals__, "ORIGIN", "https://outside.example.test")
    proofs = _proofs(ledger)
    with pytest.raises(ValueError, match="outside admitted origin"):
        _plan(ledger, proofs=proofs)


def test_runtime_identity_cannot_be_substituted_under_an_admitted_world():
    from core.behavior.experiment_admission import _runtime_action_payload

    ledger = _ledger(("files",))
    proof = _proofs(ledger)[0]
    binding = proof.bindings[0]
    fields = {
        key: value
        for key, value in vars(binding).items()
        if key != "runtime_action_binding_id"
    }
    fields["actor_identity_ref"] = stable_hash("experiment_runtime_identity", "mallory")
    payload_fields = {**fields, "endpoint_key_value": fields["endpoint_key"]}
    del payload_fields["endpoint_key"]
    forged = ExperimentRuntimeActionBinding(
        runtime_action_binding_id=stable_hash(
            "experiment_runtime_action_binding",
            _runtime_action_payload(**payload_fields),
        ),
        **fields,
    )
    proof = replace(proof, bindings=(forged, *proof.bindings[1:]))
    with pytest.raises(ValueError, match="runtime identity"):
        _plan(ledger, proofs=(proof,))


def test_runtime_method_cannot_widen_an_admitted_read_operation():
    ledger = _ledger(("files",))
    proofs = _proofs(ledger, method="POST")
    with pytest.raises(ValueError, match="action class or method"):
        _plan(ledger, proofs=proofs)
