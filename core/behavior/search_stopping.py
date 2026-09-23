"""OCB-R6: passive coverage economics over an already admitted frontier.

No caller in production, persistence, budget reservation, or transport is provided.
The default-off switch gates ordering only. R8 must separately re-admit any future
execution. Existing complete proof manifests and runtime bindings are required for
budget feasibility; incomplete costs never turn into permission to schedule.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from core.safety.proof_budget import ProofBudget

from .compiler import CompilerLimits, OperationSafety
from .constraints import ConstraintLedger
from .experiment_admission import (
    ExperimentRuntimeActionBinding,
    _canonical_origin,
    experiment_endpoint_ref,
)
from .experiment_sdk import (
    CleanupOutcome,
    ExperimentOracleEvaluation,
    OracleVerdict,
    ProofExperimentManifest,
)
from .normalize import stable_hash
from .payout_goals import (
    PayoutGoalCandidate,
    PayoutGoalPlan,
    SecurityProperty,
    SecurityWitnessGoal,
    _candidate_blockers,
)
from .receipts import BehavioralExecutionReceipt, COMPLETED
from .replanning import ConstraintReplanner
from .semantic_catalog import TargetSemanticCatalog

SEARCH_STOPPING_MODE = "behavioral_search_stopping_v1"
_FAMILIES = {
    SecurityProperty.OBJECT_AUTHORIZATION: "A",
    SecurityProperty.PREREQUISITE_ENFORCEMENT: "B",
    SecurityProperty.AUTHORITY_MONOTONICITY: "C",
    SecurityProperty.CAPABILITY_CONFINEMENT: "D",
}
_LIMITS = (
    "max_total_requests",
    "max_requests_per_endpoint",
    "max_cross_object_reads",
    "max_privilege_mutations",
    "max_creates",
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _count(value: int) -> bool:
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class SearchBudget:
    """Immutable read of the existing budget, including outstanding reservations.

    Capture must be made at a quiescent coordinator boundary. The existing lock
    protects both counters and reservations. Private counters are read here because
    snapshot() intentionally exposes neither reservations nor endpoint counters.
    Nothing is allocated, released, or consumed by this adapter.
    """

    limits: tuple[int, ...]
    consumed: tuple[int, ...]  # total, cross-object, privilege, creates
    reserved: tuple[int, ...]
    endpoints: tuple[tuple[str, int, int], ...]  # hashed key, spent, reserved
    permissions: tuple[bool, bool]

    def __post_init__(self) -> None:
        if (
            type(self.limits) is not tuple
            or len(self.limits) != 5
            or type(self.consumed) is not tuple
            or len(self.consumed) != 4
            or type(self.reserved) is not tuple
            or len(self.reserved) != 4
            or any(
                not _count(x) for x in (*self.limits, *self.consumed, *self.reserved)
            )
            or type(self.permissions) is not tuple
            or len(self.permissions) != 2
            or any(type(x) is not bool for x in self.permissions)
            or type(self.endpoints) is not tuple
            or self.endpoints != tuple(sorted(self.endpoints))
            or len({x[0] for x in self.endpoints}) != len(self.endpoints)
            or any(
                type(x) is not tuple
                or len(x) != 3
                or not _count(x[1])
                or not _count(x[2])
                for x in self.endpoints
            )
            or any(
                re.fullmatch(r"experiment_endpoint_key:[0-9a-f]{64}", x[0]) is None
                for x in self.endpoints
            )
            or sum(x[1] for x in self.endpoints) != self.consumed[0]
            or sum(x[2] for x in self.endpoints) != self.reserved[0]
            or any(x > self.consumed[0] for x in self.consumed[1:])
            or any(x > self.reserved[0] for x in self.reserved[1:])
        ):
            raise ValueError("invalid search budget snapshot")

    @classmethod
    def capture(cls, budget: ProofBudget) -> SearchBudget:
        if type(budget) is not ProofBudget:
            raise TypeError("an existing ProofBudget is required")
        with budget._lock:
            total, endpoints, cross, privilege, creates = budget._reserved_counts()
            return cls(
                tuple(getattr(budget, key) for key in _LIMITS),
                (budget._total, budget._cross, budget._priv, budget._creates),
                (total, cross, privilege, creates),
                tuple(
                    sorted(
                        (
                            stable_hash("experiment_endpoint_key", key),
                            budget._per_endpoint.get(key, 0),
                            endpoints.get(key, 0),
                        )
                        for key in set(budget._per_endpoint) | set(endpoints)
                    )
                ),
                (budget.allow_delete, budget.allow_real_user_data_access),
            )

    @property
    def remaining(self) -> int:
        return max(0, self.limits[0] - self.consumed[0] - self.reserved[0])

    def to_dict(self) -> dict[str, Any]:
        return {
            "limits": dict(zip(_LIMITS, self.limits, strict=True)),
            "consumed": list(self.consumed),
            "reserved": list(self.reserved),
            "endpoints": [list(x) for x in self.endpoints],
            "permissions": list(self.permissions),
            "remaining": self.remaining,
        }

    def require_continuation_of(self, previous: SearchBudget) -> None:
        if (
            any(a > b for a, b in zip(self.limits, previous.limits, strict=True))
            or any(a < b for a, b in zip(self.consumed, previous.consumed, strict=True))
            or any(
                a and not b
                for a, b in zip(self.permissions, previous.permissions, strict=True)
            )
            or self.remaining > previous.remaining
        ):
            raise ValueError("replanning cannot raise budget or widen authority")
        old = {key: count for key, count, _ in previous.endpoints}
        new = {key: count for key, count, _ in self.endpoints}
        if any(new.get(key, 0) < count for key, count in old.items()):
            raise ValueError("replanning cannot forget consumed endpoint budget")


@dataclass(frozen=True)
class HighValueSinkLedger:
    """Exact intersection of R1 admissible A-D goals and selected-world R2 facts.

    R1/R2 state is retained to make every signal reproducible. The content address
    binds the full input snapshots; entries cannot be appended independently.
    """

    payout_plan: PayoutGoalPlan
    catalog: TargetSemanticCatalog

    def __post_init__(self) -> None:
        if (
            type(self.payout_plan) is not PayoutGoalPlan
            or type(self.catalog) is not TargetSemanticCatalog
        ):
            raise TypeError("R1 plan and R2 semantic catalog are required")
        self.payout_plan.__post_init__()
        self.catalog.__post_init__()
        context = self.payout_plan.context
        context.__post_init__()
        if (
            len(self.payout_plan.candidates) > 128
            or len(self.catalog.operations) > 8192
        ):
            raise ValueError("bounded search input limit exceeded")
        if self.payout_plan.target_ref != self.catalog.target_ref:
            raise ValueError("R1/R2 target mismatch")
        if self.payout_plan.status == "ready" and (
            not context.authorization_approved
            or not context.origin_authorized
            or context.selected_world_ref not in context.owned_world_refs
        ):
            raise ValueError("R1 authorization context is not admitted")
        for candidate in self.payout_plan.candidates:
            candidate.__post_init__()
            candidate.goal.__post_init__()
            candidate.world_requirement.__post_init__()
            if candidate.status == "admissible" and _candidate_blockers(
                context=context,
                requirement=candidate.world_requirement,
                backend=candidate.backend,
                operation_observed=True,
            ):
                raise ValueError("candidate does not satisfy its R1 authority context")

    @property
    def candidates(self):
        if self.payout_plan.status != "ready":
            return ()
        operations = self.operations
        return tuple(
            sorted(
                (
                    x
                    for x in self.payout_plan.candidates
                    if x.status == "admissible"
                    and x.goal.security_property in _FAMILIES
                    and x.goal.terminal_operation_id in operations
                    and operations[x.goal.terminal_operation_id].observed_success
                ),
                key=lambda x: x.candidate_id,
            )
        )

    @property
    def operations(self):
        values = self.catalog.planner_operations(
            world_ref=self.payout_plan.context.selected_world_ref,
        )
        if len({x.operation_id for x in values}) != len(values):
            raise ValueError("ambiguous R2 operation projection")
        return {x.operation_id: x for x in values}

    @property
    def candidate_ids(self) -> tuple[str, ...]:
        return tuple(x.candidate_id for x in self.candidates)

    @property
    def ledger_id(self) -> str:
        return stable_hash("high_value_sink_ledger", self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "payout_plan": self.payout_plan.to_dict(),
            "catalog": self.catalog.to_dict(),
            "admitted_candidate_ids": list(self.candidate_ids),
        }

    def require_candidate(self, candidate_id: str):
        for candidate in self.candidates:
            if candidate.candidate_id == candidate_id:
                return candidate
        raise ValueError("non-admitted candidate refused")

    def _derive_frontier_candidate(
        self,
        manifest: ProofExperimentManifest,
    ) -> PayoutGoalCandidate:
        matches = tuple(
            candidate
            for candidate in self.candidates
            if SecurityWitnessGoal.derived_goal_id(
                base=candidate.goal,
                evidence_refs=manifest.backend.source_evidence_refs,
            )
            == manifest.goal_id
        )
        if len(matches) != 1:
            raise ValueError(
                "manifest does not derive from exactly one admitted candidate"
            )
        return matches[0]


@dataclass(frozen=True)
class RecordedSearchExecution:
    """A detached, immutable read of an existing SDK manifest and terminal receipt.

    The first adapter covers the existing R4 authorization receipt contract. Other
    family receipts are not guessed: without a supported bound record they cannot
    be reported as proved. The scheduler neither writes nor completes a receipt.
    """

    manifest: ProofExperimentManifest
    receipt_json: str
    accepted_kinds: frozenset[str] = field(
        default=frozenset({"proof_experiment_authorization"}),
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.manifest) is not ProofExperimentManifest:
            raise TypeError("existing experiment manifest required")
        if (
            type(self.accepted_kinds) is not frozenset
            or not self.accepted_kinds
            or any(type(item) is not str or not item for item in self.accepted_kinds)
        ):
            raise TypeError("accepted receipt kinds must be a non-empty frozenset")
        self.manifest.__post_init__()
        value = json.loads(self.receipt_json)
        receipt = BehavioralExecutionReceipt.from_dict(value)
        outcome = receipt.outcome
        if (
            self.receipt_json != _json(receipt.to_dict())
            or receipt.state != COMPLETED
            or outcome is None
            or outcome.get("kind") not in self.accepted_kinds
            or outcome["manifest_id"] != self.manifest.manifest_id
            or outcome["oracle_id"] != self.manifest.oracle.oracle_id
            or outcome["backend_receipt_ref"]
            != stable_hash("behavioral_receipt", receipt.receipt_id)
            or outcome["requests_sent"] > self.manifest.budget.total_request_units
            or receipt.context.target_ref
            != self.manifest.target_ref.replace(
                "security_obligation_target:", "behavioral_receipt_target:", 1
            )
            or {receipt.context.source_persona_ref, receipt.context.peer_persona_ref}
            != {
                x.world_ref.replace("world:", "behavioral_receipt_persona:", 1)
                for x in self.manifest.world_manifest.bindings
            }
        ):
            raise ValueError("execution receipt does not bind the manifest")
        evaluation = ExperimentOracleEvaluation.build(
            manifest=self.manifest,
            verdict=OracleVerdict(outcome["oracle_verdict"]),
            backend_receipt_ref=outcome["backend_receipt_ref"],
            control_evidence_refs=outcome["control_evidence_refs"],
            treatment_evidence_refs=outcome["treatment_evidence_refs"],
            witness_evidence_refs=outcome["witness_evidence_refs"],
            cleanup_evidence_refs=(),
            provenance_root=outcome["provenance_root"],
            cleanup_outcome=CleanupOutcome.NOT_REQUIRED,
            uncertainty_reasons=outcome["uncertainty_reasons"],
        )
        if evaluation.evaluation_id != outcome["evaluation_id"]:
            raise ValueError("execution oracle content address mismatch")

    @classmethod
    def capture(
        cls, manifest: ProofExperimentManifest, receipt: BehavioralExecutionReceipt
    ):
        return cls(manifest, _json(receipt.to_dict()))

    @property
    def outcome(self) -> dict[str, Any]:
        return json.loads(self.receipt_json)["outcome"]

    @property
    def record_id(self) -> str:
        return stable_hash("search_execution", self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "receipt": json.loads(self.receipt_json),
        }


@dataclass(frozen=True)
class SearchProof:
    """Read-only bound cost of an existing complete experiment, never a lease."""

    manifest: ProofExperimentManifest
    bindings: tuple[ExperimentRuntimeActionBinding, ...] = field(repr=False)

    def __post_init__(self) -> None:
        self.manifest.__post_init__()
        if type(self.bindings) is not tuple or len(self.bindings) != len(
            self.manifest.actions
        ):
            raise ValueError("complete proof budget bindings required")
        for action, binding in zip(self.manifest.actions, self.bindings, strict=True):
            if type(binding) is not ExperimentRuntimeActionBinding:
                raise TypeError("existing runtime action binding required")
            binding.__post_init__()
            if any(
                getattr(action, key) != getattr(binding, key)
                for key in (
                    "action_id",
                    "ordinal",
                    "phase",
                    "action_class",
                    "endpoint_ref",
                    "world_binding_id",
                )
            ):
                raise ValueError("proof budget action binding mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "bindings": [x.to_dict() for x in self.bindings],
        }


@dataclass(frozen=True)
class SearchSignals:
    payout_relevance: int
    reachability_gain: int
    information_gain: int
    proof_cost: int
    remaining_budget: int
    cleanup_risk: int

    @property
    def marginal_value(self) -> Fraction:
        # Exact rational arithmetic, no platform-dependent float ties. Scarcity
        # penalizes larger paths as the existing total request budget runs down.
        benefit = self.payout_relevance + self.reachability_gain + self.information_gain
        return Fraction(
            benefit * self.remaining_budget,
            self.proof_cost
            * (1 + self.cleanup_risk)
            * (self.remaining_budget + self.proof_cost),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **vars(self),
            "marginal_value": [
                self.marginal_value.numerator,
                self.marginal_value.denominator,
            ],
        }


@dataclass(frozen=True)
class SearchCoverageEntry:
    candidate_id: str
    family: str
    status: str
    reason: str
    evidence_refs: tuple[str, ...]
    signals: SearchSignals
    oracle_verdict: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            **vars(self),
            "evidence_refs": list(self.evidence_refs),
            "signals": self.signals.to_dict(),
        }


@dataclass(frozen=True)
class SearchPlan:
    """Validated immutable plan and certificate over a recorded input snapshot."""

    ledger: HighValueSinkLedger
    constraints: ConstraintLedger
    budget: SearchBudget
    executions: tuple[RecordedSearchExecution, ...] = ()
    enabled: bool = False
    constraints_valid: bool = True
    proofs: tuple[SearchProof, ...] = ()
    compiler_limits: CompilerLimits = CompilerLimits()
    derivation_binding: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.ledger) is not HighValueSinkLedger
            or type(self.constraints) is not ConstraintLedger
            or type(self.budget) is not SearchBudget
            or type(self.executions) is not tuple
            or type(self.proofs) is not tuple
            or type(self.compiler_limits) is not CompilerLimits
            or type(self.enabled) is not bool
            or type(self.constraints_valid) is not bool
            or type(self.derivation_binding) is not bool
        ):
            raise TypeError("invalid search inputs")
        self.ledger.__post_init__()
        self.constraints.__post_init__()
        self.budget.__post_init__()
        self.compiler_limits.__post_init__()
        proof_ids = set()
        for proof in self.proofs:
            proof.__post_init__()
            self._validate_manifest(proof.manifest)
            proof_candidate = self._candidate_for_manifest(proof.manifest)
            world_identities = {
                world.binding_id: world.world_ref.replace(
                    "world:", "experiment_runtime_identity:", 1
                )
                for world in proof.manifest.world_manifest.bindings
            }
            for binding in proof.bindings:
                action = proof.manifest.actions[binding.ordinal]
                operation = self.ledger.operations[action.operation_id]
                methods = {
                    x.method
                    for x in self.ledger.catalog.operations
                    if x.action_id == action.operation_id
                    and x.world_ref
                    == self.ledger.payout_plan.context.selected_world_ref
                }
                if methods != {binding.method} or (
                    operation.safety is OperationSafety.READ_ONLY
                    and binding.action_class.value
                    not in {"SAFE_READ", "CROSS_OBJECT_READ", "AUTHZ_PROBE"}
                ):
                    raise ValueError(
                        "proof action class or method widens admitted operation"
                    )
                # Both typed hashes commit to the same raw identity string under
                # stable_hash; no credential or identity is recovered or created.
                if (
                    binding.actor_identity_ref
                    != world_identities.get(binding.world_binding_id)
                    or (
                        binding.target_owner_identity_ref is not None
                        and binding.target_owner_identity_ref
                        not in world_identities.values()
                    )
                    or (
                        binding.action_class.value == "CROSS_OBJECT_READ"
                        and (
                            binding.target_owner_identity_ref is None
                            or binding.target_owner_identity_ref
                            == binding.actor_identity_ref
                        )
                    )
                ):
                    raise ValueError(
                        "proof runtime identity is outside admitted worlds"
                    )
                origins = []
                for scheme in ("http", "https"):
                    url = f"{scheme}://{binding.endpoint_key}"
                    origin = _canonical_origin(url)
                    if (
                        stable_hash("security_obligation_target", origin)
                        == self.ledger.payout_plan.target_ref
                        and experiment_endpoint_ref(binding.method, url)
                        == binding.endpoint_ref
                    ):
                        origins.append(origin)
                if len(origins) != 1:
                    raise ValueError(
                        "proof endpoint is outside admitted origin or budget bucket"
                    )
            proof_candidate_id = (
                proof_candidate.candidate_id
                if self.derivation_binding
                else proof.manifest.candidate_id
            )
            if proof_candidate_id in proof_ids:
                raise ValueError("duplicate candidate proof")
            proof_ids.add(proof_candidate_id)
        if len(self.executions) > len(self.ledger.candidates) or len(self.proofs) > len(
            self.ledger.candidates
        ):
            raise ValueError("execution set exceeds admitted frontier")
        ids, receipts = set(), set()
        for record in self.executions:
            record.__post_init__()
            manifest = record.manifest
            candidate = self._candidate_for_manifest(manifest)
            self._validate_manifest(manifest)
            receipt_id = json.loads(record.receipt_json)["receipt_id"]
            execution_candidate_id = (
                candidate.candidate_id
                if self.derivation_binding
                else manifest.candidate_id
            )
            if execution_candidate_id in ids or receipt_id in receipts:
                raise ValueError("duplicate candidate execution or receipt")
            ids.add(execution_candidate_id)
            receipts.add(receipt_id)
            worlds = {x.world_ref for x in manifest.world_manifest.bindings}
            if (
                (
                    not self.derivation_binding
                    and manifest.goal_id != candidate.goal.goal_id
                )
                or manifest.target_ref != self.ledger.payout_plan.target_ref
                or not worlds <= set(self.ledger.payout_plan.context.owned_world_refs)
                or candidate.goal.security_property
                is not SecurityProperty.OBJECT_AUTHORIZATION
                or any(
                    x.operation_id != candidate.goal.terminal_operation_id
                    for x in manifest.actions
                )
            ):
                raise ValueError("execution is outside admitted candidate authority")
        if (
            sum(x.outcome["requests_sent"] for x in self.executions)
            > self.budget.consumed[0]
        ):
            raise ValueError("execution evidence exceeds recorded consumed budget")

    def _candidate_for_manifest(
        self,
        manifest: ProofExperimentManifest,
    ) -> PayoutGoalCandidate:
        if self.derivation_binding:
            return self.ledger._derive_frontier_candidate(manifest)
        return self.ledger.require_candidate(manifest.candidate_id)

    def _validate_manifest(self, manifest: ProofExperimentManifest) -> None:
        candidate = self._candidate_for_manifest(manifest)
        if (
            (
                not self.derivation_binding
                and manifest.goal_id != candidate.goal.goal_id
            )
            or manifest.target_ref != self.ledger.payout_plan.target_ref
            or manifest.world_manifest.requirement != candidate.world_requirement
            or manifest.backend.backend.value != candidate.backend
            or manifest.oracle.security_property != candidate.goal.security_property
            or manifest.oracle.witness_requirements
            != candidate.goal.witness_requirements
            or (
                not self.derivation_binding
                and not set(manifest.backend.source_evidence_refs)
                & set(candidate.goal.evidence_refs)
            )
            or not {x.world_ref for x in manifest.world_manifest.bindings}
            <= set(self.ledger.payout_plan.context.owned_world_refs)
            or not {x.operation_id for x in manifest.actions}
            <= {x.goal.terminal_operation_id for x in self.ledger.candidates}
        ):
            raise ValueError("proof manifest is outside admitted candidate authority")

    @property
    def entries(self) -> tuple[SearchCoverageEntry, ...]:
        operations = self.ledger.operations
        candidates = self.ledger.candidates
        # R3 may use only operations attached to this admitted frontier. Catalog
        # membership alone never lets it add a prerequisite operation to authority.
        admitted_operations = tuple(
            operations[key]
            for key in sorted({x.goal.terminal_operation_id for x in candidates})
        )
        replanner = ConstraintReplanner(
            admitted_operations, compiler_limits=self.compiler_limits
        )
        if self.derivation_binding:
            records = {
                self._candidate_for_manifest(item.manifest).candidate_id: item
                for item in self.executions
            }
            proofs = {
                self._candidate_for_manifest(item.manifest).candidate_id: item
                for item in self.proofs
            }
        else:
            records = {x.manifest.candidate_id: x for x in self.executions}
            proofs = {x.manifest.candidate_id: x for x in self.proofs}
        entries = []
        for candidate in candidates:
            record = records.get(candidate.candidate_id)
            proof = proofs.get(candidate.candidate_id)
            operation = operations[candidate.goal.terminal_operation_id]
            result = None
            if self.enabled and self.constraints_valid:
                result = replanner.compile_witness(
                    candidate.goal, ledger=self.constraints
                )
            steps = (
                tuple(operations[key] for key in result.plan.step_ids) if result else ()
            )
            cost = max(1, sum(x.cost for x in steps) or operation.cost)
            if proof:
                cost = proof.manifest.budget.total_request_units
            reachability = len({cap.key for x in steps for cap in x.produces})
            information = len(candidate.goal.witness_requirements) + sum(
                x.operation_id == operation.operation_id
                for x in self.constraints.hypotheses
            )
            cleanup_risk = sum(x.safety is not OperationSafety.READ_ONLY for x in steps)
            if not steps:
                cleanup_risk = int(operation.safety is not OperationSafety.READ_ONLY)
            signals = SearchSignals(
                candidate.goal.impact_weight,
                reachability,
                information,
                cost,
                self.budget.remaining,
                cleanup_risk,
            )
            status, reason, refs, verdict = "never_explored", "unattempted", (), None
            if record:
                outcome = record.outcome
                verdict = outcome["oracle_verdict"]
                status = "proved" if verdict == "confirmed" else "blocked"
                reason = "recorded_oracle_" + verdict
                refs = (record.record_id, outcome["evaluation_id"])
            elif not self.enabled:
                reason = "planning_disabled"
            elif not self.constraints_valid:
                status, reason = "blocked", "constraints_invalidated"
            elif result.plan.search_exhausted:
                status, reason = "exhausted", "r3_search_exhausted"
                refs = (result.result_id,)
            elif result.status != "ready":
                status, reason = "blocked", "r3_constraints_blocked"
                refs = (result.result_id,)
            elif proof and any(
                x.operation_id
                in {action.operation_id for action in proof.manifest.actions}
                for x in self.constraints.facts
            ):
                # A constraint change on this proof's actions requires a newly
                # admitted proof in a separate run; retaining the old budget does
                # not demonstrate that its old sequence satisfies the new fact.
                status, reason = "blocked", "proof_constraints_changed"
                refs = (result.result_id,)
            elif proof is None:
                reason = "proof_budget_unavailable"
            elif cost > self.budget.remaining:
                reason = "remaining_budget_insufficient"
            entries.append(
                SearchCoverageEntry(
                    candidate.candidate_id,
                    _FAMILIES[candidate.goal.security_property],
                    status,
                    reason,
                    tuple(sorted(refs)),
                    signals,
                    verdict,
                )
            )
        return tuple(entries)

    @property
    def ordering(self) -> tuple[str, ...]:
        if not self.enabled or not self.constraints_valid:
            return ()
        frontier = sorted(
            (
                x
                for x in self.entries
                if x.status == "never_explored"
                and x.reason != "proof_budget_unavailable"
            ),
            key=lambda x: (-x.signals.marginal_value, x.candidate_id),
        )
        counts = [
            a + b
            for a, b in zip(self.budget.consumed, self.budget.reserved, strict=True)
        ]
        endpoints = {
            key: spent + reserved for key, spent, reserved in self.budget.endpoints
        }
        if self.derivation_binding:
            proofs = {
                self._candidate_for_manifest(item.manifest).candidate_id: item
                for item in self.proofs
            }
        else:
            proofs = {x.manifest.candidate_id: x for x in self.proofs}
        ordered = []
        for item in frontier:
            proof = proofs[item.candidate_id]
            proposed = counts.copy()
            proposed_endpoints = endpoints.copy()
            for binding in proof.bindings:
                proposed[0] += 1
                index = {
                    "CROSS_OBJECT_READ": 1,
                    "PRIVILEGE_MUTATION": 2,
                    "OWNED_CREATE": 3,
                }.get(binding.action_class.value)
                if index is not None:
                    proposed[index] += 1
                key = stable_hash("experiment_endpoint_key", binding.endpoint_key)
                proposed_endpoints[key] = proposed_endpoints.get(key, 0) + 1
            limits = (self.budget.limits[0], *self.budget.limits[2:])
            if all(
                count <= limit for count, limit in zip(proposed, limits, strict=True)
            ) and all(
                count <= self.budget.limits[1] for count in proposed_endpoints.values()
            ):
                ordered.append(item.candidate_id)
                counts, endpoints = proposed, proposed_endpoints
        return tuple(ordered)

    def input_dict(self) -> dict[str, Any]:
        payload = {
            "ledger": self.ledger.to_dict(),
            "constraints": self.constraints.to_dict(),
            "budget": self.budget.to_dict(),
            "enabled": self.enabled,
            "constraints_valid": self.constraints_valid,
            "proofs": [x.to_dict() for x in self.proofs],
            "compiler_limits": vars(self.compiler_limits),
            "executions": [x.to_dict() for x in self.executions],
        }
        if self.derivation_binding:
            payload["derivation_binding"] = True
        return payload

    @property
    def input_id(self) -> str:
        return stable_hash("search_inputs", self.input_dict())

    def _certificate_payload(self) -> dict[str, Any]:
        entries, ordering = self.entries, self.ordering
        if not self.enabled:
            reason = "planning_disabled"
        elif not self.constraints_valid:
            reason = "constraints_invalidated"
        elif ordering:
            reason = "frontier_remaining"
        elif any(x.reason == "proof_budget_unavailable" for x in entries):
            reason = "proof_budget_unavailable"
        elif any(x.status == "never_explored" for x in entries):
            reason = "budget_exhausted"
        else:
            reason = "frontier_exhausted"
        payload = {
            "schema_version": 1,
            "mode": SEARCH_STOPPING_MODE,
            "phase_id": "OCB-R6",
            "exit_gate": "OCB-S18",
            "input_id": self.input_id,
            "ledger_id": self.ledger.ledger_id,
            "constraint_ledger_id": self.constraints.ledger_id,
            "stop_reason": reason,
            "frontier_order": list(ordering),
            "admitted_candidate_ids": list(self.ledger.candidate_ids),
            "families": {
                family: {
                    status: [
                        x.candidate_id
                        for x in entries
                        if x.family == family and x.status == status
                    ]
                    for status in ("proved", "blocked", "exhausted", "never_explored")
                }
                for family in ("A", "B", "C", "D")
            },
            "entries": [x.to_dict() for x in entries],
            "budget": self.budget.to_dict(),
            "planned_cost_units": sum(
                x.signals.proof_cost for x in entries if x.candidate_id in ordering
            ),
            "budget_consumed_requests": self.budget.consumed[0],
            "planner_requests_sent": 0,
            "execution_authority": False,
            "finding_authority": False,
            "persistence": "none",
            "cleanup": "not_required_no_planner_state",
            "orphan_risk": False,
        }
        return payload

    def certificate(self) -> SearchStopCertificate:
        payload = self._certificate_payload()
        return SearchStopCertificate(
            _json(payload), stable_hash("search_stop_certificate", payload), self
        )


@dataclass(frozen=True)
class SearchStopCertificate:
    """Canonical immutable bytes plus SHA-256; verify against retained inputs.

    A hash is integrity, not an oracle or acceptance authority. verify(plan) also
    recomputes the entire partition from inputs, rejecting even rehashed lies.
    """

    payload_json: str
    certificate_id: str
    _plan: SearchPlan = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        payload = json.loads(self.payload_json)
        if self.payload_json != _json(payload) or self.certificate_id != stable_hash(
            "search_stop_certificate", payload
        ):
            raise ValueError("stop certificate content address mismatch")
        self._plan.__post_init__()
        if payload != self._plan._certificate_payload():
            raise ValueError("stop certificate claims do not match recorded inputs")

    def to_dict(self) -> dict[str, Any]:
        return {"certificate_id": self.certificate_id, **json.loads(self.payload_json)}

    def verify(self, plan: SearchPlan) -> bool:
        plan.__post_init__()
        return self == plan.certificate()


class MarginalValueScheduler:
    """Explicit-only, default-off ordering; no dispatch or live entry point."""

    def plan(
        self,
        *,
        ledger: HighValueSinkLedger,
        constraints: ConstraintLedger,
        budget: SearchBudget,
        enabled: bool = False,
        constraints_valid: bool = True,
        executions: tuple[RecordedSearchExecution, ...] = (),
        proofs: tuple[SearchProof, ...] = (),
        compiler_limits: CompilerLimits = CompilerLimits(),
        derivation_binding: bool = False,
        previous: SearchPlan | None = None,
    ) -> SearchPlan:
        result = SearchPlan(
            ledger,
            constraints,
            budget,
            tuple(sorted(executions, key=lambda x: x.record_id)),
            enabled,
            constraints_valid,
            tuple(sorted(proofs, key=lambda x: x.manifest.candidate_id)),
            compiler_limits,
            derivation_binding,
        )
        if previous is not None:
            previous.__post_init__()
            if ledger.ledger_id != previous.ledger.ledger_id:
                raise ValueError("replanning cannot change admitted authority")
            if derivation_binding != previous.derivation_binding:
                raise ValueError("replanning cannot change derivation binding")
            budget.require_continuation_of(previous.budget)
            if result.proofs != previous.proofs or any(
                getattr(compiler_limits, key) > value
                for key, value in vars(previous.compiler_limits).items()
            ):
                raise ValueError("replanning cannot widen proof or search budget")
            if not previous.constraints_valid and constraints_valid:
                raise ValueError(
                    "invalidated constraints cannot regain authority in this run"
                )
            if not {x.assertion_id for x in previous.constraints.facts} <= {
                x.assertion_id for x in constraints.facts
            } or not set(previous.constraints.blockers) <= set(constraints.blockers):
                raise ValueError("stale constraints cannot forget facts or blockers")
            if not {x.record_id for x in previous.executions} <= {
                x.record_id for x in executions
            }:
                raise ValueError("replanning cannot forget recorded executions")
        return result
