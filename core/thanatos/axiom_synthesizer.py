from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List

from .models import (
    BreachHypothesis,
    InvariantClass,
    InvariantDomain,
    LogicTestCase,
    MutationOpType,
    MutationSpec,
    OracleSpec,
    TargetHandle,
)


def _stable_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"|")
    return h.hexdigest()[:16]


@dataclass
class StandardAxiomSynthesizer:
    """
    Produces invariant-driven testcases for a given high-value target.
    No raw HTTP payloads. No “invented verbs.” No byte-level injection.
    """

    def synthesize(self, target: TargetHandle) -> List[LogicTestCase]:
        endpoint = target.endpoint.lower()

        cases: List[LogicTestCase] = []

        # Heuristic: payment-ish endpoints get money invariants
        if "pay" in endpoint or "charge" in endpoint or "refund" in endpoint:
            cases.extend(self._payment_invariants(target))

        # Generic authz boundary checks for high-value nodes
        cases.extend(self._authz_invariants(target))

        # Generic state-machine checks (if tagged as stateful)
        if "stateful" in target.tags or "workflow" in target.tags:
            cases.extend(self._state_machine_invariants(target))

        return cases

    def _payment_invariants(self, target: TargetHandle) -> List[LogicTestCase]:
        now = int(time.time())
        base_priority = min(1.0, target.value / 10.0)

        out: List[LogicTestCase] = []

        # NON_NEGATIVE_AMOUNT
        out.append(
            LogicTestCase(
                id=_stable_id(target.node_id, target.method, target.endpoint, "NON_NEGATIVE_AMOUNT", "SET_NUMERIC_BELOW_MIN"),
                target=target,
                hypothesis=BreachHypothesis(
                    invariant=InvariantClass.NON_NEGATIVE_AMOUNT,
                    domain=InvariantDomain.ECONOMIC,
                    rationale="Monetary amounts must not be negative; negative values can invert debit/credit semantics.",
                    required_signals=["ledger_delta", "account_balance_change", "authz_decision"],
                ),
                mutation=MutationSpec(
                    op=MutationOpType.SET_NUMERIC_BELOW_MIN,
                    params={"field": "amount", "min": 0, "strategy": "boundary_below_min"},
                ),
                oracle=OracleSpec(
                    name="no_negative_amount_applied",
                    expected={"result": "rejected_or_no_effect"},
                    forbidden={"signals": ["ledger_delta_nonzero", "balance_decrease_without_authorization"]},
                    notes="A 200 OK is not success; require ledger/balance invariants from harness signals.",
                ),
                priority=0.85 * base_priority,
                provenance={"synth": "StandardAxiomSynthesizer", "ts": now},
            )
        )

        # IDEMPOTENCY
        out.append(
            LogicTestCase(
                id=_stable_id(target.node_id, target.method, target.endpoint, "IDEMPOTENCY", "DUPLICATE_IDEMPOTENCY_KEY"),
                target=target,
                hypothesis=BreachHypothesis(
                    invariant=InvariantClass.IDEMPOTENCY,
                    domain=InvariantDomain.STATE,
                    rationale="Duplicate submissions must not double-apply economic effects.",
                    required_signals=["ledger_delta", "idempotency_key_seen", "state_change"],
                ),
                mutation=MutationSpec(
                    op=MutationOpType.DUPLICATE_IDEMPOTENCY_KEY,
                    params={"header": "Idempotency-Key", "strategy": "replay_same_key"},
                ),
                oracle=OracleSpec(
                    name="no_double_apply",
                    expected={"ledger_effect": "at_most_once"},
                    forbidden={"signals": ["double_charge_detected", "duplicate_ledger_entry"]},
                    notes="Harness should compare ledger effects across two executions with same idempotency key.",
                ),
                priority=0.95 * base_priority,
                provenance={"synth": "StandardAxiomSynthesizer", "ts": now},
            )
        )

        # CONSERVATION_OF_VALUE
        out.append(
            LogicTestCase(
                id=_stable_id(target.node_id, target.method, target.endpoint, "CONSERVATION_OF_VALUE", "REPLAY_PREVIOUS_REQUEST"),
                target=target,
                hypothesis=BreachHypothesis(
                    invariant=InvariantClass.CONSERVATION_OF_VALUE,
                    domain=InvariantDomain.ECONOMIC,
                    rationale="Economic effects must conserve value across accounts and not create/destroy funds via replay/timing.",
                    required_signals=["ledger_entries", "ledger_delta", "audit_trail"],
                ),
                mutation=MutationSpec(
                    op=MutationOpType.REPLAY_PREVIOUS_REQUEST,
                    params={"strategy": "replay_with_time_skew", "max_replays": 2},
                ),
                oracle=OracleSpec(
                    name="ledger_conserves_value",
                    expected={"sum_debits_equals_sum_credits": True},
                    forbidden={"signals": ["net_value_created", "net_value_destroyed"]},
                    notes="Harness must compute conservation across ledger entries, not trust response body.",
                ),
                priority=0.75 * base_priority,
                provenance={"synth": "StandardAxiomSynthesizer", "ts": now},
            )
        )

        return out

    def _authz_invariants(self, target: TargetHandle) -> List[LogicTestCase]:
        now = int(time.time())
        base_priority = min(1.0, target.value / 10.0)

        cases = []
        
        # AUTHZ_BOUNDARY
        cases.append(
            LogicTestCase(
                id=_stable_id(target.node_id, target.method, target.endpoint, "AUTHZ_BOUNDARY", "REMOVE_REQUIRED_FIELD"),
                target=target,
                hypothesis=BreachHypothesis(
                    invariant=InvariantClass.AUTHZ_BOUNDARY,
                    domain=InvariantDomain.AUTHZ,
                    rationale="Authorization should not be bypassable by omitting or altering identity binding inputs.",
                    required_signals=["authz_decision", "principal", "policy_rule_id"],
                ),
                mutation=MutationSpec(
                    op=MutationOpType.REMOVE_REQUIRED_FIELD,
                    params={"field": "actor_id", "strategy": "remove_identity_binding_field"},
                ),
                oracle=OracleSpec(
                    name="authz_enforced",
                    expected={"authz": "deny_or_requires_principal"},
                    forbidden={"signals": ["authz_allow_without_principal"]},
                    notes="Harness should expose authz decision + principal binding; HTTP status alone is insufficient.",
                ),
                priority=0.65 * base_priority,
                provenance={"synth": "StandardAxiomSynthesizer", "ts": now},
            )
        )
        
        # AUTHZ_EFFECT_SCOPE (New)
        cases.append(
            LogicTestCase(
                id=_stable_id(target.node_id, target.method, target.endpoint, "AUTHZ_EFFECT_SCOPE", "CROSS_TENANT_REFERENCE"),
                target=target,
                hypothesis=BreachHypothesis(
                    invariant=InvariantClass.AUTHZ_EFFECT_SCOPE,
                    domain=InvariantDomain.AUTHZ,
                    rationale="Authorized actions must not produce effects outside the caller's permission scope (e.g. cross-tenant refund).",
                    required_signals=["authz_scope", "effect_target_id"],
                ),
                mutation=MutationSpec(
                    op=MutationOpType.CROSS_TENANT_REFERENCE,
                    params={"strategy": "substitute_resource_id", "target_type": "cross_tenant"},
                ),
                oracle=OracleSpec(
                    name="effect_scoped_to_caller",
                    expected={"effect": "blocked_or_scoped"},
                    forbidden={"signals": ["cross_tenant_write", "elevation_of_privilege"]},
                    fallbacks=["audit_log_tenant_check"],
                    notes="Verifier must check that the resource ID in the effect matches the caller's tenant/scope context.",
                ),
                priority=0.90 * base_priority,  # High priority: this is a common critical vuln
                provenance={"synth": "StandardAxiomSynthesizer", "ts": now},
            )
        )
        return cases

    def _state_machine_invariants(self, target: TargetHandle) -> List[LogicTestCase]:
        now = int(time.time())
        base_priority = min(1.0, target.value / 10.0)

        return [
            LogicTestCase(
                id=_stable_id(target.node_id, target.method, target.endpoint, "VALID_STATE_TRANSITION", "SWAP_STATE_TRANSITION"),
                target=target,
                hypothesis=BreachHypothesis(
                    invariant=InvariantClass.VALID_STATE_TRANSITION,
                    domain=InvariantDomain.STATE,
                    rationale="Workflows must reject illegal state transitions (e.g., skipping required steps).",
                    required_signals=["state_before", "state_after", "transition_rule_id"],
                ),
                mutation=MutationSpec(
                    op=MutationOpType.SWAP_STATE_TRANSITION,
                    params={"strategy": "jump_forward", "notes": "Attempt a transition not adjacent in the state graph"},
                ),
                oracle=OracleSpec(
                    name="illegal_transition_rejected",
                    expected={"transition": "rejected"},
                    forbidden={"signals": ["state_changed_via_illegal_transition"]},
                    fallbacks=["state_poller"],
                    notes="Harness must validate state graph adjacency, not rely on response strings.",
                ),
                priority=0.7 * base_priority,
                provenance={"synth": "StandardAxiomSynthesizer", "ts": now},
            )
        ]
