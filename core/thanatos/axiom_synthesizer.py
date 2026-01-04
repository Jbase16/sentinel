from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List, Any

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
from .mutations import MutationLibrary


def _stable_id(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8", errors="ignore"))
        h.update(b"|")
    return h.hexdigest()[:16]


@dataclass
class MutationEngine:
    """
    Produces invariant-driven testcases using the new MutationLibrary.
    Replaces the old StandardAxiomSynthesizer.
    """
    library: MutationLibrary = MutationLibrary()

    def synthesize(self, target: TargetHandle) -> List[LogicTestCase]:
        cases: List[LogicTestCase] = []
        now = int(time.time())

        # Construct Context from TargetHandle
        # In a real system, we'd infer schema from OpenApi/Spyder, but for V1 we guess based on endpoint
        context = self._infer_context(target)
        
        # portable mutations from the library
        raw_mutations = self.library.generate_all(context)
        
        for mut in raw_mutations:
            # Map raw Mutation -> LogicTestCase
            # We need to pick a Hypothesis and Oracle for each mutation type
            # This logic mimics the old _xxx_invariants methods but dynamic
            
            hypothesis, oracle = self._derive_hypothesis_and_oracle(mut.op, target)
            
            cases.append(LogicTestCase(
                id=_stable_id(target.node_id, mut.op, mut.description),
                target=target,
                hypothesis=hypothesis,
                mutation=MutationSpec(op=mut.op, params=mut.params),
                oracle=oracle,
                priority=0.8, # Default priority
                provenance={"synth": "MutationEngine", "desc": mut.description, "ts": now}
            ))

        return cases

    def _infer_context(self, target: TargetHandle) -> Dict[str, Any]:
        """
        Infer schema/context from target tags or known profiles.
        """
        context = {"body_schema": {}}
        ep = target.endpoint
        
        # Hardcoded heuristics for V1 (Juice Shop specific)
        if "/login" in ep:
            context["body_schema"] = {"email": "string", "password": "string"}
        elif "/search" in ep:
            context["body_schema"] = {"q": "string"} # usually query param, but for simplicity
        elif "/basket" in ep or "/api/BasketItems" in ep:
             context["body_schema"] = {"ProductId": "int", "BinderId": "int", "quantity": "int"}
             
        return context

    def _derive_hypothesis_and_oracle(self, op: MutationOpType, target: TargetHandle) -> tuple[BreachHypothesis, OracleSpec]:
        """
        Map a basic mutation op to a sophisticated hypothesis/oracle pair.
        """
        if op == MutationOpType.TYPE_JUGGLING:
            return (
                BreachHypothesis(
                    invariant=InvariantClass.DATA, 
                    domain=InvariantDomain.DATA, 
                    rationale="Server should reject invalid types gracefully (400), not crash (500).",
                    required_signals=["http_status"]
                ),
                OracleSpec(
                    name="no_5xx_on_bad_types", 
                    expected={"status_code": 400}, 
                    forbidden={"status_code": 500}
                )
            )
        elif op == MutationOpType.BOUNDARY_VIOLATION:
             return (
                BreachHypothesis(
                    invariant=InvariantClass.NON_NEGATIVE_AMOUNT if "amount" in str(op) else InvariantClass.DATA,
                    domain=InvariantDomain.ECONOMIC if "amount" in str(op) else InvariantDomain.DATA,
                    rationale="Boundary values should be validated.",
                    required_signals=["http_status"]
                ),
                OracleSpec(
                    name="boundary_enforced", 
                    expected={"status_code": 400}, 
                    forbidden={"status_code": 500}
                )
             )
        elif op == MutationOpType.AUTH_CONFUSION:
             return (
                BreachHypothesis(
                    invariant=InvariantClass.AUTHZ_BOUNDARY,
                    domain=InvariantDomain.AUTHZ,
                    rationale="Removing auth headers should deny access.",
                    required_signals=["http_status"]
                ),
                OracleSpec(
                    name="auth_enforced", 
                    expected={"status_code": 401}, 
                    forbidden={"status_code": 200}
                )
             )
        else:
            # Default fallback
             return (
                BreachHypothesis(
                    invariant=InvariantClass.DATA,
                    domain=InvariantDomain.DATA,
                    rationale="Fuzzing should not cause unhandled exceptions.",
                    required_signals=["http_status"]
                ),
                OracleSpec(
                    name="robustness_check", 
                    expected={"status_code": [200, 400, 401, 403, 404]}, 
                    forbidden={"status_code": 500}
                )
             )
