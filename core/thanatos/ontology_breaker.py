from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from .axiom_synthesizer import StandardAxiomSynthesizer
from .models import InvariantClass, LogicTestCase, MutationOpType, TargetHandle
from .scope_gate import ScopeGate


SAFE_MODE: bool = True  # default ON


@dataclass
class OntologyBreakerService:
    """
    Generates invariant-driven LogicTestCases for high-value targets.
    Does not execute network operations.
    """

    scope_gate: ScopeGate
    synthesizer: StandardAxiomSynthesizer

    def hallucinate_batch(self, target: TargetHandle) -> List[LogicTestCase]:
        """
        Produce a batch of safe testcases for a target, filtered by ScopeGate.
        """
        if not SAFE_MODE:
            # Explicit Fail-Safe. This service should NEVER run with SAFE_MODE off 
            # until we have a real harness that respects it.
            # Even active scanning needs safety rails.
            raise RuntimeError("OntologyBreakerService currently requires SAFE_MODE=True for Logic Generation.")

        candidates = self.synthesizer.synthesize(target)
        out: List[LogicTestCase] = []

        max_allowed = self.scope_gate.policy.max_testcases_per_target

        for tc in candidates:
            # Cardinality Check
            if max_allowed is not None and len(out) >= max_allowed:
                break
                
            inv = tc.hypothesis.invariant
            mut = tc.mutation.op
            # Hard block anything not explicitly allowed
            self.scope_gate.assert_allowed(target, inv, mut)
            out.append(tc)

        return out

