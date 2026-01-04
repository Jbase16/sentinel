from __future__ import annotations

import logging
from typing import List
from dataclasses import dataclass

from .models import TargetHandle, LogicTestCase
from .scope_gate import ScopeGate
from .axiom_synthesizer import MutationEngine

SAFE_MODE = True
MAX_TESTS_PER_TARGET = 5

log = logging.getLogger("thanatos.breaker")

@dataclass
class OntologyBreakerService:
    """
    The High-Level "Planner" for Thanatos.
    Orchestrates the attack generation by combining Scope (Safety) and MutationEngine (Tactics).
    """
    scope_gate: ScopeGate
    synthesizer: MutationEngine

    def generate_mutations(self, target: TargetHandle) -> List[LogicTestCase]:
        """
        Produce a batch of strict, ontology-breaking test cases.
        """
        # 1. Safety Check (Scope Gate)
        # Check against policy allowlist
        if not self.scope_gate.policy.allows_target(target):
            log.warning(f"Thanatos: Target {target.endpoint} out of scope. Rejecting.")
            return []

        # 2. Strict Generation (Mutation Engine)
        cases = self.synthesizer.synthesize(target)
        
        # 3. Safety Check (Volume Cap)
        if SAFE_MODE:
            if len(cases) > MAX_TESTS_PER_TARGET:
                log.info(f"Thanatos: Capping {len(cases)} tests to {MAX_TESTS_PER_TARGET} (SAFE_MODE).")
                cases = cases[:MAX_TESTS_PER_TARGET]
        
        return cases
