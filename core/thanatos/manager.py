from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol

from .axiom_synthesizer import StandardAxiomSynthesizer
from .models import LogicTestCase, TargetHandle
from .ontology_breaker import OntologyBreakerService
from .scope_gate import ScopeGate, ScopePolicy


class EventBus(Protocol):
    async def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        ...


class AegisReader(Protocol):
    """
    Minimal read interface into Aegis.
    Implement this adapter against your actual AegisManager/BusinessModelGraph APIs.
    """
    async def get_high_value_targets(self, min_value: float) -> List[TargetHandle]:
        ...


class TestHarness(Protocol):
    """
    Interface for the execution layer (Pillar VI).
    Designed to prevent execution logic from leaking into generation.
    """
    async def evaluate(self, testcase: LogicTestCase) -> Dict[str, Any]:
        ...


@dataclass
class ThanatosManager:
    """
    Orchestrates Pillar I in a safe, auditable way.
    """
    aegis: AegisReader
    events: EventBus
    min_value: float = 8.0

    def __post_init__(self) -> None:
        # Scope is explicit. Empty allowlists mean “allow nothing” until configured.
        policy = ScopePolicy(
            allowed_node_ids=set(),
            allowed_endpoints=set(),
            allowed_methods=set(),
            allowed_invariants=set(),
            allowed_mutations=set(),
        )
        self.scope_gate = ScopeGate(policy)
        self.breaker = OntologyBreakerService(
            scope_gate=self.scope_gate,
            synthesizer=StandardAxiomSynthesizer(),
        )

    def configure_scope(self, *, node_ids: Iterable[str], endpoints: Iterable[str], methods: Iterable[str],
                        invariants: Iterable[Any], mutations: Iterable[Any]) -> None:
        """
        Explicitly configure allowlists. This should be called from a trusted config loader.
        
        TODO: Make this immutable per-run to prevent race conditions or mid-run scope creep.
        Currently allows updates for interactive REPL tuning.
        """
        # Accept enums or strings for convenience
        inv_set = set(invariants)
        mut_set = set(mutations)

        # If caller passed strings, map later (keep strictness here by expecting correct enum types)
        self.scope_gate.policy.allowed_node_ids = set(node_ids)
        self.scope_gate.policy.allowed_endpoints = set(endpoints)
        self.scope_gate.policy.allowed_methods = {m.upper() for m in methods}
        self.scope_gate.policy.allowed_invariants = inv_set
        self.scope_gate.policy.allowed_mutations = mut_set

    async def generate_for_high_value_targets(self) -> List[LogicTestCase]:
        """
        Pull high-value targets from Aegis and generate safe testcases.
        Emits events for downstream UI/pressure integration.
        """
        targets = await self.aegis.get_high_value_targets(self.min_value)
        all_cases: List[LogicTestCase] = []

        for t in targets:
            cases = self.breaker.hallucinate_batch(t)
            all_cases.extend(cases)

            await self.events.emit(
                "THANATOS_TESTCASES_GENERATED",
                {
                    "target": {
                        "node_id": t.node_id,
                        "endpoint": t.endpoint,
                        "method": t.method,
                        "value": t.value,
                        "tags": list(t.tags),
                    },
                    "count": len(cases),
                    "testcases": [c.to_dict() for c in cases],
                },
            )

        return all_cases
