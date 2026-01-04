from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Set, Tuple

from .models import InvariantClass, MutationOpType, TargetHandle


@dataclass
class ScopePolicy:
    """
    Hard allowlist. If it isn’t listed, it doesn’t happen.
    """
    allowed_node_ids: Set[str] = field(default_factory=set)
    allowed_endpoints: Set[str] = field(default_factory=set)          # exact match
    allowed_methods: Set[str] = field(default_factory=set)            # e.g., {"GET","POST"}
    allowed_invariants: Set[InvariantClass] = field(default_factory=set)
    allowed_mutations: Set[MutationOpType] = field(default_factory=set)
    max_testcases_per_target: int | None = None  # Cap generation volume

    def allows_target(self, t: TargetHandle) -> bool:
        if self.allowed_node_ids and t.node_id not in self.allowed_node_ids:
            return False
        if self.allowed_endpoints and t.endpoint not in self.allowed_endpoints:
            return False
        if self.allowed_methods and t.method.upper() not in self.allowed_methods:
            return False
        return True

    def allows_case(self, t: TargetHandle, invariant: InvariantClass, mutation: MutationOpType) -> bool:
        if not self.allows_target(t):
            return False
        if self.allowed_invariants and invariant not in self.allowed_invariants:
            return False
        if self.allowed_mutations and mutation not in self.allowed_mutations:
            return False
        return True


class ScopeGate:
    def __init__(self, policy: ScopePolicy):
        self._policy = policy

    @property
    def policy(self) -> ScopePolicy:
        return self._policy

    def assert_allowed(self, target: TargetHandle, invariant: InvariantClass, mutation: MutationOpType) -> None:
        if not self._policy.allows_case(target, invariant, mutation):
            raise PermissionError(
                f"Thanatos ScopeGate blocked testcase: "
                f"{target.method} {target.endpoint} (node={target.node_id}) "
                f"invariant={invariant.value} mutation={mutation.value}"
            )
