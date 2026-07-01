"""
core/cortex/execution_policy.py

The single gate every active request must pass. Modules never hold a raw HTTP
client — they are handed a `PolicyExecutor.send`, which classifies, scope-checks,
and budget-checks each candidate action before (maybe) delegating to the real
transport. An action the policy denies is never sent; the module sees a synthetic
non-2xx result and moves on.

    decision = policy.evaluate(method, url, body, hint=...)
    if not decision.allowed:
        record_skipped(...) ; return denied
    result = raw_send(...) ; budget.record(...)

Order of checks (all fail closed):
  1. scope   — scheme/host/port/path/method must be in the declared scope
  2. class   — the action's risk class must be allowed in this mode
  3. budget  — the class/endpoint/total budget must not be exhausted
  4. delete  — DELETE is refused unless the budget explicitly allows it

LAB mode allows all classes with an unlimited budget, so the executor is a
transparent pass-through and existing behavior is unchanged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from core.safety.action_classifier import DESTRUCTIVE, classify
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode, rules_for

logger = logging.getLogger(__name__)

# raw transport: (method, url, body, **kw) -> (status, parsed_json)
RawSend = Callable[..., Awaitable[Tuple[int, Any]]]
ScopeFilter = Callable[[str], bool]

DENIED_STATUS = 0   # distinct from any real HTTP code (incl. 401/403 "exists-but-forbidden")


@dataclass
class Decision:
    allowed: bool
    reason: str
    action_class: str


class ExecutionPolicy:
    def __init__(self, mode: str, *, scope_filter: Optional[ScopeFilter] = None,
                 budget: Optional[ProofBudget] = None):
        self.mode = ProofMode.normalize(mode)
        allowed, default_budget = rules_for(self.mode)
        self.allowed = allowed                 # None → all allowed (LAB)
        self.budget = budget or default_budget
        self.scope_filter = scope_filter

    def evaluate(self, method: str, url: str, body: Any = None, *,
                 hint: Optional[str] = None) -> Decision:
        # 1. Scope — never touch anything outside the declared scope.
        if self.scope_filter is not None:
            try:
                in_scope = bool(self.scope_filter(url))
            except Exception:
                in_scope = False
            if not in_scope:
                return Decision(False, "out_of_scope", "SCOPE")

        ac = classify(method, url, body, hint=hint)

        # 2. Class allow-list (None = all allowed in LAB).
        if self.allowed is not None and ac not in self.allowed:
            return Decision(False, f"class_{ac}_denied_in_{self.mode}", ac)

        # 3. DELETE guard — refused unless explicitly permitted.
        if ac == DESTRUCTIVE and not self.budget.allow_delete:
            return Decision(False, "destructive_action_denied", ac)

        # 4. Budget.
        ok, reason = self.budget.allows(ac, endpoint_key(url))
        if not ok:
            return Decision(False, reason, ac)

        return Decision(True, "ok", ac)

    def record(self, action_class: str, url: str) -> None:
        self.budget.record(action_class, endpoint_key(url))


class PolicyExecutor:
    """The only `send` a module ever receives. Enforces the policy at the seam."""

    def __init__(self, raw_send: RawSend, policy: ExecutionPolicy):
        self.raw_send = raw_send
        self.policy = policy
        self.skipped: List[Dict[str, Any]] = []

    async def send(self, method: str, url: str, body: Any = None, *,
                   hint: Optional[str] = None, **kw: Any) -> Tuple[int, Any]:
        decision = self.policy.evaluate(method, url, body, hint=hint)
        if not decision.allowed:
            self.skipped.append({"method": method, "url": url,
                                 "class": decision.action_class, "reason": decision.reason})
            logger.info("[execution_policy] DENIED %s %s — %s (%s)",
                        method, url, decision.reason, decision.action_class)
            return DENIED_STATUS, {"_policy_denied": decision.reason}
        status, resp = await self.raw_send(method, url, body, **kw)
        self.policy.record(decision.action_class, url)
        return status, resp

    def restraint_summary(self) -> Dict[str, Any]:
        """What was done and what was refused — for the report's restraint section."""
        return {"mode": self.policy.mode, "budget": self.policy.budget.snapshot(),
                "skipped": len(self.skipped),
                "skipped_reasons": sorted({s["reason"].split(" (")[0] for s in self.skipped})}


def make_executor(raw_send: RawSend, *, mode: str,
                  scope_filter: Optional[ScopeFilter] = None) -> PolicyExecutor:
    return PolicyExecutor(raw_send, ExecutionPolicy(mode, scope_filter=scope_filter))
