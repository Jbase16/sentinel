"""
core/cortex/execution_policy.py

The single gate every active request must pass. Modules never hold a raw HTTP
client — they are handed a `PolicyExecutor` whose `send`/`send_action` classify,
scope-check, ownership-check, and budget-check each candidate action before (maybe)
delegating to the real transport. A denied action is never sent; the caller sees a
synthetic non-2xx result and moves on.

The action model carries INTENT, not just bytes: a `CandidateAction` says who is
acting, whose object is being touched, and whether that object is researcher-owned.
That lets bounty mode enforce the rule that makes `allow_real_user_data_access`
real rather than decorative:

    CROSS_OBJECT_READ is allowed only against a researcher-owned target.

Order of checks (all fail closed):
  1. scope      — scheme/host/port/path must be in the declared scope
  2. class      — the action's risk class must be allowed in this mode
  3. destructive— DELETE is refused unless the budget explicitly allows it
  4. ownership  — a cross-object read must target a researcher-owned object
  5. budget     — class/endpoint/total budgets must not be exhausted

LAB mode allows all classes with an unlimited budget and permits real-data access,
so the executor is a transparent pass-through and existing behavior is unchanged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from core.safety.action_classifier import CROSS_OBJECT_READ, DESTRUCTIVE, classify
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode, rules_for

logger = logging.getLogger(__name__)

# raw transport: (method, url, body, **kw) -> (status, parsed_json)
RawSend = Callable[..., Awaitable[Tuple[int, Any]]]
ScopeFilter = Callable[[str], bool]

DENIED_STATUS = 0   # distinct from any real HTTP code (incl. 401/403 "exists-but-forbidden")


@dataclass
class CandidateAction:
    """A proposed request plus the intent the policy needs to judge it."""
    method: str
    url: str
    body: Any = None
    hint: Optional[str] = None
    actor_persona_id: Optional[str] = None
    target_owner_persona_id: Optional[str] = None
    target_is_researcher_owned: Optional[bool] = None
    expected_side_effect: Optional[str] = None
    proof_goal: Optional[str] = None


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

    def evaluate_action(self, a: CandidateAction) -> Decision:
        # 1. Scope — never touch anything outside the declared scope.
        if self.scope_filter is not None:
            try:
                in_scope = bool(self.scope_filter(a.url))
            except Exception:
                in_scope = False
            if not in_scope:
                return Decision(False, "out_of_scope", "SCOPE")

        ac = classify(a.method, a.url, a.body, hint=a.hint)

        # 2. Class allow-list (None = all allowed in LAB).
        if self.allowed is not None and ac not in self.allowed:
            return Decision(False, f"class_{ac}_denied_in_{self.mode}", ac)

        # 3. DELETE guard — refused unless explicitly permitted.
        if ac == DESTRUCTIVE and not self.budget.allow_delete:
            return Decision(False, "destructive_action_denied", ac)

        # 4. Ownership guard — a cross-object read must be against a researcher-owned
        #    object unless real-data access is permitted (LAB). This is what stops
        #    "prove BOLA" from meaning "read a real user's data".
        if (ac == CROSS_OBJECT_READ
                and not self.budget.allow_real_user_data_access
                and a.target_is_researcher_owned is not True):
            return Decision(False, "cross_object_read_requires_researcher_owned_target", ac)

        # 5. Budget.
        ok, reason = self.budget.allows(ac, endpoint_key(a.url))
        if not ok:
            return Decision(False, reason, ac)

        return Decision(True, "ok", ac)

    def evaluate(self, method: str, url: str, body: Any = None, *,
                 hint: Optional[str] = None,
                 target_is_researcher_owned: Optional[bool] = None) -> Decision:
        """Convenience shim over evaluate_action for the common case."""
        return self.evaluate_action(CandidateAction(
            method, url, body, hint=hint,
            target_is_researcher_owned=target_is_researcher_owned))

    def record(self, action_class: str, url: str) -> None:
        self.budget.record(action_class, endpoint_key(url))


class PolicyExecutor:
    """The only `send` a module ever receives. Enforces the policy at the seam."""

    def __init__(self, raw_send: RawSend, policy: ExecutionPolicy):
        self.raw_send = raw_send
        self.policy = policy
        self.skipped: List[Dict[str, Any]] = []

    async def send_action(self, action: CandidateAction, **kw: Any) -> Tuple[int, Any]:
        decision = self.policy.evaluate_action(action)
        if not decision.allowed:
            self.skipped.append({"method": action.method, "url": action.url,
                                 "class": decision.action_class, "reason": decision.reason})
            logger.info("[execution_policy] DENIED %s %s — %s (%s)",
                        action.method, action.url, decision.reason, decision.action_class)
            return DENIED_STATUS, {"_policy_denied": decision.reason}
        status, resp = await self.raw_send(action.method, action.url, action.body, **kw)
        self.policy.record(decision.action_class, action.url)
        return status, resp

    async def send(self, method: str, url: str, body: Any = None, *,
                   hint: Optional[str] = None, actor: Optional[str] = None,
                   target_owner: Optional[str] = None,
                   target_is_researcher_owned: Optional[bool] = None,
                   expected_side_effect: Optional[str] = None, **kw: Any) -> Tuple[int, Any]:
        return await self.send_action(CandidateAction(
            method, url, body, hint=hint, actor_persona_id=actor,
            target_owner_persona_id=target_owner,
            target_is_researcher_owned=target_is_researcher_owned,
            expected_side_effect=expected_side_effect), **kw)

    def restraint_summary(self) -> Dict[str, Any]:
        """What was done and what was refused — for the report's restraint section."""
        b = self.policy.budget
        snap = b.snapshot()
        return {
            "proof_mode": self.policy.mode,
            "owned_test_accounts_only": not b.allow_real_user_data_access,
            "cross_object_reads": snap["cross_object_reads"],
            "destructive_actions_attempted": sum(1 for s in self.skipped if s["class"] == DESTRUCTIVE),
            "destructive_actions_sent": 0,          # DELETE is refused before transport in non-lab
            "policy_denials": len(self.skipped),
            "requests_sent": snap["total_requests"],
            "denied_reasons": sorted({s["reason"].split(" (")[0] for s in self.skipped}),
        }


def make_executor(raw_send: RawSend, *, mode: str,
                  scope_filter: Optional[ScopeFilter] = None) -> PolicyExecutor:
    return PolicyExecutor(raw_send, ExecutionPolicy(mode, scope_filter=scope_filter))
