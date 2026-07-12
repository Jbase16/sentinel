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

from core.safety.action_classifier import CROSS_OBJECT_READ, DESTRUCTIVE, OWNED_CREATE, classify
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget, endpoint_key
from core.safety.proof_mode import ProofMode, rules_for
from core.safety.provenance import (
    ProvenanceEvent, ProvenanceSink, _url_path, body_hash, response_shape,
)

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
                 budget: Optional[ProofBudget] = None,
                 ownership_registry: Optional[OwnershipRegistry] = None):
        self.mode = ProofMode.normalize(mode)
        allowed, default_budget = rules_for(self.mode)
        self.allowed = allowed                 # None → all allowed (LAB)
        self.budget = budget or default_budget
        self.scope_filter = scope_filter
        # When wired, a CROSS_OBJECT_READ must target an object PROVEN researcher-created
        # in this session — not merely one the caller labelled researcher-owned.
        self.ownership_registry = ownership_registry

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
        #    object unless real-data access is permitted (LAB). Two layers:
        #      (a) the caller must DECLARE intent (target_is_researcher_owned), and
        #      (b) if an ownership registry is wired, that claim must be PROVEN — the
        #          target must have been researcher-CREATED in this session (observed
        #          conduct), closing the "a module can just assert ownership" hole.
        if ac == CROSS_OBJECT_READ and not self.budget.allow_real_user_data_access:
            if a.target_is_researcher_owned is not True:
                return Decision(False, "cross_object_read_requires_researcher_owned_target", ac)
            if (self.ownership_registry is not None
                    and not self.ownership_registry.is_owned(a.url)):
                return Decision(False, "cross_object_read_target_not_proven_researcher_created", ac)

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

    def record(self, action_class: str, url: str, status: Optional[int] = None) -> None:
        self.budget.record(action_class, endpoint_key(url), status)

    def digest(self) -> str:
        """A short, stable fingerprint of the safety envelope this policy enforces, so
        a conduct trail can commit to 'these actions ran under THIS policy'."""
        b = self.budget
        return body_hash({
            "mode": self.mode,
            "allowed_classes": sorted(self.allowed) if self.allowed else None,
            "max_total_requests": b.max_total_requests,
            "max_requests_per_endpoint": b.max_requests_per_endpoint,
            "max_cross_object_reads": b.max_cross_object_reads,
            "max_privilege_mutations": b.max_privilege_mutations,
            "max_creates": b.max_creates,
            "allow_delete": b.allow_delete,
            "allow_real_user_data_access": b.allow_real_user_data_access,
        }) or ""


class PolicyExecutor:
    """The only `send` a module ever receives. Enforces the policy at the seam."""

    def __init__(self, raw_send: RawSend, policy: ExecutionPolicy,
                 provenance: Optional[ProvenanceSink] = None):
        self.raw_send = raw_send
        self.policy = policy
        self.provenance = provenance          # optional conduct trail (Merkle chain)
        self.skipped: List[Dict[str, Any]] = []

    async def send_action(self, action: CandidateAction, **kw: Any) -> Tuple[int, Any]:
        decision = self.policy.evaluate_action(action)
        if not decision.allowed:
            self.skipped.append({"method": action.method, "url": action.url,
                                 "class": decision.action_class, "reason": decision.reason})
            logger.info("[execution_policy] DENIED %s %s — %s (%s)",
                        action.method, action.url, decision.reason, decision.action_class)
            # A denial is EVIDENCE — record that the safety layer refused, un-sent.
            self._emit_provenance(action, decision, allowed=False, status=None, resp=None)
            return DENIED_STATUS, {"_policy_denied": decision.reason}
        status, resp = await self.raw_send(action.method, action.url, action.body, **kw)
        self.policy.record(decision.action_class, action.url, status)
        self._register_ownership(action, decision, status, resp)
        self._emit_provenance(action, decision, allowed=True, status=status, resp=resp)
        return status, resp

    def _register_ownership(self, action: CandidateAction, decision: Decision,
                            status: Optional[int], resp: Any) -> None:
        """After a successful OWNED_CREATE, record the created object so a later
        CROSS_OBJECT_READ of it can be PROVEN researcher-owned rather than asserted."""
        reg = self.policy.ownership_registry
        if reg is None or decision.action_class != OWNED_CREATE:
            return
        try:
            if 200 <= int(status) < 300:
                reg.register_created(action.url, resp, actor_persona=action.actor_persona_id)
        except Exception as exc:
            logger.warning("[execution_policy] ownership register failed: %s: %s",
                           type(exc).__name__, exc)

    def _emit_provenance(self, action: CandidateAction, decision: Decision, *,
                         allowed: bool, status: Optional[int], resp: Any) -> None:
        """Record one conduct block for this action. Best-effort: a provenance fault
        must never break the proof path (the request has already happened)."""
        if self.provenance is None:
            return
        try:
            self.provenance.record_policy_action(ProvenanceEvent(
                method=action.method, url_path=_url_path(action.url),
                action_class=decision.action_class, policy_mode=self.policy.mode,
                allowed=allowed, actor_persona_id=action.actor_persona_id,
                denial_reason=(None if allowed else decision.reason),
                target_owner_persona_id=action.target_owner_persona_id,
                target_is_researcher_owned=action.target_is_researcher_owned,
                status=status, request_body_hash=body_hash(action.body),
                response_body_hash=(body_hash(resp) if allowed else None),
                response_summary=(response_shape(resp) if allowed else {}),
                budget_snapshot_after=self.policy.budget.snapshot()))
        except Exception as exc:
            logger.warning("[execution_policy] provenance emit failed: %s: %s",
                           type(exc).__name__, exc)

    async def send(self, method: str, url: str, body: Any = None, *,
                   hint: Optional[str] = None, actor: Optional[str] = None,
                   target_owner: Optional[str] = None,
                   target_is_researcher_owned: Optional[bool] = None,
                   expected_side_effect: Optional[str] = None,
                   proof_goal: Optional[str] = None, **kw: Any) -> Tuple[int, Any]:
        # NB: every CandidateAction field is named here so it lands on the action,
        # not in **kw — **kw is reserved for genuine transport kwargs (e.g. _auth)
        # and is forwarded to the raw send. Leaking an intent field (proof_goal) into
        # a raw send that doesn't accept it raises TypeError and silently kills the probe.
        return await self.send_action(CandidateAction(
            method, url, body, hint=hint, actor_persona_id=actor,
            target_owner_persona_id=target_owner,
            target_is_researcher_owned=target_is_researcher_owned,
            expected_side_effect=expected_side_effect, proof_goal=proof_goal), **kw)

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
                  scope_filter: Optional[ScopeFilter] = None,
                  provenance: Optional[ProvenanceSink] = None) -> PolicyExecutor:
    return PolicyExecutor(raw_send, ExecutionPolicy(mode, scope_filter=scope_filter),
                          provenance=provenance)
