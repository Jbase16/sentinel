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
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from core.safety.action_classifier import CROSS_OBJECT_READ, DESTRUCTIVE, OWNED_CREATE, classify
from core.safety.ownership_locator import (
    LocatorOwnershipProof,
    LocatorOwnershipVerification,
)
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
    budget_reservation_id: Optional[str] = field(default=None, repr=False)


@dataclass
class Decision:
    allowed: bool
    reason: str
    action_class: str


class LocatorRuntimeAuthorityDenied(RuntimeError):
    """A single-use admitted locator action no longer matches its authority."""


@dataclass(frozen=True)
class ProposalExecutionClaim:
    """Opaque, single-use authority for one exact proposed action.

    Proposal producers may retain this value, but only the ``PolicyExecutor``
    instance that issued it can consume it.  The executor's private registry is
    authoritative; constructing or copying a look-alike value grants nothing.
    """

    claim_id: str
    action_ref: str
    max_requests: int = 1


def _candidate_runtime_fingerprint(action: CandidateAction) -> str:
    value = body_hash({
        "method": str(action.method or "").strip().upper(),
        "url": str(action.url),
        "body": action.body,
        "hint": action.hint,
        "actor_persona_id": action.actor_persona_id,
        "target_owner_persona_id": action.target_owner_persona_id,
        "target_is_researcher_owned": action.target_is_researcher_owned,
        "expected_side_effect": action.expected_side_effect,
        "proof_goal": action.proof_goal,
    })
    if value is None:
        raise LocatorRuntimeAuthorityDenied(
            "locator_runtime_action_identity_is_invalid"
        )
    return value


class LocatorRuntimePermit:
    """One in-memory R4 claim capability for one exact locator-bound action.

    Construction is restricted to the R4 admission handoff.  The permit commits
    to the unreserved action identity, the exact reservation, the R5A2 admission,
    and the R5A3a proof.  Its admission-owned callback makes consumption atomic
    with the live claim rather than trusting a caller-supplied boolean.
    """

    def __init__(
        self,
        *,
        runtime_action_binding_id: str,
        action_fingerprint: str,
        budget_reservation_id: str,
        locator_proof_ref: str,
        source_admission_ref: str,
        source_plan_ref: str,
        transport_context_ref: str,
        runtime_claim_token: str,
        consume_callback: Callable[[str, str], None],
    ) -> None:
        material = {
            "runtime_action_binding_id": runtime_action_binding_id,
            "action_fingerprint": action_fingerprint,
            "budget_reservation_id": budget_reservation_id,
            "locator_proof_ref": locator_proof_ref,
            "source_admission_ref": source_admission_ref,
            "source_plan_ref": source_plan_ref,
            "transport_context_ref": transport_context_ref,
        }
        authority_hash = body_hash(material)
        if (
            authority_hash is None
            or not runtime_action_binding_id.startswith(
                "experiment_runtime_action_binding:"
            )
            or not action_fingerprint.startswith("sha256:")
            or not budget_reservation_id
            or not locator_proof_ref.startswith("locator_ownership_proof:")
            or not source_admission_ref.startswith(
                "ownership_experiment_admission:"
            )
            or not source_plan_ref.startswith(
                "generalized_authorization_plan:"
            )
            or not transport_context_ref.startswith(
                "locator_transport_context:"
            )
            or not runtime_claim_token
            or not callable(consume_callback)
        ):
            raise ValueError("locator runtime permit contract is invalid")
        self.authority_ref = authority_hash.replace(
            "sha256:", "locator_runtime_authority:", 1
        )
        self.runtime_action_binding_id = runtime_action_binding_id
        self.locator_proof_ref = locator_proof_ref
        self.source_admission_ref = source_admission_ref
        self.source_plan_ref = source_plan_ref
        self.transport_context_ref = transport_context_ref
        self._action_fingerprint = action_fingerprint
        self._budget_reservation_id = budget_reservation_id
        self._runtime_claim_token = runtime_claim_token
        self._consume_callback = consume_callback
        self._lock = threading.Lock()
        self._consumed = False

    def __repr__(self) -> str:
        return (
            "LocatorRuntimePermit("
            f"authority_ref={self.authority_ref!r}, capability=REDACTED)"
        )

    def _consume(
        self,
        action: CandidateAction,
        proof: LocatorOwnershipProof,
        transport_context_ref: str,
    ) -> None:
        with self._lock:
            if self._consumed:
                raise LocatorRuntimeAuthorityDenied(
                    "locator_runtime_authority_already_consumed"
                )
            if (
                not isinstance(action, CandidateAction)
                or not isinstance(proof, LocatorOwnershipProof)
                or action.budget_reservation_id
                != self._budget_reservation_id
                or proof.proof_ref != self.locator_proof_ref
                or transport_context_ref != self.transport_context_ref
                or _candidate_runtime_fingerprint(action)
                != self._action_fingerprint
            ):
                raise LocatorRuntimeAuthorityDenied(
                    "locator_runtime_authority_identity_mismatch"
                )
            try:
                self._consume_callback(
                    self._runtime_claim_token,
                    self.authority_ref,
                )
            except Exception as exc:
                raise LocatorRuntimeAuthorityDenied(
                    "locator_runtime_authority_is_not_active"
                ) from exc
            self._consumed = True


def _issue_locator_runtime_permit(
    *,
    runtime_action_binding_id: str,
    action: CandidateAction,
    budget_reservation_id: str,
    locator_proof_ref: str,
    source_admission_ref: str,
    source_plan_ref: str,
    transport_context_ref: str,
    runtime_claim_token: str,
    consume_callback: Callable[[str, str], None],
) -> LocatorRuntimePermit:
    """Private construction seam used only by an active R4 admission claim."""

    return LocatorRuntimePermit(
        runtime_action_binding_id=runtime_action_binding_id,
        action_fingerprint=_candidate_runtime_fingerprint(action),
        budget_reservation_id=budget_reservation_id,
        locator_proof_ref=locator_proof_ref,
        source_admission_ref=source_admission_ref,
        source_plan_ref=source_plan_ref,
        transport_context_ref=transport_context_ref,
        runtime_claim_token=runtime_claim_token,
        consume_callback=consume_callback,
    )


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

    def _evaluate_action(
        self,
        a: CandidateAction,
        *,
        locator_ownership_verified: bool = False,
    ) -> Decision:
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
            if (
                self.ownership_registry is not None
                and not locator_ownership_verified
                and not self.ownership_registry.is_owned(a.url)
            ):
                return Decision(False, "cross_object_read_target_not_proven_researcher_created", ac)

        # 5. Budget.
        ok, reason = self.budget.allows(
            ac,
            endpoint_key(a.url),
            reservation_id=a.budget_reservation_id,
        )
        if not ok:
            return Decision(False, reason, ac)

        return Decision(True, "ok", ac)

    def evaluate_action(self, a: CandidateAction) -> Decision:
        """Evaluate the ordinary URL-owned action path without locator authority."""

        return self._evaluate_action(a)

    def evaluate_locator_action(
        self,
        action: CandidateAction,
        proof: LocatorOwnershipProof,
    ) -> Decision:
        """Evaluate one exact locator proof without treating it as ambient authority."""

        verification = self.verify_locator_ownership(action, proof)
        if not verification.verified:
            try:
                action_class = classify(
                    action.method,
                    action.url,
                    action.body,
                    hint=action.hint,
                )
            except Exception:
                action_class = "UNKNOWN"
            return Decision(False, verification.reason, action_class)
        return self._evaluate_action(
            action,
            locator_ownership_verified=True,
        )

    def evaluate(self, method: str, url: str, body: Any = None, *,
                 hint: Optional[str] = None,
                 target_is_researcher_owned: Optional[bool] = None) -> Decision:
        """Convenience shim over evaluate_action for the common case."""
        return self.evaluate_action(CandidateAction(
            method, url, body, hint=hint,
            target_is_researcher_owned=target_is_researcher_owned))

    def verify_locator_ownership(
        self,
        action: CandidateAction,
        proof: LocatorOwnershipProof,
    ) -> LocatorOwnershipVerification:
        """Validate generalized ownership without authorizing or recording an action.

        R5A3a deliberately keeps this verifier separate from ``evaluate_action``.
        A verified result consumes no budget and cannot reach ``PolicyExecutor``;
        a later admitted adapter must explicitly bind it to execution authority.
        """

        proof_ref = proof.proof_ref if isinstance(proof, LocatorOwnershipProof) else None

        def denied(reason: str) -> LocatorOwnershipVerification:
            return LocatorOwnershipVerification(False, reason, proof_ref)

        if not isinstance(action, CandidateAction):
            return denied("locator_ownership_action_is_invalid")
        if self.mode != ProofMode.BOUNTY_SAFE:
            return denied("locator_ownership_requires_bounty_safe_policy")
        if self.budget.allow_real_user_data_access:
            return denied("locator_ownership_requires_owned_data_only_policy")
        if self.scope_filter is None:
            return denied("locator_ownership_scope_filter_is_unavailable")
        try:
            in_scope = bool(self.scope_filter(action.url))
        except Exception:
            in_scope = False
        if not in_scope:
            return denied("locator_ownership_action_is_out_of_scope")
        try:
            action_class = classify(
                action.method,
                action.url,
                action.body,
                hint=action.hint,
            )
        except Exception:
            return denied("locator_ownership_action_classification_failed")
        if action_class != CROSS_OBJECT_READ:
            return denied("locator_ownership_requires_cross_object_read")
        if action.target_is_researcher_owned is not True:
            return denied("locator_ownership_intent_is_missing")
        if self.ownership_registry is None:
            return denied("locator_ownership_registry_is_unavailable")
        actor = str(action.actor_persona_id or "").strip()
        owner = str(action.target_owner_persona_id or "").strip()
        if not actor or not owner or actor == owner:
            return denied("locator_ownership_actor_or_owner_mismatch")
        return self.ownership_registry.verify_locator_proof(
            proof,
            actor_persona_id=actor,
            target_owner_persona_id=owner,
            method=action.method,
            url=action.url,
            body=action.body,
        )

    def record(
        self,
        action_class: str,
        url: str,
        status: Optional[int] = None,
        *,
        reservation_id: Optional[str] = None,
    ) -> None:
        self.budget.record(
            action_class,
            endpoint_key(url),
            status,
            reservation_id=reservation_id,
        )

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
        self._proposal_claims: Dict[str, str] = {}
        self._proposal_claim_lock = threading.Lock()

    def claim_proposal_action(
        self,
        action: CandidateAction,
    ) -> Optional[ProposalExecutionClaim]:
        """Admit and bind one proposal without touching the transport.

        A claim is intentionally single-use and executor-local.  Policy is
        evaluated again at execution time so a claim cannot preserve stale
        scope or budget authority.
        """

        if not isinstance(action, CandidateAction):
            return None
        decision = self.policy.evaluate_action(action)
        if not decision.allowed:
            self.skipped.append({
                "method": action.method,
                "url": action.url,
                "class": decision.action_class,
                "reason": decision.reason,
            })
            self._emit_provenance(
                action,
                decision,
                allowed=False,
                status=None,
                resp=None,
            )
            return None

        action_ref = _candidate_runtime_fingerprint(action)
        claim = ProposalExecutionClaim(
            claim_id=str(uuid.uuid4()),
            action_ref=action_ref,
        )
        with self._proposal_claim_lock:
            self._proposal_claims[claim.claim_id] = action_ref
        return claim

    async def send_claimed_action(
        self,
        action: CandidateAction,
        claim: Optional[ProposalExecutionClaim],
        **kw: Any,
    ) -> Tuple[int, Any]:
        """Consume one exact proposal claim, then use ordinary policy send.

        Missing, forged, replayed, or action-mismatched claims fail before the
        raw transport.  A mismatch burns the claim so it cannot be used as an
        oracle and then replayed with the originally admitted action.
        """

        action_ref = (
            _candidate_runtime_fingerprint(action)
            if isinstance(action, CandidateAction)
            else None
        )
        registered_ref: Optional[str] = None
        if isinstance(claim, ProposalExecutionClaim):
            with self._proposal_claim_lock:
                registered_ref = self._proposal_claims.pop(claim.claim_id, None)

        claim_valid = (
            isinstance(action, CandidateAction)
            and isinstance(claim, ProposalExecutionClaim)
            and claim.max_requests == 1
            and registered_ref is not None
            and registered_ref == claim.action_ref == action_ref
        )
        if not claim_valid:
            try:
                action_class = classify(
                    action.method,
                    action.url,
                    action.body,
                    hint=action.hint,
                )
            except Exception:
                action_class = "UNKNOWN"
            decision = Decision(
                False,
                "proposal_execution_claim_unavailable",
                action_class,
            )
            if isinstance(action, CandidateAction):
                self.skipped.append({
                    "method": action.method,
                    "url": action.url,
                    "class": decision.action_class,
                    "reason": decision.reason,
                })
                self._emit_provenance(
                    action,
                    decision,
                    allowed=False,
                    status=None,
                    resp=None,
                )
            return DENIED_STATUS, {"_policy_denied": decision.reason}

        return await self.send_action(action, **kw)

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
        self.policy.record(
            decision.action_class,
            action.url,
            status,
            reservation_id=action.budget_reservation_id,
        )
        self._register_ownership(action, decision, status, resp)
        self._emit_provenance(action, decision, allowed=True, status=status, resp=resp)
        return status, resp

    async def send_locator_action(
        self,
        action: CandidateAction,
        proof: LocatorOwnershipProof,
        *,
        runtime_permit: LocatorRuntimePermit,
        **kw: Any,
    ) -> Tuple[int, Any]:
        """Send one locator-owned action under an exact single-use R4 permit."""

        authority_ref = (
            runtime_permit.authority_ref
            if isinstance(runtime_permit, LocatorRuntimePermit)
            else None
        )
        source_admission_ref = (
            runtime_permit.source_admission_ref
            if isinstance(runtime_permit, LocatorRuntimePermit)
            else None
        )
        source_plan_ref = (
            runtime_permit.source_plan_ref
            if isinstance(runtime_permit, LocatorRuntimePermit)
            else None
        )
        transport_context_ref = (
            runtime_permit.transport_context_ref
            if isinstance(runtime_permit, LocatorRuntimePermit)
            else None
        )
        proof_ref = proof.proof_ref if isinstance(proof, LocatorOwnershipProof) else None
        try:
            if not isinstance(runtime_permit, LocatorRuntimePermit):
                raise LocatorRuntimeAuthorityDenied(
                    "locator_runtime_authority_is_invalid"
                )
            registry = self.policy.ownership_registry
            if registry is None:
                raise LocatorRuntimeAuthorityDenied(
                    "locator_runtime_ownership_registry_is_unavailable"
                )
            try:
                actual_transport_context_ref = registry.transport_context_ref(
                    kw.get("headers") or {}
                )
            except Exception as exc:
                raise LocatorRuntimeAuthorityDenied(
                    "locator_runtime_transport_context_is_invalid"
                ) from exc
            runtime_permit._consume(
                action,
                proof,
                actual_transport_context_ref,
            )
            decision = self.policy.evaluate_locator_action(action, proof)
        except LocatorRuntimeAuthorityDenied as exc:
            try:
                action_class = classify(
                    action.method,
                    action.url,
                    action.body,
                    hint=action.hint,
                )
            except Exception:
                action_class = "UNKNOWN"
            decision = Decision(False, str(exc), action_class)
        if not decision.allowed:
            self.skipped.append({
                "method": action.method,
                "url": action.url,
                "class": decision.action_class,
                "reason": decision.reason,
            })
            logger.info(
                "[execution_policy] DENIED %s %s — %s (%s)",
                action.method,
                action.url,
                decision.reason,
                decision.action_class,
            )
            self._emit_provenance(
                action,
                decision,
                allowed=False,
                status=None,
                resp=None,
                ownership_proof_ref=proof_ref,
                runtime_authority_ref=authority_ref,
                source_admission_ref=source_admission_ref,
                source_plan_ref=source_plan_ref,
                transport_context_ref=transport_context_ref,
            )
            return DENIED_STATUS, {"_policy_denied": decision.reason}
        status, resp = await self.raw_send(
            action.method,
            action.url,
            action.body,
            **kw,
        )
        self.policy.record(
            decision.action_class,
            action.url,
            status,
            reservation_id=action.budget_reservation_id,
        )
        self._emit_provenance(
            action,
            decision,
            allowed=True,
            status=status,
            resp=resp,
            ownership_proof_ref=proof_ref,
            runtime_authority_ref=authority_ref,
            source_admission_ref=source_admission_ref,
            source_plan_ref=source_plan_ref,
            transport_context_ref=transport_context_ref,
        )
        return status, resp

    def _register_ownership(self, action: CandidateAction, decision: Decision,
                            status: Optional[int], resp: Any) -> None:
        """After a successful OWNED_CREATE, record the created object so a later
        CROSS_OBJECT_READ of it can be PROVEN researcher-owned rather than asserted."""
        reg = self.policy.ownership_registry
        if reg is None or decision.action_class != OWNED_CREATE:
            return
        try:
            if status is not None and 200 <= int(status) < 300:
                reg.register_created(action.url, resp, actor_persona=action.actor_persona_id)
        except Exception as exc:
            logger.warning("[execution_policy] ownership register failed: %s: %s",
                           type(exc).__name__, exc)

    def _emit_provenance(self, action: CandidateAction, decision: Decision, *,
                         allowed: bool, status: Optional[int], resp: Any,
                         ownership_proof_ref: Optional[str] = None,
                         runtime_authority_ref: Optional[str] = None,
                         source_admission_ref: Optional[str] = None,
                         source_plan_ref: Optional[str] = None,
                         transport_context_ref: Optional[str] = None) -> None:
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
                ownership_proof_ref=ownership_proof_ref,
                runtime_authority_ref=runtime_authority_ref,
                source_admission_ref=source_admission_ref,
                source_plan_ref=source_plan_ref,
                transport_context_ref=transport_context_ref,
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
                   proof_goal: Optional[str] = None,
                   budget_reservation_id: Optional[str] = None,
                   **kw: Any) -> Tuple[int, Any]:
        # NB: every CandidateAction field is named here so it lands on the action,
        # not in **kw — **kw is reserved for genuine transport kwargs (e.g. _auth)
        # and is forwarded to the raw send. Leaking an intent field (proof_goal) into
        # a raw send that doesn't accept it raises TypeError and silently kills the probe.
        return await self.send_action(CandidateAction(
            method, url, body, hint=hint, actor_persona_id=actor,
            target_owner_persona_id=target_owner,
            target_is_researcher_owned=target_is_researcher_owned,
            expected_side_effect=expected_side_effect,
            proof_goal=proof_goal,
            budget_reservation_id=budget_reservation_id,
        ), **kw)

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
