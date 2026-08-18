"""Canonical admission adapter for AI and scheduler tool proposals.

Proposal producers describe work; they do not own execution authority.  This
adapter turns a tool proposal into one exact ``CandidateAction`` and delegates
both claim issuance and claim consumption to ``PolicyExecutor``.  The wrapped
transport is therefore unreachable without a live, single-use executor claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, FrozenSet, Iterable, Mapping, Optional, Tuple

from core.cortex.execution_policy import (
    CandidateAction,
    Decision,
    PolicyExecutor,
    ProposalExecutionClaim,
)
from core.safety.action_classifier import AUTHZ_PROBE, SAFE_READ
from core.safety.provenance import body_hash


_PROPOSAL_SOURCES = frozenset({"ai_action_dispatcher", "strategos"})
_TOOL_SELECTION_ACTION_CLASS = "TOOL_SELECTION"


class ToolPolicyInputError(ValueError):
    """A scheduler policy input cannot be represented without ambiguity."""


def _policy_int(value: Any, *, field: str, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise ToolPolicyInputError(f"{field} must be an integer >= {minimum}")
    return value


def _policy_tags(value: Any, *, field: str) -> FrozenSet[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ToolPolicyInputError(f"{field} must be a collection of strings")
    if any(type(item) is not str or not item for item in value):
        raise ToolPolicyInputError(f"{field} must contain only non-empty strings")
    return frozenset(value)


@dataclass(frozen=True)
class ToolPolicySnapshot:
    """Immutable scheduling facts consumed by the three constitution policies."""

    phase_index: int
    knowledge_tags: FrozenSet[str]
    active_tools: int
    max_concurrent: int
    tool_phase: int
    prerequisite_gates: FrozenSet[str]
    resource_cost: int

    def __post_init__(self) -> None:
        _policy_int(self.phase_index, field="phase_index", minimum=0)
        _policy_int(self.active_tools, field="active_tools", minimum=0)
        _policy_int(self.max_concurrent, field="max_concurrent", minimum=1)
        _policy_int(self.tool_phase, field="tool_phase", minimum=0)
        _policy_int(self.resource_cost, field="resource_cost", minimum=0)
        if not isinstance(self.knowledge_tags, frozenset):
            raise ToolPolicyInputError("knowledge_tags must be a frozenset")
        if not isinstance(self.prerequisite_gates, frozenset):
            raise ToolPolicyInputError("prerequisite_gates must be a frozenset")
        _policy_tags(self.knowledge_tags, field="knowledge_tags")
        _policy_tags(self.prerequisite_gates, field="prerequisite_gates")

    @classmethod
    def from_inputs(
        cls,
        context: Any,
        tool: Any,
    ) -> "ToolPolicySnapshot":
        if not isinstance(context, Mapping):
            raise ToolPolicyInputError("context must be a mapping")
        if not isinstance(tool, Mapping):
            raise ToolPolicyInputError("tool must be a mapping")

        knowledge = context.get("knowledge")
        if not isinstance(knowledge, Mapping):
            raise ToolPolicyInputError("context.knowledge must be a mapping")

        return cls(
            phase_index=_policy_int(
                context.get("phase_index"), field="context.phase_index", minimum=0
            ),
            knowledge_tags=_policy_tags(
                knowledge.get("tags"), field="context.knowledge.tags"
            ),
            active_tools=_policy_int(
                context.get("active_tools"), field="context.active_tools", minimum=0
            ),
            max_concurrent=_policy_int(
                context.get("max_concurrent"), field="context.max_concurrent", minimum=1
            ),
            tool_phase=_policy_int(
                tool.get("phase"), field="tool.phase", minimum=0
            ),
            prerequisite_gates=_policy_tags(
                tool.get("gates"), field="tool.gates"
            ),
            resource_cost=_policy_int(
                tool.get("resource_cost"), field="tool.resource_cost", minimum=0
            ),
        )

    def to_material(self) -> Mapping[str, Any]:
        """Return deterministic proposal material without granting authority."""

        return {
            "phase_index": self.phase_index,
            "knowledge_tags": sorted(self.knowledge_tags),
            "active_tools": self.active_tools,
            "max_concurrent": self.max_concurrent,
            "tool_phase": self.tool_phase,
            "prerequisite_gates": sorted(self.prerequisite_gates),
            "resource_cost": self.resource_cost,
        }


class PassiveBeforeActivePolicy:
    name = "PassiveBeforeActive"

    @staticmethod
    def violation(snapshot: ToolPolicySnapshot) -> Optional[str]:
        if snapshot.phase_index < 2 and snapshot.tool_phase >= 2:
            return (
                "Passive Mode Violation: "
                f"Phase {snapshot.phase_index} cannot run Phase {snapshot.tool_phase} tool"
            )
        return None


class EvidenceGatesPolicy:
    name = "EvidenceGates"

    @staticmethod
    def violation(snapshot: ToolPolicySnapshot) -> Optional[str]:
        if not snapshot.prerequisite_gates.issubset(snapshot.knowledge_tags):
            missing = sorted(snapshot.prerequisite_gates - snapshot.knowledge_tags)
            return f"Missing Prerequisite: {missing}"
        return None


class ResourceAwarenessPolicy:
    name = "ResourceAwareness"

    @staticmethod
    def violation(snapshot: ToolPolicySnapshot) -> Optional[str]:
        projected = snapshot.active_tools + snapshot.resource_cost
        if projected > snapshot.max_concurrent:
            return (
                "System load too high "
                f"({snapshot.active_tools} + {snapshot.resource_cost} "
                f"> {snapshot.max_concurrent})"
            )
        return None


class CanonicalToolSelectionPolicy:
    """Typed, fail-closed pre-admission policy for Strategos proposals.

    This policy can reject a proposal, but cannot authorize transport.  A proposal
    that passes still needs a live, single-use claim from ``PolicyExecutor``.
    """

    _policies = (
        PassiveBeforeActivePolicy(),
        EvidenceGatesPolicy(),
        ResourceAwarenessPolicy(),
    )

    def evaluate(self, context: Any, tool: Any) -> Decision:
        try:
            snapshot = ToolPolicySnapshot.from_inputs(context, tool)
        except (ToolPolicyInputError, TypeError, ValueError):
            return Decision(
                False,
                "TypedToolPolicyInput: malformed scheduling policy input",
                _TOOL_SELECTION_ACTION_CLASS,
            )
        return self.evaluate_snapshot(snapshot)

    def evaluate_snapshot(self, snapshot: Any) -> Decision:
        if not isinstance(snapshot, ToolPolicySnapshot):
            return Decision(
                False,
                "TypedToolPolicyInput: malformed scheduling policy snapshot",
                _TOOL_SELECTION_ACTION_CLASS,
            )
        for policy in self._policies:
            violation = policy.violation(snapshot)
            if violation is not None:
                return Decision(
                    False,
                    f"{policy.name}: {violation}",
                    _TOOL_SELECTION_ACTION_CLASS,
                )
        return Decision(True, "All typed tool policies passed", _TOOL_SELECTION_ACTION_CLASS)


class ToolProposalAdmissionDenied(RuntimeError):
    """A tool proposal could not obtain canonical execution authority."""


@dataclass(frozen=True)
class ToolExecutionProposal:
    """Deterministic, transport-free description of one proposed tool run."""

    source: str
    tool: str
    args: Tuple[str, ...]
    target: str
    reason: str
    proposal_ref: str

    @classmethod
    def build(
        cls,
        *,
        source: str,
        tool: str,
        args: Iterable[str],
        target: str,
        reason: str,
    ) -> "ToolExecutionProposal":
        normalized_source = str(source or "").strip().lower()
        normalized_tool = str(tool or "").strip().lower()
        normalized_target = str(target or "").strip()
        normalized_reason = str(reason or "").strip()
        if isinstance(args, (str, bytes)):
            raise ValueError("tool proposal arguments must be an iterable of strings")
        normalized_args = tuple(args)

        if normalized_source not in _PROPOSAL_SOURCES:
            raise ValueError("tool proposal source is not supported")
        if not normalized_tool or len(normalized_tool) > 64:
            raise ValueError("tool proposal name is invalid")
        if not normalized_target or len(normalized_target) > 2048:
            raise ValueError("tool proposal target is invalid")
        if not normalized_reason or len(normalized_reason) > 512:
            raise ValueError("tool proposal reason is invalid")
        if len(normalized_args) > 32 or any(
            not isinstance(value, str) or len(value) > 512
            for value in normalized_args
        ):
            raise ValueError("tool proposal arguments are invalid")

        material = {
            "source": normalized_source,
            "tool": normalized_tool,
            "args": list(normalized_args),
            "target": normalized_target,
            "reason": normalized_reason,
        }
        digest = body_hash(material)
        if digest is None:
            raise ValueError("tool proposal commitment is unavailable")
        return cls(
            source=normalized_source,
            tool=normalized_tool,
            args=normalized_args,
            target=normalized_target,
            reason=normalized_reason,
            proposal_ref=f"tool_execution_proposal:{digest.removeprefix('sha256:')}",
        )

    def transport_payload(self) -> Mapping[str, Any]:
        """Return the exact non-authoritative payload consumed by the adapter."""

        return {
            "proposal_ref": self.proposal_ref,
            "source": self.source,
            "tool": self.tool,
            "args": list(self.args),
        }


class CanonicalToolExecutionAdmission:
    """Bind tool proposals to the canonical ``PolicyExecutor`` claim path."""

    def __init__(
        self,
        *,
        executor: PolicyExecutor,
        allowed_tools: Iterable[str],
        safe_tools: Iterable[str],
    ) -> None:
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("executor must be a PolicyExecutor")
        self.executor = executor
        self.allowed_tools = frozenset(
            str(tool).strip().lower() for tool in allowed_tools if str(tool).strip()
        )
        self.safe_tools = frozenset(
            str(tool).strip().lower() for tool in safe_tools if str(tool).strip()
        )

    def action_for(self, proposal: ToolExecutionProposal) -> CandidateAction:
        if not isinstance(proposal, ToolExecutionProposal):
            raise TypeError("proposal must be a ToolExecutionProposal")
        if proposal.tool not in self.allowed_tools:
            raise ToolProposalAdmissionDenied("tool_not_allowed_for_scan")

        action_class = (
            SAFE_READ if proposal.tool in self.safe_tools else AUTHZ_PROBE
        )
        return CandidateAction(
            method="EXECUTE",
            url=proposal.target,
            body=dict(proposal.transport_payload()),
            hint=action_class,
            expected_side_effect="bounded_scanner_tool_invocation",
            proof_goal=proposal.proposal_ref,
        )

    def claim(
        self,
        proposal: ToolExecutionProposal,
    ) -> ProposalExecutionClaim:
        action = self.action_for(proposal)
        claim = self.executor.claim_proposal_action(action)
        if claim is None:
            reason = (
                self.executor.skipped[-1]["reason"]
                if self.executor.skipped
                else "proposal_execution_policy_denied"
            )
            raise ToolProposalAdmissionDenied(str(reason))
        return claim

    async def execute_claimed(
        self,
        proposal: ToolExecutionProposal,
        claim: Optional[ProposalExecutionClaim],
    ) -> Tuple[int, Any]:
        return await self.executor.send_claimed_action(
            self.action_for(proposal),
            claim,
        )

    async def admit_and_execute(
        self,
        proposal: ToolExecutionProposal,
    ) -> Tuple[int, Any]:
        claim = self.claim(proposal)
        return await self.execute_claimed(proposal, claim)


__all__ = [
    "CanonicalToolExecutionAdmission",
    "ToolExecutionProposal",
    "ToolProposalAdmissionDenied",
]
