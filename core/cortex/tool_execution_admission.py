"""Canonical admission adapter for AI and scheduler tool proposals.

Proposal producers describe work; they do not own execution authority.  This
adapter turns a tool proposal into one exact ``CandidateAction`` and delegates
both claim issuance and claim consumption to ``PolicyExecutor``.  The wrapped
transport is therefore unreachable without a live, single-use executor claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Tuple

from core.cortex.execution_policy import (
    CandidateAction,
    PolicyExecutor,
    ProposalExecutionClaim,
)
from core.safety.action_classifier import AUTHZ_PROBE, SAFE_READ
from core.safety.provenance import body_hash


_PROPOSAL_SOURCES = frozenset({"ai_action_dispatcher", "strategos"})


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
