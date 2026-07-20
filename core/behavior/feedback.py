"""Passive conversion of terminal behavioral receipts into graph dispositions.

The adapter is intentionally narrow.  It recognizes only the established
three-leg authorization receipt schema and never treats a successfully executed
compiled setup sequence as proof that an authorization boundary held.  It has no
transport, cannot reserve budget, and cannot execute or promote an experiment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import islice
from typing import Any, Dict, Iterable, Optional, Tuple

from .closure import ObligationDisposition
from .normalize import stable_hash
from .obligations import BLOCKED, OPEN, UPHELD, VIOLATED, SecurityObligationGraph
from .receipts import (
    ABORTED,
    COMPLETED,
    RESERVED,
    BehavioralExecutionReceipt,
    BehavioralReceiptContext,
    ReceiptStoreError,
)

RECEIPT_FEEDBACK_MODE = "behavioral_receipt_feedback_v1"
_FEEDBACK_STATUSES = frozenset({"empty", "ready", "no_dispositions"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")


class ReceiptFeedbackDenied(ValueError):
    """Raised when supplied receipt evidence cannot be trusted or bound exactly."""


@dataclass(frozen=True)
class ReceiptFeedbackDiagnostics:
    receipts_seen: int
    dispositions_created: int
    unbound_receipts: int
    unsupported_receipts: int

    def __post_init__(self) -> None:
        values = vars(self).values()
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ) or self.receipts_seen != (
            self.dispositions_created
            + self.unbound_receipts
            + self.unsupported_receipts
        ):
            raise ValueError("receipt feedback diagnostics are inconsistent")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _batch_payload(
    *,
    status: str,
    graph_digest: str,
    receipt_refs: Tuple[str, ...],
    dispositions: Tuple[ObligationDisposition, ...],
    diagnostics: ReceiptFeedbackDiagnostics,
) -> Dict[str, Any]:
    return {
        "status": status,
        "graph_digest": graph_digest,
        "receipt_refs": list(receipt_refs),
        "dispositions": [item.to_dict() for item in dispositions],
        "diagnostics": diagnostics.to_dict(),
        "mode": RECEIPT_FEEDBACK_MODE,
        "executable": False,
    }


@dataclass(frozen=True)
class ReceiptDispositionBatch:
    batch_id: str
    status: str
    graph_digest: str
    receipt_refs: Tuple[str, ...]
    dispositions: Tuple[ObligationDisposition, ...]
    diagnostics: ReceiptFeedbackDiagnostics
    mode: str = RECEIPT_FEEDBACK_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _batch_payload(
            status=self.status,
            graph_digest=self.graph_digest,
            receipt_refs=self.receipt_refs,
            dispositions=self.dispositions,
            diagnostics=self.diagnostics,
        )
        expected_status = (
            "empty"
            if self.diagnostics.receipts_seen == 0
            else "ready" if self.dispositions else "no_dispositions"
        )
        obligation_ids = tuple(item.obligation_id for item in self.dispositions)
        if (
            self.batch_id != stable_hash("receipt_disposition_batch", payload)
            or self.status != expected_status
            or self.status not in _FEEDBACK_STATUSES
            or self.mode != RECEIPT_FEEDBACK_MODE
            or self.executable
            or not isinstance(self.graph_digest, str)
            or not self.graph_digest.startswith("security_obligation_graph:")
            or _HASH_REF.fullmatch(self.graph_digest) is None
            or tuple(sorted(set(self.receipt_refs))) != self.receipt_refs
            or any(
                _HASH_REF.fullmatch(item) is None
                or not item.startswith("behavioral_receipt:")
                for item in self.receipt_refs
            )
            or len(self.receipt_refs) != self.diagnostics.receipts_seen
            or obligation_ids != tuple(sorted(set(obligation_ids)))
            or len(self.dispositions) != self.diagnostics.dispositions_created
        ):
            raise ValueError("receipt disposition batch contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "batch_id": self.batch_id,
            **_batch_payload(
                status=self.status,
                graph_digest=self.graph_digest,
                receipt_refs=self.receipt_refs,
                dispositions=self.dispositions,
                diagnostics=self.diagnostics,
            ),
        }


def _receipt_ref(receipt: BehavioralExecutionReceipt) -> str:
    return f"behavioral_receipt:{receipt.fingerprint}"


def _disposition_status(outcome: Dict[str, Any]) -> Tuple[str, str]:
    execution = outcome.get("execution")
    if outcome.get("status") == "aborted":
        return BLOCKED, "authorization_execution_aborted"
    if not isinstance(execution, dict):
        raise ReceiptFeedbackDenied("receipt_execution_summary_is_missing")
    verdict = execution.get("legacy_verdict")
    if verdict == "BOLA_CONFIRMED":
        return VIOLATED, "bola_cross_read_confirmed"
    if verdict == "DENIED":
        return UPHELD, "authorization_boundary_denied"
    if verdict == "NO_CROSS_READ":
        return UPHELD, "victim_private_marker_absent"
    if verdict == "AMBIGUOUS":
        return BLOCKED, "authorization_evidence_ambiguous"
    if verdict == "ERROR":
        return BLOCKED, "authorization_execution_error"
    raise ReceiptFeedbackDenied("receipt_authorization_verdict_is_unknown")


class ReceiptDispositionAdapter:
    """Bind terminal authorization receipts to exact open graph obligations."""

    def __init__(self, *, max_receipts: int = 512) -> None:
        if isinstance(max_receipts, bool) or not isinstance(max_receipts, int):
            raise TypeError("max_receipts must be an integer")
        if max_receipts <= 0:
            raise ValueError("max_receipts must be positive")
        self.max_receipts = max_receipts

    @staticmethod
    def _authorization_obligation(
        graph: SecurityObligationGraph,
        proposal_id: str,
    ):
        matches = tuple(
            item
            for item in graph.obligations
            if item.status == OPEN
            and item.kind == "authorization_counterexample"
            and item.source_kind == "authorization_proposal"
            and item.risk_class == "read"
            and proposal_id in item.evidence_refs
        )
        if len(matches) != 1:
            raise ReceiptFeedbackDenied("receipt_proposal_has_no_exact_open_obligation")
        return matches[0]

    def adapt(
        self,
        graph: SecurityObligationGraph,
        receipts: Iterable[BehavioralExecutionReceipt] = (),
        *,
        expected_context: Optional[BehavioralReceiptContext] = None,
    ) -> ReceiptDispositionBatch:
        if not isinstance(graph, SecurityObligationGraph):
            raise TypeError("graph must be a SecurityObligationGraph")
        if isinstance(receipts, (str, bytes)):
            raise TypeError("receipts must contain BehavioralExecutionReceipt values")
        receipt_values = tuple(islice(receipts, self.max_receipts + 1))
        if len(receipt_values) > self.max_receipts:
            raise ReceiptFeedbackDenied("receipt_feedback_limit_exceeded")
        if receipt_values and not isinstance(expected_context, BehavioralReceiptContext):
            raise ReceiptFeedbackDenied("receipt_feedback_context_is_required")

        receipt_refs = []
        dispositions = []
        disposition_obligations = set()
        unbound = 0
        unsupported = 0
        for receipt in receipt_values:
            if not isinstance(receipt, BehavioralExecutionReceipt):
                raise TypeError(
                    "receipts must contain BehavioralExecutionReceipt values"
                )
            try:
                validated = BehavioralExecutionReceipt.from_dict(receipt.to_dict())
            except ReceiptStoreError as exc:
                raise ReceiptFeedbackDenied("receipt_contract_is_invalid") from exc
            if validated.context != expected_context:
                raise ReceiptFeedbackDenied("receipt_feedback_context_mismatch")
            receipt_ref = _receipt_ref(validated)
            if receipt_ref in receipt_refs:
                raise ReceiptFeedbackDenied("duplicate_receipt_feedback")
            receipt_refs.append(receipt_ref)

            if validated.state == RESERVED:
                raise ReceiptFeedbackDenied("receipt_feedback_is_not_terminal")
            if validated.state == ABORTED:
                # Aborted store receipts contain no selected proposal, so they cannot
                # be attached to an exact obligation without inventing a binding.
                unbound += 1
                continue
            if validated.state != COMPLETED or validated.outcome is None:
                raise ReceiptFeedbackDenied("receipt_feedback_terminal_state_is_invalid")
            outcome = validated.outcome
            if outcome.get("kind") == "compiled_sequence":
                # A setup sequence can prove that owned state was manufactured and
                # cleaned up.  It cannot prove a cross-principal boundary verdict.
                unsupported += 1
                continue
            plan = outcome.get("plan")
            if not isinstance(plan, dict):
                raise ReceiptFeedbackDenied("receipt_plan_summary_is_missing")
            proposal_id = plan.get("selected_proposal_id")
            if proposal_id is None:
                unbound += 1
                continue
            if not isinstance(proposal_id, str):
                raise ReceiptFeedbackDenied("receipt_proposal_reference_is_invalid")
            obligation = self._authorization_obligation(graph, proposal_id)
            if obligation.obligation_id in disposition_obligations:
                raise ReceiptFeedbackDenied("multiple_receipts_resolve_one_obligation")
            status, reason_code = _disposition_status(outcome)
            disposition_obligations.add(obligation.obligation_id)
            dispositions.append(
                ObligationDisposition.create(
                    obligation_id=obligation.obligation_id,
                    status=status,
                    evidence_refs=(receipt_ref,),
                    reason_code=reason_code,
                )
            )

        ordered_refs = tuple(sorted(receipt_refs))
        ordered_dispositions = tuple(
            sorted(dispositions, key=lambda item: item.obligation_id)
        )
        diagnostics = ReceiptFeedbackDiagnostics(
            receipts_seen=len(receipt_values),
            dispositions_created=len(ordered_dispositions),
            unbound_receipts=unbound,
            unsupported_receipts=unsupported,
        )
        status = (
            "empty"
            if not receipt_values
            else "ready" if ordered_dispositions else "no_dispositions"
        )
        payload = _batch_payload(
            status=status,
            graph_digest=graph.graph_digest,
            receipt_refs=ordered_refs,
            dispositions=ordered_dispositions,
            diagnostics=diagnostics,
        )
        return ReceiptDispositionBatch(
            batch_id=stable_hash("receipt_disposition_batch", payload),
            status=status,
            graph_digest=graph.graph_digest,
            receipt_refs=ordered_refs,
            dispositions=ordered_dispositions,
            diagnostics=diagnostics,
        )


__all__ = [
    "RECEIPT_FEEDBACK_MODE",
    "ReceiptDispositionAdapter",
    "ReceiptDispositionBatch",
    "ReceiptFeedbackDenied",
    "ReceiptFeedbackDiagnostics",
]
