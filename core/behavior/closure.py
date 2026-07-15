"""Passive, evidence-referenced closure over a security-obligation graph.

Closure is intentionally narrower than vulnerability absence.  It records which
derived obligations remain open, are blocked, or have evidence-referenced terminal
dispositions, and it can certify only that the current evidence frontier reached
an unchanged derivation round.  It performs no target I/O and grants no execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import islice
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from .normalize import stable_hash
from .obligations import (
    BLOCKED,
    OPEN,
    SUBSUMED,
    UNREACHABLE,
    UPHELD,
    VIOLATED,
    SecurityObligation,
    SecurityObligationGraph,
)

SECURITY_CLOSURE_MODE = "behavioral_security_closure_v1"

FINDING = "finding"
CONDITIONALLY_CLOSED = "conditionally_closed"
CLOSURE_STATUSES = frozenset({OPEN, BLOCKED, FINDING, CONDITIONALLY_CLOSED})
TERMINAL_DISPOSITIONS = frozenset({UPHELD, VIOLATED, SUBSUMED, BLOCKED, UNREACHABLE})
MAX_DISPOSITION_EVIDENCE_REFS = 64

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_REASON_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_HARD_BLOCKERS = frozenset(
    {
        "no_security_obligations",
        "obligation_limit_truncated",
        "dependency_limit_truncated",
        "evidence_limit_truncated",
        "evidence_blocked",
        "obligation_unreachable",
    }
)
_CLOSURE_BLOCKERS = _HARD_BLOCKERS | {"fixed_point_not_reached"}


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    if not isinstance(value, str) or _HASH_REF.fullmatch(value) is None:
        return False
    return prefix is None or value.startswith(f"{prefix}:")


def _disposition_payload(
    *,
    obligation_id: str,
    status: str,
    evidence_refs: Sequence[str],
    reason_code: str,
    covered_by_obligation_id: Optional[str],
) -> Dict[str, Any]:
    return {
        "obligation_id": obligation_id,
        "status": status,
        "evidence_refs": list(evidence_refs),
        "reason_code": reason_code,
        "covered_by_obligation_id": covered_by_obligation_id,
    }


@dataclass(frozen=True)
class ObligationDisposition:
    """One content-addressed, evidence-referenced terminal decision."""

    disposition_id: str
    obligation_id: str
    status: str
    evidence_refs: Tuple[str, ...]
    reason_code: str
    covered_by_obligation_id: Optional[str] = None
    mode: str = SECURITY_CLOSURE_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _disposition_payload(
            obligation_id=self.obligation_id,
            status=self.status,
            evidence_refs=self.evidence_refs,
            reason_code=self.reason_code,
            covered_by_obligation_id=self.covered_by_obligation_id,
        )
        covered_by_valid = (
            self.status == SUBSUMED
            and _hash_ref(
                self.covered_by_obligation_id,
                "security_obligation",
            )
        ) or (self.status != SUBSUMED and self.covered_by_obligation_id is None)
        if (
            self.disposition_id
            != stable_hash("security_obligation_disposition", payload)
            or self.mode != SECURITY_CLOSURE_MODE
            or self.executable
            or not _hash_ref(self.obligation_id, "security_obligation")
            or self.status not in TERMINAL_DISPOSITIONS
            or not self.evidence_refs
            or len(self.evidence_refs) > MAX_DISPOSITION_EVIDENCE_REFS
            or tuple(sorted(set(self.evidence_refs))) != self.evidence_refs
            or any(not _hash_ref(item) for item in self.evidence_refs)
            or _REASON_CODE.fullmatch(self.reason_code) is None
            or not covered_by_valid
        ):
            raise ValueError("security obligation disposition contract is invalid")

    @classmethod
    def create(
        cls,
        *,
        obligation_id: str,
        status: str,
        evidence_refs: Iterable[str],
        reason_code: str,
        covered_by_obligation_id: Optional[str] = None,
    ) -> "ObligationDisposition":
        consumed_evidence = tuple(
            islice(evidence_refs, MAX_DISPOSITION_EVIDENCE_REFS + 1)
        )
        if len(consumed_evidence) > MAX_DISPOSITION_EVIDENCE_REFS:
            raise ValueError("security obligation disposition evidence limit exceeded")
        ordered_evidence = tuple(sorted(set(consumed_evidence)))
        payload = _disposition_payload(
            obligation_id=obligation_id,
            status=status,
            evidence_refs=ordered_evidence,
            reason_code=reason_code,
            covered_by_obligation_id=covered_by_obligation_id,
        )
        return cls(
            disposition_id=stable_hash(
                "security_obligation_disposition",
                payload,
            ),
            obligation_id=obligation_id,
            status=status,
            evidence_refs=ordered_evidence,
            reason_code=reason_code,
            covered_by_obligation_id=covered_by_obligation_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "disposition_id": self.disposition_id,
            **_disposition_payload(
                obligation_id=self.obligation_id,
                status=self.status,
                evidence_refs=self.evidence_refs,
                reason_code=self.reason_code,
                covered_by_obligation_id=self.covered_by_obligation_id,
            ),
            "mode": self.mode,
            "executable": self.executable,
        }


def _certificate_payload(
    *,
    status: str,
    target_ref: str,
    graph_digest: str,
    previous_graph_digest: Optional[str],
    disposition_digest: str,
    fixed_point: bool,
    derivation_round: int,
    counts: Dict[str, int],
    unresolved_ids: Sequence[str],
    blocked_ids: Sequence[str],
    finding_ids: Sequence[str],
    blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "status": status,
        "target_ref": target_ref,
        "graph_digest": graph_digest,
        "previous_graph_digest": previous_graph_digest,
        "disposition_digest": disposition_digest,
        "fixed_point": fixed_point,
        "derivation_round": derivation_round,
        "counts": counts,
        "unresolved_ids": list(unresolved_ids),
        "blocked_ids": list(blocked_ids),
        "finding_ids": list(finding_ids),
        "blockers": list(blockers),
    }


@dataclass(frozen=True)
class SecurityClosureCertificate:
    """A redacted statement about one bounded evidence frontier."""

    certificate_id: str
    status: str
    target_ref: str
    graph_digest: str
    previous_graph_digest: Optional[str]
    disposition_digest: str
    fixed_point: bool
    derivation_round: int
    open_count: int
    upheld_count: int
    violated_count: int
    subsumed_count: int
    blocked_count: int
    unreachable_count: int
    unresolved_ids: Tuple[str, ...]
    blocked_ids: Tuple[str, ...]
    finding_ids: Tuple[str, ...]
    blockers: Tuple[str, ...]
    mode: str = SECURITY_CLOSURE_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        counts = self.counts()
        payload = _certificate_payload(
            status=self.status,
            target_ref=self.target_ref,
            graph_digest=self.graph_digest,
            previous_graph_digest=self.previous_graph_digest,
            disposition_digest=self.disposition_digest,
            fixed_point=self.fixed_point,
            derivation_round=self.derivation_round,
            counts=counts,
            unresolved_ids=self.unresolved_ids,
            blocked_ids=self.blocked_ids,
            finding_ids=self.finding_ids,
            blockers=self.blockers,
        )
        hard_blocked = bool(set(self.blockers) & _HARD_BLOCKERS)
        if self.finding_ids:
            expected_status = FINDING
        elif hard_blocked:
            expected_status = BLOCKED
        elif self.unresolved_ids or not self.fixed_point:
            expected_status = OPEN
        else:
            expected_status = CONDITIONALLY_CLOSED
        valid_counts = all(
            not isinstance(value, bool) and isinstance(value, int) and value >= 0
            for value in counts.values()
        )
        valid_ids = all(
            tuple(sorted(set(values))) == values
            and all(_hash_ref(item, "security_obligation") for item in values)
            for values in (
                self.unresolved_ids,
                self.blocked_ids,
                self.finding_ids,
            )
        )
        id_sets = (
            set(self.unresolved_ids),
            set(self.blocked_ids),
            set(self.finding_ids),
        )
        ids_are_disjoint = all(
            not left & right
            for index, left in enumerate(id_sets)
            for right in id_sets[index + 1 :]
        )
        fixed_point_valid = not self.fixed_point or (
            self.derivation_round >= 2
            and self.previous_graph_digest == self.graph_digest
        )
        conditional_valid = self.status != CONDITIONALLY_CLOSED or (
            sum(counts.values()) > 0
            and self.open_count == 0
            and self.violated_count == 0
            and self.blocked_count == 0
            and self.unreachable_count == 0
            and not self.blockers
        )
        if (
            self.certificate_id != stable_hash("security_closure_certificate", payload)
            or self.status not in CLOSURE_STATUSES
            or self.status != expected_status
            or self.mode != SECURITY_CLOSURE_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.graph_digest, "security_obligation_graph")
            or (
                self.previous_graph_digest is not None
                and not _hash_ref(
                    self.previous_graph_digest,
                    "security_obligation_graph",
                )
            )
            or not _hash_ref(
                self.disposition_digest,
                "security_obligation_dispositions",
            )
            or isinstance(self.fixed_point, bool) is False
            or isinstance(self.derivation_round, bool)
            or not isinstance(self.derivation_round, int)
            or self.derivation_round <= 0
            or not valid_counts
            or not valid_ids
            or not ids_are_disjoint
            or len(self.unresolved_ids) != self.open_count
            or len(self.blocked_ids) != self.blocked_count + self.unreachable_count
            or len(self.finding_ids) != self.violated_count
            or tuple(sorted(set(self.blockers))) != self.blockers
            or not set(self.blockers).issubset(_CLOSURE_BLOCKERS)
            or any(_REASON_CODE.fullmatch(item) is None for item in self.blockers)
            or not fixed_point_valid
            or not conditional_valid
        ):
            raise ValueError("security closure certificate contract is invalid")

    def counts(self) -> Dict[str, int]:
        return {
            OPEN: self.open_count,
            UPHELD: self.upheld_count,
            VIOLATED: self.violated_count,
            SUBSUMED: self.subsumed_count,
            BLOCKED: self.blocked_count,
            UNREACHABLE: self.unreachable_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "certificate_id": self.certificate_id,
            **_certificate_payload(
                status=self.status,
                target_ref=self.target_ref,
                graph_digest=self.graph_digest,
                previous_graph_digest=self.previous_graph_digest,
                disposition_digest=self.disposition_digest,
                fixed_point=self.fixed_point,
                derivation_round=self.derivation_round,
                counts=self.counts(),
                unresolved_ids=self.unresolved_ids,
                blocked_ids=self.blocked_ids,
                finding_ids=self.finding_ids,
                blockers=self.blockers,
            ),
        }


def _same_security_question(
    left: SecurityObligation,
    right: SecurityObligation,
) -> bool:
    return (
        left.target_ref == right.target_ref
        and left.property_kind == right.property_kind
        and left.subject_ref == right.subject_ref
        and left.risk_class == right.risk_class
        and left.requires_execution == right.requires_execution
    )


def _validate_subsumptions(
    *,
    obligations: Dict[str, SecurityObligation],
    dispositions: Dict[str, ObligationDisposition],
    final_status: Dict[str, str],
) -> None:
    coverage = {
        obligation_id: item.covered_by_obligation_id
        for obligation_id, item in dispositions.items()
        if item.status == SUBSUMED
    }
    for obligation_id, covered_by_id in coverage.items():
        if covered_by_id is None or covered_by_id not in obligations:
            raise ValueError("subsumed obligation coverage target is unknown")
        if covered_by_id == obligation_id:
            raise ValueError("subsumed obligation cannot cover itself")
        if not _same_security_question(
            obligations[obligation_id],
            obligations[covered_by_id],
        ):
            raise ValueError(
                "subsumed obligation coverage is not semantically equivalent"
            )

        visited = {obligation_id}
        cursor = covered_by_id
        while cursor in coverage:
            if cursor in visited:
                raise ValueError("subsumed obligation coverage contains a cycle")
            visited.add(cursor)
            next_cursor = coverage[cursor]
            if next_cursor is None:
                raise ValueError("subsumed obligation coverage target is invalid")
            cursor = next_cursor
        if final_status.get(cursor) != UPHELD:
            raise ValueError(
                "subsumed obligation is not covered by an upheld obligation"
            )


class SecurityClosureEvaluator:
    """Evaluate a graph without executing, discovering, or resolving evidence."""

    def evaluate(
        self,
        graph: SecurityObligationGraph,
        *,
        dispositions: Iterable[ObligationDisposition] = (),
        previous_graph: Optional[SecurityObligationGraph] = None,
        derivation_round: int = 1,
    ) -> SecurityClosureCertificate:
        if not isinstance(graph, SecurityObligationGraph):
            raise TypeError("graph must be a SecurityObligationGraph")
        if previous_graph is not None and not isinstance(
            previous_graph,
            SecurityObligationGraph,
        ):
            raise TypeError("previous_graph must be a SecurityObligationGraph")
        if isinstance(derivation_round, bool) or not isinstance(derivation_round, int):
            raise TypeError("derivation_round must be an integer")
        if derivation_round <= 0:
            raise ValueError("derivation_round must be positive")
        if previous_graph is not None and previous_graph.target_ref != graph.target_ref:
            raise ValueError("previous graph target does not match current graph")

        obligation_by_id = graph.by_id()
        disposition_by_obligation: Dict[str, ObligationDisposition] = {}
        for index, disposition in enumerate(dispositions):
            if index >= len(graph.obligations):
                raise ValueError("dispositions exceed graph obligation count")
            if not isinstance(disposition, ObligationDisposition):
                raise TypeError(
                    "dispositions must contain ObligationDisposition values"
                )
            obligation = obligation_by_id.get(disposition.obligation_id)
            if obligation is None:
                raise ValueError("disposition references an unknown obligation")
            if obligation.status != OPEN:
                raise ValueError("only open obligations can receive dispositions")
            if disposition.obligation_id in disposition_by_obligation:
                raise ValueError("an obligation cannot receive multiple dispositions")
            disposition_by_obligation[disposition.obligation_id] = disposition

        final_status = {
            obligation_id: obligation.status
            for obligation_id, obligation in obligation_by_id.items()
        }
        final_status.update(
            {
                obligation_id: disposition.status
                for obligation_id, disposition in disposition_by_obligation.items()
            }
        )
        _validate_subsumptions(
            obligations=obligation_by_id,
            dispositions=disposition_by_obligation,
            final_status=final_status,
        )
        for obligation_id, disposition in disposition_by_obligation.items():
            if disposition.status not in {UPHELD, VIOLATED, SUBSUMED}:
                continue
            unresolved_prerequisites = tuple(
                prerequisite
                for prerequisite in obligation_by_id[obligation_id].prerequisite_ids
                if final_status[prerequisite] not in {UPHELD, SUBSUMED}
            )
            if unresolved_prerequisites:
                raise ValueError(
                    "terminal disposition has unresolved prerequisite obligations"
                )

        ordered_dispositions = tuple(
            disposition_by_obligation[key] for key in sorted(disposition_by_obligation)
        )
        disposition_digest = stable_hash(
            "security_obligation_dispositions",
            [item.to_dict() for item in ordered_dispositions],
        )
        previous_graph_digest = (
            previous_graph.graph_digest if previous_graph is not None else None
        )
        fixed_point = bool(
            previous_graph is not None
            and derivation_round >= 2
            and previous_graph.graph_digest == graph.graph_digest
        )
        ids_by_status = {
            status: tuple(
                sorted(
                    obligation_id
                    for obligation_id, final in final_status.items()
                    if final == status
                )
            )
            for status in (OPEN, UPHELD, VIOLATED, SUBSUMED, BLOCKED, UNREACHABLE)
        }
        blockers = set()
        diagnostics = graph.diagnostics
        if not graph.obligations:
            blockers.add("no_security_obligations")
        if diagnostics.dropped_obligations:
            blockers.add("obligation_limit_truncated")
        if diagnostics.dropped_dependencies:
            blockers.add("dependency_limit_truncated")
        if diagnostics.dropped_evidence_refs:
            blockers.add("evidence_limit_truncated")
        if ids_by_status[BLOCKED]:
            blockers.add("evidence_blocked")
        if ids_by_status[UNREACHABLE]:
            blockers.add("obligation_unreachable")

        hard_blocked = bool(blockers)
        if ids_by_status[VIOLATED]:
            status = FINDING
        elif hard_blocked:
            status = BLOCKED
        elif ids_by_status[OPEN]:
            status = OPEN
        elif not fixed_point:
            status = OPEN
            blockers.add("fixed_point_not_reached")
        else:
            status = CONDITIONALLY_CLOSED

        ordered_blockers = tuple(sorted(blockers))
        counts = {status_name: len(ids) for status_name, ids in ids_by_status.items()}
        blocked_ids = tuple(sorted(ids_by_status[BLOCKED] + ids_by_status[UNREACHABLE]))
        payload = _certificate_payload(
            status=status,
            target_ref=graph.target_ref,
            graph_digest=graph.graph_digest,
            previous_graph_digest=previous_graph_digest,
            disposition_digest=disposition_digest,
            fixed_point=fixed_point,
            derivation_round=derivation_round,
            counts=counts,
            unresolved_ids=ids_by_status[OPEN],
            blocked_ids=blocked_ids,
            finding_ids=ids_by_status[VIOLATED],
            blockers=ordered_blockers,
        )
        return SecurityClosureCertificate(
            certificate_id=stable_hash("security_closure_certificate", payload),
            status=status,
            target_ref=graph.target_ref,
            graph_digest=graph.graph_digest,
            previous_graph_digest=previous_graph_digest,
            disposition_digest=disposition_digest,
            fixed_point=fixed_point,
            derivation_round=derivation_round,
            open_count=counts[OPEN],
            upheld_count=counts[UPHELD],
            violated_count=counts[VIOLATED],
            subsumed_count=counts[SUBSUMED],
            blocked_count=counts[BLOCKED],
            unreachable_count=counts[UNREACHABLE],
            unresolved_ids=ids_by_status[OPEN],
            blocked_ids=blocked_ids,
            finding_ids=ids_by_status[VIOLATED],
            blockers=ordered_blockers,
        )


__all__ = [
    "CLOSURE_STATUSES",
    "CONDITIONALLY_CLOSED",
    "FINDING",
    "MAX_DISPOSITION_EVIDENCE_REFS",
    "SECURITY_CLOSURE_MODE",
    "TERMINAL_DISPOSITIONS",
    "ObligationDisposition",
    "SecurityClosureCertificate",
    "SecurityClosureEvaluator",
]
