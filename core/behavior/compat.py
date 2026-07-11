"""Static compatibility checks between proposal mode and the legacy BOLA planner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

from .proposals import ProposalBatch


@dataclass(frozen=True)
class BolaCompatibilityReport:
    proposal_labels: Tuple[str, ...]
    legacy_labels: Tuple[str, ...]
    matched_labels: Tuple[str, ...]
    missing_from_proposals: Tuple[str, ...]
    additional_proposal_labels: Tuple[str, ...]
    legacy_pair_detected: bool
    candidate_equivalent: bool
    mode: str = "static_comparison_only"
    executable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "executable": self.executable,
            "legacy_pair_detected": self.legacy_pair_detected,
            "candidate_equivalent": self.candidate_equivalent,
            "proposal_labels": list(self.proposal_labels),
            "legacy_labels": list(self.legacy_labels),
            "matched_labels": list(self.matched_labels),
            "missing_from_proposals": list(self.missing_from_proposals),
            "additional_proposal_labels": list(self.additional_proposal_labels),
        }


def compare_with_legacy_bola(
    batch: ProposalBatch,
    source_records: Sequence[Mapping[str, Any]],
    peer_records: Sequence[Mapping[str, Any]],
) -> BolaCompatibilityReport:
    """Compare candidate operation labels without replaying a single request."""
    from core.wraith.bola_replay import (
        detect_swap_pairs,
        find_object_scoped_ops,
        parse_capture,
    )

    source = parse_capture([dict(record) for record in source_records])
    peer = parse_capture([dict(record) for record in peer_records])
    pairs = detect_swap_pairs(source, peer)
    legacy_labels: set[str] = set()
    if pairs:
        _, source_value, _ = pairs[0]
        legacy_labels = {op.label for op in find_object_scoped_ops(source, source_value)}

    proposal_labels = set(batch.operation_labels())
    matched = proposal_labels & legacy_labels
    missing = legacy_labels - proposal_labels
    additional = proposal_labels - legacy_labels
    return BolaCompatibilityReport(
        proposal_labels=tuple(sorted(proposal_labels)),
        legacy_labels=tuple(sorted(legacy_labels)),
        matched_labels=tuple(sorted(matched)),
        missing_from_proposals=tuple(sorted(missing)),
        additional_proposal_labels=tuple(sorted(additional)),
        legacy_pair_detected=bool(pairs),
        candidate_equivalent=proposal_labels == legacy_labels,
    )
