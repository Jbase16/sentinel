from __future__ import annotations

from dataclasses import dataclass

from ..contracts.models import BaselineSignature, DeltaVector
from ..contracts.enums import DeltaSeverity


@dataclass
class DeltaEngine:
    """
    Deterministic differ. Agent can improve similarity scoring but must preserve contract outputs.
    """
    def diff(self, base: BaselineSignature, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> DeltaVector:
        status_delta = status - base.status_code
        # naive metric: use status + timing as first pass; Agent can add structural hashing comparisons.
        timing_delta = None
        if base.total_ms is not None:
            timing_delta = total_ms - base.total_ms

        severity = DeltaSeverity.INFO
        notes: list[str] = []
        if status_delta != 0:
            severity = DeltaSeverity.LOW
            notes.append(f"status_delta={status_delta}")
        if timing_delta is not None and abs(timing_delta) >= 1500:
            severity = DeltaSeverity.MEDIUM
            notes.append(f"timing_delta_ms={timing_delta}")

        return DeltaVector(
            status_delta=status_delta if status_delta != 0 else None,
            body_length_delta=None,
            structural_delta=0.0,
            timing_delta_ms=timing_delta,
            severity=severity,
            notes=notes,
        )
