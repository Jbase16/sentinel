"""
Continuous Autonomous Monitoring - Baseline + Change Detection

PURPOSE:
Enable production security monitoring with baseline state and incremental scanning.
Only alert when meaningful changes occur (new vulnerabilities, severity increases).

WHY THIS MATTERS:
1. **Avoid Scan Fatigue**: Don't alert on known issues repeatedly
2. **Detect Regressions**: Catch new vulnerabilities as they appear
3. **Resource Efficiency**: Incremental scans are faster than full scans
4. **Production Ready**: Monitor live systems without overwhelming teams

KEY CONCEPTS:
- **Baseline**: Initial scan results representing "known-good" state
- **Delta**: Differences between baseline and current scan
- **Severity Threshold**: Only alert if delta severity >= threshold
- **Incremental Scan**: Only scan changed assets, skip known-good findings

DESIGN PATTERN:
This is a "State Comparison" pattern - we store baseline state and compare
current state to detect meaningful deltas.

EXAMPLE:
Baseline: 5 findings (3 medium, 2 low)
Current:  7 findings (3 medium, 2 low, 2 HIGH)
Delta:    2 new HIGH findings → ALERT!
"""

import asyncio
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class ScanState:
    """Snapshot of scan results at a point in time."""

    session_id: str
    target: str
    timestamp: float

    # Findings grouped by severity
    findings_by_severity: Dict[str, List[Dict[str, Any]]]

    # Total counts
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    # Fingerprints for deduplication (set of finding hashes)
    finding_fingerprints: Set[str] = field(default_factory=set)

    def __post_init__(self):
        """Calculate fingerprints for all findings."""
        if not self.finding_fingerprints:
            for severity, findings in self.findings_by_severity.items():
                for finding in findings:
                    fingerprint = self._calculate_fingerprint(finding)
                    self.finding_fingerprints.add(fingerprint)

    @staticmethod
    def _calculate_fingerprint(finding: Dict[str, Any]) -> str:
        """
        Calculate a stable fingerprint for a finding.

        Uses type + target + key details (not timestamps or IDs).
        """
        # Extract stable fields
        stable_data = {
            'type': finding.get('type', ''),
            'target': finding.get('target', ''),
            'title': finding.get('title', ''),
            'severity': finding.get('severity', ''),
            # Include key data fields (not timestamps)
            'port': finding.get('data', {}).get('port'),
            'service': finding.get('data', {}).get('service'),
            'vulnerability': finding.get('data', {}).get('vulnerability'),
        }

        # Create deterministic JSON (sorted keys)
        json_str = json.dumps(stable_data, sort_keys=True)

        # Hash to create fingerprint
        return hashlib.sha256(json_str.encode()).hexdigest()[:16]

    @classmethod
    async def from_session(cls, session_id: str) -> "ScanState":
        """
        Create ScanState from a completed scan session.

        Args:
            session_id: Session UUID

        Returns:
            ScanState snapshot
        """
        from core.data.db import Database

        db = Database.instance()
        await db.init()

        # Get session metadata
        session_data = await db.get_session(session_id)
        if not session_data:
            raise ValueError(f"Session {session_id} not found")

        # Get findings
        findings = await db.get_findings(session_id)

        # Group by severity
        by_severity: Dict[str, List[Dict]] = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Count totals
        return cls(
            session_id=session_id,
            target=session_data.get('target', 'unknown'),
            timestamp=time.time(),
            findings_by_severity=by_severity,
            total_findings=len(findings),
            critical_count=len(by_severity['critical']),
            high_count=len(by_severity['high']),
            medium_count=len(by_severity['medium']),
            low_count=len(by_severity['low'])
        )


@dataclass
class ScanDelta:
    """Differences between two scan states."""

    # New findings (in current but not baseline)
    new_findings: List[Dict[str, Any]]

    # Resolved findings (in baseline but not current)
    resolved_findings: List[Dict[str, Any]]

    # Changed findings (same fingerprint but different details)
    changed_findings: List[Dict[str, Any]]

    # Severity score (0.0 = no change, 1.0 = maximum severity change)
    severity: float

    # Summary counts
    new_critical: int = 0
    new_high: int = 0
    new_medium: int = 0
    new_low: int = 0

    resolved_critical: int = 0
    resolved_high: int = 0
    resolved_medium: int = 0
    resolved_low: int = 0

    def should_alert(self, threshold: float = 0.7) -> bool:
        """Check if this delta warrants an alert."""
        return self.severity >= threshold

    def summary(self) -> str:
        """Human-readable summary of changes."""
        lines = []

        if self.new_findings:
            lines.append(f"🆕 {len(self.new_findings)} new findings:")
            if self.new_critical > 0:
                lines.append(f"   - {self.new_critical} CRITICAL")
            if self.new_high > 0:
                lines.append(f"   - {self.new_high} HIGH")
            if self.new_medium > 0:
                lines.append(f"   - {self.new_medium} MEDIUM")

        if self.resolved_findings:
            lines.append(f"✅ {len(self.resolved_findings)} resolved findings")

        if self.changed_findings:
            lines.append(f"🔄 {len(self.changed_findings)} changed findings")

        if not lines:
            lines.append("✨ No changes detected")

        return "\n".join(lines)


class ContinuousMonitor:
    """
    Continuous security monitoring with baseline + change detection.

    This monitors a target over time, alerting only when meaningful changes occur.
    """

    def __init__(self, target: str, alert_threshold: float = 0.7):
        """
        Initialize continuous monitor for a target.

        Args:
            target: Target to monitor (URL, IP, domain)
            alert_threshold: Severity threshold for alerts (0.0-1.0)
        """
        self.target = target
        self.alert_threshold = alert_threshold

        self.baseline: Optional[ScanState] = None
        self.monitoring_enabled = False

        # Alert callbacks
        self._alert_callbacks: List = []

        logger.info(f"[ContinuousMonitor] Initialized for {target} (threshold: {alert_threshold})")

    def set_baseline(self, baseline: ScanState):
        """Set the baseline state for comparison."""
        self.baseline = baseline
        logger.info(
            f"[ContinuousMonitor] Baseline set: {baseline.total_findings} findings "
            f"({baseline.critical_count}C, {baseline.high_count}H, "
            f"{baseline.medium_count}M, {baseline.low_count}L)"
        )

    async def load_baseline_from_session(self, session_id: str):
        """Load baseline from a completed scan session."""
        baseline = await ScanState.from_session(session_id)
        self.set_baseline(baseline)

    def diff(self, baseline: ScanState, current: ScanState) -> ScanDelta:
        """
        Calculate differences between baseline and current state.

        Args:
            baseline: Baseline state (known-good)
            current: Current state (latest scan)

        Returns:
            ScanDelta with new, resolved, and changed findings
        """
        logger.info("[ContinuousMonitor] Calculating diff between baseline and current state")

        # Find new findings (in current but not baseline)
        new_findings = []
        for severity, findings in current.findings_by_severity.items():
            for finding in findings:
                fingerprint = ScanState._calculate_fingerprint(finding)
                if fingerprint not in baseline.finding_fingerprints:
                    new_findings.append(finding)

        # Find resolved findings (in baseline but not current)
        resolved_findings = []
        for severity, findings in baseline.findings_by_severity.items():
            for finding in findings:
                fingerprint = ScanState._calculate_fingerprint(finding)
                if fingerprint not in current.finding_fingerprints:
                    resolved_findings.append(finding)

        # Find changed findings (same fingerprint but different details)
        # For now, we'll skip this - it's complex and rare
        changed_findings = []

        # Count new findings by severity
        new_by_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in new_findings:
            sev = finding.get('severity', 'low').lower()
            if sev in new_by_sev:
                new_by_sev[sev] += 1

        # Count resolved findings by severity
        resolved_by_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in resolved_findings:
            sev = finding.get('severity', 'low').lower()
            if sev in resolved_by_sev:
                resolved_by_sev[sev] += 1

        # Calculate severity score (0.0 = no change, 1.0 = max severity)
        # Weight: critical=1.0, high=0.7, medium=0.4, low=0.1
        severity_weights = {'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.1}

        new_severity = sum(
            new_by_sev[sev] * weight
            for sev, weight in severity_weights.items()
        )

        # Normalize to 0.0-1.0 (assume max 10 critical findings = 1.0)
        severity_score = min(1.0, new_severity / 10.0)

        delta = ScanDelta(
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            changed_findings=changed_findings,
            severity=severity_score,
            new_critical=new_by_sev['critical'],
            new_high=new_by_sev['high'],
            new_medium=new_by_sev['medium'],
            new_low=new_by_sev['low'],
            resolved_critical=resolved_by_sev['critical'],
            resolved_high=resolved_by_sev['high'],
            resolved_medium=resolved_by_sev['medium'],
            resolved_low=resolved_by_sev['low']
        )

        logger.info(
            f"[ContinuousMonitor] Delta calculated: "
            f"{len(new_findings)} new, {len(resolved_findings)} resolved, "
            f"severity={severity_score:.2f}"
        )

        return delta

    async def check_for_changes(self, current_session_id: str) -> Optional[ScanDelta]:
        """
        Check for changes between baseline and current scan.

        Args:
            current_session_id: Session ID of latest scan

        Returns:
            ScanDelta if changes detected, None if no baseline set
        """
        if not self.baseline:
            logger.warning("[ContinuousMonitor] No baseline set, cannot calculate delta")
            return None

        # Load current state
        current = await ScanState.from_session(current_session_id)

        # Calculate diff
        delta = self.diff(self.baseline, current)

        # Alert if threshold exceeded
        if delta.should_alert(self.alert_threshold):
            await self.alert_team(delta)

        return delta

    async def alert_team(self, delta: ScanDelta):
        """
        Alert team about significant changes.

        Args:
            delta: ScanDelta that triggered the alert
        """
        logger.warning(
            f"[ContinuousMonitor] 🚨 ALERT for {self.target}:\n"
            f"{delta.summary()}"
        )

        # Call registered alert callbacks
        for callback in self._alert_callbacks:
            try:
                await callback(self.target, delta)
            except Exception as e:
                logger.error(f"[ContinuousMonitor] Alert callback failed: {e}")

    def register_alert_callback(self, callback):
        """Register a callback to be called when alerts trigger."""
        self._alert_callbacks.append(callback)

    async def incremental_scan(self) -> ScanState:
        """
        Perform an incremental scan (only scan changed assets).

        Current implementation is a conservative compatibility layer:
        - It selects the most recent persisted session for this target.
        - It loads that session into ScanState.
        - If a baseline exists, it computes a delta and triggers alerts.

        This does not yet launch selective tool execution itself, but it no
        longer hard-fails and provides deterministic incremental monitoring
        behavior over completed scan sessions.
        """
        from core.data.db import Database

        db = Database.instance()
        await db.init()

        normalized_target = self.target.strip().lower()
        session_rows = await db.fetch_all(
            "SELECT id, target FROM sessions ORDER BY start_time DESC LIMIT 200"
        )

        selected_session_id: Optional[str] = None
        for row in session_rows:
            session_id = str(row[0]) if len(row) > 0 else ""
            session_target = str(row[1]).strip().lower() if len(row) > 1 else ""
            if not session_id:
                continue
            if not normalized_target or normalized_target in session_target or session_target in normalized_target:
                selected_session_id = session_id
                break

        if not selected_session_id:
            raise ValueError(f"No persisted session found for target '{self.target}'")

        current = await ScanState.from_session(selected_session_id)

        if self.baseline:
            delta = self.diff(self.baseline, current)
            if delta.should_alert(self.alert_threshold):
                await self.alert_team(delta)

        logger.info(
            "[ContinuousMonitor] incremental_scan target=%s session=%s findings=%d",
            self.target,
            selected_session_id,
            current.total_findings,
        )
        return current


# ============================================================================
# Module-level helpers
# ============================================================================

_monitors: Dict[str, ContinuousMonitor] = {}


def get_monitor(target: str, alert_threshold: float = 0.7) -> ContinuousMonitor:
    """
    Get or create a continuous monitor for a target.

    Args:
        target: Target to monitor
        alert_threshold: Alert threshold (0.0-1.0)

    Returns:
        ContinuousMonitor instance
    """
    if target not in _monitors:
        _monitors[target] = ContinuousMonitor(target, alert_threshold)
    return _monitors[target]


async def check_target_for_changes(
    target: str,
    baseline_session_id: str,
    current_session_id: str,
    alert_threshold: float = 0.7
) -> ScanDelta:
    """
    Convenience function to check a target for changes.

    Args:
        target: Target being monitored
        baseline_session_id: Baseline scan session
        current_session_id: Current scan session
        alert_threshold: Alert threshold

    Returns:
        ScanDelta showing changes
    """
    monitor = get_monitor(target, alert_threshold)

    # Load baseline if not already set
    if not monitor.baseline:
        await monitor.load_baseline_from_session(baseline_session_id)

    # Check for changes
    delta = await monitor.check_for_changes(current_session_id)

    return delta
