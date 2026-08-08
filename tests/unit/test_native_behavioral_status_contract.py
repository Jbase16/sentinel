"""Source contracts for the native completed-behavioral-result handoff.

The macOS app is built as an Xcode application rather than an importable Swift
package, so these checks protect the small state-selection contract alongside
the native compilation gate.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCAN_CONTROL = ROOT / "ui" / "Sources" / "Views" / "Scan" / "ScanControlView.swift"
APP_STATE = ROOT / "ui" / "Sources" / "Models" / "HelixAppState.swift"


def test_completed_behavioral_result_falls_back_after_live_state() -> None:
    source = SCAN_CONTROL.read_text(encoding="utf-8")
    live = source.index(
        "appState.engineStatus?.scanState?.behavioralOneClick"
    )
    running_guard = source.index(
        "guard !appState.isScanRunning else { return nil }",
        live,
    )
    completed = source.index(
        "return appState.apiResults?.behavioralOneClick",
        running_guard,
    )

    assert live < running_guard < completed


def test_terminal_scan_events_refresh_status_and_results() -> None:
    source = APP_STATE.read_text(encoding="utf-8")

    for terminal_case in ("case .scanCompleted:", "case .scanFailed:"):
        start = source.index(terminal_case)
        end = source.index("case .", start + len(terminal_case))
        branch = source[start:end]

        assert "self.refreshStatus()" in branch
        assert "self.refreshResults()" in branch
