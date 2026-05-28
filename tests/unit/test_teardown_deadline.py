"""
Regression tests for the interpreter-teardown deadman switch.

Two scenarios:
  1. A vanilla script that constructs a ScanSession and returns must
     exit within a reasonable time (the deadline is 10s; we allow 15s
     wall-clock to account for cold-start import time).
  2. A script that deliberately leaks a non-daemon thread (the worst-
     case scenario we're guarding against) must STILL exit, because
     the deadman switch should force it. We allow 20s for this case
     (10s deadline + import startup + buffer).

We use subprocess.run with a timeout — that gives us a deterministic
"did it exit?" answer. The earlier teardown bug was: scripts hung
indefinitely, and the only way to detect that was to time out the
parent. Now the child should self-terminate.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_script(source: str, timeout_s: float) -> subprocess.CompletedProcess:
    """Write `source` to a temp file and run it under python3 with timeout.

    Returns the completed-process result if it exited; raises if the
    timeout expired (which means the deadman switch FAILED).
    """
    # Use a tempfile under repo root so the script can import core.* cleanly.
    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", dir=str(REPO_ROOT), delete=False
    ) as f:
        f.write(source)
        script_path = f.name
    try:
        proc = subprocess.run(
            [sys.executable, "-u", script_path],
            timeout=timeout_s,
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        return proc
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass


def test_scan_session_construction_exits_cleanly():
    """A bare ScanSession construction + immediate return must exit
    within 15 seconds. This is the no-leak baseline — if even this
    fails, the deadman switch isn't installing."""
    script = textwrap.dedent("""
        from core.base.session import ScanSession
        s = ScanSession(target="http://127.0.0.1:65535")
        # Return immediately. No verify_phase, no network.
    """)
    result = _run_script(script, timeout_s=15.0)
    # Don't assert returncode==0; even returncode 130 (SIGINT) is fine
    # if the deadman switch forced exit. What we care about: it EXITED.
    assert result.returncode is not None


def test_simulated_orphan_thread_does_not_hang_interpreter():
    """If something inside SentinelForge leaks a NON-daemon thread that
    sleeps forever, the deadman switch must still force exit.

    This simulates the worst-case scenario: a real bug somewhere in
    the stack creates an orphaned thread. Before the deadman switch,
    this would hang the interpreter on `_thread._shutdown()` waiting
    for the thread to join (it never will). After the deadman switch,
    we get bounded exit time.

    We allow 20s wall-clock (10s deadline + cold-start import time
    + buffer)."""
    script = textwrap.dedent("""
        import threading, time

        # Install ScanSession first so the deadman switch arms.
        from core.base.session import ScanSession
        s = ScanSession(target="http://127.0.0.1:65535")

        # Now leak a NON-daemon thread that runs forever. Without the
        # deadman switch, this would prevent interpreter exit.
        def _leaker():
            while True:
                time.sleep(100)
        t = threading.Thread(target=_leaker, daemon=False, name="leaker")
        t.start()

        # Return immediately. The leaker thread is still running.
    """)
    result = _run_script(script, timeout_s=20.0)
    # We expect the deadman switch to fire and write its message to stderr.
    # The process should exit (returncode != None means subprocess.run
    # got an exit code; if it had hung, TimeoutExpired would have raised).
    assert result.returncode is not None, "process never exited — deadman switch broken"
    # Optionally verify the deadman message landed — informational, not
    # strict (the timer could fire AFTER stderr flush in racy cases).
    if "teardown-deadline" not in result.stderr:
        # The thread was forcibly cleaned up some other way — that's
        # still a win (exit was bounded), but log it for visibility.
        sys.stderr.write(
            "[test] note: deadman-switch message not in child stderr; "
            "exit may have come from another path. stderr was: "
            + result.stderr[-500:] + "\\n"
        )


def test_install_shutdown_deadline_is_idempotent():
    """Repeated install calls must not re-register the atexit hook —
    otherwise multiple deadman timers would fire and produce confusing
    stderr noise."""
    from core.base.teardown import install_shutdown_deadline

    # First call: installs (returns True) OR is no-op (returns False)
    # depending on whether some earlier test already triggered it.
    first = install_shutdown_deadline(seconds=10.0)
    second = install_shutdown_deadline(seconds=10.0)
    third = install_shutdown_deadline(seconds=10.0)

    # After the first call, subsequent ones must all return False.
    if first:
        assert second is False
        assert third is False
    else:
        # Already installed from earlier in the test session — fine.
        assert second is False
        assert third is False


def test_env_var_opt_out_disables_install():
    """Setting SENTINEL_DISABLE_TEARDOWN_DEADLINE must prevent
    installation, so debugging sessions can use faulthandler / gdb
    without the deadman switch interfering."""
    # We have to test this in a subprocess because the deadline state
    # is module-level (set on first install). A fresh subprocess gives
    # us a clean module state.
    script = textwrap.dedent("""
        import os
        os.environ["SENTINEL_DISABLE_TEARDOWN_DEADLINE"] = "1"
        # Re-import the teardown module fresh.
        from core.base.teardown import install_shutdown_deadline
        result = install_shutdown_deadline(seconds=10.0)
        print(f"install_returned={result}")
    """)
    result = _run_script(script, timeout_s=15.0)
    assert "install_returned=False" in result.stdout
