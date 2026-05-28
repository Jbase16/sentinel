"""
core/base/teardown.py

Bounded interpreter teardown — defensive guard against orphaned threads.

SentinelForge spins up a lot of async subsystems (mitmproxy, httpx
connection pools, anyio worker pools, asyncio tasks, a sqlite writer,
LLM clients, …) and any one of them can leak a non-daemon thread or a
finalizer-blocked resource in ways that depend on GC timing, async
loop state, or import order. Reproducing every leak is impractical —
they're racy.

Rather than chase each leak individually, this module provides a
HARD CEILING on interpreter shutdown time. After Python's atexit
handlers run, if `_thread._shutdown()` (or any later step) hasn't
completed within the configured window, a daemon timer thread calls
`os._exit(0)`, bypassing all Python cleanup.

This is the "if the house is on fire, get out" pattern. It does NOT
fix any individual leak — but it makes the WORST CASE bounded, which
matters disproportionately for offensive tooling that may be invoked
from CI / scripts / cron / etc. where a 3-hour ghost process is far
worse than an unclean exit.

Calibration history (Run #26 / Phase 3 follow-up):
  * Two separate live verify_phase runs hung for 3+ hours each after
    logically completing. Root cause was Python-shutdown-machinery
    race condition, not application code. Adding this deadman switch
    bounds future occurrences to `seconds` (default 10).

Disable for debugging with:  SENTINEL_DISABLE_TEARDOWN_DEADLINE=1
"""
from __future__ import annotations

import atexit
import logging
import os
import sys
import threading
import time

logger = logging.getLogger(__name__)


# Idempotent — repeated calls do nothing. Tests + ScanSession both
# attempt to install; whoever runs first wins.
_INSTALLED = False

# Operator opt-out: set this env var to disable the deadline (e.g. when
# debugging an actual leak with `gdb`/`py-spy`/`faulthandler` and you
# need the process to stay alive past shutdown).
_DISABLE_ENV = "SENTINEL_DISABLE_TEARDOWN_DEADLINE"


def install_shutdown_deadline(seconds: float = 10.0) -> bool:
    """Arm a deadman switch that forces `os._exit(0)` if interpreter
    shutdown takes longer than `seconds` seconds.

    Returns True if the deadline was installed; False if it was already
    installed or disabled by env.

    Implementation — Python 3.14 considerations:

      * `atexit.register` is the OBVIOUS choice but DOES NOT WORK on
        3.14: by the time atexit handlers fire, `_thread._shutdown()`
        has already started blocking on non-daemon threads. Tested
        during Phase 3 calibration — handler was never invoked.

      * `threading._register_atexit` (private CPython API, present
        since 3.9) is the correct hook. Per its docstring: "The
        registered func is called with its arguments just before all
        non-daemon threads are joined in `_shutdown()`." That's the
        precise moment we need: shutdown has begun, non-daemon
        threads haven't been joined yet, daemon threads can still
        acquire the GIL.

      * Inside that hook we spawn a DAEMON timer thread. If interpreter
        shutdown completes normally within the window, the daemon dies
        with the process and the timer never fires. If shutdown stalls
        (typical case: a non-daemon thread that can't be joined), the
        timer fires `os._exit(0)` — which bypasses ALL Python cleanup
        machinery and exits at the OS level.

      * `os._exit` is a syscall, not a Python-level operation. It does
        not need the GIL and works even if the interpreter is in an
        inconsistent state. This is the property that makes the bound
        actually bounded.

    Fallback: if `_register_atexit` is unavailable on a future Python
    version, we fall back to `atexit.register` and log a warning. The
    fallback won't reliably fire on 3.14+ but at least the install call
    won't error out, and the deadman switch is best-effort by design.
    """
    global _INSTALLED
    if _INSTALLED:
        return False
    if _DISABLE_ENV in os.environ:
        logger.info(
            f"[teardown] deadline disabled by env ({_DISABLE_ENV} set); "
            f"interpreter shutdown is unbounded"
        )
        return False
    _INSTALLED = True

    def _arm_during_threading_shutdown():
        def _kill():
            # Daemon timer thread. Sleeps `seconds`; if interpreter
            # shutdown completes before then, this thread dies with
            # the process. Otherwise it forces exit.
            time.sleep(seconds)
            try:
                sys.stderr.write(
                    f"[teardown-deadline] interpreter still alive "
                    f"{seconds:.1f}s after threading shutdown started; "
                    f"forcing os._exit(0). This indicates an orphaned "
                    f"non-daemon thread or a finalizer deadlock — "
                    f"investigate if seen often.\n"
                )
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(0)

        t = threading.Thread(
            target=_kill,
            name="sentinel-teardown-deadline",
            daemon=True,
        )
        t.start()

    register_fn = getattr(threading, "_register_atexit", None)
    if register_fn is not None:
        try:
            register_fn(_arm_during_threading_shutdown)
            return True
        except RuntimeError:
            # Shutdown already in progress — too late, nothing we can
            # do. Don't fail the import.
            return False
    # Fallback for hypothetical future Python without _register_atexit.
    # On 3.14 this path is unreachable; on earlier-or-later Pythons
    # without the private API, atexit is the next-best hook.
    logger.warning(
        "[teardown] threading._register_atexit not available; falling "
        "back to atexit (unreliable on 3.14+)"
    )
    atexit.register(_arm_during_threading_shutdown)
    return True
