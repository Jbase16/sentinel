"""
Sentinel Core API + lightweight local HTTP bridge.

This file is intentionally beginner-friendly and over-commented so it is easy
to extend. It does two things:
  1) Exposes a small CoreAPI class for programmatic use.
  2) Runs a tiny HTTP server (standard library only) so the SwiftUI app can
     talk to Python over localhost without extra dependencies.

Endpoints (when run as a script, default port 8765):
  GET  /ping       -> {"status": "ok"}
  POST /scan       -> kicks off a scan in a background thread
  GET  /logs       -> returns any buffered log lines since last call
  GET  /results    -> latest findings/issues/killchain/phase_results

Notes for entry-level contributors:
- We keep everything JSON-serializable to make Swift ↔ Python IPC simple.
- Scans run in a separate thread so the HTTP server stays responsive.
- Log streaming here is pull-based (poll /logs); later you can upgrade to SSE.
"""

from __future__ import annotations

import http.server
import json
import queue
import threading
from typing import Any, Dict, Iterable, Optional

from core.scan_orchestrator import ScanOrchestrator

# ---------------------------------------------------------------------------
# Shared state for the in-process API and the HTTP handler.
# ---------------------------------------------------------------------------

# Queue buffers log lines coming from the orchestrator.
_log_queue: "queue.Queue[str]" = queue.Queue(maxsize=10_000)

# Stores the latest scan results snapshot for the UI.
_latest_result: Dict[str, Any] = {}

# Tracks the currently running scan thread (if any).
_current_scan_thread: Optional[threading.Thread] = None

# Simple lock so we don't start overlapping scans.
_scan_lock = threading.Lock()

# Flag to request cancellation (best-effort).
_cancel_requested = threading.Event()

def _log_sink(msg: str) -> None:
    """Callback passed to ScanOrchestrator to collect log lines."""
    try:
        _log_queue.put_nowait(msg)
    except queue.Full:
        # If the queue is full, drop logs to avoid blocking scans.
        pass


def _scan_runner(target: str) -> None:
    """
    Runs a scan synchronously and stores the latest result snapshot.
    Executed inside a background thread so HTTP requests stay responsive.
    """
    global _latest_result
    _cancel_requested.clear()
    orchestrator = ScanOrchestrator(log_fn=_log_sink)
    # If ScanOrchestrator gains native cancellation, wire _cancel_requested into it.
    ctx = orchestrator.run_sync(target)
    # Store only JSON-serializable structures for the UI to consume.
    _latest_result = {
        "target": ctx.target,
        "findings": ctx.findings,
        "issues": ctx.issues,
        "killchain_edges": ctx.killchain_edges,
        "phase_results": ctx.phase_results,
        "logs": ctx.logs,
    }
    _cancel_requested.clear()


def start_scan(target: str) -> None:
    """
    Public helper that starts a scan in a background thread.
    Raises RuntimeError if a scan is already running.
    """
    global _current_scan_thread
    with _scan_lock:
        if _current_scan_thread and _current_scan_thread.is_alive():
            raise RuntimeError("A scan is already running")

        thread = threading.Thread(target=_scan_runner, args=(target,), daemon=True)
        _current_scan_thread = thread
        thread.start()


def cancel_scan() -> bool:
    """
    Best-effort cancellation toggle. Scanner engine does not yet expose
    cooperative cancellation; for now we just set a flag and return whether
    a scan was in flight.
    """
    global _current_scan_thread
    with _scan_lock:
        if _current_scan_thread and _current_scan_thread.is_alive():
            _cancel_requested.set()
            return True
    return False


def drain_logs() -> Dict[str, Any]:
    """
    Pull any buffered log lines since the last call.
    Returns a dict to keep HTTP and programmatic consumers consistent.
    """
    lines = []
    while True:
        try:
            lines.append(_log_queue.get_nowait())
        except queue.Empty:
            break
    return {"lines": lines}


def get_latest_results() -> Dict[str, Any]:
    """
    Snapshot of the most recent scan. If no scan has run yet, returns {}.
    """
    return dict(_latest_result)


# ---------------------------------------------------------------------------
# Programmatic API class (usable without HTTP).
# ---------------------------------------------------------------------------

class CoreAPI:
    """
    Lightweight façade over the scanner/orchestrator layers.
    Exposes simple methods that the Swift side can mirror for IPC.
    """

    def ping(self) -> Dict[str, str]:
        return {"status": "ok"}

    def start_scan(self, target: str, modules: Optional[Iterable[str]] = None) -> None:
        # modules are ignored for now; wire selective module runs later.
        start_scan(target)

    def stream_logs(self) -> Iterable[str]:
        # This yields and drains buffered log lines.
        while True:
            batch = drain_logs()["lines"]
            if not batch:
                break
            for line in batch:
                yield line

    def latest_results(self) -> Dict[str, Any]:
        return get_latest_results()

    def cancel_scan(self) -> bool:
        return cancel_scan()

# ---------------------------------------------------------------------------
# Minimal HTTP server for local IPC (no external deps).
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    """Tiny JSON-only handler with a few endpoints."""

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Silence default stdout logging to avoid clutter.
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/ping":
            return self._send_json(200, {"status": "ok"})

        if self.path == "/logs":
            return self._send_json(200, drain_logs())

        if self.path == "/results":
            result = get_latest_results()
            status = 200 if result else 204
            return self._send_json(status, result)

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/scan":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            raw = self.rfile.read(length) if length else b""
            try:
                data = json.loads(raw or "{}")
            except json.JSONDecodeError:
                return self._send_json(400, {"error": "invalid json"})

            target = (data.get("target") or "").strip()
            if not target:
                return self._send_json(400, {"error": "target is required"})

            try:
                start_scan(target)
            except RuntimeError as exc:
                return self._send_json(409, {"error": str(exc)})

            return self._send_json(202, {"status": "started", "target": target})

        if self.path == "/cancel":
            if cancel_scan():
                return self._send_json(202, {"status": "cancelling"})
            return self._send_json(409, {"error": "no active scan"})

        self._send_json(404, {"error": "not found"})


def serve(port: int = 8765) -> None:
    """
    Start the local HTTP server. Run with:
      python -m core.api
    or:
      python core/api.py
    """
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"[sentinel-api] listening on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[sentinel-api] shutting down...")
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
