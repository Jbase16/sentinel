"""
Sentinel Core API + lightweight local HTTP bridge.

This file is intentionally beginner-friendly and over-commented so it is easy
to extend. It does two things:
  1) Exposes a small CoreAPI class for programmatic use.
  2) Runs a tiny HTTP server (standard library only) so the SwiftUI app can
     talk to Python over localhost without extra dependencies.

Endpoints (when run as a script, default port 8765):
  GET  /ping       -> {"status": "ok"}
  GET  /status     -> engine + AI status (model availability, running scan)
  POST /scan       -> kicks off a scan in a background thread
  GET  /logs       -> returns any buffered log lines since last call
  GET  /results    -> structured findings/issues/killchain/phase_results/evidence

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
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from core.ai_engine import AIEngine
from core.evidence_store import EvidenceStore
from core.reasoning import reasoning_engine
from core.scan_orchestrator import ScanOrchestrator

# ---------------------------------------------------------------------------
# Shared state for the in-process API and the HTTP handler.
# ---------------------------------------------------------------------------

# Queue buffers log lines coming from the orchestrator.
_log_queue: "queue.Queue[str]" = queue.Queue(maxsize=10_000)

# Stores the latest scan results snapshot for the UI.
_latest_result: Dict[str, Any] = {}

# Tracks meta about the most recent scan (target, status, timings).
_scan_state: Dict[str, Any] = {}

# Tracks the currently running scan thread (if any).
_current_scan_thread: Optional[threading.Thread] = None

# Simple lock so we don't start overlapping scans.
_scan_lock = threading.Lock()

# Flag to request cancellation (best-effort).
_cancel_requested = threading.Event()

# Shared AI engine singleton for status reporting.
_ai_engine = AIEngine.instance()

def _log_sink(msg: str) -> None:
    """Callback passed to ScanOrchestrator to collect log lines."""
    try:
        _log_queue.put_nowait(msg)
    except queue.Full:
        # If the queue is full, drop logs to avoid blocking scans.
        pass


def _ai_status() -> Dict[str, Any]:
    """Expose AI engine health + available models in a JSON-friendly shape."""
    try:
        return _ai_engine.status()
    except Exception:
        return {
            "provider": "unknown",
            "model": None,
            "connected": False,
            "fallback_enabled": True,
            "available_models": [],
        }


def _evidence_snapshot() -> List[Dict[str, Any]]:
    """
    Summarize evidence entries without shipping raw output over IPC.
    """
    items: List[Dict[str, Any]] = []
    evidence = EvidenceStore.instance().get_all()
    for eid, data in evidence.items():
        raw = data.get("raw_output") or ""
        items.append({
            "id": eid,
            "tool": data.get("tool"),
            "summary": data.get("summary"),
            "metadata": data.get("metadata") or {},
            "raw_preview": raw[:500],
            "raw_bytes": len(raw.encode("utf-8")) if raw else 0,
            "finding_count": len(data.get("findings") or []),
        })
    return items


def _build_result_envelope(
    target: str,
    modules: List[str],
    ctx,
    started_at: datetime,
    finished_at: datetime,
    cancelled: bool = False,
) -> Dict[str, Any]:
    duration_ms = int((finished_at - started_at).total_seconds() * 1000)
    phase_counts = {name: len(items) for name, items in (ctx.phase_results or {}).items()}
    reasoning = reasoning_engine.analyze()
    status = "cancelled" if cancelled else "completed"

    return {
        "scan": {
            "target": target,
            "modules": modules,
            "status": status,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": duration_ms,
        },
        "summary": {
            "counts": {
                "findings": len(ctx.findings or []),
                "issues": len(ctx.issues or []),
                "killchain_edges": len(ctx.killchain_edges or []),
                "logs": len(ctx.logs or []),
                "phase_results": phase_counts,
            },
            "ai": _ai_status(),
        },
        "findings": ctx.findings,
        "issues": ctx.issues,
        "killchain": {
            "edges": ctx.killchain_edges,
            "attack_paths": reasoning.get("attack_paths", []),
            "degraded_paths": reasoning.get("degraded_paths", []),
            "recommended_phases": reasoning.get("recommended_phases", []),
        },
        "phase_results": ctx.phase_results,
        "evidence": _evidence_snapshot(),
        "logs": ctx.logs,
    }


def _scan_runner(target: str, modules: Optional[Iterable[str]] = None) -> None:
    """
    Runs a scan synchronously and stores the latest result snapshot.
    Executed inside a background thread so HTTP requests stay responsive.
    """
    global _latest_result, _scan_state
    module_list = list(modules) if modules else []
    started_at = datetime.now(timezone.utc)
    _scan_state = {
        "target": target,
        "modules": module_list,
        "status": "running",
        "started_at": started_at.isoformat(),
    }
    _cancel_requested.clear()
    orchestrator = ScanOrchestrator(log_fn=_log_sink)
    # Pass the cancel flag down so scanner engine can stop launching new tools.
    try:
        ctx = orchestrator.run_sync(target, modules=module_list, cancel_flag=_cancel_requested)
        finished_at = datetime.now(timezone.utc)
        cancelled = _cancel_requested.is_set()
        _latest_result = _build_result_envelope(
            target=target,
            modules=module_list,
            ctx=ctx,
            started_at=started_at,
            finished_at=finished_at,
            cancelled=cancelled,
        )
        _scan_state.update({
            "status": "cancelled" if cancelled else "completed",
            "finished_at": finished_at.isoformat(),
            "duration_ms": int((finished_at - started_at).total_seconds() * 1000),
        })
    except Exception as exc:
        finished_at = datetime.now(timezone.utc)
        _latest_result = {
            "scan": {
                "target": target,
                "modules": module_list,
                "status": "error",
                "error": str(exc),
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
            },
            "summary": {"counts": {}, "ai": _ai_status()},
            "logs": [],
        }
        _scan_state.update({
            "status": "error",
            "error": str(exc),
            "finished_at": finished_at.isoformat(),
        })
    finally:
        _cancel_requested.clear()


def start_scan(target: str, modules: Optional[Iterable[str]] = None) -> None:
    """
    Public helper that starts a scan in a background thread.
    Raises RuntimeError if a scan is already running.
    """
    global _current_scan_thread
    with _scan_lock:
        if _current_scan_thread and _current_scan_thread.is_alive():
            raise RuntimeError("A scan is already running")

        thread = threading.Thread(
            target=_scan_runner,
            args=(target, modules),
            daemon=True,
        )
        _current_scan_thread = thread
        thread.start()


def cancel_scan() -> bool:
    """
    Best-effort cancellation toggle. Scanner engine does not yet expose
    cooperative cancellation; for now we just set a flag and return whether
    a scan was in flight.
    """
    global _current_scan_thread, _scan_state
    with _scan_lock:
        if _current_scan_thread and _current_scan_thread.is_alive():
            _cancel_requested.set()
            _scan_state["status"] = "cancelling"
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


def get_status() -> Dict[str, Any]:
    """
    Lightweight health endpoint for the SwiftUI client.
    """
    with _scan_lock:
        running = _current_scan_thread is not None and _current_scan_thread.is_alive()

    status = {
        "status": "ok",
        "scan_running": running,
        "latest_target": _scan_state.get("target"),
        "ai": _ai_status(),
    }

    if _scan_state:
        status["scan_state"] = dict(_scan_state)
    if running:
        status["cancel_requested"] = _cancel_requested.is_set()

    return status


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
        start_scan(target, modules=modules)

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

    def status(self) -> Dict[str, Any]:
        return get_status()

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

        if self.path == "/status":
            return self._send_json(200, get_status())

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

            modules_raw = data.get("modules")
            modules: Optional[List[str]] = None
            if isinstance(modules_raw, list):
                modules = [str(item) for item in modules_raw if isinstance(item, str)]

            try:
                start_scan(target, modules=modules)
            except RuntimeError as exc:
                return self._send_json(409, {"error": str(exc)})

            return self._send_json(202, {"status": "started", "target": target, "modules": modules or []})

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
