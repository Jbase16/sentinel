#!/usr/bin/env python3
"""
SentinelForge scan inspector.

After a scan runs, this tool answers four questions:
    1. What target did Sentinel scan, and did it finish?
    2. What did each tool find, and which tools failed?
    3. What findings/issues were recorded, and at what severity?
    4. What decisions did the engine make, and why?

It reads the SQLite database directly (no running backend required), so you
can inspect any past scan even if Sentinel is offline. It uses only stdlib
sqlite3, no other deps.

Usage:
    python3 scripts/inspect_scan.py list                    # last 10 sessions
    python3 scripts/inspect_scan.py show --latest           # most recent session
    python3 scripts/inspect_scan.py show --session ID       # a specific session
    python3 scripts/inspect_scan.py show --latest --json    # machine-readable

DESIGN NOTE
-----------
This is intentionally a thin read-only view. It does NOT consult any of the
Sentinel managers (Nexus, Cronus, Mimic), does NOT spin up the AI engine,
and does NOT import core/ modules — so you can run it during a live scan
without contending for the DB lock.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ANSI colors — only when stdout is a TTY
_IS_TTY = sys.stdout.isatty()
DIM = "\033[2m" if _IS_TTY else ""
BOLD = "\033[1m" if _IS_TTY else ""
RED = "\033[31m" if _IS_TTY else ""
GREEN = "\033[32m" if _IS_TTY else ""
YELLOW = "\033[33m" if _IS_TTY else ""
CYAN = "\033[36m" if _IS_TTY else ""
RESET = "\033[0m" if _IS_TTY else ""

DEFAULT_DB = Path.home() / ".sentinelforge" / "sentinel.db"


# ---------------------------------------------------------------------------
# DB access
# ---------------------------------------------------------------------------

def _open_db(path: Path) -> sqlite3.Connection:
    if not path.exists():
        sys.exit(f"{RED}no database found at {path}{RESET}\n"
                 f"has Sentinel run yet? Backend creates the DB on first start.")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _safe_json(blob: Optional[str]) -> Any:
    if not blob:
        return None
    try:
        return json.loads(blob)
    except (json.JSONDecodeError, TypeError):
        return blob  # return raw if not JSON


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """The sessions table holds either ISO strings ('2026-05-14T...') OR
    Unix timestamps stored as strings ('1778821320.67109'). Handle both."""
    if not value:
        return None
    s = str(value)
    # Try numeric Unix timestamp first
    try:
        return datetime.fromtimestamp(float(s))
    except (ValueError, TypeError):
        pass
    # Fall back to ISO parsing
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _fmt_duration(start: Optional[str], end: Optional[str]) -> str:
    if not start:
        return "?"
    if not end:
        return f"running (started {start})"
    try:
        s = _parse_ts(start)
        e = _parse_ts(end)
        if s is None or e is None:
            return "?"
        secs = (e - s).total_seconds()
        if secs < 60:
            return f"{secs:.1f}s"
        if secs < 3600:
            return f"{secs / 60:.1f}m"
        return f"{secs / 3600:.2f}h"
    except (ValueError, TypeError):
        return "?"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(conn: sqlite3.Connection, limit: int) -> int:
    # Migration 004 normalized all session timestamps to ISO 8601 UTC strings,
    # which sort correctly lexicographically. The earlier band-aid CASE
    # expression (handling mixed Unix-float / ISO formats) is no longer
    # needed. See docs/CALIBRATION_RUN_012.md.
    rows = conn.execute(
        "SELECT id, target, status, start_time, end_time "
        "FROM sessions ORDER BY start_time DESC LIMIT ?",
        (limit,),
    ).fetchall()

    if not rows:
        print("no sessions found")
        return 0

    print(f"{BOLD}{'session id':<38} {'target':<32} {'status':<10} {'duration'}{RESET}")
    for r in rows:
        sid = r["id"]
        target = (r["target"] or "")[:30]
        status = r["status"] or "?"
        duration = _fmt_duration(r["start_time"], r["end_time"])
        status_color = GREEN if status == "completed" else (
            YELLOW if status == "running" else (
                RED if status in ("failed", "error") else DIM
            )
        )
        print(f"{sid:<38} {target:<32} {status_color}{status:<10}{RESET} {duration}")

    return 0


def _resolve_session_id(conn: sqlite3.Connection, args) -> Optional[str]:
    if args.session:
        return args.session
    if args.latest:
        # Same dual-format sort as in cmd_list, since the writer is
        # inconsistent about timestamp format.
        row = conn.execute(
            "SELECT id FROM sessions ORDER BY start_time DESC LIMIT 1"
        ).fetchone()
        return row["id"] if row else None
    return None


def _gather_session_data(conn: sqlite3.Connection, sid: str) -> Optional[Dict[str, Any]]:
    session = conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not session:
        return None

    findings = conn.execute(
        "SELECT id, tool, type, severity, target, data, timestamp FROM findings "
        "WHERE session_id=? ORDER BY timestamp ASC",
        (sid,),
    ).fetchall()

    issues = conn.execute(
        "SELECT id, title, severity, target, data, timestamp FROM issues "
        "WHERE session_id=? ORDER BY timestamp ASC",
        (sid,),
    ).fetchall()

    evidence = conn.execute(
        "SELECT id, tool, metadata, timestamp FROM evidence "
        "WHERE session_id=? ORDER BY timestamp ASC",
        (sid,),
    ).fetchall()

    scans: List[sqlite3.Row] = []
    if _table_exists(conn, "scans"):
        scans = conn.execute(
            "SELECT * FROM scans WHERE session_id=? ORDER BY scan_sequence ASC",
            (sid,),
        ).fetchall()

    decisions: List[sqlite3.Row] = []
    if _table_exists(conn, "decisions"):
        decisions = conn.execute(
            "SELECT id, event_sequence, type, chosen, reason FROM decisions "
            "ORDER BY event_sequence ASC LIMIT 50"
        ).fetchall()

    edge_count = 0
    if _table_exists(conn, "graph_edges"):
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM graph_edges WHERE session_id=?", (sid,)
        ).fetchone()
        edge_count = row["c"] if row else 0

    return {
        "session": session,
        "findings": findings,
        "issues": issues,
        "evidence": evidence,
        "scans": scans,
        "decisions": decisions,
        "edge_count": edge_count,
    }


def cmd_show_text(data: Dict[str, Any]) -> None:
    session = data["session"]
    findings = data["findings"]
    issues = data["issues"]
    evidence = data["evidence"]
    scans = data["scans"]
    decisions = data["decisions"]

    # ─── Header ───────────────────────────────────────────────────────────
    print(f"{BOLD}=== Session {session['id']} ==={RESET}")
    print(f"  target  : {session['target']}")
    print(f"  status  : {session['status']}")
    print(f"  duration: {_fmt_duration(session['start_time'], session['end_time'])}")
    print(f"  started : {session['start_time']}")
    print(f"  ended   : {session['end_time'] or '(in progress)'}")
    print()

    # ─── Counts ───────────────────────────────────────────────────────────
    print(f"{BOLD}Counts{RESET}")
    print(f"  findings    : {len(findings)}")
    print(f"  issues      : {len(issues)}")
    print(f"  evidence    : {len(evidence)}")
    print(f"  graph edges : {data['edge_count']}")
    if decisions:
        print(f"  decisions   : {len(decisions)} (showing first 50)")
    print()

    # ─── Tool execution summary ───────────────────────────────────────────
    tool_runs: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"runs": 0, "failed": 0, "timed_out": 0, "exit_codes": Counter()}
    )
    for e in evidence:
        meta = _safe_json(e["metadata"]) or {}
        tool = e["tool"] or meta.get("tool", "unknown")
        rec = tool_runs[tool]
        rec["runs"] += 1
        ec = meta.get("exit_code")
        if ec is not None:
            rec["exit_codes"][ec] += 1
        if ec not in (0, None):
            rec["failed"] += 1
        if meta.get("timed_out"):
            rec["timed_out"] += 1

    if tool_runs:
        print(f"{BOLD}Tool execution{RESET}")
        for tool, stats in sorted(tool_runs.items()):
            ec_summary = ", ".join(f"exit={k}×{v}" for k, v in sorted(stats["exit_codes"].items()))
            badge = GREEN + "ok" + RESET if stats["failed"] == 0 else RED + "!!" + RESET
            extra = f" (timed_out: {stats['timed_out']})" if stats["timed_out"] else ""
            print(f"  [{badge}] {tool:<20} runs={stats['runs']}  {ec_summary}{extra}")
        print()

    # ─── Findings by severity ─────────────────────────────────────────────
    if findings:
        # Severity strings are stored inconsistently (MEDIUM/medium/Medium) —
        # normalize before counting so the bucket display works regardless.
        sev_counts = Counter((f["severity"] or "unknown").lower() for f in findings)
        print(f"{BOLD}Findings by severity{RESET}")
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev in sev_counts:
                color = {
                    "critical": RED, "high": RED, "medium": YELLOW,
                    "low": CYAN, "info": DIM, "unknown": DIM,
                }.get(sev, "")
                print(f"  {color}{sev:<10}{RESET} {sev_counts[sev]}")
        print()

        # Show first 10 findings as a sample
        print(f"{BOLD}Findings (first 10){RESET}")
        for f in findings[:10]:
            sev = (f["severity"] or "?").lower()
            sev_color = {
                "critical": RED, "high": RED, "medium": YELLOW,
                "low": CYAN,
            }.get(sev, DIM)
            type_str = f["type"] or "?"
            target = (f["target"] or "?")[:40]
            print(f"  {sev_color}{sev:<8}{RESET} {f['tool']:<14} {type_str:<24} {target}")
        if len(findings) > 10:
            print(f"  {DIM}... and {len(findings) - 10} more{RESET}")
        print()

    # ─── Issues ───────────────────────────────────────────────────────────
    if issues:
        print(f"{BOLD}Issues (rule-derived vulnerabilities, first 5){RESET}")
        for i in issues[:5]:
            sev = (i["severity"] or "?").lower()
            sev_color = {
                "critical": RED, "high": RED, "medium": YELLOW,
                "low": CYAN,
            }.get(sev, DIM)
            print(f"  {sev_color}{sev:<8}{RESET} {(i['title'] or '?')[:60]}")
            if i["target"]:
                print(f"           target: {i['target']}")
        if len(issues) > 5:
            print(f"  {DIM}... and {len(issues) - 5} more{RESET}")
        print()

    # ─── Decisions ────────────────────────────────────────────────────────
    if decisions:
        types = Counter(d["type"] or "?" for d in decisions)
        print(f"{BOLD}Decisions by type{RESET}")
        for t, c in sorted(types.items(), key=lambda kv: -kv[1]):
            print(f"  {t:<28} {c}")

        # Highlight rejection-flavored decisions (scope, validation)
        rejections = [d for d in decisions if d["type"] and (
            "reject" in d["type"].lower() or "deny" in d["type"].lower()
            or "scope" in d["type"].lower()
        )]
        if rejections:
            print()
            print(f"{BOLD}Rejection/scope events (first 5){RESET}")
            for d in rejections[:5]:
                reason = (d["reason"] or "")[:80]
                print(f"  {YELLOW}{d['type']}{RESET} chose={d['chosen']!r} — {reason}")
        print()

    # ─── Scan failures ────────────────────────────────────────────────────
    failed_scans = [s for s in scans if s["status"] in ("failed", "error")]
    if failed_scans:
        print(f"{BOLD}Failed scan records{RESET}")
        for s in failed_scans:
            phase = s["failure_phase"] or "?"
            err = (s["error_message"] or "?")[:80]
            print(f"  {RED}{s['status']:<10}{RESET} phase={phase} — {err}")
        print()


def cmd_show_json(data: Dict[str, Any]) -> None:
    """JSON output for piping into jq or other tools."""
    def row_to_dict(r):
        if r is None:
            return None
        return {k: r[k] for k in r.keys()}

    payload = {
        "session": row_to_dict(data["session"]),
        "counts": {
            "findings": len(data["findings"]),
            "issues": len(data["issues"]),
            "evidence": len(data["evidence"]),
            "decisions": len(data["decisions"]),
            "edges": data["edge_count"],
        },
        "findings": [row_to_dict(f) for f in data["findings"]],
        "issues": [row_to_dict(i) for i in data["issues"]],
        "decisions": [row_to_dict(d) for d in data["decisions"]],
    }
    # data column may be JSON in string form — try to parse
    for f in payload["findings"]:
        if f.get("data"):
            f["data"] = _safe_json(f["data"])
    for i in payload["issues"]:
        if i.get("data"):
            i["data"] = _safe_json(i["data"])

    print(json.dumps(payload, indent=2, default=str))


def cmd_show(conn: sqlite3.Connection, args) -> int:
    sid = _resolve_session_id(conn, args)
    if not sid:
        print(f"{RED}no session specified.{RESET} use --session ID or --latest", file=sys.stderr)
        return 2

    data = _gather_session_data(conn, sid)
    if not data:
        print(f"{RED}session {sid} not found{RESET}", file=sys.stderr)
        return 2

    if args.json:
        cmd_show_json(data)
    else:
        cmd_show_text(data)
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect a SentinelForge scan session from the local SQLite store"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help=f"path to sentinel.db (default: {DEFAULT_DB})",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="show recent scan sessions")
    p_list.add_argument("--limit", type=int, default=10, help="max sessions to show")

    p_show = sub.add_parser("show", help="show details of a session")
    p_show.add_argument("--session", type=str, help="session UUID")
    p_show.add_argument("--latest", action="store_true", help="use most recent session")
    p_show.add_argument("--json", action="store_true", help="emit JSON")

    args = parser.parse_args()

    conn = _open_db(args.db)
    try:
        if args.cmd == "list":
            return cmd_list(conn, args.limit)
        if args.cmd == "show":
            return cmd_show(conn, args)
        parser.print_help()
        return 2
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
