#!/usr/bin/env python3
"""
SentinelForge CLI (PySentinel)

A headless, terminal-based interface for running SentinelForge scans.
This tool connects to the local SentinelForge backend (just like the Xcode app),
authenticates using your local token, starts a scan, and streams verbose logs
in real-time to your console.

Usage:
    python3 pysentinel.py --target "http://example.com" [--modules nmap,wappalyzer]
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import List, Optional

import httpx

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("PySentinel")


API_BASE = "http://127.0.0.1:8765"
TOKEN_PATH = Path.home() / ".sentinelforge" / "api_token"
SSE_ENDPOINTS = ("/v1/events/stream", "/v1/events")

# Re-import here so type hints resolve even if typing isn't imported above.
from typing import Optional, Dict, Any  # noqa: E402


class SentinelCLI:
    def __init__(self):
        self.token = self._load_token()
        self.client = httpx.AsyncClient(
            base_url=API_BASE,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=10.0
        )
        self.running = True
        self.active_session_id: Optional[str] = None

    def _load_token(self) -> str:
        """Load API token from ~/.sentinelforge/api_token"""
        if not TOKEN_PATH.exists():
            print(f"❌ API token not found at {TOKEN_PATH}")
            print("Please verify the backend is running and has generated a token.")
            sys.exit(1)
        return TOKEN_PATH.read_text().strip()

    async def check_connection(self) -> bool:
        """Ping the backend to ensure connectivity"""
        try:
            resp = await self.client.get("/v1/ping")
            resp.raise_for_status()
            print("✅ Connected to SentinelForge Backend")
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False

    async def start_scan(
        self,
        target: str,
        modules: List[str] = None,
        mode: str = "standard",
        scope: Optional[List[str]] = None,
        scope_strict: bool = False,
        personas: Optional[List[Dict[str, Any]]] = None,
        oob: Optional[Dict[str, Any]] = None,
        restrictions: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Start a new scan session"""
        payload = {
            "target": target,
            "force": True,
            "mode": mode
        }
        if modules:
            payload["modules"] = modules
        if scope:
            payload["scope"] = scope
            payload["scope_strict"] = scope_strict
        if personas:
            payload["personas"] = personas
        if oob:
            payload["oob"] = oob
        if restrictions:
            payload["restrictions"] = restrictions

        scope_note = f" | scope={len(scope)} rules ({'strict' if scope_strict else 'permissive'})" if scope else ""
        personas_note = f" | personas={len(personas)}" if personas else ""
        oob_note = f" | oob={oob.get('provider', '?')}" if oob else ""
        print(f"🚀 Starting scan for target: {target} (Mode: {mode}){scope_note}{personas_note}{oob_note}")
        try:
            resp = await self.client.post("/v1/scans/start", json=payload)
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
            session_id = str(body.get("session_id") or "").strip()
            if not session_id:
                raise RuntimeError(f"Backend returned no session_id: {body}")
            self.active_session_id = session_id
            print(f"✅ Scan initiated successfully. session={session_id[:12]}")
            print("   Waiting for events...")
            return session_id
        except httpx.HTTPStatusError as e:
            print(f"❌ Failed to start scan: {e.response.text}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Failed to start scan: {e}")
            sys.exit(1)

    def _event_scan_id(self, payload: dict) -> Optional[str]:
        scan_id = payload.get("scan_id") or payload.get("session_id")
        if scan_id is None:
            return None
        text = str(scan_id).strip()
        return text or None

    async def stream_events(self):
        """Stream SSE events from the backend"""
        print("📡 Listening for events...")

        err_count = 0
        while self.running:
            try:
                stream_cm = None
                response = None
                used_endpoint = None

                # Try canonical SSE route first; keep legacy fallback for older backends.
                for endpoint in SSE_ENDPOINTS:
                    candidate_stream = self.client.stream(
                        "GET",
                        endpoint,
                        timeout=None,
                        headers={"Accept": "text/event-stream"},
                    )
                    candidate_response = await candidate_stream.__aenter__()
                    if candidate_response.status_code == 404:
                        await candidate_stream.__aexit__(None, None, None)
                        continue
                    candidate_response.raise_for_status()
                    stream_cm = candidate_stream
                    response = candidate_response
                    used_endpoint = endpoint
                    break

                if response is None or stream_cm is None:
                    raise RuntimeError("No SSE endpoint found (tried /v1/events/stream and /v1/events)")

                print(f"✅ Connected to event stream {used_endpoint} (status: {response.status_code})")

                try:
                    buffer = ""
                    async for chunk in response.aiter_text():
                        if not self.running:
                            break

                        buffer += chunk
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            line = line.strip()

                            if line.startswith("data: "):
                                data = line[6:]
                                try:
                                    event = json.loads(data)
                                    self._handle_event(event)
                                except json.JSONDecodeError as e:
                                    logger.debug(f"JSON decode error: {e}")

                        # Reset error count on successful read
                        err_count = 0
                finally:
                    # Ensure streaming connection is released even on parser/runtime errors.
                    await stream_cm.__aexit__(None, None, None)

            except Exception as e:
                err_count += 1
                if err_count > 5:
                    print(f"❌ Lost connection to event stream: {e}")
                    self.running = False
                await asyncio.sleep(1)

    def _handle_event(self, event: dict):
        """Process and print a single event"""
        event_type = event.get("type", "unknown")
        payload = event.get("payload", {})
        event_scan_id = self._event_scan_id(payload)

        # Ignore all events until we know which session we're responsible for.
        if not self.active_session_id:
            return

        # Strictly scope state-bearing events to the active session.
        scoped_types = {
            "scan_started",
            "scan_phase_changed",
            "scan_completed",
            "scan_failed",
            "finding_created",
            "decision_made",
            "narrative_emitted",
            "tool_started",
            "tool_completed",
        }
        if event_type in scoped_types and event_scan_id != self.active_session_id:
            return

        # -- LOGS --
        if event_type == "log":
            # If scan_id is available, enforce session scope. If absent, allow
            # passthrough because some producers emit unscoped logs.
            if event_scan_id and event_scan_id != self.active_session_id:
                return
            msg = payload.get("line") or payload.get("message")
            if msg:
                print(f"  {msg}")

        # -- SCAN LIFECYCLE --
        elif event_type == "scan_started":
            target = payload.get("target")
            session_id = (event_scan_id or "")[:8]
            print(f"\n🟢 SCAN STARTED: {target} (session: {session_id})")

        elif event_type == "scan_completed":
            duration = payload.get("duration_seconds", 0)
            findings = payload.get("findings_count", 0)
            status = payload.get("status", "completed")
            print(f"\n🏁 SCAN {status.upper()} in {duration:.2f}s")
            print(f"   Total Findings: {findings}")
            self.running = False  # Exit loop

        elif event_type == "scan_failed":
            error = payload.get("error")
            print(f"\n🔴 SCAN FAILED: {error}")
            self.running = False

        # -- PHASE CHANGES --
        elif event_type == "scan_phase_changed":
            phase = payload.get("phase")
            prev_phase = payload.get("previous_phase")
            print(f"\n📍 Phase Transition: {prev_phase} → {phase}")

        # -- FINDINGS --
        elif event_type == "finding_created":
            f_type = payload.get("type")
            value = payload.get("value")
            print(f"⚠️  [FINDING] {f_type}: {value}")

        # -- DECISIONS --
        elif event_type == "decision_made":
            intent = payload.get("intent")
            reason = payload.get("reason")
            print(f"🧠 [{intent}] {reason}")

        # -- NARRATIVES (Strategic insights) --
        elif event_type == "narrative_emitted":
            narrative = payload.get("narrative")
            decision_type = payload.get("decision_type", "")
            if decision_type in ["phase_transition", "intent_transition", "tool_selection"]:
                print(f"📖 {narrative}")

        # -- TOOLS --
        elif event_type == "tool_started":
            tool = payload.get("tool")
            print(f"\n🔧 [TOOL] Running {tool}...")

        elif event_type == "tool_completed":
            tool = payload.get("tool")
            findings = payload.get("findings_count", 0)
            exit_code = payload.get("exit_code", 0)
            status_icon = "✅" if exit_code == 0 else "❌"
            print(f"{status_icon} [TOOL] {tool} finished ({findings} findings, exit: {exit_code})")

    async def run(
        self,
        target: str,
        modules: List[str] = None,
        mode: str = "standard",
        scope: Optional[List[str]] = None,
        scope_strict: bool = False,
        personas: Optional[List[Dict[str, Any]]] = None,
        oob: Optional[Dict[str, Any]] = None,
        restrictions: Optional[Dict[str, Any]] = None,
    ):
        if not await self.check_connection():
            return

        # Start the listener task first so we don't miss early logs
        listen_task = asyncio.create_task(self.stream_events())

        # Brief pause to ensure connection established
        await asyncio.sleep(0.5)

        # Kick off the scan
        await self.start_scan(
            target, modules, mode,
            scope=scope, scope_strict=scope_strict,
            personas=personas, oob=oob,
            restrictions=restrictions,
        )

        # Wait for scan to complete (signaled by self.running = False in stream_events)
        while self.running:
            await asyncio.sleep(0.1)
            if listen_task.done():
                break
        
        # Cleanup
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            pass


def _load_scope_file(path: str) -> List[str]:
    """Read a scope file (one rule per line, # comments, blank lines ignored)."""
    rules: List[str] = []
    p = Path(path)
    if not p.exists():
        print(f"❌ scope file not found: {path}")
        sys.exit(2)
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line)
    if not rules:
        print(f"❌ scope file {path} has no non-comment rules")
        sys.exit(2)
    return rules


def _load_personas_file(path: str) -> List[Dict[str, Any]]:
    """Read a persona JSON file. Must be a list of persona dicts, each with a 'name' field.

    Personas drive wraith_persona_diff (differential authentication testing).
    Without personas configured, the wraith_persona_diff tool is silently
    skipped at intent selection — see core/scheduler/strategos.py:_select_tools.
    """
    p = Path(path)
    if not p.exists():
        print(f"❌ personas file not found: {path}")
        sys.exit(2)
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print(f"❌ personas file {path} is not valid JSON: {e}")
        sys.exit(2)
    if not isinstance(data, list) or not data:
        print(f"❌ personas file {path} must be a non-empty JSON list of persona objects")
        sys.exit(2)
    for i, persona in enumerate(data):
        if not isinstance(persona, dict):
            print(f"❌ personas[{i}] must be a JSON object")
            sys.exit(2)
        if not persona.get("name"):
            print(f"❌ personas[{i}] missing required 'name' field")
            sys.exit(2)
    return data


def _load_oob_file(path: str) -> Dict[str, Any]:
    """Read an OOB config JSON file. Must contain 'provider' and 'base_domain'.

    OOB drives wraith_oob_probe (out-of-band callback detection). Without
    this configured, the tool is silently skipped.
    """
    p = Path(path)
    if not p.exists():
        print(f"❌ OOB config file not found: {path}")
        sys.exit(2)
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print(f"❌ OOB config file {path} is not valid JSON: {e}")
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"❌ OOB config must be a JSON object")
        sys.exit(2)
    for field in ("provider", "base_domain"):
        if not data.get(field):
            print(f"❌ OOB config missing required '{field}' field")
            sys.exit(2)
    return data


def _load_restrictions_file(path: str) -> Dict[str, Any]:
    """Read a restrictions.json file produced by ``sentinel-ingest``.

    Returns the parsed dict; the server-side policy_enforcer translates
    it into a ``PolicyEnforcement`` and applies it before scan start.
    Missing or malformed files exit the CLI with code 2 — better to fail
    loud than silently scan without the restrictions the operator
    intended to apply.
    """
    p = Path(path)
    if not p.exists():
        print(f"❌ restrictions file not found: {path}")
        sys.exit(2)
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        print(f"❌ restrictions file {path} is not valid JSON: {e}")
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"❌ restrictions file must be a JSON object")
        sys.exit(2)
    # Don't validate further here — the server's policy_enforcer is the
    # authoritative parser and surfaces schema mismatches as warnings.
    return data


async def main():
    parser = argparse.ArgumentParser(description="SentinelForge Headless Scanner")
    parser.add_argument("--target", help="Target URL/IP to scan")
    parser.add_argument("--modules", help="Comma-separated list of tools to run (optional)")
    parser.add_argument("--mode", default="standard", help="Scan mode (standard, bug_bounty, stealth, passive)")
    parser.add_argument(
        "--scope",
        type=str,
        default=None,
        help="Path to a scope file (one rule per line). Required for bug-bounty work.",
    )
    parser.add_argument(
        "--scope-strict",
        action="store_true",
        help="Reject targets that don't match any inclusion rule. Recommended for bounty scans.",
    )
    parser.add_argument(
        "--personas",
        type=str,
        default=None,
        help="Path to a JSON file with persona profiles (list of objects with at least 'name'). "
             "Unlocks wraith_persona_diff for differential-auth IDOR testing.",
    )
    parser.add_argument(
        "--oob",
        type=str,
        default=None,
        help="Path to a JSON file with OOB provider config (object with 'provider' and 'base_domain'). "
             "Unlocks wraith_oob_probe for out-of-band callback detection (SQLi/XXE/SSRF/RCE).",
    )
    parser.add_argument(
        "--restrictions",
        type=str,
        default=None,
        help="Path to a <program>-restrictions.json file produced by "
             "`sentinel-ingest`. Enforces program-policy at scan-time: bans "
             "categorically-disallowed tools (e.g. nuclei_mutating under NO_DOS), "
             "caps rate limits, and refuses the scan entirely if the policy "
             "blocks automated scanning.",
    )

    args = parser.parse_args()

    target = args.target
    if not target:
        try:
            target = input("Enter target to scan: ").strip()
        except KeyboardInterrupt:
            print("\nCancelled.")
            return

    if not target:
        print("Error: Target is required.")
        return

    modules = args.modules.split(",") if args.modules else None
    scope = _load_scope_file(args.scope) if args.scope else None
    personas = _load_personas_file(args.personas) if args.personas else None
    oob = _load_oob_file(args.oob) if args.oob else None
    restrictions = _load_restrictions_file(args.restrictions) if args.restrictions else None

    # Defensive: bounty mode without a scope file is almost always a misconfiguration.
    # Bug-bounty work treats "no scope" as "deny everything", so the scan will
    # produce nothing useful. Warn loudly.
    if args.mode == "bug_bounty" and scope is None:
        print("⚠ WARNING: --mode bug_bounty without --scope will reject everything.")
        print("   Pass --scope <file> with explicit allow rules.")

    cli = SentinelCLI()
    
    # Handle Ctrl+C gracefully
    def handle_sigint():
        print("\nStopping...")
        cli.running = False
    
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, handle_sigint)
    except NotImplementedError:
        # Windows/some environments don't support add_signal_handler in this context
        pass

    await cli.run(
        target, modules, args.mode,
        scope=scope, scope_strict=args.scope_strict,
        personas=personas, oob=oob,
        restrictions=restrictions,
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
