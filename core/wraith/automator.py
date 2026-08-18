#
# PURPOSE:
# This module is part of the wraith package in SentinelForge.
# The Hand of God - Automated attack verification.
#

"""
core/wraith/automator.py
The Hand of God.
Listens for AI Hypotheses and automatically executes verification strikes.
"""

import logging
import asyncio
from typing import Dict
from core.base.session import ScanSession

logger = logging.getLogger(__name__)

class WraithAutomator:
    """
    Observer that reacts to new 'hypothesis' findings.
    """
    
    def __init__(self, session: ScanSession):
        """Function __init__."""
        self.session = session

    async def on_hypothesis(self, finding: Dict) -> None:
        """
        Called when a new Hypothesis Finding is added.
        Schedules bounded verification; finding promotion remains downstream.
        """
        ftype = finding.get("type", "")
        if not ftype.startswith("hypothesis::"):
            return None

        target = finding.get("target")
        metadata = finding.get("metadata", {})
        payloads = metadata.get("payloads", [])
        
        self.session.log(f"[Wraith] Analyzed Hypothesis: {ftype}. preparing verification...")
        # Schedule verification
        asyncio.create_task(self._execute_verification(target, payloads, ftype))
        logger.info("[Wraith] Launched verification task for %s", ftype)

    async def _execute_verification(self, target: str, payloads: list, ftype: str):
        """Execute real HTTP-based attack verification against the target.

        Flow:
        1. Determine injection method from vuln_class (query-param, body, path).
        2. For each payload, send an HTTP request via the evasion engine
           (which auto-detects WAF blocks and mutates payloads).
        3. Evaluate the response with oracle heuristics (status-code diff,
           reflection detection, timing anomalies).
        4. Emit a verified finding only when response signals support it.
        """
        import httpx
        from core.wraith.evasion import WraithEngine
        from core.net.egress import EgressBroker, same_origin_authorizer
        from core.net.http_factory import create_async_client

        vuln_class = ftype.split("::")[-1] if "::" in ftype else "unknown"
        evasion = WraithEngine.instance()

        success = False
        used_payload = None
        response_signals: Dict = {}

        # Resolve target URL: if target is a bare hostname, prepend http://
        target_url = target if target.startswith("http") else f"http://{target}"

        async with create_async_client(
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            broker = EgressBroker(client, same_origin_authorizer(target_url))
            # --- Capture baseline response for differential analysis ---
            baseline_status = None
            baseline_length = 0
            try:
                baseline = await broker.get(target_url)
                baseline_status = baseline.status_code
                baseline_length = len(baseline.text)
            except Exception:
                pass  # Target may not respond to bare GET; that's fine

            for payload in payloads:
                if not payload:
                    continue
                try:
                    result = await evasion.stealth_send(
                        broker, target_url, "GET", payload, vuln_class.lower(),
                    )

                    resp = result.get("response")
                    status = result.get("status", "failed")  # success | bypassed | failed

                    if resp is None:
                        continue

                    # --- Oracle heuristics: determine if the payload worked ---
                    hit = False
                    resp_text = resp.text if hasattr(resp, "text") else ""
                    resp_status = resp.status_code if hasattr(resp, "status_code") else 0

                    # H1: Reflection detection (XSS)
                    if vuln_class.lower() in ("xss", "reflected_xss"):
                        if payload in resp_text or payload.replace('"', "&quot;") in resp_text:
                            hit = True

                    # H2: SQL error signatures (SQLi)
                    if vuln_class.lower() in ("sqli", "sql_injection"):
                        sql_sigs = [
                            "syntax error", "mysql", "mariadb", "postgresql",
                            "sqlite", "ora-", "unclosed quotation",
                            "you have an error in your sql",
                        ]
                        if any(sig in resp_text.lower() for sig in sql_sigs):
                            hit = True
                        # Tautology check: response significantly larger than baseline
                        if baseline_length and len(resp_text) > baseline_length * 2:
                            hit = True

                    # H3: IDOR — different status or significantly different body
                    if vuln_class.lower() in ("idor", "broken_access_control"):
                        if baseline_status and resp_status == 200 and baseline_status != 200:
                            hit = True
                        if resp_status == 200 and baseline_length and len(resp_text) != baseline_length:
                            hit = True

                    # H4: Path traversal — file content signatures
                    if vuln_class.lower() in ("path_traversal", "lfi"):
                        traversal_sigs = ["root:", "/bin/", "[extensions]", "win.ini"]
                        if any(sig in resp_text for sig in traversal_sigs):
                            hit = True

                    # H5: WAF bypass succeeded (evasion engine mutated payload)
                    if status == "bypassed":
                        hit = True

                    # H6: Generic anomaly — 500 on a payload that shouldn't crash
                    if resp_status >= 500 and baseline_status and baseline_status < 500:
                        hit = True

                    if hit:
                        success = True
                        used_payload = result.get("bypass_payload") or result.get("payload") or payload
                        response_signals = {
                            "status_code": resp_status,
                            "body_length": len(resp_text),
                            "baseline_status": baseline_status,
                            "baseline_length": baseline_length,
                            "evasion_status": status,
                        }
                        break

                except Exception as exc:
                    logger.debug("[Wraith] Payload delivery failed for %s: %s", target_url, exc)
                    continue

        if success:
            self.session.log(f"[Wraith] TARGET HIT! {ftype} verified with payload: {used_payload}")

            self.session.findings.add_finding({
                "tool": "wraith_automator",
                "type": f"vuln::{vuln_class}",
                "severity": "HIGH",
                "target": target,
                "value": f"Verified exploitable {ftype}. Payload: {used_payload}",
                "metadata": {
                    "payload": used_payload,
                    "verified": True,
                    "response_signals": response_signals,
                }
            })
        else:
            self.session.log(f"[Wraith] Hypothesis {ftype} failed verification — no exploitation indicators")
