#
# PURPOSE:
# This module is part of the wraith package in SentinelForge.
# The Hand of God - Automated attack verification.
#
# CAL INTEGRATION:
# - on_hypothesis: Asserts a Claim ("target is exploitable via vuln_class")
# - _execute_verification: Adds Evidence to validate or dispute the claim
#

"""
core/wraith/automator.py
The Hand of God.
Listens for AI Hypotheses and automatically executes verification strikes.
Now integrated with CAL for claim-based reasoning.
"""

import logging
import asyncio
from typing import Dict, Optional
from core.base.session import ScanSession
from core.cal.types import Evidence, Provenance, Claim

logger = logging.getLogger(__name__)

class WraithAutomator:
    """
    Observer that reacts to new 'hypothesis' findings.
    
    CAL INTEGRATION:
    Every hypothesis becomes a Claim in the global ReasoningSession.
    Verification results become Evidence that supports or disputes the Claim.
    """
    
    def __init__(self, session: ScanSession):
        """Function __init__."""
        self.session = session
        
        # [CAL INTEGRATION]
        from core.cortex.reasoning import get_reasoning_engine
        self.reasoning_engine = get_reasoning_engine()
        
        logger.info("[Wraith] CAL integration enabled - attacks will emit Claims")

    async def on_hypothesis(self, finding: Dict) -> Optional[Claim]:
        """
        Called when a new Hypothesis Finding is added.
        Asserts a CAL Claim and schedules verification.
        
        Returns the created Claim for tracking.
        """
        ftype = finding.get("type", "")
        if not ftype.startswith("hypothesis::"):
            return None

        target = finding.get("target")
        metadata = finding.get("metadata", {})
        payloads = metadata.get("payloads", [])
        
        self.session.log(f"[Wraith] Analyzed Hypothesis: {ftype}. preparing verification...")
        
        # ═══════════════════════════════════════════════════════════════════
        # CAL INTEGRATION: Assert a Claim for this hypothesis
        # ═══════════════════════════════════════════════════════════════════
        vuln_class = ftype.split("::")[-1] if "::" in ftype else "unknown"
        
        claim = self.reasoning_engine.assert_claim(
            statement=f"{target} is exploitable via {vuln_class}",
            source="Wraith",
            evidence_content={
                "hypothesis_type": ftype,
                "target": target,
                "payloads": payloads,
                "status": "pending_verification"
            },
            confidence=0.3,  # Low confidence until verified
            metadata={
                "vuln_class": vuln_class,
                "target": target,
                "payloads": payloads
            }
        )
        
        self.session.log(f"[CAL] Wraith asserted Claim {claim.id}: {claim.statement}")
        
        # Schedule verification
        asyncio.create_task(self._execute_verification(target, payloads, ftype, claim.id))
        logger.info(f"[Wraith] Launched verification task for Claim {claim.id}")
        
        return claim

    async def _execute_verification(self, target: str, payloads: list, ftype: str, claim_id: str):
        """Execute real HTTP-based attack verification against the target.

        Flow:
        1. Determine injection method from vuln_class (query-param, body, path).
        2. For each payload, send an HTTP request via the evasion engine
           (which auto-detects WAF blocks and mutates payloads).
        3. Evaluate the response with oracle heuristics (status-code diff,
           reflection detection, timing anomalies).
        4. Emit CAL Evidence supporting or disputing the Claim.
        """
        import httpx
        from core.wraith.evasion import WraithEngine

        vuln_class = ftype.split("::")[-1] if "::" in ftype else "unknown"
        evasion = WraithEngine.instance()

        success = False
        used_payload = None
        response_signals: Dict = {}

        # Resolve target URL: if target is a bare hostname, prepend http://
        target_url = target if target.startswith("http") else f"http://{target}"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            verify=False,
            follow_redirects=True,
        ) as client:
            # --- Capture baseline response for differential analysis ---
            baseline_status = None
            baseline_length = 0
            try:
                baseline = await client.get(target_url)
                baseline_status = baseline.status_code
                baseline_length = len(baseline.text)
            except Exception:
                pass  # Target may not respond to bare GET; that's fine

            for payload in payloads:
                if not payload:
                    continue
                try:
                    result = await evasion.stealth_send(
                        client, target_url, "GET", payload, vuln_class.lower(),
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

        # ═══════════════════════════════════════════════════════════════════
        # CAL INTEGRATION: Add Evidence based on verification result
        # ═══════════════════════════════════════════════════════════════════
        verification_evidence = Evidence(
            content={
                "target": target,
                "payload_used": used_payload,
                "success": success,
                "vuln_class": vuln_class,
                "status": "verified" if success else "failed",
                "response_signals": response_signals,
            },
            description=(
                f"Wraith verification: {'SUCCESS — payload reflected/executed' if success else 'FAILED — no exploitation indicators'}"
            ),
            provenance=Provenance(
                source="Wraith:verification",
                method="automated_http_attack",
                run_id=self.session.session_id
            ),
            confidence=0.9 if success else 0.8
        )

        self.reasoning_engine.add_evidence(
            claim_id=claim_id,
            evidence=verification_evidence,
            supporting=success,
        )

        if success:
            self.session.log(f"[Wraith] TARGET HIT! {ftype} verified with payload: {used_payload}")
            self.session.log(f"[CAL] Claim {claim_id} strengthened by verification Evidence")

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
                    "cal_claim_id": claim_id,
                    "cal_evidence_id": verification_evidence.id,
                }
            })
        else:
            self.session.log(f"[Wraith] Hypothesis {ftype} failed verification — no exploitation indicators")
            self.session.log(f"[CAL] Claim {claim_id} disputed by verification Evidence")
