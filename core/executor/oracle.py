"""
core/executor/oracle.py

Purpose:
    The "Judge". Evaluates valid ExecutionResults against the OracleSpec.
    Decides: SECURE, BREACH, or ANOMALY.
    
    V1 Upgrade:
    - Crash Fingerprinting (Deduplication)
    - Distinguish 5xx (Crash) vs 4xx (Rejection) vs 2xx (Bypass)

Magnum Opus Standards:
    - Zero False Positives: If we say BREACH, it must be a breach.
    - Evidence: Every verdict must point to the signal that caused it.
"""

import logging
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime

from .models import ExecutionResult, ExecutionStatus, BreachStatus, OracleSpec

log = logging.getLogger("executor.oracle")

class StandardOracleEvaluator:
    def __init__(self):
        self.crash_hashes = set()

    def evaluate(self, result: ExecutionResult, spec: OracleSpec) -> BreachStatus:
        """
        Compare result signals against spec expectations.
        """
        if result.status == ExecutionStatus.ERROR:
            # Harness failed (network/timeout), not necessarily the target's fault
            # unless we were testing for DoS.
            return BreachStatus.UNKNOWN

        signals = result.signals or {}
        status_code = signals.get("status_code")

        # 1. Critical Anomaly Check (5xx)
        if status_code and status_code >= 500:
            signature = self._fingerprint(result)
            if signature not in self.crash_hashes:
                log.warning(f"🚨 ANOMALY: Server returned {status_code} (New Crash Signature)")
                self.crash_hashes.add(signature)
                return BreachStatus.ANOMALY
            else:
                log.info(f"Anomaly {status_code} detected (Duplicate Signature). Suppressing.")
                # We still return ANOMALY but maybe LogLess?
                # For now, return ANOMALY so the system knows, but we suppressed the log spam.
                return BreachStatus.ANOMALY

        # 2. Check Forbidden Signals (Breach)
        forbidden = spec.forbidden
        if "status_code" in forbidden:
            forbidden_code = forbidden["status_code"]
            if status_code == forbidden_code:
                log.critical(f"BREACH: Forbidden status {status_code} observed.")
                return BreachStatus.BREACH

        # 3. Check Expected Signals (Secure)
        expected = spec.expected
        if "status_code" in expected:
            expected_codes = expected["status_code"]
            if isinstance(expected_codes, int):
                expected_codes = [expected_codes]
            
            if status_code in expected_codes:
                return BreachStatus.SECURE
            
            # If not expected and not forbidden (e.g. 403 when expecting 400), 
            # it's usually SECURE or UNKNOWN, but let's be conservative.
            # If we expected 400 (Bad Request) and got 200 (OK), that's bad.
            # If we expected 401 (Unauthorized) and got 200 (OK), that's bad.
        
        # Fallback Logic for "Bypass" detection
        # If we expected 4xx and got 2xx => BREACH
        if self._is_bypass(expected_codes=expected.get("status_code"), actual_code=status_code):
             log.critical(f"BREACH: Auth Bypass detected. Expected {expected.get('status_code')}, got {status_code}")
             return BreachStatus.BREACH

        return BreachStatus.SECURE

    def _fingerprint(self, result: ExecutionResult) -> str:
        """
        Create a stable hash of the crash to prevent log spam.
        """
        signals = result.signals
        # We hash: URL path + Method + Status Code + First 100 bytes of body
        # This groups same-endpoint crashes together.
        
        url = signals.get("url", "unknown")
        # Normalize url to path
        try:
             # fast hacky url parse
             path = url.split("://")[-1].split("/", 1)[-1].split("?")[0]
        except:
             path = url
             
        status = str(signals.get("status_code", 0))
        body_snippet = signals.get("body", "")[:100]
        
        raw = f"{path}|{status}|{body_snippet}"
        return hashlib.md5(raw.encode("utf-8", errors="ignore")).hexdigest()

    def _is_bypass(self, expected_codes: Any, actual_code: Optional[int]) -> bool:
        if not actual_code or not expected_codes:
            return False
            
        if isinstance(expected_codes, int):
            expected_codes = [expected_codes]
            
        # Heuristic: If we expect failure (4xx) and get success (2xx) -> Bypass
        expect_failure = any(400 <= c < 500 for c in expected_codes)
        got_success = 200 <= actual_code < 300
        
        return expect_failure and got_success
