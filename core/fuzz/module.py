#
# PURPOSE:
# This module is part of the fuzz package in SentinelForge.
# [Specific purpose based on module name: module]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

"""
Minimal parameter fuzzing module.

This is a safe-ish starter stub:
- Sends a handful of payloads to a target URL as query params.
- Looks for basic reflection and HTTP 500s as signals.
- Returns findings as simple dicts (matching AraUltra-style shape).

Only run against authorized targets.
"""

from __future__ import annotations

import asyncio
from typing import Callable, List

import httpx

LogFn = Callable[[str], None]

# Starter payloads; expand with context-aware mutations later.
PAYLOADS = [
    "'\"",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "%7B%7B7*7%7D%7D",  # template injection probe
    "() { :;}; echo vulnerable",  # shellshock-ish
]


class ParamFuzzer:
    """
    Tiny param fuzzer. Not exhaustive—meant to prove the module wiring.
    """

    def __init__(self, log_fn: LogFn | None = None, timeout: float = 10.0):
        """Function __init__."""
        self.log = log_fn or (lambda msg: None)
        self.timeout = timeout

    async def fuzz(self, url: str, param_name: str = "test") -> List[dict]:
        """AsyncFunction fuzz."""
        findings: List[dict] = []

        async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=self.timeout) as client:
            for payload in PAYLOADS:
                params = {param_name: payload}
                try:
                    resp = await client.get(url, params=params)
                except Exception as exc:  # pragma: no cover - network exceptions vary
                    self.log(f"[fuzz] request error for {url} ({payload}): {exc}")
                    continue

                body = resp.text or ""
                reflected = payload in body
                status = resp.status_code

                sev = "LOW"
                ftype = "Fuzz Probe"
                proof = f"{param_name}={payload} -> HTTP {status}"

                if status >= 500:
                    sev = "MEDIUM"
                    ftype = "Potential server error on fuzz input"
                if reflected:
                    sev = "MEDIUM"
                    ftype = "Input reflection detected"

                findings.append(
                    {
                        "type": ftype,
                        "severity": sev,
                        "tool": "sentinel-fuzzer",
                        "target": url,
                        "proof": proof,
                        "tags": ["fuzz", "recon"],
                        "families": ["fuzzing"],
                        "metadata": {
                            "param": param_name,
                            "payload": payload,
                            "status": status,
                            "reflected": reflected,
                        },
                    }
                )

                self.log(f"[fuzz] {proof} (reflected={reflected})")

        return findings

    def run_sync(self, url: str, param_name: str = "test") -> List[dict]:
        """
        Convenience sync wrapper.
        """
        return asyncio.run(self.fuzz(url, param_name))
