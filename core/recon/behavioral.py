"""Module behavioral: inline documentation for /Users/jason/Developer/sentinelforge/core/recon/behavioral.py."""
#
# PURPOSE:
# This module is part of the recon package in SentinelForge.
# [Specific purpose based on module name: behavioral]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

# core/recon.py — Reconnaissance and behavioral probes

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import hashlib
import socket
import ssl
import statistics
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode

from core.data.findings import findings_store
from core.data.evidence import evidence_store


# Passive recon omitted for brevity…
class PassiveReconEngine:
    """Legacy passive recon (httpx, dnsx, sslscan)."""

    TOOLS = {
        "httpx": {
            "cmd": ["httpx", "-silent", "-title", "-status-code", "-tech-detect", "-json", "-u", "{target}"],
            "parser": "parse_httpx",
        },
        "dnsx": {
            "cmd": ["dnsx", "-silent", "-resp", "-a", "-aaaa", "-json", "-d", "{target}"],
            "parser": "parse_dnsx",
        },
        "sslscan": {
            "cmd": ["sslscan", "{target}"],
            "parser": "parse_sslscan",
        },
    }

    async def run_all(self, target: str):
        """AsyncFunction run_all."""
        results = []

        # Loop over items.
        for tool, meta in self.TOOLS.items():
            if shutil.which(meta["cmd"][0]) is None:
                continue

            cmd = [arg.replace("{target}", target) for arg in meta["cmd"]]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            out = await proc.communicate()
            stdout = out[0].decode("utf-8", errors="ignore")

            parser = getattr(self, meta["parser"])
            parsed = await parser(target, stdout)
            if parsed:
                findings_store.bulk_add(parsed)
                results.extend(parsed)

        return results

    async def parse_httpx(self, target: str, output: str):
        """AsyncFunction parse_httpx."""
        findings = []
        # Loop over items.
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            title = data.get("title", "Unknown")
            status = data.get("status-code", "?")
            tech = ", ".join(data.get("tech", []))

            findings.append({
                "type": "HTTP Fingerprint",
                "severity": "LOW",
                "tool": "httpx",
                "target": target,
                "proof": f"Status={status}, Title='{title}', Tech={tech}",
                "timestamp": datetime.now().isoformat(),
                "tags": ["recon", "fingerprint"],
                "families": ["recon-phase:fingerprint"],
            })
        return findings

    # ... rest unchanged ...

    async def parse_dnsx(self, target: str, output: str):
        """AsyncFunction parse_dnsx."""
        findings = []
        # Loop over items.
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            resp = data.get("resp", [])
            if resp:
                findings.append({
                    "type": "DNS Record",
                    "severity": "LOW",
                    "tool": "dnsx",
                    "target": target,
                    "proof": json.dumps(resp),
                    "timestamp": datetime.now().isoformat(),
                    "tags": ["recon", "dns"],
                    "families": ["recon-phase:dns"],
                })
        return findings

    async def parse_sslscan(self, target: str, output: str):
        """AsyncFunction parse_sslscan."""
        findings = []

        # Conditional branch.
        if "SSLv2" in output or "SSLv3" in output:
            findings.append({
                "type": "Weak SSL Protocol",
                "severity": "MEDIUM",
                "tool": "sslscan",
                "target": target,
                "proof": "Server supports deprecated SSL versions",
                "timestamp": datetime.now().isoformat(),
                "tags": ["crypto", "legacy"],
                "families": ["recon-phase:tls"],
            })

        ciphers = [line.strip() for line in output.splitlines() if "Cipher" in line]
        # Conditional branch.
        if ciphers:
            findings.append({
                "type": "Cipher Enumeration",
                "severity": "LOW",
                "tool": "sslscan",
                "target": target,
                "proof": "\n".join(ciphers[:10]),
                "timestamp": datetime.now().isoformat(),
                "tags": ["crypto", "ciphers"],
                "families": ["recon-phase:tls"],
            })

        return findings


ReconEngine = PassiveReconEngine  # backward compatibility


@dataclass
class RequestVariant:
    """Class RequestVariant."""
    name: str
    description: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    query_suffix: str = ""
    url_transform: Optional[Callable[[str], str]] = None


class BehavioralRecon:
    """Active behavioral recon: header fuzzing, replay, differential analysis."""

    VARIANTS: List[RequestVariant] = [
        RequestVariant("baseline", "Baseline request with default headers."),
        RequestVariant(
            "spoofed-ip",
            "Spoof client IP headers to probe WAF/CDN behavior.",
            headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        ),
        RequestVariant(
            "debug-probe",
            "Toggle common debug headers to elicit verbose responses.",
            headers={"X-Debug": "true", "X-Original-URL": "/admin"},
        ),
        RequestVariant(
            "cache-bust",
            "Bypass caches via headers.",
            headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
        ),
        RequestVariant(
            "alt-user-agent",
            "Rotate User-Agent to detect differential routing.",
            headers={"User-Agent": "AraUltra/Behavioral Recon"},
        ),
        RequestVariant(
            "param-fuzz:append-junk",
            "Append traversal payload to querystring.",
            query_suffix="_junk=..%2f..%2f..%2f",
        ),
        RequestVariant(
            "param-fuzz:dup-key",
            "Duplicate keys to probe server parsing.",
            query_suffix="id=1&id=1",
        ),
        RequestVariant(
            "param-fuzz:encoded",
            "Double-encoded traversal payload.",
            query_suffix="file=%252e%252e%252fetc%252fpasswd",
        ),
        RequestVariant(
            "param-fuzz:utf7",
            "UTF-7 encoded script payload.",
            query_suffix="payload=%2bADw-script%2bAD4-alert(1)%2bADw-%2fscript%2bAD4-",
        ),
        RequestVariant(
            "param-fuzz:protocol",
            "Redirect parameter injection.",
            query_suffix="redirect=http://127.0.0.1",
        ),
        RequestVariant(
            "param-fuzz:space",
            "Whitespace query fuzzing.",
            query_suffix="q=%20%20%09",
        ),
        RequestVariant(
            "param-fuzz:post-json",
            "POST JSON payload fuzzing.",
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b'{"id":"../etc/passwd"}',
        ),
    ]

    def __init__(self, log_fn=None, verify_ssl: Optional[bool] = None):
        """Function __init__."""
        self.log = log_fn or (lambda msg: None)
        # Conditional branch.
        if verify_ssl is None:
            verify_ssl = os.getenv("ARAULTRA_BEHAVIORAL_STRICT_SSL", "").lower() in ("1", "true", "yes", "on")
        self.verify_ssl = verify_ssl
        self._ssl_context = ssl.create_default_context()
        # Conditional branch.
        if not self.verify_ssl:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    async def run(self, target: str) -> List[dict]:
        """AsyncFunction run."""
        url = self._normalize_target(target)
        variant_results = await self._execute_variants(url)
        findings = self._analyze_differentials(variant_results, url)
        findings.extend(await self._run_tls_probe(url))
        findings.extend(await self._run_timing_phase(url))
        return findings

    async def _execute_variants(self, url: str) -> List[Dict[str, object]]:
        """AsyncFunction _execute_variants."""
        loop = asyncio.get_running_loop()
        tasks = []
        # Loop over items.
        for variant in self.VARIANTS:
            self.log(f"[behavioral] {variant.name} probe → {url}")
            tasks.append(loop.run_in_executor(None, self._perform_request, url, variant))
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        results: List[Dict[str, object]] = []
        # Loop over items.
        for variant, result in zip(self.VARIANTS, gathered):
            if isinstance(result, Exception):
                self.log(f"[behavioral] {variant.name} execution error: {result}")
                continue
            results.append(result)
        return results

    def _perform_request(self, url: str, variant: RequestVariant) -> Dict[str, object]:
        """Function _perform_request."""
        start = time.perf_counter()
        mutated_url = self._apply_variant_url(url, variant)
        req = urllib.request.Request(mutated_url, method=variant.method)
        # Loop over items.
        for key, value in variant.headers.items():
            req.add_header(key, value)

        # Error handling block.
        try:
            with urllib.request.urlopen(req, data=variant.body, timeout=15, context=self._ssl_context) as resp:
                body = resp.read()
                elapsed = (time.perf_counter() - start) * 1000
                headers = {k.lower(): v for k, v in resp.headers.items()}
                evidence_path = self._record_evidence(variant.name, mutated_url, resp.status, headers, body)
                return {
                    "variant": variant.name,
                    "status": resp.status,
                    "length": len(body),
                    "elapsed_ms": elapsed,
                    "headers": headers,
                    "body": body[:4096],
                    "hash": hashlib.sha256(body).hexdigest(),
                    "evidence_path": evidence_path,
                }
        except urllib.error.HTTPError as err:
            body = err.read()
            elapsed = (time.perf_counter() - start) * 1000
            headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
            evidence_path = self._record_evidence(variant.name, mutated_url, err.code, headers, body)
            return {
                "variant": variant.name,
                "status": err.code,
                "length": len(body),
                "elapsed_ms": elapsed,
                "headers": headers,
                "body": body[:4096],
                "hash": hashlib.sha256(body).hexdigest(),
                "evidence_path": evidence_path,
            }
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            self.log(f"[behavioral] {variant.name} error: {exc}")
            return {
                "variant": variant.name,
                "status": None,
                "length": 0,
                "elapsed_ms": elapsed,
                "headers": {},
                "body": b"",
                "hash": "",
                "error": str(exc),
            }

    def _analyze_differentials(self, results: List[Dict[str, object]], target: str) -> List[dict]:
        """Function _analyze_differentials."""
        findings: List[dict] = []
        baseline = next((r for r in results if r["variant"] == "baseline" and r.get("status") is not None), None)
        # Conditional branch.
        if not baseline:
            return findings

        base_status = baseline["status"]
        base_length = baseline["length"] or 1
        base_elapsed = baseline["elapsed_ms"]

        # Loop over items.
        for res in results:
            if res["variant"] == "baseline":
                continue
            status = res.get("status")
            if status is None:
                continue

            headers = res.get("headers", {})
            snippet = res.get("body", b"")[:400].decode("utf-8", errors="ignore")
            evidence = snippet or f"Variant={res['variant']}, status={status}"
            metadata = {"variant": res["variant"]}
            if res.get("evidence_path"):
                metadata["evidence_path"] = res["evidence_path"]

            if status != base_status:
                severity = "HIGH" if base_status and base_status >= 400 and status < 400 else "MEDIUM"
                findings.append(self._make_finding(
                    target,
                    "Response Differential (Status)",
                    severity,
                    f"{res['variant']} returned {status} vs baseline {base_status}",
                    evidence,
                    tags=["logic-behavior-diff"],
                    variant=res["variant"],
                    metadata=metadata,
                ))

            length_delta = abs(res["length"] - baseline["length"])
            if base_length and (length_delta / base_length) > 0.2:
                findings.append(self._make_finding(
                    target,
                    "Response Size Differential",
                    "MEDIUM",
                    f"{res['variant']} length={res['length']} vs baseline {baseline['length']}",
                    evidence,
                    tags=["cache-misconfig"],
                    variant=res["variant"],
                    metadata=metadata,
                ))

            elapsed_delta = res["elapsed_ms"] - base_elapsed
            if abs(elapsed_delta) > 250 and abs(elapsed_delta) / (base_elapsed or 1) > 0.2:
                findings.append(self._make_finding(
                    target,
                    "Timing Variance Detected",
                    "LOW",
                    f"{res['variant']} latency delta {elapsed_delta:.1f} ms",
                    evidence,
                    tags=["timing-variance"],
                    variant=res["variant"],
                    metadata=metadata,
                ))

            if res["variant"] == "debug-probe" and "debug" in snippet.lower():
                findings.append(self._make_finding(
                    target,
                    "Debug Response Surface",
                    "HIGH",
                    "Debug headers exposed verbose server output.",
                    evidence,
                    tags=["debug-toggle"],
                    variant=res["variant"],
                    metadata=metadata,
                ))

            if base_status == 403 and status < 400:
                findings.append(self._make_finding(
                    target,
                    "Potential WAF Bypass via Header Variation",
                    "HIGH",
                    f"{res['variant']} succeeded ({status}) whereas baseline was blocked ({base_status}).",
                    evidence,
                    tags=["waf-bypass"],
                    variant=res["variant"],
                    metadata=metadata,
                ))

            if "set-cookie" in headers and "secure" not in headers.get("set-cookie", ""):
                findings.append(self._make_finding(
                    target,
                    "Session Behavior Exposure",
                    "MEDIUM",
                    f"{res['variant']} response altered cookies: {headers.get('set-cookie')}",
                    evidence,
                    tags=["session", "behavioral"],
                    variant=res["variant"],
                    metadata=metadata,
                ))

        return findings

    @staticmethod
    def _normalize_target(target: str) -> str:
        """Function _normalize_target."""
        parsed = urlparse(target)
        # Conditional branch.
        if not parsed.scheme:
            return f"https://{target}"
        return target

    @staticmethod
    def _make_finding(target: str, ftype: str, severity: str, message: str, proof: str, tags: List[str], variant: Optional[str] = None, families: Optional[List[str]] = None, metadata: Optional[Dict[str, object]] = None):
        """Function _make_finding."""
        metadata = metadata.copy() if metadata else {}
        # Conditional branch.
        if variant:
            metadata.setdefault("variant", variant)
        return {
            "type": ftype,
            "severity": severity,
            "tool": "behavioral-recon",
            "target": target,
            "proof": proof,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "tags": tags,
            "families": families or ["recon-phase:behavior"],
            "metadata": metadata,
        }

    def _apply_variant_url(self, url: str, variant: RequestVariant) -> str:
        """Function _apply_variant_url."""
        # Conditional branch.
        if variant.url_transform:
            return variant.url_transform(url)
        # Conditional branch.
        if not variant.query_suffix:
            return url
        parsed = urlsplit(url)
        existing = parse_qsl(parsed.query, keep_blank_values=True)
        suffix_pairs = parse_qsl(variant.query_suffix, keep_blank_values=True)
        merged = existing + suffix_pairs
        query = urlencode(merged, doseq=True)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    def _record_evidence(self, variant: str, url: str, status: Optional[int], headers: Dict[str, str], body: bytes) -> Optional[str]:
        """Function _record_evidence."""
        host = urlparse(url).netloc or "behavioral"
        preview = body[:2000].decode("utf-8", errors="ignore")
        lines = [
            f"Variant: {variant}",
            f"URL: {url}",
            f"Status: {status}",
            "",
            "Headers:",
        ]
        # Loop over items.
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append("Body Preview:")
        lines.append(preview)
        content = "\n".join(lines)
        # Error handling block.
        try:
            return evidence_store.save_text(f"behavioral_{variant}", host, content)
        except Exception as exc:
            self.log(f"[behavioral] evidence save failed: {exc}")
            return None

    async def _run_tls_probe(self, url: str) -> List[dict]:
        """AsyncFunction _run_tls_probe."""
        parsed = urlparse(url)
        # Conditional branch.
        if parsed.scheme != "https" or not parsed.hostname:
            return []
        
        from core.tls import TLSAnalyzer
        
        host = parsed.hostname
        port = parsed.port or 443
        
        analyzer = TLSAnalyzer(host, port)
        results = await analyzer.analyze()
        
        findings: List[dict] = []
        cert = results.get("certificate", {})
        
        # Conditional branch.
        if "error" in cert:
            self.log(f"[behavioral] TLS probe error: {cert['error']}")
            return []

        # Basic Handshake Finding
        proof_lines = [
            f"Subject: {cert.get('subject')}",
            f"Issuer: {cert.get('issuer')}",
            f"Valid: {cert.get('not_valid_before')} to {cert.get('not_valid_after')}",
            f"Fingerprint: {cert.get('fingerprint_sha256')}",
        ]
        
        # Add version info
        versions = results.get("versions", {})
        supported_versions = [v for v, supported in versions.items() if supported is True]
        proof_lines.append(f"Supported Versions: {', '.join(supported_versions)}")
        
        base_proof = "\n".join(proof_lines)
        
        findings.append(self._make_finding(
            url,
            "TLS Certificate Details",
            "INFO",
            f"Certificate for {cert.get('subject')}",
            base_proof,
            tags=["tls", "cert"],
            variant="tls-probe",
            families=["recon-phase:tls-active"],
        ))

        # Check Expiration
        status = cert.get("status")
        # Conditional branch.
        if status == "EXPIRED":
            findings.append(self._make_finding(
                url,
                "TLS Certificate Expired",
                "HIGH",
                f"Certificate expired on {cert.get('not_valid_after')}",
                base_proof,
                tags=["tls", "cert", "expired"],
                variant="tls-probe",
                families=["recon-phase:tls-active"],
            ))
        elif status == "VALID" and cert.get("days_remaining", 999) < 30:
             findings.append(self._make_finding(
                url,
                "TLS Certificate Expiring Soon",
                "MEDIUM",
                f"Certificate expires in {cert.get('days_remaining')} days",
                base_proof,
                tags=["tls", "cert", "expiring"],
                variant="tls-probe",
                families=["recon-phase:tls-active"],
            ))

        # Check Weak Versions
        weak_versions = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
        found_weak = [v for v in supported_versions if v in weak_versions]
        # Conditional branch.
        if found_weak:
            findings.append(self._make_finding(
                url,
                "Deprecated TLS Protocol",
                "HIGH",
                f"Server supports: {', '.join(found_weak)}",
                base_proof,
                tags=["tls", "weak-tls"],
                variant="tls-probe",
                families=["recon-phase:tls-active"],
            ))

        return findings

    async def _run_timing_phase(self, url: str) -> List[dict]:
        """AsyncFunction _run_timing_phase."""
        samples = await self._collect_timing_samples(url)
        # Conditional branch.
        if len(samples) < 5:
            return []
        median = statistics.median(samples)
        stdev = statistics.pstdev(samples)
        delta = max(samples) - min(samples)
        findings: List[dict] = []
        # Conditional branch.
        if stdev > 150 or delta > 500:
            severity = "MEDIUM" if delta > 750 else "LOW"
            proof = json.dumps({
                "samples_ms": samples,
                "median_ms": median,
                "stdev_ms": stdev,
                "delta_ms": delta,
            })
            findings.append(self._make_finding(
                url,
                "Timing Anomaly",
                severity,
                f"{len(samples)} samples median={median:.1f}ms stdev={stdev:.1f}ms delta={delta:.1f}ms",
                proof,
                tags=["timing-variance"],
                variant="timing-phase",
                families=["recon-phase:timing"],
            ))
        return findings

    async def _collect_timing_samples(self, url: str, count: int = 8) -> List[float]:
        """AsyncFunction _collect_timing_samples."""
        loop = asyncio.get_running_loop()
        tasks = [loop.run_in_executor(None, self._time_single_request, url) for _ in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        samples = []
        # Loop over items.
        for res in results:
            if isinstance(res, Exception):
                continue
            if res is not None:
                samples.append(res)
        return samples

    def _time_single_request(self, url: str) -> Optional[float]:
        """Function _time_single_request."""
        req = urllib.request.Request(url, method="GET")
        start = time.perf_counter()
        # Error handling block.
        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ssl_context) as resp:
                resp.read(256)
        except Exception as exc:
            self.log(f"[behavioral] timing sample error: {exc}")
            return None
        return (time.perf_counter() - start) * 1000
