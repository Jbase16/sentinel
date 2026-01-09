from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .types import PoCArtifact, iso_now


@dataclass(frozen=True)
class PoCTemplate:
    title: str
    risk: str
    commands: List[str]
    notes: List[str]


class PoCSafetyError(RuntimeError):
    pass


class PoCGenerator:
    """
    Generates strictly non-destructive verification commands for findings.

    Design:
    - Output is a list of shell commands as *strings* for operator copy/paste.
    - Safety is enforced by:
        1) command allowlist (by executable)
        2) verb/flag denylist (common exploit primitives)
        3) URL/path sanitization
    """

    # Allowed executables (first token)
    _ALLOW_CMDS = {
        "curl",
        "nc",
        "ncat",
        "openssl",
        "dig",
        "nslookup",
        "host",
        "ping",
        "traceroute",
        "mtr",
        "nmap",
        "python3",
    }

    # Dangerous patterns we never allow to appear anywhere in the command string.
    # This is intentionally paranoid.
    _DENY_PATTERNS = [
        r"\brm\s+-rf\b",
        r"\bchmod\s+\+x\b",
        r"\bbash\s+-c\b",
        r"\bsh\s+-c\b",
        r"\bpython3?\s+-c\b",
        r"\beval\b",
        r"\bexec\b",
        r"\bperl\b",
        r"\bruby\b",
        r"\bpowershell\b",
        r"\bmsfconsole\b",
        r"\bmetasploit\b",
        r"\bsqlmap\b",
        r"\bhydra\b",
        r"\bncrack\b",
        r"\bnetcat\s+-e\b",
        r"\bnc\s+-e\b",
        r"\bncat\s+--exec\b",
        r"(?:^|\s)--script\b",      # nmap NSE can cross into exploitation
        r"(?:^|\s)--data\b",        # curl can become state-changing
        r"(?:^|\s)-d\b",            # curl -d
        r"(?:^|\s)--form\b",        # curl --form
        r"(?:^|\s)-F\b",            # curl -F
        r"\bPUT\b",           # curl -X PUT
        r"\bPOST\b",          # curl -X POST
        r"\bDELETE\b",        # curl -X DELETE
        r"\bPATCH\b",         # curl -X PATCH
        r"(?:^|\s)--request\b",
        r"(?:^|\s)-X\b",
    ]

    # Minimal URL/host sanitization: allow typical hostnames, IPv4/IPv6 (bracketed),
    # optional port, optional path/query for HTTP(S).
    _HOST_RE = re.compile(r"^[A-Za-z0-9\.\-\_]+$")
    _IPV6_BRACKET_RE = re.compile(r"^\[[0-9a-fA-F:]+\]$")

    def generate_for_finding(self, finding: Dict[str, Any], target_hint: Optional[str] = None) -> PoCArtifact:
        finding_id = str(finding.get("id") or finding.get("finding_id") or "")
        if not finding_id:
            raise ValueError("Finding is missing id/finding_id")

        ftype = str(finding.get("type") or finding.get("finding_type") or "unknown").lower()

        # Common fields (best-effort, no hard dependency on internal schemas)
        host = (finding.get("host") or finding.get("hostname") or target_hint or "").strip()
        ip = (finding.get("ip") or "").strip()
        port = finding.get("port")
        protocol = (finding.get("protocol") or "tcp").strip().lower()
        scheme = (finding.get("scheme") or "").strip().lower()
        path = (finding.get("path") or "/").strip() or "/"

        host_or_ip = host or ip
        if host_or_ip:
            self._assert_safe_host(host_or_ip)

        # Build templates by type (keep it boring; boring is safe)
        template = self._template_for_type(
            ftype=ftype,
            host=host_or_ip,
            port=port,
            protocol=protocol,
            scheme=scheme,
            path=path,
            raw=finding,
        )

        commands = [self._normalize_command(c) for c in template.commands]
        for c in commands:
            self._assert_safe_command(c)

        return PoCArtifact(
            finding_id=finding_id,
            title=template.title,
            risk=template.risk,
            safe=True,
            commands=commands,
            notes=template.notes,
            created_at=iso_now(),
        )

    def _template_for_type(
        self,
        ftype: str,
        host: str,
        port: Any,
        protocol: str,
        scheme: str,
        path: str,
        raw: Dict[str, Any],
    ) -> PoCTemplate:
        # Normalize port
        try:
            port_i = int(port) if port is not None else None
        except Exception:
            port_i = None

        # Pick scheme defaults
        if not scheme:
            if port_i == 443:
                scheme = "https"
            elif port_i == 80:
                scheme = "http"

        # ----- Common template helpers
        def http_url() -> str:
            p = f":{port_i}" if port_i and port_i not in (80, 443) else ""
            s = scheme if scheme in ("http", "https") else "http"
            safe_path = path if path.startswith("/") else f"/{path}"
            return f"{s}://{host}{p}{safe_path}"

        def hostport() -> str:
            return f"{host} {port_i}" if port_i else f"{host}"

        # ----- Templates
        if ftype in ("open_port", "port_open", "service_open"):
            title = f"Verify open port {port_i}/{protocol} on {host}"
            cmds = []
            if port_i:
                # Banner-safe connect test
                cmds.append(f"nc -zv {host} {port_i}")
                # Version detection with safe nmap flags only (no scripts)
                cmds.append(f"nmap -sV -p {port_i} {host}")
                # If HTTP-ish, also HEAD
                if port_i in (80, 443) or scheme in ("http", "https"):
                    cmds.append(f"curl -sS -I {http_url()}")
            else:
                cmds.append(f"nmap -sV {host}")
            notes = [
                "These commands only verify reachability and service version detection.",
                "No exploitation, payload injection, or state-changing requests are performed.",
            ]
            return PoCTemplate(title=title, risk="info", commands=cmds, notes=notes)

        if ftype in ("http_endpoint", "http_service", "web_service"):
            title = f"Verify HTTP service on {host}"
            url = http_url()
            cmds = [
                f"curl -sS -I {url}",
                f"curl -sS -o /dev/null -w '%{{http_code}}\\n' {url}",
            ]
            notes = [
                "Uses HTTP HEAD and a simple GET to verify status code only.",
                "No POST/PUT/DELETE/PATCH requests are allowed by the PoC safety policy.",
            ]
            return PoCTemplate(title=title, risk="info", commands=cmds, notes=notes)

        if ftype in ("tls_issue", "tls_misconfig", "ssl_issue"):
            title = f"Verify TLS configuration on {host}"
            if not port_i:
                port_i = 443
            cmds = [
                f"openssl s_client -connect {host}:{port_i} -servername {host} -brief </dev/null",
                f"nmap -sV -p {port_i} {host}",
            ]
            notes = [
                "OpenSSL handshake output helps validate cert chain and protocol negotiation.",
                "No brute force or downgrade attacks are performed.",
            ]
            return PoCTemplate(title=title, risk="medium", commands=cmds, notes=notes)

        if ftype in ("dns_issue", "dangling_dns", "dns_misconfig"):
            title = f"Verify DNS records for {host}"
            cmds = [
                f"dig +short {host} A",
                f"dig +short {host} AAAA",
                f"dig +short {host} CNAME",
            ]
            notes = [
                "DNS queries are read-only verification.",
                "For dangling DNS findings, validate NXDOMAIN/NoAnswer or unexpected CNAME targets.",
            ]
            return PoCTemplate(title=title, risk="medium", commands=cmds, notes=notes)

        # Generic fallback (safe, but less helpful)
        title = f"Verify finding {ftype} for {host or 'target'}"
        cmds = []
        if host:
            cmds.append(f"nmap -sV {host}")
        notes = [
            "Finding type not mapped to a specialized template; emitted generic version detection only.",
        ]
        return PoCTemplate(title=title, risk=str(raw.get("risk") or "unknown"), commands=cmds, notes=notes)

    def _normalize_command(self, cmd: str) -> str:
        # Collapse whitespace; keep it simple.
        cmd = cmd.strip()
        cmd = re.sub(r"\s+", " ", cmd)
        return cmd

    def _assert_safe_host(self, host: str) -> None:
        host = host.strip()
        if self._IPV6_BRACKET_RE.match(host):
            return
        if self._HOST_RE.match(host):
            return
        raise PoCSafetyError(f"Unsafe host value: {host!r}")

    def _assert_safe_command(self, cmd: str) -> None:
        if not cmd:
            raise PoCSafetyError("Empty command")

        exe = cmd.split(" ", 1)[0].strip()
        if exe not in self._ALLOW_CMDS:
            raise PoCSafetyError(f"Command not allowlisted: {exe}")

        for pat in self._DENY_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                raise PoCSafetyError(f"Command violates safety policy (matched {pat}): {cmd}")

        # Extra rule: python must not execute inline code
        if exe == "python3":
            if " -c " in f" {cmd} ":
                raise PoCSafetyError("Inline python execution is not allowed")

        # Extra rule: curl must be read-only-ish (no -X / --data etc already denied above)
        if exe == "curl":
            # Extra paranoia: explicitly iterate tokens to block -X, --data, etc.
            # (Regex should catch them, but tokenizer is safer against obfuscation)
            tokens = cmd.split()
            for t in tokens:
                if t.startswith("-") and not t.startswith("--"):
                    # Short flags: check characters
                    for char in t[1:]:
                        if char in "XdF": # X=method, d=data, F=form
                            raise PoCSafetyError(f"curl flag -{char} is unsafe")
                if t.startswith("--"):
                    if t in ("--data", "--form", "--request", "--upload-file"):
                         raise PoCSafetyError(f"curl flag {t} is unsafe")

        if exe == "nmap":
             tokens = cmd.split()
             for t in tokens:
                 if t in ("--script", "--script-args"):
                      raise PoCSafetyError("nmap scripts are not allowed in PoC")
