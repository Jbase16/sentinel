from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .types import PoCArtifact, iso_now


def _normalize_ftype(raw_type: str) -> str:
    """Map a classifier finding-type name to a PoC template category.

    The classifier emits Title-Case names with spaces ("Open Port",
    "Missing Security Header"); the templates dispatch on snake_case keys
    ("open_port"). Without this translation, EVERY finding fell through to
    the empty generic fallback — the Proof Lab produced zero commands for
    100% of real findings (Calibration Run #20 finding).

    Uses substring matching so naming variants ("Java Framework Detected",
    "Php Framework Detected") map to the same category without an
    exhaustive table.
    """
    t = (raw_type or "").strip().lower().replace("_", " ")

    # Most specific first.
    if "framework" in t or "version" in t or "outdated" in t:
        return "version_disclosure"
    if "header" in t:
        return "missing_header"
    if "cookie" in t:
        return "cookie_misconfig"
    if "directory listing" in t or "index of" in t:
        return "directory_listing"
    if "open port" in t or t in ("port open", "service open"):
        return "open_port"
    if "subdomain" in t or "dns" in t:
        # Subdomain takeover / DNS records both verify via dig + HEAD.
        return "subdomain" if "subdomain" in t else "dns_issue"
    if "tls" in t or "ssl" in t or "certificate" in t:
        return "tls_issue"
    if any(k in t for k in (
        "backup", "ssrf", "nikto", "enumeration", "business logic",
        "endpoint", "exposure", "disclosure", "directory", "waf", "listing",
        "misconfiguration",
    )):
        return "http_fetch"
    if "http" in t or "web" in t or "endpoint" in t:
        return "http_endpoint"
    return "generic"


def _parse_target(target: str) -> Tuple[str, str, Optional[int], str]:
    """Parse a target (URL or bare host[:port]) into (scheme, host, port, path)."""
    if not target:
        return "", "", None, ""
    t = target.strip()
    if "://" not in t:
        t = "//" + t  # let urlparse treat it as netloc
    parsed = urlparse(t, scheme="")
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or ""
    return scheme, host, port, path


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

        raw_type = str(finding.get("type") or finding.get("finding_type") or "unknown")
        ftype = _normalize_ftype(raw_type)

        # Field extraction. The classifier stores host/port/scheme/path inside
        # ``metadata`` and the host in ``target`` (a URL or bare host) — NOT at
        # the top level. The old code only read top-level fields, so even when a
        # template matched it had no host/port. We pull from metadata + target.
        meta = finding.get("metadata") or {}

        host = (
            finding.get("host") or finding.get("hostname")
            or meta.get("host") or ""
        ).strip()
        ip = (finding.get("ip") or meta.get("ip") or "").strip()
        port = finding.get("port") if finding.get("port") is not None else meta.get("port")
        protocol = (finding.get("protocol") or meta.get("protocol") or "tcp").strip().lower()
        scheme = (finding.get("scheme") or meta.get("scheme") or "").strip().lower()
        path = (finding.get("path") or meta.get("path") or "").strip()

        # Derive host/scheme/port/path from the target URL when not explicit.
        target = (finding.get("target") or finding.get("asset") or target_hint or "").strip()
        if target:
            t_scheme, t_host, t_port, t_path = _parse_target(target)
            host = host or t_host
            scheme = scheme or t_scheme
            if port is None:
                port = t_port
            path = path or t_path
        if not path:
            path = "/"

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
            # Default to https when scheme is unknown: modern web targets are
            # https-first, and an http:// header/cookie check against an
            # https-only host would just redirect (or fail), producing a
            # misleading PoC. Port 80 still implies http via the scheme-default
            # logic above.
            s = scheme if scheme in ("http", "https") else "https"
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

        # ----- Missing security header: prove the header is absent in the response
        if ftype == "missing_header":
            header = str(raw.get("metadata", {}).get("header") or "").strip()
            url = http_url()
            title = (
                f"Verify missing `{header}` header on {host}" if header
                else f"Verify missing security header on {host}"
            )
            cmds = [f"curl -sS -I {url}"]
            grep_note = (
                f"The `{header}` header should be ABSENT from the response above, "
                f"confirming the finding."
                if header else
                "The flagged security header should be ABSENT from the response above."
            )
            notes = [
                "HEAD request prints the response headers (read-only).",
                grep_note,
            ]
            return PoCTemplate(title=title, risk="low", commands=cmds, notes=notes)

        # ----- Session cookie misconfiguration: inspect Set-Cookie attributes
        if ftype == "cookie_misconfig":
            url = http_url()
            title = f"Verify cookie attributes on {host}"
            cmds = [f"curl -sS -I {url}"]
            notes = [
                "Inspect the `Set-Cookie` header(s) in the response above.",
                "The finding flags missing Secure / HttpOnly / SameSite attributes — "
                "confirm which are absent.",
            ]
            return PoCTemplate(title=title, risk="low", commands=cmds, notes=notes)

        # ----- Directory listing: prove the auto-index renders
        if ftype == "directory_listing":
            url = http_url()
            title = f"Verify directory listing on {host}"
            cmds = [f"curl -sS {url}"]
            notes = [
                "The response body should contain an auto-generated index "
                "(e.g. 'Index of /', 'Parent Directory'), confirming listing is enabled.",
                "Read-only GET; no files are written or modified.",
            ]
            return PoCTemplate(title=title, risk="medium", commands=cmds, notes=notes)

        # ----- Discovered subdomain: confirm it resolves + responds
        if ftype == "subdomain":
            title = f"Verify subdomain {host} is live"
            cmds = [f"dig +short {host} A"]
            if scheme in ("http", "https") or port_i in (80, 443):
                cmds.append(f"curl -sS -I {http_url()}")
            else:
                cmds.append(f"curl -sS -I https://{host}/")
            notes = [
                "Confirms the subdomain resolves and serves a response.",
                "For subdomain-takeover findings, check for a dangling CNAME and a "
                "third-party 'no such app' fingerprint in the response.",
            ]
            return PoCTemplate(title=title, risk="medium", commands=cmds, notes=notes)

        # ----- Version / framework disclosure: surface the version banner
        if ftype == "version_disclosure":
            url = http_url()
            ver = str(raw.get("metadata", {}).get("version") or "").strip()
            title = (
                f"Verify version disclosure ({ver}) on {host}" if ver
                else f"Verify version/framework disclosure on {host}"
            )
            cmds = [f"curl -sS -I {url}"]
            notes = [
                "Inspect the `Server` / `X-Powered-By` headers in the response above.",
                "Cross-reference the disclosed version against known CVEs for that "
                "component to establish impact.",
            ]
            return PoCTemplate(title=title, risk="low", commands=cmds, notes=notes)

        # ----- Generic read-only HTTP verification (nikto/ssrf/backup/dir-enum/etc.)
        if ftype == "http_fetch":
            url = http_url()
            title = f"Verify finding at {host}"
            cmds = [
                f"curl -sS -I {url}",
                f"curl -sS -o /dev/null -w '%{{http_code}}\\n' {url}",
            ]
            notes = [
                "Read-only HEAD + status-code check to confirm the flagged resource "
                "is reachable and responds as reported.",
                "Inspect the supporting evidence for the specific indicator to confirm.",
            ]
            return PoCTemplate(title=title, risk=str(raw.get("severity") or raw.get("risk") or "info").lower(),
                               commands=cmds, notes=notes)

        # Generic fallback (safe, but less helpful) — should now be rare.
        title = f"Verify finding {ftype} for {host or 'target'}"
        cmds = []
        if host and scheme in ("http", "https"):
            cmds.append(f"curl -sS -I {http_url()}")
        elif host:
            cmds.append(f"nmap -sV {host}")
        notes = [
            "Finding type not mapped to a specialized template; emitted a generic "
            "read-only reachability check.",
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
