# core/raw_classifier.py
# Normalizes raw tool output into structured findings for downstream engines.

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Tuple

ManagementPortMap = {
    22: "SSH",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    5900: "VNC",
    4848: "GlassFish Admin",
    5432: "PostgreSQL",
}

CMS_SIGNATURES = {
    "wordpress": re.compile(r"wordpress[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "joomla": re.compile(r"joomla[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "drupal": re.compile(r"drupal[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "magento": re.compile(r"magento[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "prestashop": re.compile(r"prestashop[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "opencart": re.compile(r"opencart[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "typo3": re.compile(r"typo3[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "ghost": re.compile(r"ghost[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "concrete5": re.compile(r"concrete5[\s/:_-]*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
}

PRIVATE_IP_REGEX = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)

SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"(?i)aws(.{0,10})?(secret|key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("stripe-secret", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("firebase", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("twilio-sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("twilio-auth", re.compile(r"(?i)\btwilio(.{0,5})?(secret|token)['\"]?\s*[:=]\s*['\"]([0-9a-fA-F]{32})")),
    ("jwt-key", re.compile(r"-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----")),
    ("generic-secret", re.compile(r"(?i)(secret|token|api[_-]?key)['\"=:\s]+([A-Za-z0-9_\-]{24,})")),
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "x-content-type-options",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]

FRAMEWORK_PATTERNS: Dict[str, re.Pattern[str]] = {
    "express": re.compile(r"express/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "flask": re.compile(r"flask/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "django": re.compile(r"django/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "rails": re.compile(r"rails/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "laravel": re.compile(r"laravel/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "spring": re.compile(r"spring boot/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "aspnet": re.compile(r"asp\.net(?: core)?/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "fastapi": re.compile(r"fastapi/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "phoenix": re.compile(r"phoenix/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "nextjs": re.compile(r"next\.js/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "nuxtjs": re.compile(r"nuxt\.js/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "node": re.compile(r"node\.js/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "java": re.compile(r"java/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "php": re.compile(r"php/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
}

FRAMEWORK_MINIMUMS = {
    "express": (4, 18, 2),
    "flask": (2, 2, 0),
    "django": (5, 0),
    "rails": (7, 1),
    "laravel": (10, 0),
    "spring": (3, 2),
    "aspnet": (8, 0),
    "fastapi": (0, 104),
    "phoenix": (1, 7),
    "nextjs": (14, 0),
    "nuxtjs": (3, 0),
    "node": (18, 0),
    "java": (17, 0),
    "php": (8, 2),
}


def _parse_version(raw: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", raw or "")
    return tuple(int(n) for n in nums[:3])


ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


@dataclass
class RawFinding:
    type: str
    severity: str
    tool: str
    target: str
    message: str = ""
    proof: str = ""
    tags: List[str] = field(default_factory=list)
    families: List[str] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict:
        data = asdict(self)
        # Normalize to sorted unique tags/families for downstream consumers.
        data["tags"] = sorted(set(self.tags))
        data["families"] = sorted(set(self.families))
        return data


def classify(tool: str, target: str, output: str) -> List[dict]:
    handler = _HANDLERS.get(tool.lower())
    findings: List[RawFinding] = []
    if handler:
        findings.extend(handler(target, output))
    findings.extend(_global_detectors(tool, target, output))
    return [finding.as_dict() for finding in findings]


# ----------------------------------------------------------------------
# Tool-specific handlers
# ----------------------------------------------------------------------


def _handle_nmap(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    for line in output.splitlines():
        if "open" not in line or "/" not in line:
            continue
        parts = line.split()
        port_proto = parts[0]
        service = parts[2] if len(parts) > 2 else "unknown"
        try:
            port = int(port_proto.split("/")[0])
        except (ValueError, IndexError):
            port = None

        tags = ["exposure"]
        families = ["exposure"]
        metadata = {"port": port, "service": service}
        severity = "LOW"

        if port in ManagementPortMap:
            tags.extend(["management-surface", ManagementPortMap[port].lower()])
            families.append("exposure")
            severity = "MEDIUM"

        if port == 443 or service in ("https", "http", "http-proxy"):
            tags.append("surface-http")

        findings.append(
            RawFinding(
                type="Open Port",
                severity=severity,
                tool="nmap",
                target=target,
                message=f"{port_proto} {service}".strip(),
                proof=line.strip(),
                tags=tags,
                families=families,
                metadata=metadata,
            )
        )
    findings.extend(_detect_http_methods(target, output))
    return findings


def _handle_whatweb(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        plugins = data.get("plugins") or {}
        for name, details in plugins.items():
            text = ""
            if isinstance(details, dict):
                string_values = details.get("string")
                if isinstance(string_values, list):
                    text = ", ".join(string_values)
                elif isinstance(string_values, str):
                    text = string_values

            tags = ["tech-fingerprint"]
            families = ["supply-chain"]
            metadata = {"plugin": name}

            findings.append(
                RawFinding(
                    type="Technology Fingerprint",
                    severity="INFO",
                    tool="whatweb",
                    target=target,
                    message=f"{name}: {text}",
                    proof=json.dumps({name: details}),
                    tags=tags,
                    families=families,
                    metadata=metadata,
                )
            )

            for cms, regex in CMS_SIGNATURES.items():
                match = regex.search(f"{name} {text}")
                if match:
                    version = match.group(1) or "unknown"
                    findings.append(
                        RawFinding(
                            type=f"{cms.title()} Detected",
                            severity="INFO",
                            tool="whatweb",
                            target=target,
                            message=f"{cms.title()} version {version}",
                            proof=line,
                            tags=["cms", cms],
                            families=["patching", "supply-chain"],
                            metadata={"version": version, "cms": cms},
                        )
                    )

    findings.extend(_detect_json_endpoints(target, output))
    findings.extend(_detect_dev_surfaces(target, output))
    findings.extend(_detect_cors_headers(target, output))
    findings.extend(_detect_graphql_markers(target, output))
    findings.extend(_detect_upload_endpoints(target, output))
    findings.extend(_detect_private_ranges(target, output))
    findings.extend(_detect_verbose_errors(target, output))
    return findings


def _handle_wafw00f(target: str, output: str) -> List[RawFinding]:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    if not data.get("identified"):
        return []

    waf_name = data.get("firewall", "Unknown WAF")
    return [
        RawFinding(
            type="WAF Detected",
            severity="INFO",
            tool="wafw00f",
            target=target,
            message=waf_name,
            proof=output,
            tags=["waf", "defense"],
            families=["misconfiguration"],
            metadata={"waf": waf_name},
        )
    ]


def _handle_httpx(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"(https?://\S+)\s+\[(\d{3})\]\s*(?:\[(.*?)\])?\s*(?:\[(.*?)\])?")
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        if not clean.startswith("http"):
            continue
        match = pattern.match(clean)
        if not match:
            continue
        url = match.group(1)
        status = int(match.group(2))
        title = (match.group(3) or "").strip()
        tech = (match.group(4) or "").strip()
        severity = "INFO"
        if status >= 500:
            severity = "HIGH"
        elif status >= 400:
            severity = "MEDIUM"
        findings.append(
            RawFinding(
                type="HTTP Endpoint",
                severity=severity,
                tool="httpx",
                target=target,
                message=f"{url} returned {status}",
                proof=clean,
                tags=["surface-http", f"status-{status}"],
                families=["exposure"],
                metadata={"url": url, "status": status, "title": title, "tech": tech},
            )
        )
    return findings


def _handle_dirsearch(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"(\d{3})\s*-\s*[^\-]*-\s*(\S+)(?:\s*->\s*(\S+))?")
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        match = pattern.search(clean)
        if not match:
            continue
        status = int(match.group(1))
        url = match.group(2)
        redirect = match.group(3)
        findings.append(
            RawFinding(
                type="Hidden Directory",
                severity="MEDIUM" if status < 400 else "LOW",
                tool="dirsearch",
                target=target,
                message=f"{url} (status {status})",
                proof=clean,
                tags=["dir-enum", "surface-http"],
                families=["exposure"],
                metadata={"status": status, "redirect": redirect},
            )
        )
    return findings


def _handle_gobuster(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"^([^\s]+)\s+\(Status:\s*(\d{3})\)")
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        match = pattern.match(clean)
        if not match:
            continue
        path = match.group(1)
        status = int(match.group(2))
        findings.append(
            RawFinding(
                type="Brute Forced Path",
                severity="MEDIUM",
                tool="gobuster",
                target=target,
                message=f"{path} (status {status})",
                proof=clean,
                tags=["dir-enum", "surface-http"],
                families=["exposure"],
                metadata={"status": status, "path": path},
            )
        )
    return findings


def _handle_feroxbuster(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"^(\d{3})\s+\S+\s+\S+\s+(https?://\S+)")
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        match = pattern.match(clean)
        if not match:
            continue
        status = int(match.group(1))
        url = match.group(2)
        findings.append(
            RawFinding(
                type="Recursive Discovery",
                severity="MEDIUM",
                tool="feroxbuster",
                target=target,
                message=f"{url} (status {status})",
                proof=clean,
                tags=["dir-enum", "surface-http"],
                families=["exposure"],
                metadata={"status": status, "url": url},
            )
        )
    return findings


def _handle_nikto(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"\[nikto-shim\]\s+([A-Z]+):\s+(.*)")
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        match = pattern.match(clean)
        if not match:
            continue
        severity = match.group(1).upper()
        message = match.group(2).strip()
        findings.append(
            RawFinding(
                type="Nikto Finding",
                severity=severity if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "INFO",
                tool="nikto",
                target=target,
                message=message,
                proof=clean,
                tags=["web-scanner", "nikto"],
                families=["exposure", "misconfiguration"],
            )
        )
    return findings


def _handle_masscan(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"Discovered open port (\d+)/(tcp|udp) on ([^\s]+)")
    for line in output.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        port = int(match.group(1))
        proto = match.group(2)
        host = match.group(3)
        findings.append(
            RawFinding(
                type="Open Port",
                severity="MEDIUM" if port in ManagementPortMap else "LOW",
                tool="masscan",
                target=target,
                message=f"{host}:{port}/{proto}",
                proof=line.strip(),
                tags=["exposure", "masscan"],
                families=["exposure"],
                metadata={"port": port, "protocol": proto, "host": host},
            )
        )
    return findings


def _handle_naabu(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        if ":" not in clean or clean.startswith("["):
            continue
        host, _, port_str = clean.partition(":")
        if not port_str.isdigit():
            continue
        port = int(port_str)
        findings.append(
            RawFinding(
                type="Open Port",
                severity="MEDIUM" if port in ManagementPortMap else "LOW",
                tool="naabu",
                target=target,
                message=f"{host}:{port}",
                proof=clean,
                tags=["exposure", "surface-expansion"],
                families=["exposure"],
                metadata={"port": port, "host": host},
            )
        )
    return findings


def _handle_dnsx(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"([^\s]+)\s+\[(\w+)\]\s+\[([^\]]+)\]")
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        match = pattern.search(clean)
        if not match:
            continue
        host, record_type, value = match.groups()
        findings.append(
            RawFinding(
                type="DNS Record",
                severity="INFO",
                tool="dnsx",
                target=target,
                message=f"{host} {record_type} {value}",
                proof=clean,
                tags=["dns", "surface-mapping"],
                families=["recon-phase:dns"],
            )
        )
    return findings


def _handle_hakrevdns(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    pattern = re.compile(r"\[hakrevdns-shim\]\s+([^\s]+)\s*->\s*(.*)")
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        match = pattern.match(clean)
        if not match:
            continue
        ip = match.group(1)
        ptr = match.group(2)
        findings.append(
            RawFinding(
                type="Reverse DNS Mapping",
                severity="INFO",
                tool="hakrevdns",
                target=target,
                message=f"{ip} -> {ptr}",
                proof=clean,
                tags=["dns", "surface-mapping"],
                families=["recon-phase:dns"],
            )
        )
    return findings


def _handle_hakrawler(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    interesting = [
        "admin",
        "login",
        "swagger",
        "graphql",
        "api",
        ".git",
        "backup",
        "secret",
        "staff",
    ]
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        if not clean.startswith("http"):
            continue
        sev = "INFO"
        lowered = clean.lower()
        if any(keyword in lowered for keyword in interesting):
            sev = "MEDIUM"
        findings.append(
            RawFinding(
                type="Crawled Endpoint",
                severity=sev,
                tool="hakrawler",
                target=target,
                message=clean,
                proof=clean,
                tags=["crawler", "surface-http"],
                families=["exposure"],
            )
        )
    return findings


def _handle_assetfinder(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        if not clean or "." not in clean:
            continue
        findings.append(
            RawFinding(
                type="Discovered Subdomain",
                severity="INFO",
                tool="assetfinder",
                target=target,
                message=clean,
                proof=clean,
                tags=["subdomain", "surface-expansion"],
                families=["recon-phase:subdomain"],
            )
        )
    return findings


def _handle_subfinder(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        if not clean or "." not in clean:
            continue
        findings.append(
            RawFinding(
                type="Discovered Subdomain",
                severity="INFO",
                tool="subfinder",
                target=target,
                message=clean,
                proof=clean,
                tags=["subdomain", "surface-expansion"],
                families=["recon-phase:subdomain"],
            )
        )
    return findings


def _handle_httprobe(target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        if not clean.startswith("http"):
            continue
        findings.append(
            RawFinding(
                type="Reachable Service",
                severity="INFO",
                tool="httprobe",
                target=target,
                message=clean,
                proof=clean,
                tags=["surface-http"],
                families=["exposure"],
            )
        )
    return findings


# ----------------------------------------------------------------------
# Global detectors
# ----------------------------------------------------------------------


def _global_detectors(tool: str, target: str, output: str) -> List[RawFinding]:
    findings: List[RawFinding] = []
    findings.extend(_detect_user_enum(target, output))
    findings.extend(_detect_metadata_exposure(target, output))
    findings.extend(_detect_business_logic_hooks(target, output))
    findings.extend(_detect_secrets(target, output))
    findings.extend(_detect_security_headers(target, output))
    findings.extend(_detect_frameworks(target, output))
    findings.extend(_detect_directory_listing(target, output))
    findings.extend(_detect_backup_files(target, output))
    findings.extend(_detect_login_flows(target, output))
    findings.extend(_detect_session_misconfigs(target, output))
    findings.extend(_detect_timing_patterns(target, output))
    findings.extend(_detect_ssrf_indicators(target, output))
    findings.extend(_detect_waf_behaviors(target, output))
    findings.extend(_detect_cloud_storage(target, output))
    return findings


def _detect_json_endpoints(target: str, output: str) -> List[RawFinding]:
    findings = []
    for line in output.splitlines():
        if "/api/" not in line.lower():
            continue
        looks_json = any(token in line.lower() for token in ("json", "application/json", "{", "}"))
        has_auth = any(token in line.lower() for token in ("auth", "token", "bearer", "apikey", "api-key"))
        has_cookie = "set-cookie" in line.lower()
        has_rate_limit = "x-ratelimit" in line.lower()
        if not looks_json:
            continue
        if has_auth or has_cookie or has_rate_limit:
            continue
        findings.append(
            RawFinding(
                type="API Endpoint Without Auth",
                severity="MEDIUM",
                tool="whatweb",
                target=target,
                message=line.strip(),
                proof=line.strip(),
                tags=["api", "exposure", "no-auth"],
                families=["auth", "exposure"],
                metadata={"hint": "json-no-auth"},
            )
        )
    return findings


def _detect_dev_surfaces(target: str, output: str) -> List[RawFinding]:
    keywords = [
        "/swagger",
        "/api-docs",
        "/graphql",
        "/graphiql",
        "/actuator",
        "/debug",
        "/__debug__",
        "/adminer.php",
        "/phpinfo.php",
    ]
    matches = []
    for line in output.splitlines():
        lowered = line.lower()
        for keyword in keywords:
            if keyword in lowered:
                matches.append((keyword, line.strip()))
                break
    return [
        RawFinding(
            type="Development Surface Exposed",
            severity="MEDIUM",
            tool="whatweb",
            target=target,
            message=match[1],
            proof=match[1],
            tags=["dev-surface", "exposure"],
            families=["exposure", "surface"],
            metadata={"keyword": match[0]},
        )
        for match in matches
    ]


def _detect_cors_headers(target: str, output: str) -> List[RawFinding]:
    findings = []
    for block in output.split("\n\n"):
        block_lower = block.lower()
        if "access-control-allow-origin" not in block_lower:
            continue
        aca_origin = re.search(r"access-control-allow-origin:\s*([^\s]+)", block_lower)
        aca_credentials = re.search(r"access-control-allow-credentials:\s*(true|1)", block_lower)
        if aca_origin and (
            aca_origin.group(1) == "*" or "http" in aca_origin.group(1)
        ):
            if aca_origin.group(1) == "*" or "origin" in aca_origin.group(1):
                findings.append(
                    RawFinding(
                        type="Permissive CORS Policy",
                        severity="HIGH" if aca_credentials else "MEDIUM",
                        tool="whatweb",
                        target=target,
                        message=block.strip(),
                        proof=block.strip(),
                        tags=["cors", "misconfiguration"],
                        families=["misconfiguration", "auth"],
                        metadata={"credentials": bool(aca_credentials)},
                    )
                )
    return findings


def _detect_http_methods(target: str, output: str) -> List[RawFinding]:
    findings = []
    method_line = re.search(r"Allowed methods:\s*(.+)", output, re.IGNORECASE)
    if not method_line:
        return findings
    methods = [m.strip().upper() for m in method_line.group(1).split(",")]
    dangerous = [m for m in methods if m in {"PUT", "DELETE", "TRACE", "OPTIONS"}]
    if dangerous:
        findings.append(
            RawFinding(
                type="Dangerous HTTP Methods Enabled",
                severity="MEDIUM",
                tool="nmap",
                target=target,
                message=f"Methods: {', '.join(methods)}",
                proof=method_line.group(0),
                tags=["http", "surface-expansion"],
                families=["exposure"],
                metadata={"methods": methods},
            )
        )
    return findings


def _detect_upload_endpoints(target: str, output: str) -> List[RawFinding]:
    findings = []
    pattern = re.compile(r"/[A-Za-z0-9_\-]+upload[a-z/0-9_\-]*", re.IGNORECASE)
    for match in pattern.findall(output):
        findings.append(
            RawFinding(
                type="Unauthenticated Upload Surface",
                severity="MEDIUM",
                tool="whatweb",
                target=target,
                message=match,
                proof=match,
                tags=["upload", "dangerous-feature"],
                families=["exposure"],
                metadata={"path": match},
            )
        )
    return findings


def _detect_private_ranges(target: str, output: str) -> List[RawFinding]:
    matches = PRIVATE_IP_REGEX.findall(output)
    if not matches:
        return []
    sample = sorted(set(matches))[:5]
    return [
        RawFinding(
            type="Internal Network Disclosure",
            severity="MEDIUM",
            tool="whatweb",
            target=target,
            message=", ".join(sample),
            proof=", ".join(sample),
            tags=["private-ip", "info-disclosure"],
            families=["exposure"],
            metadata={"ips": sample},
        )
    ]


def _detect_verbose_errors(target: str, output: str) -> List[RawFinding]:
    error_keywords = [
        "stacktrace",
        "traceback (most recent call last)",
        "fatal error",
        "nullpointerexception",
        "odbc",
        "jdbc",
        "unhandled exception",
    ]
    findings = []
    for keyword in error_keywords:
        if keyword in output.lower():
            findings.append(
                RawFinding(
                    type="Verbose Error Message",
                    severity="MEDIUM",
                    tool="scanner",
                    target=target,
                    message=keyword,
                    proof=_extract_snippet(output, keyword),
                    tags=["error-leakage"],
                    families=["exposure"],
                )
            )
    return findings


def _detect_graphql_markers(target: str, output: str) -> List[RawFinding]:
    keywords = ["__schema", "__typename", "introspection query"]
    for keyword in keywords:
        if keyword in output.lower():
            return [
                RawFinding(
                    type="GraphQL Introspection Enabled",
                    severity="MEDIUM",
                    tool="whatweb",
                    target=target,
                    message=keyword,
                    proof=_extract_snippet(output, keyword),
                    tags=["graphql", "exposure"],
                    families=["exposure"],
                )
            ]
    return []


def _detect_user_enum(target: str, output: str) -> List[RawFinding]:
    if "user not found" in output.lower() and "invalid password" in output.lower():
        return [
            RawFinding(
                type="User Enumeration Signals",
                severity="MEDIUM",
                tool="scanner",
                target=target,
                message="Distinct login responses detected",
                proof=_extract_snippet(output, "user"),
                tags=["auth", "user-enum"],
                families=["auth"],
            )
        ]
    return []


def _detect_metadata_exposure(target: str, output: str) -> List[RawFinding]:
    if "169.254.169.254" in output or "/latest/meta-data" in output.lower():
        return [
            RawFinding(
                type="Cloud Metadata Interface Leakage",
                severity="HIGH",
                tool="scanner",
                target=target,
                message="Metadata endpoint referenced",
                proof=_extract_snippet(output, "169.254.169.254"),
                tags=["cloud", "ssrf"],
                families=["exposure"],
            )
        ]
    return []


def _detect_business_logic_hooks(target: str, output: str) -> List[RawFinding]:
    suspect_terms = ["user_id", "account_id", "role_id", "permission", "idor", "rbac"]
    hits = [term for term in suspect_terms if term in output.lower()]
    if not hits:
        return []
    return [
        RawFinding(
            type="Business Logic Indicator",
            severity="INFO",
            tool="scanner",
            target=target,
            message=f"Potential logic surface keywords: {', '.join(hits)}",
            proof=_extract_snippet(output, hits[0]),
            tags=["business-logic", "hook"],
            families=["auth"],
            metadata={"keywords": hits},
        )
    ]


def _detect_secrets(target: str, output: str) -> List[RawFinding]:
    findings = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(output):
            snippet = _extract_snippet(output, match.group(0))
            findings.append(
                RawFinding(
                    type="Secret Exposure",
                    severity="CRITICAL",
                    tool="scanner",
                    target=target,
                    message=f"{label} leaked",
                    proof=snippet,
                    tags=["secret-leak", label],
                    families=["supply-chain", "exposure"],
                    metadata={"match": match.group(0)},
                )
            )
    return findings


def _detect_security_headers(target: str, output: str) -> List[RawFinding]:
    findings = []
    blocks = [block for block in output.split("\n\n") if "http/" in block.lower()]
    for block in blocks:
        lowered = block.lower()
        uses_https = "https://" in lowered or target.lower().startswith("https")
        for header in SECURITY_HEADERS:
            if header in lowered:
                continue
            severity = "MEDIUM"
            if header == "strict-transport-security" and uses_https:
                severity = "HIGH"
            findings.append(
                RawFinding(
                    type="Missing Security Header",
                    severity=severity,
                    tool="scanner",
                    target=target,
                    message=f"{header} absent",
                    proof=block[:400],
                    tags=["header-missing", header],
                    families=["misconfiguration"],
                    metadata={"header": header},
                )
            )
    return findings


def _detect_frameworks(target: str, output: str) -> List[RawFinding]:
    findings = []
    for framework, pattern in FRAMEWORK_PATTERNS.items():
        for match in pattern.finditer(output):
            version = match.group(1) or ""
            findings.append(
                RawFinding(
                    type=f"{framework.title()} Framework Detected",
                    severity="INFO",
                    tool="scanner",
                    target=target,
                    message=f"{framework} {version}".strip(),
                    proof=_extract_snippet(output, match.group(0)),
                    tags=["framework", framework],
                    families=["supply-chain", "patching"],
                    metadata={"framework": framework, "version": version},
                )
            )
    return findings


def _detect_directory_listing(target: str, output: str) -> List[RawFinding]:
    keywords = ["index of /", "parent directory"]
    matches = []
    for keyword in keywords:
        if keyword in output.lower():
            matches.append(keyword)
    if not matches:
        return []
    return [
        RawFinding(
            type="Directory Listing Enabled",
            severity="MEDIUM",
            tool="scanner",
            target=target,
            message="; ".join(matches),
            proof=_extract_snippet(output, matches[0]),
            tags=["directory-listing", "exposure"],
            families=["exposure"],
        )
    ]


def _detect_backup_files(target: str, output: str) -> List[RawFinding]:
    patterns = [
        r"\.bak\b",
        r"\.old\b",
        r"\.zip\b",
        r"\.tar(?:\.gz)?\b",
        r"\.swp\b",
        r"\.env\b",
        r"\.git/config",
        r"\.sql\b",
        r"config\.php\.old",
    ]
    findings = []
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            findings.append(
                RawFinding(
                    type="Backup Artifact Exposed",
                    severity="HIGH",
                    tool="scanner",
                    target=target,
                    message=match.group(0),
                    proof=_extract_snippet(output, match.group(0)),
                    tags=["backup-leak", "exposure"],
                    families=["exposure"],
                )
            )
    return findings


def _detect_login_flows(target: str, output: str) -> List[RawFinding]:
    keywords = ["reset password", "forgot password", "otp", "2fa reset"]
    matches = []
    for keyword in keywords:
        if keyword in output.lower():
            matches.append(keyword)
    if not matches:
        return []
    return [
        RawFinding(
            type="Password Reset Surface",
            severity="INFO",
            tool="scanner",
            target=target,
            message=", ".join(matches),
            proof=_extract_snippet(output, matches[0]),
            tags=["auth", "pw-reset"],
            families=["auth"],
        )
    ]


def _detect_session_misconfigs(target: str, output: str) -> List[RawFinding]:
    findings = []
    for match in re.finditer(r"set-cookie:\s*([^\n]+)", output, re.IGNORECASE):
        cookie = match.group(1)
        lowered = cookie.lower()
        missing_secure = "secure" not in lowered
        missing_http_only = "httponly" not in lowered
        samesite_none = "samesite=none" in lowered
        tags = ["session", "cookie"]
        severity = "MEDIUM"
        if missing_http_only:
            severity = "HIGH"
            tags.append("http-only-missing")
        if missing_secure and target.lower().startswith("https"):
            severity = "HIGH"
            tags.append("secure-missing")
        if samesite_none and missing_secure:
            severity = "CRITICAL"
            tags.append("samesite-insecure")
        if missing_secure or missing_http_only or samesite_none:
            findings.append(
                RawFinding(
                    type="Session Cookie Misconfiguration",
                    severity=severity,
                    tool="scanner",
                    target=target,
                    message=cookie.strip(),
                    proof=cookie.strip(),
                    tags=tags,
                    families=["auth"],
                )
            )
    return findings


def _detect_timing_patterns(target: str, output: str) -> List[RawFinding]:
    # Placeholder for advanced timing inference (phase 3); currently no-op.
    return []


def _detect_ssrf_indicators(target: str, output: str) -> List[RawFinding]:
    keywords = [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "gopher://",
        "file://",
        "dict://",
        "metadata.google.internal",
        "169.254.169.254",
        "callback=",
        "redirect=",
        "next=",
        "url=",
    ]
    matches = [kw for kw in keywords if kw in output.lower()]
    if not matches:
        return []
    return [
        RawFinding(
            type="SSRF Indicator",
            severity="HIGH",
            tool="scanner",
            target=target,
            message=", ".join(matches),
            proof=_extract_snippet(output, matches[0]),
            tags=["ssrf-source"],
            families=["exposure"],
        )
    ]


def _detect_waf_behaviors(target: str, output: str) -> List[RawFinding]:
    waf_keywords = ["cloudflare", "akamai", "imperva", "incapsula", "f5", "radware", "datadome"]
    matches = [kw for kw in waf_keywords if kw in output.lower()]
    if not matches:
        return []
    return [
        RawFinding(
            type="WAF Behavior Observed",
            severity="INFO",
            tool="scanner",
            target=target,
            message=", ".join(matches),
            proof=_extract_snippet(output, matches[0]),
            tags=["waf"],
            families=["misconfiguration"],
        )
    ]


def _detect_cloud_storage(target: str, output: str) -> List[RawFinding]:
    patterns = [
        (r"https?://[a-z0-9\-\.]+\.s3\.amazonaws\.com/[^\s\"']+", "aws-s3"),
        (r"https?://storage\.googleapis\.com/[^\s\"']+", "gcp-storage"),
        (r"https?://[a-z0-9\-\.]+\.blob\.core\.windows\.net/[^\s\"']+", "azure-blob"),
    ]
    findings = []
    for pattern, label in patterns:
        for match in re.findall(pattern, output, re.IGNORECASE):
            findings.append(
                RawFinding(
                    type="Cloud Storage Exposure",
                    severity="MEDIUM",
                    tool="scanner",
                    target=target,
                    message=match,
                    proof=match,
                    tags=["cloud-storage", label],
                    families=["exposure"],
                )
            )
    return findings


def _extract_snippet(output: str, needle: str, radius: int = 240) -> str:
    match = re.search(re.escape(needle), output, re.IGNORECASE)
    if not match:
        return output[:radius]
    start = max(0, match.start() - radius // 2)
    end = min(len(output), match.end() + radius // 2)
    return output[start:end]


_HANDLERS: Dict[str, Callable[[str, str], List[RawFinding]]] = {
    "nmap": _handle_nmap,
    "whatweb": _handle_whatweb,
    "wafw00f": _handle_wafw00f,
    "httpx": _handle_httpx,
    "dirsearch": _handle_dirsearch,
    "gobuster": _handle_gobuster,
    "feroxbuster": _handle_feroxbuster,
    "nikto": _handle_nikto,
    "masscan": _handle_masscan,
    "naabu": _handle_naabu,
    "dnsx": _handle_dnsx,
    "hakrevdns": _handle_hakrevdns,
    "hakrawler": _handle_hakrawler,
    "assetfinder": _handle_assetfinder,
    "subfinder": _handle_subfinder,
    "httprobe": _handle_httprobe,
}


__all__ = ["classify", "RawFinding"]
