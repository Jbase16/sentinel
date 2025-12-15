# ============================================================================
# core/toolkit/vuln_rules.py
# Vuln Rules Module
# ============================================================================
#
# PURPOSE:
# This module is part of the toolkit package in SentinelForge.
# [Specific purpose based on module name: vuln_rules]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

# core/vuln_rules.py
# Higher-order vulnerability correlation engine

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Tuple

TextAccumulator = Callable[[List[dict]], List[dict]]


def _pluck_text(finding: dict) -> str:
    parts = []
    for key in ("type", "message", "proof", "evidence"):
        val = finding.get(key)
        if isinstance(val, str):
            parts.append(val)
    return " ".join(parts).lower()


def _extract_paths(text: str) -> List[str]:
    matches = re.findall(r"(/[A-Za-z0-9_\-\.]{3,})", text)
    # Deduplicate while preserving order
    seen = set()
    ordered = []
    for path in matches:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered[:5]


def _parse_version(raw: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", raw)
    if not nums:
        return tuple()
    return tuple(int(n) for n in nums[:3])


def _version_lt(current: Tuple[int, ...], minimum: Tuple[int, ...]) -> bool:
    if not current:
        return False
    length = max(len(current), len(minimum))
    current += (0,) * (length - len(current))
    minimum += (0,) * (length - len(minimum))
    return current < minimum


def _gather_findings(findings: Iterable[dict], predicate: Callable[[dict], bool]) -> Dict[str, List[dict]]:
    buckets: Dict[str, List[dict]] = {}
    for item in findings:
        if predicate(item):
            target = item.get("target", "unknown")
            buckets.setdefault(target, []).append(item)
    return buckets


@dataclass
class VulnRule:
    id: str
    title: str
    severity: str
    description: str
    tags: List[str]
    families: List[str]
    base_score: float
    remediation: str
    matcher: TextAccumulator = field(repr=False)

    def apply(self, findings: List[dict]) -> List[dict]:
        matches = self.matcher(findings)
        enriched = []
        for idx, match in enumerate(matches, start=1):
            target = match.get("target", "unknown")
            evidence = match.get("evidence", [])
            issue_id = match.get("id") or f"{self.id}:{target}:{idx}"
            enriched.append({
                "id": issue_id,
                "rule_id": self.id,
                "title": self.title,
                "severity": match.get("severity", self.severity),
                "score": match.get("score", self.base_score),
                "target": target,
                "description": match.get("description", self.description),
                "impact": match.get("impact", ""),
                "remediation": match.get("remediation", self.remediation),
                "tags": sorted(set(self.tags + match.get("tags", []))),
                "supporting_findings": evidence,
                "families": sorted(set(self.families + match.get("families", []))),
                "evidence_summary": match.get("evidence_summary") or self._summarize_evidence(evidence),
            })
        return enriched

    @staticmethod
    def _summarize_evidence(evidence: List[dict]) -> str:
        if not evidence:
            return ""
        samples = []
        for item in evidence[:3]:
            msg = item.get("message") or item.get("proof") or item.get("type")
            if msg:
                samples.append(str(msg))
        return " | ".join(samples)


# ----------------------------------------------------------------------
# Rule matchers
# ----------------------------------------------------------------------

ADMIN_KEYWORDS = [
    "/wp-admin",
    "/admin",
    "/administrator",
    "/login",
    "/console",
    "phpmyadmin",
    "jenkins",
    "grafana",
    "kibana",
    "splunk",
]


def _match_admin_interfaces(findings: List[dict]) -> List[dict]:
    buckets = _gather_findings(
        findings,
        lambda f: "admin-exposure" in f.get("tags", [])
        or any(key in _pluck_text(f) for key in ADMIN_KEYWORDS),
    )
    results: List[dict] = []
    for target, items in buckets.items():
        texts = " ".join(_pluck_text(f) for f in items)
        results.append({
            "target": target,
            "evidence": items,
            "evidence_summary": ", ".join(_extract_paths(texts) or ["admin keyword located"]),
            "tags": ["admin-exposure"],
            "impact": "Attackers can directly attempt password spraying, exploit default creds, or chain auth weaknesses.",
        })
    return results


SSL_KEYWORDS = ["weak ssl", "sslv3", "tlsv1", "rc4", "cbc", "insecure cipher", "self-signed", "expired"]
LOGIN_KEYWORDS = ["login", "signin", "auth", "portal", "account", "mfa"]


def _match_weak_ssl_on_login(findings: List[dict]) -> List[dict]:
    def predicate(item: dict) -> bool:
        text = _pluck_text(item)
        if not any(token in text for token in SSL_KEYWORDS):
            return False
        return any(token in text for token in LOGIN_KEYWORDS) or any(
            token in item.get("target", "").lower() for token in LOGIN_KEYWORDS
        )

    buckets = _gather_findings(findings, predicate)
    results = []
    for target, items in buckets.items():
        results.append({
            "target": target,
            "evidence": items,
            "tags": ["crypto", "login"],
            "impact": "Sensitive credentials can be intercepted or tampered with because the login endpoint is using weak TLS.",
        })
    return results


CMS_MINIMUMS = {
    "wordpress": (6, 4),
    "joomla": (4, 0),
    "drupal": (10, 0),
    "magento": (2, 4),
    "prestashop": (8, 0),
    "opencart": (3, 0),
    "typo3": (12, 4),
    "ghost": (5, 0),
    "concrete5": (9, 0),
}

CMS_REGEX = re.compile(r"(wordpress|joomla|drupal)[\s:/-]*([0-9]+(?:\.[0-9]+){0,2})", re.IGNORECASE)
CMS_REGEX_EXTENDED = re.compile(
    r"(wordpress|joomla|drupal|magento|prestashop|opencart|typo3|ghost|concrete5)[\s:/-]*([0-9]+(?:\.[0-9]+){0,2})",
    re.IGNORECASE,
)

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


def _match_outdated_cms(findings: List[dict]) -> List[dict]:
    hits = []
    for item in findings:
        text = _pluck_text(item)
        for match in CMS_REGEX_EXTENDED.finditer(text):
            product = match.group(1).lower()
            version = _parse_version(match.group(2))
            minimum = CMS_MINIMUMS.get(product)
            if minimum and _version_lt(version, minimum):
                hits.append({
                    "target": item.get("target", "unknown"),
                    "evidence": [item],
                    "tags": ["cms", product],
                    "evidence_summary": f"{product.title()} {match.group(2)} detected",
                    "impact": f"Running {product.title()} {match.group(2)} exposes dozens of public exploits; upgrade to {'.'.join(map(str, minimum))}+.",
                })
    return hits


MANAGEMENT_PORTS = {
    22: "SSH",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    5900: "VNC",
    445: "SMB",
}

PORT_REGEX = re.compile(r"(\d{2,5})/(tcp|udp)")


def _match_management_ports(findings: List[dict]) -> List[dict]:
    buckets: Dict[Tuple[str, int], List[dict]] = {}
    for item in findings:
        text_candidates = [item.get("proof"), item.get("message"), item.get("evidence")]
        port_num = None
        for candidate in text_candidates:
            if not isinstance(candidate, str):
                continue
            match = PORT_REGEX.search(candidate.lower())
            if match:
                value = int(match.group(1))
                if value in MANAGEMENT_PORTS:
                    port_num = value
                    break
        if port_num is None:
            continue
        target = item.get("target", "unknown")
        buckets.setdefault((target, port_num), []).append(item)

    results = []
    for (target, port), items in buckets.items():
        service = MANAGEMENT_PORTS[port]
        results.append({
            "target": target,
            "evidence": items,
            "tags": ["management-surface", service.lower()],
            "severity": "HIGH",
            "score": 8.5,
            "evidence_summary": f"{service} exposed on port {port}",
            "impact": f"{service} is reachable from the assessment scope, enabling brute-force, credential stuffing, or remote exploitation attempts.",
        })
    return results


# Additional matchers leveraging tags emitted by the classifier


def _match_by_tag(required_tags: List[str]):
    def matcher(findings: List[dict]) -> List[dict]:
        results = []
        for item in findings:
            tags = set(item.get("tags", []))
            if all(tag in tags for tag in required_tags):
                results.append({
                    "target": item.get("target", "unknown"),
                    "evidence": [item],
                    "tags": list(tags),
                    "families": item.get("families", []),
                    "evidence_summary": item.get("message") or item.get("proof") or item.get("type"),
                    "impact": item.get("impact", ""),
                })
        return results
    return matcher


def _match_api_exposure(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["api", "exposure", "no-auth"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Attackers can interact with backend APIs without authentication, enabling data harvesting or account takeover chaining.",
        )
        match.setdefault("tags", []).append("api-exposure")
    return matches


def _match_cors(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["cors", "misconfiguration"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Permissive CORS combined with credentialed requests allows malicious websites to read authenticated responses.",
        )
    return matches


def _match_dev_surfaces(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["dev-surface", "exposure"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Developer utilities leak internal API schemas and promote attack surface discovery.",
        )
    return matches


def _match_user_enum(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["auth", "user-enum"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Usernames can be harvested to enable credential stuffing and password spraying attacks.",
        )
    return matches


def _match_metadata(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["cloud", "ssrf"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Cloud metadata endpoints reveal credentials or tokens that unlock cloud services.",
        )
        match.setdefault("severity", "CRITICAL")
        match.setdefault("score", 9.0)
    return matches


def _match_dangerous_http(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["surface-expansion"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Unsafe HTTP verbs may permit unauthorized writes, deletes, or diagnostic queries.",
        )
    return matches


def _match_uploads(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["upload"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Unauthenticated upload endpoints can be weaponized for malware hosting or stored XSS.",
        )
    return matches


def _match_private_ip(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["private-ip"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Internal addressing hints accelerate SSRF chaining and lateral movement.",
        )
    return matches


def _match_verbose_errors(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["error-leakage"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Detailed stack traces reveal software versions, stack components, and exploitable code paths.",
        )
    return matches


def _match_graphql(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["graphql"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Introspection reveals the entire GraphQL schema, simplifying logic abuse.",
        )
    return matches


def _match_business_logic(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["business-logic"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Endpoints reference business logic identifiers. Review for IDOR, RBAC bypass, or mass-assignment.",
        )
        match.setdefault("severity", "INFO")
        match.setdefault("score", 4.0)
    return matches


def _match_session_header_chain(findings: List[dict]) -> List[dict]:
    results = []
    targets = _gather_target_tag_map(findings)
    for target, tags in targets.items():
        if "session" not in tags:
            continue
        header_findings = [
            f for f in findings
            if f.get("target") == target and "header-missing" in f.get("tags", [])
        ]
        if not header_findings:
            continue
        header_names = sorted({f.get("metadata", {}).get("header", "header") for f in header_findings})
        session_items = [
            f for f in findings
            if f.get("target") == target and "session" in f.get("tags", [])
        ]
        results.append({
            "target": target,
            "evidence": session_items + header_findings,
            "severity": "HIGH",
            "score": 8.2,
            "tags": ["session", "header-missing"],
            "impact": f"Session cookies lack protections while {', '.join(header_names)} header(s) are missing, enabling hijacking.",
        })
    return results


def _match_api_rate_limit_gap(findings: List[dict]) -> List[dict]:
    results = []
    targets = _gather_target_tag_map(findings)
    for target, tags in targets.items():
        if "api" not in tags or "no-auth" not in tags:
            continue
        if "rate-limit" in tags:
            continue
        api_items = [
            f for f in findings
            if f.get("target") == target and "api" in f.get("tags", [])
        ]
        if not api_items:
            continue
        results.append({
            "target": target,
            "evidence": api_items,
            "severity": "HIGH",
            "score": 8.3,
            "tags": ["api", "rate-limit-missing"],
            "impact": "Unauthenticated API endpoints respond without rate limiting, enabling brute-force enumeration and data scraping.",
        })
    return results


def _match_cloud_storage_chain(findings: List[dict]) -> List[dict]:
    results = []
    targets = _gather_target_tag_map(findings)
    for target, tags in targets.items():
        if "cloud-storage" not in tags:
            continue
        if "backup-leak" not in tags and "secret-leak" not in tags:
            continue
        evidence = [
            f for f in findings
            if f.get("target") == target and any(tag in f.get("tags", []) for tag in ("cloud-storage", "backup-leak", "secret-leak"))
        ]
        results.append({
            "target": target,
            "evidence": evidence,
            "severity": "CRITICAL",
            "score": 9.1,
            "tags": ["cloud-storage", "supply-chain"],
            "impact": "Cloud buckets plus leaked artifacts allow full source/data exfiltration.",
        })
    return results


def _match_waf_param_combo(findings: List[dict]) -> List[dict]:
    results = []
    targets = _gather_target_tag_map(findings)
    for target, tags in targets.items():
        if "waf-bypass" in tags and any(tag.startswith("param-fuzz") for tag in tags):
            evidence = [f for f in findings if f.get("target") == target and "waf-bypass" in f.get("tags", [])]
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "CRITICAL",
                "score": 9.4,
                "tags": ["waf-bypass", "param-fuzz"],
                "impact": "WAF bypass triggered alongside parameter fuzzing indicates a critical bypass path.",
            })
    return results


def _match_timing_debug_combo(findings: List[dict]) -> List[dict]:
    results = []
    targets = _gather_target_tag_map(findings)
    for target, tags in targets.items():
        if "timing-variance" in tags and "debug-toggle" in tags:
            evidence = [f for f in findings if f.get("target") == target]
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "HIGH",
                "score": 8.5,
                "tags": ["timing-variance", "debug-toggle"],
                "impact": "Timing noise plus debug leaks suggest internal code paths and potential info disclosure.",
            })
    return results


def _match_tls_timing(findings: List[dict]) -> List[dict]:
    results = []
    targets = _gather_target_tag_map(findings)
    for target, tags in targets.items():
        if "tls-probe" in tags and "timing-anomaly" in tags:
            evidence = [f for f in findings if f.get("target") == target]
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "HIGH",
                "score": 8.0,
                "tags": ["tls-probe", "timing-anomaly"],
                "impact": "TLS handshake quirks and timing discrepancies point to detection evasion or hidden logic.",
            })
    return results


def _match_secret_exposure(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["secret-leak"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault("severity", "CRITICAL")
        match.setdefault("score", 9.5)
        match.setdefault(
            "impact",
            "Leaked credentials allow attackers to hijack infrastructure or pivot across environments.",
        )
    return matches


def _match_session_weakness(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["session", "cookie"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Session cookies lack essential flags, enabling hijacking via XSS, MitM, or CSRF.",
        )
        match.setdefault("tags", []).append("session-hardening")
    return matches


def _gather_target_tag_map(findings: List[dict]) -> Dict[str, set]:
    tag_map: Dict[str, set] = {}
    for item in findings:
        target = item.get("target", "unknown")
        for tag in item.get("tags", []):
            tag_map.setdefault(target, set()).add(tag)
    return tag_map


def _match_auth_chain(findings: List[dict]) -> List[dict]:
    tag_map = _gather_target_tag_map(findings)
    results = []
    for target, tags in tag_map.items():
        signals = [
            any(t in tags for t in ("pw-reset", "auth")),
            "dev-surface" in tags,
            "header-missing" in tags,
            "crypto" in tags,
        ]
        if sum(bool(s) for s in signals) >= 3:
            evidence = [f for f in findings if f.get("target", "unknown") == target]
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "HIGH",
                "score": 8.8,
                "tags": ["auth-chain", "workflow"],
                "impact": "Credential interception and privilege escalation chain detected (weak TLS + missing hardening + exposed admin/login flows).",
            })
    return results


def _match_directory_upload_chain(findings: List[dict]) -> List[dict]:
    tag_map = _gather_target_tag_map(findings)
    results = []
    for target, tags in tag_map.items():
        if "directory-listing" in tags and "upload" in tags:
            evidence = [f for f in findings if f.get("target", "unknown") == target]
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "HIGH",
                "score": 7.8,
                "tags": ["directory-listing", "upload"],
                "impact": "Directory listing + upload surface enables easy discovery and retrieval of uploaded payloads.",
            })
    return results


def _match_ssrf_chain(findings: List[dict]) -> List[dict]:
    tag_map = _gather_target_tag_map(findings)
    results = []
    for target, tags in tag_map.items():
        if "ssrf-source" in tags and "cloud" in tags:
            evidence = [f for f in findings if f.get("target", "unknown") == target and any(tag in f.get("tags", []) for tag in ("ssrf-source", "cloud", "ssrf"))]
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "CRITICAL",
                "score": 9.2,
                "tags": ["ssrf-chain"],
                "impact": "URL parameters referencing internal hosts plus metadata endpoints indicates a critical SSRF chain.",
            })
    return results


def _match_cloud_storage_rule(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["cloud-storage"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Public cloud storage buckets may host sensitive data or enable malware distribution.",
        )
        match.setdefault("severity", "MEDIUM")
    return matches


def _match_outdated_frameworks(findings: List[dict]) -> List[dict]:
    hits = []
    for item in findings:
        meta = item.get("metadata") or {}
        framework = meta.get("framework")
        version_str = meta.get("version")
        if not framework or framework not in FRAMEWORK_MINIMUMS:
            continue
        version = _parse_version(str(version_str))
        minimum = FRAMEWORK_MINIMUMS[framework]
        if _version_lt(version, minimum):
            hits.append({
                "target": item.get("target", "unknown"),
                "evidence": [item],
                "tags": ["framework", framework],
                "families": ["patching", "supply-chain"],
                "severity": "MEDIUM",
                "score": 6.9,
                "evidence_summary": f"{framework} {version_str} detected (< {'.'.join(map(str, minimum))})",
                "impact": f"Outdated {framework.title()} {version_str} is vulnerable to known CVEs; upgrade to {'.'.join(map(str, minimum))}+.",
            })
    return hits


def _match_header_chain(findings: List[dict]) -> List[dict]:
    tag_map = _gather_target_tag_map(findings)
    results = []
    for target, tags in tag_map.items():
        missing_csp = any(f.get("metadata", {}).get("header") == "content-security-policy" for f in findings if f.get("target", "unknown") == target)
        upload_surface = "upload" in tags
        missing_hsts = any(f.get("metadata", {}).get("header") == "strict-transport-security" for f in findings if f.get("target", "unknown") == target)
        weak_tls = "crypto" in tags
        evidence = [f for f in findings if f.get("target", "unknown") == target]
        if missing_csp and upload_surface:
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "HIGH",
                "score": 7.4,
                "tags": ["stored-xss-chain"],
                "impact": "Missing CSP combined with upload functionality enables stored XSS weaponization.",
            })
        if missing_hsts and weak_tls:
            results.append({
                "target": target,
                "evidence": evidence,
                "severity": "HIGH",
                "score": 7.9,
                "tags": ["tls-downgrade"],
                "impact": "Missing HSTS plus weak TLS configuration permits protocol downgrade and credential theft.",
            })
    return results


def _match_backup_rule(findings: List[dict]) -> List[dict]:
    matcher = _match_by_tag(["backup-leak"])
    matches = matcher(findings)
    for match in matches:
        match.setdefault(
            "impact",
            "Backup or source artifacts exposed publicly provide full application source and secrets.",
        )
        match.setdefault("severity", "HIGH")
        match.setdefault("score", 7.7)
    return matches


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------

RULES: List[VulnRule] = [
    VulnRule(
        id="EXPOSED_ADMIN",
        title="Public Administrative Interface",
        severity="HIGH",
        description="Administrative or privileged interfaces are exposed to the internet.",
        tags=["admin", "exposure"],
        families=["exposure"],
        base_score=7.5,
        remediation="Restrict access to administrative endpoints via VPN, IP allow-lists, or strong authentication gateways.",
        matcher=_match_admin_interfaces,
    ),
    VulnRule(
        id="WEAK_SSL_LOGIN",
        title="Weak TLS on Authentication Surface",
        severity="HIGH",
        description="Login or authentication endpoints are served with weak TLS settings.",
        tags=["crypto", "login"],
        families=["crypto", "auth"],
        base_score=8.0,
        remediation="Disable legacy protocols/ciphers and enforce modern TLS (1.2+) with strong certificates on login flows.",
        matcher=_match_weak_ssl_on_login,
    ),
    VulnRule(
        id="OUTDATED_CMS",
        title="Outdated Public CMS",
        severity="MEDIUM",
        description="A publicly reachable CMS is running an outdated version with known vulnerabilities.",
        tags=["cms", "patching"],
        families=["patching", "supply-chain"],
        base_score=6.5,
        remediation="Plan an accelerated upgrade to a supported CMS release and remove unused plugins/themes.",
        matcher=_match_outdated_cms,
    ),
    VulnRule(
        id="MANAGEMENT_SURFACE",
        title="Exposed Management Service",
        severity="HIGH",
        description="Remote administration services are directly exposed.",
        tags=["management", "exposure"],
        families=["exposure"],
        base_score=8.5,
        remediation="Limit management interfaces to trusted networks and enforce MFA with credential hygiene.",
        matcher=_match_management_ports,
    ),
    VulnRule(
        id="API_UNAUTH",
        title="Unauthenticated Sensitive API",
        severity="HIGH",
        description="API endpoints respond with JSON data without evidence of authentication controls.",
        tags=["api", "exposure", "auth"],
        families=["auth", "exposure"],
        base_score=8.2,
        remediation="Enforce authentication, authorization, and rate-limiting on all API routes.",
        matcher=_match_api_exposure,
    ),
    VulnRule(
        id="USER_ENUM",
        title="User Enumeration via Login Responses",
        severity="MEDIUM",
        description="Authentication mechanisms reveal whether an account exists.",
        tags=["auth", "user-enum"],
        families=["auth"],
        base_score=6.5,
        remediation="Return uniform messages, status codes, and timing for unknown users vs bad passwords.",
        matcher=_match_user_enum,
    ),
    VulnRule(
        id="CORS_MISCONFIG",
        title="Misconfigured CORS Policy",
        severity="HIGH",
        description="Cross-origin resource sharing allows arbitrary origins with credentials.",
        tags=["cors", "misconfiguration"],
        families=["misconfiguration", "auth"],
        base_score=7.5,
        remediation="Lock CORS origins to trusted domains and disable credential sharing for wildcard origins.",
        matcher=_match_cors,
    ),
    VulnRule(
        id="CLOUD_METADATA",
        title="Cloud Metadata Service Exposed",
        severity="CRITICAL",
        description="Responses reference cloud metadata endpoints, implying SSRF potential.",
        tags=["cloud", "ssrf"],
        families=["exposure"],
        base_score=9.0,
        remediation="Block metadata access from public workloads and introduce SSRF protections.",
        matcher=_match_metadata,
    ),
    VulnRule(
        id="DEV_SURFACE",
        title="Public Development Surface",
        severity="MEDIUM",
        description="Debug or developer endpoints (swagger, actuator, etc.) are reachable.",
        tags=["dev-surface", "exposure"],
        families=["exposure"],
        base_score=6.2,
        remediation="Disable developer utilities or restrict them to internal networks.",
        matcher=_match_dev_surfaces,
    ),
    VulnRule(
        id="DANGEROUS_HTTP",
        title="Dangerous HTTP Verbs Enabled",
        severity="MEDIUM",
        description="PUT/DELETE/TRACE are enabled without mitigating controls.",
        tags=["http", "surface-expansion"],
        families=["exposure"],
        base_score=6.0,
        remediation="Disable unused HTTP verbs on front-door services and implement strict routing rules.",
        matcher=_match_dangerous_http,
    ),
    VulnRule(
        id="UPLOAD_UNAUTH",
        title="Unauthenticated File Upload",
        severity="MEDIUM",
        description="File upload functionality is exposed without authentication checkpoints.",
        tags=["upload", "dangerous-feature"],
        families=["exposure"],
        base_score=7.2,
        remediation="Require authentication, validate file types, and store uploads outside of web roots.",
        matcher=_match_uploads,
    ),
    VulnRule(
        id="PRIVATE_IP_LEAK",
        title="Internal IP Disclosure",
        severity="LOW",
        description="Responses leak RFC1918 or corporate hostnames.",
        tags=["private-ip", "info-disclosure"],
        families=["exposure"],
        base_score=4.5,
        remediation="Scrub internal references from responses destined for public clients.",
        matcher=_match_private_ip,
    ),
    VulnRule(
        id="VERBOSE_ERRORS",
        title="Verbose Server Errors",
        severity="MEDIUM",
        description="Stack traces or unhandled exceptions are returned to clients.",
        tags=["error-leakage"],
        families=["exposure"],
        base_score=5.5,
        remediation="Return generic error pages and capture details server-side only.",
        matcher=_match_verbose_errors,
    ),
    VulnRule(
        id="GRAPHQL_INTROSPECTION",
        title="GraphQL Introspection Enabled",
        severity="MEDIUM",
        description="GraphQL responds to introspection queries, revealing the schema.",
        tags=["graphql", "exposure"],
        families=["exposure"],
        base_score=6.8,
        remediation="Disable introspection in production deployments and require authorization tokens.",
        matcher=_match_graphql,
    ),
    VulnRule(
        id="BUSINESS_LOGIC_SURFACE",
        title="Business Logic Indicators",
        severity="INFO",
        description="Endpoints expose identifiers related to authorization or workflow logic.",
        tags=["business-logic"],
        families=["auth"],
        base_score=4.0,
        remediation="Review identified endpoints for IDOR, RBAC, or mass-assignment weaknesses.",
        matcher=_match_business_logic,
    ),
    VulnRule(
        id="SECRET_LEAK",
        title="Secrets Exposed in Responses",
        severity="CRITICAL",
        description="Static responses contain API keys, tokens, or credentials.",
        tags=["secret-leak"],
        families=["supply-chain"],
        base_score=9.5,
        remediation="Revoke compromised credentials, rotate secrets, and audit logs for abuse.",
        matcher=_match_secret_exposure,
    ),
    VulnRule(
        id="SESSION_WEAKNESS",
        title="Session Cookie Misconfiguration",
        severity="HIGH",
        description="Cookies lack Secure/HttpOnly/SameSite protections.",
        tags=["session"],
        families=["auth"],
        base_score=7.5,
        remediation="Set Secure, HttpOnly, and strict SameSite attributes on all auth cookies.",
        matcher=_match_session_weakness,
    ),
    VulnRule(
        id="AUTH_CHAIN",
        title="Credential Workflow Attack Chain",
        severity="HIGH",
        description="Multiple auth surface weaknesses align for interception/escalation.",
        tags=["workflow", "auth-chain"],
        families=["auth", "exposure"],
        base_score=8.8,
        remediation="Harden login flows: enforce TLS, add MFA, restrict admin access, and restore CSP/headers.",
        matcher=_match_auth_chain,
    ),
    VulnRule(
        id="DIR_UPLOAD_CHAIN",
        title="Directory Listing + Upload Exposure",
        severity="HIGH",
        description="Uploads combined with directory browsing expose attacker payloads.",
        tags=["directory-listing", "upload"],
        families=["exposure"],
        base_score=7.8,
        remediation="Disable directory browsing and restrict uploads to authenticated, validated workflows.",
        matcher=_match_directory_upload_chain,
    ),
    VulnRule(
        id="SSRF_CHAIN",
        title="Critical SSRF Attack Chain",
        severity="CRITICAL",
        description="Parameters referencing localhost/metadata endpoints indicate chained SSRF.",
        tags=["ssrf-chain"],
        families=["exposure"],
        base_score=9.2,
        remediation="Restrict outbound requests, validate URLs, and block metadata endpoints.",
        matcher=_match_ssrf_chain,
    ),
    VulnRule(
        id="CLOUD_STORAGE",
        title="Public Cloud Storage Exposure",
        severity="MEDIUM",
        description="Cloud storage endpoints appear to host publicly accessible data.",
        tags=["cloud-storage"],
        families=["exposure"],
        base_score=6.0,
        remediation="Ensure buckets enforce authentication and disable public listing unless intentional.",
        matcher=_match_cloud_storage_rule,
    ),
    VulnRule(
        id="OUTDATED_FRAMEWORK",
        title="Outdated Framework Version",
        severity="MEDIUM",
        description="Application frameworks run below supported patch levels.",
        tags=["framework"],
        families=["patching", "supply-chain"],
        base_score=6.9,
        remediation="Upgrade the detected framework to a supported release with security fixes.",
        matcher=_match_outdated_frameworks,
    ),
    VulnRule(
        id="HEADER_CHAIN",
        title="Header Hardening Chain Risk",
        severity="HIGH",
        description="Missing headers combined with upload or weak TLS allows chained exploitation.",
        tags=["header-missing"],
        families=["misconfiguration"],
        base_score=7.6,
        remediation="Reinstate CSP, HSTS, XFO, and related headers particularly on upload or auth endpoints.",
        matcher=_match_header_chain,
    ),
    VulnRule(
        id="BACKUP_EXPOSURE",
        title="Backup / Source Artifact Exposure",
        severity="HIGH",
        description="Backup or repository artifacts are publicly reachable.",
        tags=["backup-leak"],
        families=["exposure"],
        base_score=7.7,
        remediation="Remove backup artifacts from web roots and rotate any embedded secrets.",
        matcher=_match_backup_rule,
    ),
    VulnRule(
        id="SESSION_HEADER_CHAIN",
        title="Session Weakness + Missing Headers",
        severity="HIGH",
        description="Cookies lack protections and security headers are absent, amplifying hijack risk.",
        tags=["session", "header-missing"],
        families=["auth", "misconfiguration"],
        base_score=8.2,
        remediation="Set Secure/HttpOnly/SameSite and restore strict security headers (HSTS, CSP, etc.).",
        matcher=_match_session_header_chain,
    ),
    VulnRule(
        id="API_RATE_LIMIT_GAP",
        title="Unauthenticated API Without Rate Limiting",
        severity="HIGH",
        description="APIs respond unauthenticated and no throttling is observed.",
        tags=["api", "rate-limit-missing"],
        families=["exposure", "auth"],
        base_score=8.3,
        remediation="Enforce authentication plus per-client rate limiting for exposed APIs.",
        matcher=_match_api_rate_limit_gap,
    ),
    VulnRule(
        id="CLOUD_STORAGE_CHAIN",
        title="Cloud Storage + Artifact Exposure",
        severity="CRITICAL",
        description="Cloud storage leaks combine with backup/secret artifacts, enabling full compromise.",
        tags=["cloud-storage", "backup-leak"],
        families=["exposure", "supply-chain"],
        base_score=9.1,
        remediation="Lock down buckets, remove public artifacts, and rotate any impacted credentials.",
        matcher=_match_cloud_storage_chain,
    ),
    VulnRule(
        id="WAF_PARAM_BYPASS",
        title="WAF Bypass + Parameter Fuzzing",
        severity="CRITICAL",
        description="Parameter fuzzing reveals an inconsistency while the WAF allows the request, indicating a bypass path.",
        tags=["waf-bypass", "param-fuzz"],
        families=["exposure", "recon"],
        base_score=9.5,
        remediation="Harden WAF signatures, normalize inputs, and log anomalies for post-mortem.",
        matcher=_match_waf_param_combo,
    ),
    VulnRule(
        id="TIMING_DEBUG_CHAIN",
        title="Timing Variance With Debug Leakage",
        severity="HIGH",
        description="Timing anomalies coincide with debug content, suggesting internal state exposure.",
        tags=["timing-variance", "debug-toggle"],
        families=["recon", "misconfiguration"],
        base_score=8.5,
        remediation="Mask debug responses and stabilize timing/padding; treat anomalous headers as indicators.",
        matcher=_match_timing_debug_combo,
    ),
    VulnRule(
        id="TLS_TIMING_ANOMALY",
        title="TLS Probe + Timing Anomaly",
        severity="HIGH",
        description="Active TLS quirks and timing discrepancies indicate filtered endpoints or detection signatures.",
        tags=["tls-probe", "timing-anomaly"],
        families=["recon", "crypto"],
        base_score=8.0,
        remediation="Audit TLS configuration, align ciphers, and investigate downstream timing/drift issues.",
        matcher=_match_tls_timing,
    ),
]


def apply_rules(findings: List[dict]):
    """
    Apply all vulnerability rules to the incoming findings list.

    Returns:
        tuple(enriched_issues, grouped_by_asset, killchain_edges)
    """
    enriched: List[dict] = []
    for rule in RULES:
        enriched.extend(rule.apply(findings))

    grouped: Dict[str, List[dict]] = {}
    for issue in enriched:
        grouped.setdefault(issue["target"], []).append(issue)

    killchain_edges = [
        {
            "source": issue["target"],
            "target": issue["id"],
            "label": issue["title"],
            "severity": issue["severity"],
        }
        for issue in enriched
    ]

    return enriched, grouped, killchain_edges


__all__ = ["VulnRule", "RULES", "apply_rules"]
