"""
core/reporting/cvss_scorer.py
Automatic CVSS 3.1 vector and base score derivation from SentinelForge findings.

Does NOT require manual input — it maps the signals already present in a finding dict
(severity, vuln_type, capability_tiers, metadata, proof context) to a CVSS 3.1 vector.

The output is intentionally conservative: we underestimate where signals are ambiguous
rather than overstate a score that could mislead a triage reviewer.

CVSS 3.1 Base Metric Groups:
  Exploitability:  Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR),
                   User Interaction (UI)
  Impact:          Scope (S), Confidentiality (C), Integrity (I), Availability (A)

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# CVSS 3.1 metric value weights (from the spec)
# ---------------------------------------------------------------------------

_AV = {
    "N": 0.85,  # Network
    "A": 0.62,  # Adjacent
    "L": 0.55,  # Local
    "P": 0.20,  # Physical
}

_AC = {
    "L": 0.77,  # Low
    "H": 0.44,  # High
}

_PR = {
    "N": 0.85,  # None
    "L": {False: 0.62, True: 0.50},  # Low — scope unchanged / changed
    "H": {False: 0.27, True: 0.50},  # High — scope unchanged / changed
}

_UI = {
    "N": 0.85,  # None
    "R": 0.62,  # Required
}

_C_I_A = {
    "N": 0.00,  # None
    "L": 0.22,  # Low
    "H": 0.56,  # High
}

_ISS_COEFF = 1.0  # scope unchanged; 1.08 for scope changed (applied below)


def _iss(c: float, i: float, a: float) -> float:
    return 1 - (1 - c) * (1 - i) * (1 - a)


def _iss_scope(c: float, i: float, a: float, scope_changed: bool) -> float:
    base = _iss(c, i, a)
    if scope_changed:
        return min(7.52 * (base - 0.029) - 3.25 * ((base - 0.02) ** 15), 10)
    return 6.42 * base


def _exploitability(av: float, ac: float, pr: float, ui: float) -> float:
    return 8.22 * av * ac * pr * ui


def _roundup(x: float) -> float:
    """CVSS 3.1 'Roundup' function: round up to nearest 0.1."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def _base_score(av: str, ac: str, pr: str, ui: str, scope: str, c: str, i_: str, a: str) -> float:
    scope_changed = scope == "C"
    pr_val = _PR[pr][scope_changed] if isinstance(_PR[pr], dict) else _PR[pr]

    exp = _exploitability(_AV[av], _AC[ac], pr_val, _UI[ui])
    imp_sub = _iss_scope(_C_I_A[c], _C_I_A[i_], _C_I_A[a], scope_changed)

    if imp_sub <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (imp_sub + exp), 10)
    else:
        raw = min(imp_sub + exp, 10)

    return _roundup(raw)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CVSSResult:
    """CVSS 3.1 scoring result for a single finding."""

    # Vector components
    av: str = "N"   # Attack Vector
    ac: str = "L"   # Attack Complexity
    pr: str = "N"   # Privileges Required
    ui: str = "N"   # User Interaction
    scope: str = "U"  # Scope
    c: str = "N"    # Confidentiality
    i: str = "N"    # Integrity
    a: str = "N"    # Availability

    base_score: float = 0.0
    severity_label: str = "NONE"
    vector_string: str = ""
    confidence: str = "LOW"   # LOW / MEDIUM / HIGH — how confident the auto-derivation is

    # Human-readable note about derivation choices
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.vector_string:
            self.vector_string = self._build_vector()
        if not self.base_score:
            self.base_score = _base_score(
                self.av, self.ac, self.pr, self.ui,
                self.scope, self.c, self.i, self.a
            )
        if not self.severity_label:
            self.severity_label = _score_to_label(self.base_score)

    def _build_vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}"
            f"/UI:{self.ui}/S:{self.scope}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector": self.vector_string,
            "base_score": self.base_score,
            "severity": self.severity_label,
            "confidence": self.confidence,
            "notes": self.notes,
            "components": {
                "AV": self.av, "AC": self.ac, "PR": self.pr, "UI": self.ui,
                "S": self.scope, "C": self.c, "I": self.i, "A": self.a,
            },
        }


def _score_to_label(score: float) -> str:
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Vuln-type → CVSS component lookup table
# Covers all rule IDs in vuln_rules.py plus common internal tool finding types.
# Each entry is (AV, AC, PR, UI, Scope, C, I, A, confidence, notes)
# ---------------------------------------------------------------------------

_VULN_TABLE: Dict[str, Tuple[str, str, str, str, str, str, str, str, str, str]] = {
    # rule_id / type                AV   AC   PR   UI   S    C    I    A    conf    note
    "EXPOSED_ADMIN":               ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "Admin UI network-reachable, no auth assumed"),
    "WEAK_SSL_LOGIN":              ("N", "H", "N", "N", "U", "H", "N", "N", "HIGH", "MITM on login surface"),
    "OUTDATED_CMS":                ("N", "L", "N", "N", "U", "L", "L", "N", "MEDIUM", "Known CVE profile assumed"),
    "MANAGEMENT_SURFACE":          ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "Management surface accessible"),
    "API_UNAUTH":                  ("N", "L", "N", "N", "U", "H", "L", "N", "HIGH", "Unauth API read/write"),
    "USER_ENUM":                   ("N", "L", "N", "N", "U", "L", "N", "N", "HIGH", "User enumeration via timing/response"),
    "CORS_MISCONFIG":              ("N", "L", "N", "R", "U", "H", "L", "N", "HIGH", "CORS requires attacker page + victim click"),
    "CLOUD_METADATA":              ("N", "L", "N", "N", "C", "H", "H", "N", "HIGH", "SSRF → IMDSv1 exposes cloud credentials"),
    "DEV_SURFACE":                 ("N", "L", "N", "N", "U", "L", "N", "N", "MEDIUM", "Dev endpoints vary in exposure"),
    "DANGEROUS_HTTP":              ("N", "L", "N", "N", "U", "N", "L", "N", "MEDIUM", "Unsafe verbs enabled"),
    "UPLOAD_UNAUTH":               ("N", "L", "N", "N", "U", "N", "H", "N", "HIGH", "Unauth file upload"),
    "PRIVATE_IP_LEAK":             ("N", "L", "N", "N", "U", "L", "N", "N", "HIGH", "Internal IP in response headers"),
    "VERBOSE_ERRORS":              ("N", "L", "N", "N", "U", "L", "N", "N", "HIGH", "Stack trace / path disclosure"),
    "GRAPHQL_INTROSPECTION":       ("N", "L", "N", "N", "U", "L", "N", "N", "HIGH", "Schema introspection enabled"),
    "BUSINESS_LOGIC_SURFACE":      ("N", "L", "N", "R", "U", "L", "L", "N", "LOW", "Business logic indicators only"),
    "SECRET_LEAK":                 ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "Hardcoded secret in response"),
    "SESSION_WEAKNESS":            ("N", "H", "N", "N", "U", "H", "N", "N", "HIGH", "Session cookie missing Secure/HttpOnly"),
    "AUTH_CHAIN":                  ("N", "L", "N", "N", "U", "H", "H", "N", "MEDIUM", "Auth workflow chained"),
    "DIR_UPLOAD_CHAIN":            ("N", "L", "N", "N", "U", "H", "H", "N", "MEDIUM", "Directory listing + upload chain"),
    "SSRF_CHAIN":                  ("N", "L", "N", "N", "C", "H", "H", "N", "HIGH", "SSRF chain to internal resources"),
    "CLOUD_STORAGE":               ("N", "L", "N", "N", "U", "H", "N", "N", "HIGH", "Public cloud storage bucket"),
    "OUTDATED_FRAMEWORK":          ("N", "L", "N", "N", "U", "L", "L", "N", "MEDIUM", "Outdated framework — CVE risk"),
    "HEADER_CHAIN":                ("N", "L", "N", "N", "U", "N", "L", "N", "HIGH", "Header misconfig chain"),
    "BACKUP_EXPOSURE":             ("N", "L", "N", "N", "U", "H", "N", "N", "HIGH", "Backup file exposed"),
    "SESSION_HEADER_CHAIN":        ("N", "L", "N", "N", "U", "H", "L", "N", "MEDIUM", "Session + header chain"),
    "API_RATE_LIMIT_GAP":          ("N", "L", "N", "N", "U", "L", "H", "N", "HIGH", "No rate limit on unauth API"),
    "CLOUD_STORAGE_CHAIN":         ("N", "L", "N", "N", "C", "H", "H", "N", "HIGH", "Cloud storage + artifact chain"),
    "WAF_PARAM_BYPASS":            ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "WAF bypassed — injection reached server"),
    "TIMING_DEBUG_CHAIN":          ("N", "H", "N", "N", "U", "L", "N", "N", "MEDIUM", "Timing + debug info chain"),
    "TLS_TIMING_ANOMALY":          ("N", "H", "N", "N", "U", "N", "N", "N", "LOW", "TLS timing anomaly"),

    # Internal tool finding types
    "Verified SQLi":               ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "SQL injection confirmed"),
    "Verified XSS":                ("N", "L", "N", "R", "C", "L", "L", "N", "HIGH", "XSS confirmed — scope changed (browser context)"),
    "Verified SSRF":               ("N", "L", "N", "N", "C", "H", "H", "N", "HIGH", "SSRF confirmed with OOB callback"),
    "Verified RCE":                ("N", "L", "N", "N", "C", "H", "H", "H", "HIGH", "RCE confirmed with OOB callback"),
    "Verified XXE":                ("N", "L", "N", "N", "C", "H", "H", "N", "HIGH", "XXE with OOB exfil"),
    "Verified IDOR":               ("N", "L", "L", "N", "U", "H", "H", "N", "HIGH", "IDOR — auth required to trigger"),
    "Auth Bypass":                 ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "Differential auth bypass"),
    "Privilege Escalation":        ("N", "L", "L", "N", "U", "H", "H", "N", "HIGH", "Low-priv to high-priv confirmed"),
    "Horizontal IDOR":             ("N", "L", "L", "N", "U", "H", "L", "N", "HIGH", "Access to peer account objects"),
    "Vertical IDOR":               ("N", "L", "L", "N", "U", "H", "H", "N", "HIGH", "Access to higher-priv account objects"),
    "API Discovery":               ("N", "L", "N", "N", "U", "L", "N", "N", "MEDIUM", "Undocumented API endpoint discovered"),
    "Open Redirect":               ("N", "L", "N", "R", "U", "N", "L", "N", "HIGH", "Open redirect — requires user click"),
    "Path Traversal":              ("N", "L", "N", "N", "U", "H", "N", "N", "HIGH", "Directory traversal to sensitive files"),
    "SSTI":                        ("N", "L", "N", "N", "C", "H", "H", "H", "HIGH", "Server-side template injection"),
    "Deserialization":             ("N", "L", "N", "N", "C", "H", "H", "H", "HIGH", "Insecure deserialization"),
    "JWT Weakness":                ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "JWT alg:none or weak secret"),
    "OAuth Misconfiguration":      ("N", "L", "N", "R", "U", "H", "H", "N", "HIGH", "OAuth redirect_uri not validated"),
    "Mass Assignment":             ("N", "L", "L", "N", "U", "H", "H", "N", "HIGH", "Mass assignment via unfiltered body"),
    "Rate Limit Bypass":           ("N", "L", "N", "N", "U", "N", "H", "N", "HIGH", "Rate limiting absent or bypassable"),
    "Subdomain Takeover":          ("N", "L", "N", "N", "U", "H", "H", "N", "HIGH", "CNAME pointing to unclaimed resource"),
    "Security Header Missing":     ("N", "L", "N", "N", "U", "N", "L", "N", "MEDIUM", "Missing security headers"),
    "Information Disclosure":      ("N", "L", "N", "N", "U", "L", "N", "N", "MEDIUM", "Sensitive data in response"),
}


# ---------------------------------------------------------------------------
# Severity-based fallback when vuln type is unknown
# ---------------------------------------------------------------------------

_SEVERITY_FALLBACK: Dict[str, Tuple[str, str, str, str, str, str, str, str]] = {
    # severity  AV   AC   PR   UI   S    C    I    A
    "CRITICAL": ("N", "L", "N", "N", "C", "H", "H", "N"),
    "HIGH":     ("N", "L", "N", "N", "U", "H", "H", "N"),
    "MEDIUM":   ("N", "L", "N", "N", "U", "L", "L", "N"),
    "LOW":      ("N", "H", "N", "N", "U", "L", "N", "N"),
    "INFO":     ("N", "H", "N", "N", "U", "N", "N", "N"),
}


# ---------------------------------------------------------------------------
# Context signal refiners — adjust individual metrics based on finding metadata
# ---------------------------------------------------------------------------

def _refine_from_metadata(
    result: CVSSResult,
    finding: Dict[str, Any],
) -> CVSSResult:
    """
    Apply metadata signals to refine initial vector components.

    Modifiable fields: AC, PR, UI, C, I, A
    Non-modifiable: AV (always network for web findings)
    """
    meta = finding.get("metadata") or {}
    notes: list[str] = [result.notes] if result.notes else []

    # Auth context → Privileges Required
    if meta.get("requires_auth") or meta.get("authenticated"):
        if result.pr == "N":
            result.pr = "L"
            notes.append("PR upgraded to L (authenticated endpoint)")

    # WAF present → Attack Complexity High
    if meta.get("waf_detected") or meta.get("waf_bypassed"):
        result.ac = "H"
        notes.append("AC=H (WAF detected/bypassed)")

    # Availability impact — DoS/resource exhaustion indicators
    tags = finding.get("tags") or []
    families = finding.get("families") or []
    all_labels = [t.lower() for t in tags + families]
    if any(x in all_labels for x in ("dos", "denial", "resource_exhaustion", "crash")):
        result.a = "H"
        notes.append("A=H (DoS/resource exhaustion tag)")

    # Verified OOB callback → High confidence on C/I/A
    if meta.get("oob_callback_received"):
        result.c = "H"
        if result.i == "N":
            result.i = "L"
        notes.append("C=H (OOB callback confirmed exfil)")

    # Confidentiality — data leak signals
    if any(x in all_labels for x in ("pii", "credential", "secret", "token", "key")):
        result.c = "H"
        notes.append("C=H (credential/PII leak tag)")

    result.notes = "; ".join(notes)
    # Recompute score after refinements
    result.base_score = _base_score(
        result.av, result.ac, result.pr, result.ui,
        result.scope, result.c, result.i, result.a
    )
    result.vector_string = result._build_vector()
    result.severity_label = _score_to_label(result.base_score)
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score_finding(finding: Dict[str, Any]) -> CVSSResult:
    """
    Derive a CVSS 3.1 vector and base score from a SentinelForge finding dict.

    Lookup order:
      1. Exact match on finding['rule_id'] in the vuln table
      2. Exact match on finding['type'] in the vuln table
      3. Partial / case-insensitive match on finding['type']
      4. Severity-based fallback
      5. Refine with metadata signals

    Args:
        finding: A finding dict from FindingsStore / IssuesStore.

    Returns:
        CVSSResult with populated vector, base_score, severity_label.
    """
    rule_id = (finding.get("rule_id") or "").upper()
    vuln_type = finding.get("type") or finding.get("title") or finding.get("name") or ""
    severity = (finding.get("severity") or "MEDIUM").upper()

    entry = None
    matched_key = ""

    # 1. Exact rule_id match
    if rule_id and rule_id in _VULN_TABLE:
        entry = _VULN_TABLE[rule_id]
        matched_key = rule_id

    # 2. Exact type match
    if entry is None and vuln_type in _VULN_TABLE:
        entry = _VULN_TABLE[vuln_type]
        matched_key = vuln_type

    # 3. Case-insensitive partial match on type
    if entry is None and vuln_type:
        vt_lower = vuln_type.lower()
        for key, val in _VULN_TABLE.items():
            if key.lower() == vt_lower or vt_lower in key.lower() or key.lower() in vt_lower:
                entry = val
                matched_key = key
                break

    notes = ""
    confidence = "MEDIUM"

    if entry is not None:
        av, ac, pr, ui, scope, c, i_, a, confidence, notes = entry
        result = CVSSResult(av=av, ac=ac, pr=pr, ui=ui, scope=scope, c=c, i=i_, a=a,
                             confidence=confidence, notes=notes)
        if matched_key != vuln_type and matched_key != rule_id:
            result.confidence = "MEDIUM"
            result.notes = f"Matched via partial lookup ({matched_key}); " + notes
    else:
        # Fallback to severity-based generic profile
        fb = _SEVERITY_FALLBACK.get(severity, _SEVERITY_FALLBACK["MEDIUM"])
        av, ac, pr, ui, scope, c, i_, a = fb
        notes = f"No vuln-type match for {vuln_type!r}; using severity-based fallback ({severity})"
        confidence = "LOW"
        result = CVSSResult(av=av, ac=ac, pr=pr, ui=ui, scope=scope, c=c, i=i_, a=a,
                             confidence=confidence, notes=notes)

    # Compute base_score and vector now that components are set
    result.base_score = _base_score(
        result.av, result.ac, result.pr, result.ui,
        result.scope, result.c, result.i, result.a
    )
    result.vector_string = result._build_vector()
    result.severity_label = _score_to_label(result.base_score)

    # Apply metadata refinements
    result = _refine_from_metadata(result, finding)

    return result


def score_findings(findings: list[Dict[str, Any]]) -> list[CVSSResult]:
    """Batch-score a list of findings."""
    return [score_finding(f) for f in findings]
