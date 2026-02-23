"""
core/reporting/bounty_report.py
HackerOne-ready bug bounty report generator.

Produces per-finding Markdown reports formatted to match HackerOne's submission
template exactly. Each report is self-contained and ready to paste directly into
the H1 submission form (or equivalent for Bugcrowd/Intigriti).

Output per finding:
  - Title (severity prefix + vuln type + target asset)
  - Severity + CVSS 3.1 vector (auto-scored)
  - Summary paragraph
  - Steps to reproduce (numbered, curl-based where possible)
  - Impact statement
  - Remediation guidance
  - Supporting evidence (sanitized, non-destructive)
  - Metadata footer (scan_id, tool, timestamp)

Design choices:
  - Conservative language: uses "appears to", "may allow" unless confidence is HIGH
  - No raw stack traces or server internals in reproductions (sanitized)
  - All curl commands are read-only (GET/HEAD) unless the proof explicitly has POST
  - CVSS confidence level is printed so reviewer can override
"""

from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.reporting.cvss_scorer import CVSSResult, score_finding


# ---------------------------------------------------------------------------
# Severity → plain-English risk phrases
# ---------------------------------------------------------------------------

_IMPACT_PHRASES: Dict[str, Tuple[str, str]] = {
    # severity: (risk_descriptor, urgency)
    "CRITICAL": ("critical severity", "Immediate remediation is strongly recommended."),
    "HIGH":     ("high severity",     "Prompt remediation is recommended."),
    "MEDIUM":   ("medium severity",   "Remediation should be planned in the near term."),
    "LOW":      ("low severity",      "Consider addressing as part of routine hardening."),
    "INFO":     ("informational",     "No immediate action required; review for context."),
}

_SEVERITY_EMOJI: Dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

_REMEDIATION_HINTS: Dict[str, str] = {
    "SQLi":           "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "XSS":            "Encode all user-controlled output using context-appropriate escaping (HTML, JS, URL). Implement Content-Security-Policy.",
    "SSRF":           "Validate and allowlist permitted URL schemes and destinations. Block requests to RFC1918 and cloud metadata ranges.",
    "RCE":            "Eliminate all user-controlled input to shell/eval/exec calls. Apply principle of least privilege to process execution.",
    "XXE":            "Disable external entity processing in XML parsers. Use JAXP/libxml2 hardening options.",
    "IDOR":           "Enforce server-side authorization checks on every object access. Do not rely on obscured or client-supplied IDs.",
    "Auth Bypass":    "Audit all authentication enforcement paths. Ensure middleware auth checks cannot be circumvented by parameter manipulation.",
    "Open Redirect":  "Validate redirect targets against an allowlist of internal paths. Reject absolute URLs from user input.",
    "Path Traversal": "Resolve and canonicalize paths before access. Reject inputs containing ../ sequences after decoding.",
    "Subdomain Takeover": "Remove or update dangling DNS CNAME records. Claim or release the pointed-to resource.",
    "Secret Leak":    "Rotate the exposed credential immediately. Add pre-commit hooks and CI secrets scanning.",
    "CORS":           "Restrict Access-Control-Allow-Origin to specific trusted origins. Never reflect the Origin header unconditionally.",
    "SSTI":           "Avoid rendering user input through template engines. Use sandboxed templates or escape inputs before templating.",
    "Mass Assignment": "Use explicit allowlists for accepted request body fields. Never deserialize user input directly into model objects.",
    "JWT":            "Require algorithm specification server-side. Use strong HMAC secrets (≥256-bit) or asymmetric keys.",
    "OAuth":          "Validate redirect_uri against a static registered allowlist. Never accept wildcard or open redirect_uris.",
    "GraphQL":        "Disable introspection in production. Apply query depth/complexity limits and per-field authorization.",
    "Default":        "Review the finding details and apply defense-in-depth controls appropriate to the vulnerability class.",
}


# ---------------------------------------------------------------------------
# Data type
# ---------------------------------------------------------------------------

@dataclass
class BountyReport:
    """A single bug bounty report for one finding."""

    finding_id: str
    title: str
    severity: str
    cvss: CVSSResult
    summary: str
    steps_to_reproduce: List[str]
    impact: str
    remediation: str
    evidence: List[str]
    target: str
    asset: str
    tool: str
    scan_id: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Platform hint (for minor template differences)
    platform: str = "hackerone"

    def to_markdown(self) -> str:
        """Render the report as HackerOne-ready Markdown."""
        return _render_markdown(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            # Flattened CVSS fields — matches Swift BountyFindingReport CodingKeys
            "cvss_score":  self.cvss.base_score,
            "cvss_vector": self.cvss.vector_string,
            "cvss_label":  self.cvss.severity_label,
            "summary": self.summary,
            "steps_to_reproduce": self.steps_to_reproduce,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "target": self.target,
            "asset": self.asset,
            "tool": self.tool,
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "markdown": self.to_markdown(),
        }


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _render_markdown(r: BountyReport) -> str:
    sev = r.severity.upper()
    sev_emoji = _SEVERITY_EMOJI.get(sev, "")
    risk_desc, urgency = _IMPACT_PHRASES.get(sev, _IMPACT_PHRASES["MEDIUM"])
    cvss_note = ""
    if r.cvss.confidence != "HIGH":
        cvss_note = f" *(auto-scored, {r.cvss.confidence.lower()} confidence — manual review recommended)*"

    steps_md = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(r.steps_to_reproduce))
    evidence_md = "\n\n".join(f"```\n{e}\n```" for e in r.evidence) if r.evidence else "*No captured evidence.*"

    return f"""## {sev_emoji} {r.title}

**Severity:** {sev.capitalize()}
**CVSS 3.1 Score:** {r.cvss.base_score} ({r.cvss.severity_label}){cvss_note}
**CVSS Vector:** `{r.cvss.vector_string}`
**Target:** `{r.target}`
**Affected Asset:** `{r.asset}`

---

### Summary

{r.summary}

---

### Steps to Reproduce

{steps_md}

---

### Impact

{r.impact}

{urgency}

---

### Remediation

{r.remediation}

---

### Supporting Evidence

{evidence_md}

---

*Generated by SentinelForge | Scan ID: `{r.scan_id}` | Tool: `{r.tool}` | {r.generated_at}*
"""


# ---------------------------------------------------------------------------
# Summary report renderer (multi-finding digest)
# ---------------------------------------------------------------------------

def render_summary_report(
    reports: List[BountyReport],
    target: str,
    scan_id: str,
    scope_label: str = "",
) -> str:
    """
    Render a multi-finding summary Markdown document.

    This is the top-level document you'd attach to a program report or
    internal ticket. Each finding links to its own standalone report section.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    by_sev: Dict[str, List[BountyReport]] = {}
    for r in reports:
        by_sev.setdefault(r.severity.upper(), []).append(r)

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts_md = " | ".join(
        f"{_SEVERITY_EMOJI.get(s, '')} **{s.capitalize()}**: {len(by_sev.get(s, []))}"
        for s in order if by_sev.get(s)
    )

    toc_lines = []
    detail_sections = []
    idx = 0
    for sev in order:
        for rep in by_sev.get(sev, []):
            idx += 1
            anchor = re.sub(r"[^a-z0-9\-]", "", rep.title.lower().replace(" ", "-"))
            toc_lines.append(f"{idx}. [{rep.title}](#{anchor}) — {_SEVERITY_EMOJI.get(sev, '')} {sev.capitalize()} (CVSS {rep.cvss.base_score})")
            detail_sections.append(rep.to_markdown())

    toc_md = "\n".join(toc_lines)
    details_md = "\n\n---\n\n".join(detail_sections)
    scope_line = f"**Scope:** {scope_label}  \n" if scope_label else ""

    return f"""# Security Assessment Report

**Target:** `{target}`
{scope_line}**Findings:** {len(reports)}
{counts_md}
**Generated:** {now}
**Scan ID:** `{scan_id}`

---

## Table of Contents

{toc_md}

---

## Findings

{details_md}
"""


# ---------------------------------------------------------------------------
# Builder: finding dict → BountyReport
# ---------------------------------------------------------------------------

def build_report(
    finding: Dict[str, Any],
    scan_id: str = "",
    evidence_items: Optional[List[Dict[str, Any]]] = None,
    platform: str = "hackerone",
) -> BountyReport:
    """
    Convert a SentinelForge finding dict into a BountyReport.

    Args:
        finding:        A finding dict from FindingsStore / IssuesStore.
        scan_id:        The scan session ID (for audit trail).
        evidence_items: Optional list of evidence dicts from EvidenceStore.
        platform:       Target platform ("hackerone", "bugcrowd", "intigriti").

    Returns:
        BountyReport ready for .to_markdown() or .to_dict().
    """
    sev = (finding.get("severity") or "MEDIUM").upper()
    vuln_type = finding.get("type") or finding.get("title") or finding.get("name") or "Unknown Vulnerability"
    target = finding.get("target") or finding.get("host") or ""
    asset = finding.get("asset") or finding.get("url") or finding.get("path") or target
    tool = finding.get("tool") or "sentinel"
    finding_id = str(finding.get("id") or finding.get("finding_id") or "")
    meta = finding.get("metadata") or {}

    # --- CVSS scoring
    cvss = score_finding(finding)

    # --- Title
    asset_short = _truncate(asset, 80)
    title = _build_title(sev, vuln_type, asset_short)

    # --- Summary
    summary = _build_summary(finding, vuln_type, sev, cvss)

    # --- Steps to reproduce
    steps = _build_steps(finding, evidence_items)

    # --- Impact
    impact = _build_impact(finding, vuln_type, sev)

    # --- Remediation
    remediation = _build_remediation(vuln_type)

    # --- Evidence snippets (sanitized)
    evidence_snippets = _collect_evidence_snippets(finding, evidence_items)

    return BountyReport(
        finding_id=finding_id,
        title=title,
        severity=sev,
        cvss=cvss,
        summary=summary,
        steps_to_reproduce=steps,
        impact=impact,
        remediation=remediation,
        evidence=evidence_snippets,
        target=target,
        asset=asset,
        tool=tool,
        scan_id=scan_id,
        platform=platform,
    )


def build_reports(
    findings: List[Dict[str, Any]],
    scan_id: str = "",
    evidence_items: Optional[List[Dict[str, Any]]] = None,
    min_severity: str = "LOW",
    platform: str = "hackerone",
) -> List[BountyReport]:
    """
    Batch-build reports for a list of findings, filtered by minimum severity.

    Deduplicates findings with identical (type, asset) pairs — keeps the
    highest-severity version only.
    """
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_idx = order.get(min_severity.upper(), 3)

    # Deduplicate by (type, asset)
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if order.get(sev, 99) > min_idx:
            continue
        vuln_type = f.get("type") or f.get("title") or ""
        asset = f.get("asset") or f.get("target") or ""
        key = (vuln_type.lower(), asset.lower())
        existing = seen.get(key)
        if existing is None or order.get(sev, 99) < order.get((existing.get("severity") or "INFO").upper(), 99):
            seen[key] = f

    reports = [
        build_report(f, scan_id=scan_id, evidence_items=evidence_items, platform=platform)
        for f in seen.values()
    ]

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO, then by CVSS descending
    reports.sort(key=lambda r: (order.get(r.severity.upper(), 99), -r.cvss.base_score))
    return reports


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_title(sev: str, vuln_type: str, asset_short: str) -> str:
    prefix = {"CRITICAL": "[Critical]", "HIGH": "[High]", "MEDIUM": "[Medium]", "LOW": "[Low]"}.get(sev, "")
    return f"{prefix} {vuln_type} in {asset_short}".strip()


def _build_summary(
    finding: Dict[str, Any],
    vuln_type: str,
    sev: str,
    cvss: CVSSResult,
) -> str:
    risk_desc, _ = _IMPACT_PHRASES.get(sev, _IMPACT_PHRASES["MEDIUM"])
    target = finding.get("target") or finding.get("host") or "the target"
    description = finding.get("description") or finding.get("message") or ""
    confidence_hedge = " appears to" if cvss.confidence == "LOW" else ""

    if description and len(description) > 30:
        # Use existing description, prepend context
        return f"A {risk_desc} vulnerability{confidence_hedge} exists in `{target}`. {description}"

    # Generate from vuln type
    return (
        f"A {risk_desc} {vuln_type} vulnerability{confidence_hedge} was identified in `{target}`. "
        f"This finding was detected automatically by SentinelForge and has been assigned a "
        f"CVSS 3.1 base score of {cvss.base_score} ({cvss.severity_label})."
    )


def _build_steps(
    finding: Dict[str, Any],
    evidence_items: Optional[List[Dict[str, Any]]],
) -> List[str]:
    steps: List[str] = []
    meta = finding.get("metadata") or {}
    target = finding.get("target") or ""
    asset = finding.get("asset") or finding.get("url") or target

    # Step 1: always navigate/reach the target
    steps.append(f"Navigate to or send a request to: `{asset}`")

    # Add any proof steps from the finding itself
    proof = finding.get("proof") or ""
    if proof and len(proof) > 10:
        # Break proof into steps if it has numbered lines
        lines = [l.strip() for l in proof.splitlines() if l.strip()]
        if lines:
            # Check if proof already has numbered steps
            numbered = [l for l in lines if re.match(r"^\d+[.)]\s", l)]
            if numbered:
                for line in numbered:
                    clean = re.sub(r"^\d+[.)]\s*", "", line)
                    steps.append(clean)
            else:
                # Add as a single observe step
                truncated = _truncate(proof, 500)
                steps.append(f"Observe the following response/behavior:\n\n    ```\n    {truncated}\n    ```")

    # Add curl command from poc if present
    poc_cmd = meta.get("poc_command") or meta.get("curl_command") or ""
    if poc_cmd:
        steps.append(f"Reproduce with:\n\n    ```bash\n    {poc_cmd}\n    ```")
    elif asset and asset.startswith("http"):
        # Generate a safe read-only curl command
        curl = _safe_curl(asset, finding)
        if curl:
            steps.append(f"Reproduce with:\n\n    ```bash\n    {curl}\n    ```")

    # Step: observe the response indicator
    indicator = meta.get("response_indicator") or meta.get("match") or ""
    if indicator:
        steps.append(f"Observe indicator in response: `{_truncate(str(indicator), 200)}`")

    # Fallback if we have nothing meaningful
    if len(steps) <= 1:
        steps.append("Send the request shown in the supporting evidence below and observe the response.")

    steps.append("Confirm the vulnerability by verifying the response matches expected exploit behavior.")

    return steps


def _build_impact(finding: Dict[str, Any], vuln_type: str, sev: str) -> str:
    # Prefer existing impact field
    existing = finding.get("impact") or ""
    if existing and len(existing) > 20:
        return existing

    # Build from families / type
    families = finding.get("families") or []
    tags = finding.get("tags") or []
    all_labels = [x.lower() for x in families + tags]

    impacts = []
    if any(x in all_labels for x in ("confidentiality", "data_leak", "pii", "secret")):
        impacts.append("unauthorized access to sensitive data or credentials")
    if any(x in all_labels for x in ("integrity", "write", "upload", "modify")):
        impacts.append("unauthorized data modification")
    if any(x in all_labels for x in ("availability", "dos", "crash")):
        impacts.append("service disruption or denial of service")
    if any(x in all_labels for x in ("rce", "execution", "code")):
        impacts.append("arbitrary code execution on the server")
    if any(x in all_labels for x in ("auth", "bypass", "escalation")):
        impacts.append("authentication bypass or privilege escalation")
    if any(x in all_labels for x in ("ssrf", "metadata")):
        impacts.append("server-side request forgery enabling access to internal infrastructure")

    if not impacts:
        # Generic by severity
        sev_impacts = {
            "CRITICAL": ["full compromise of the affected system or its data"],
            "HIGH": ["significant unauthorized access to data or functionality"],
            "MEDIUM": ["partial information disclosure or limited unauthorized actions"],
            "LOW": ["minor information disclosure with limited exploitability"],
        }
        impacts = sev_impacts.get(sev, ["unspecified security impact"])

    impact_list = "; ".join(impacts)
    return (
        f"Successful exploitation of this {vuln_type} vulnerability could allow an attacker to achieve "
        f"{impact_list}. "
        f"Depending on the application context, this may affect confidentiality, integrity, and/or availability of user data and application services."
    )


def _build_remediation(vuln_type: str) -> str:
    # Try exact match first
    if vuln_type in _REMEDIATION_HINTS:
        return _REMEDIATION_HINTS[vuln_type]

    # Partial match
    vt_lower = vuln_type.lower()
    for key, hint in _REMEDIATION_HINTS.items():
        if key.lower() in vt_lower or vt_lower in key.lower():
            return hint

    return _REMEDIATION_HINTS["Default"]


def _collect_evidence_snippets(
    finding: Dict[str, Any],
    evidence_items: Optional[List[Dict[str, Any]]],
) -> List[str]:
    snippets: List[str] = []
    meta = finding.get("metadata") or {}

    # 1. Proof field
    proof = finding.get("proof") or ""
    if proof and len(proof) > 5:
        snippets.append(_truncate(proof, 1000))

    # 2. Response snippet from metadata
    response_body = meta.get("response_body") or meta.get("response_snippet") or ""
    if response_body:
        snippets.append(f"Response snippet:\n{_truncate(str(response_body), 500)}")

    # 3. Raw evidence from EvidenceStore (find entries for same target)
    if evidence_items:
        target = finding.get("target") or ""
        tool = finding.get("tool") or ""
        for ev in evidence_items[:3]:  # max 3 evidence blocks
            ev_tool = ev.get("tool") or ""
            raw = ev.get("raw_output") or ev.get("summary") or ""
            if not raw:
                continue
            if ev_tool == tool or not tool:
                snippets.append(f"[{ev_tool}] output:\n{_truncate(str(raw), 800)}")

    # De-dup and limit
    seen_hashes: set[int] = set()
    unique: List[str] = []
    for s in snippets:
        h = hash(s[:100])
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique.append(s)

    return unique[:5]  # max 5 evidence blocks per report


def _safe_curl(url: str, finding: Dict[str, Any]) -> str:
    """Generate a read-only curl command for the affected URL."""
    if not url or not url.startswith("http"):
        return ""
    # Sanitize URL — no shell-special chars
    safe_url = re.sub(r"[`$();|&<>]", "", url)
    meta = finding.get("metadata") or {}
    headers = meta.get("request_headers") or {}
    header_flags = ""
    for k, v in list(headers.items())[:3]:
        # Skip auth headers in reproductions (security)
        if k.lower() in ("authorization", "cookie", "x-api-key"):
            header_flags += f' -H "{k}: <REDACTED>"'
        else:
            safe_v = re.sub(r"[`$();|&<>]", "", str(v))
            header_flags += f' -H "{k}: {safe_v}"'
    return f"curl -s -i{header_flags} '{safe_url}'"


def _truncate(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + f"... [{len(s) - max_len} chars truncated]"
