"""Module vuln_rules: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/vuln_rules.py."""
#
# PURPOSE:
# This module is the "correlation engine" that transforms low-level findings
# (discovered by tools like nmap, httpx) into high-confidence security issues.
# Think of it as the "intelligence layer" that connects the dots between
# individual discoveries to identify real vulnerabilities.
#
# WHAT IS CORRELATION?
# Correlation means combining multiple findings to build a stronger case for
# a vulnerability. For example:
# - Finding 1: "Port 22 (SSH) is open"
# - Finding 2: "Weak TLS configuration detected"
# - Finding 3: "Login endpoint at /admin"
# - Correlation: "Weak TLS on login endpoint" (HIGH severity issue)
#
# WHY CORRELATION MATTERS:
# - Reduces false positives (single finding might be noise)
# - Increases confidence (multiple findings = stronger evidence)
# - Identifies attack chains (how findings connect to form exploits)
# - Prioritizes remediation (correlated issues are more dangerous)
#
# HOW IT WORKS:
# 1. Raw findings come from raw_classifier.py (ports, services, headers, etc.)
# 2. VulnRule matchers analyze findings for patterns
# 3. Matched findings are grouped by target and enriched with context
# 4. Issues are created with severity, impact, and remediation guidance
# 5. Evidence chains link supporting findings to the final issue
#
# KEY CONCEPTS:
# - **Finding**: Low-level discovery (e.g., "port 80 open")
# - **Issue**: High-confidence vulnerability (e.g., "Outdated WordPress with RCE")
# - **Evidence Chain**: Multiple findings that support an issue
# - **Matcher Function**: Logic that identifies which findings correlate
# - **VulnRule**: Template defining a vulnerability pattern and how to detect it
#
# EXAMPLE WORKFLOW:
# 1. raw_classifier.py finds: "WordPress 5.2.3 detected"
# 2. _match_outdated_cms() checks: Is 5.2.3 < 6.4? (Yes, vulnerable)
# 3. VulnRule creates issue: "Outdated Public CMS" (MEDIUM severity)
# 4. Evidence chain: [finding about WordPress detection]
# 5. Issue includes: Impact, remediation, CVSS-like score
#
# VERSION COMPARISON LOGIC:
# The engine compares detected software versions against known safe minimums.
# Example: WordPress 5.2.3 vs minimum 6.4.0
# - Parses version string to tuple: (5, 2, 3)
# - Compares lexicographically: (5, 2, 3) < (6, 4, 0) = True (vulnerable)
# - Handles missing patch versions: (5, 2) becomes (5, 2, 0) for comparison
#
# EVIDENCE CHAIN BUILDING:
# When multiple findings support an issue, they form an "evidence chain":
# - Issue: "Weak TLS on Login Endpoint"
# - Evidence: [
#     Finding 1: "TLS 1.0 enabled",
#     Finding 2: "Login endpoint at /login",
#     Finding 3: "Weak cipher suite detected"
#   ]
# - Impact: "Sensitive credentials can be intercepted"
#
# RULE MATCHING PROCESS:
# 1. Each VulnRule has a matcher function (e.g., _match_weak_ssl_on_login)
# 2. Matcher scans all findings for matching patterns
# 3. Groups findings by target (same target = same issue)
# 4. Enriches with severity, impact, remediation
# 5. Returns list of issue dictionaries
#
# SEVERITY LEVELS:
# - CRITICAL (9.0-10.0): Immediate compromise (secret leaks, SSRF chains)
# - HIGH (7.0-8.9): Significant risk (auth bypass, RCE potential)
# - MEDIUM (5.0-6.9): Moderate risk (outdated software, misconfigurations)
# - LOW (3.0-4.9): Minor risk (info disclosure, weak headers)
# - INFO (0.0-2.9): Informational (business logic indicators)
#
# INTEGRATION:
# - Used by: core/data/issues_store.py (stores correlated issues)
# - Depends on: core/toolkit/raw_classifier.py (provides raw findings)
# - Called from: core/toolkit/vuln_rules.py::apply_rules()
#
# TESTING:
# To test a new rule:
# 1. Create test findings that should match
# 2. Call rule.matcher(findings)
# 3. Verify returned issues have correct severity/impact
# 4. Check evidence chains include all supporting findings
#
# ============================================================================

from __future__ import annotations

import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Tuple

TextAccumulator = Callable[[List[dict]], List[dict]]

RULES_FILE = Path(__file__).parents[1] / "cortex" / "rules.yaml"

from core.data.constants import CREDENTIAL_INDICATORS, CONFIRMATION_MULTIPLIERS


def _pluck_text(finding: dict) -> str:
    """
    Extract all text content from a finding for pattern matching.
    
    This helper function concatenates all text fields from a finding into
    a single lowercase string, making it easy to search for keywords or patterns.
    
    Args:
        finding: Finding dictionary with keys like "type", "message", "proof", "evidence"
    
    Returns:
        Lowercase string containing all text from the finding
    
    Example:
        finding = {
            "type": "Open Port",
            "message": "Port 22 (SSH) open",
            "proof": "nmap output: 22/tcp open ssh"
        }
        
        Result: "open port port 22 (ssh) open nmap output: 22/tcp open ssh"
    
    Why Lowercase:
        Makes pattern matching case-insensitive. "WordPress" and "wordpress" both match.
    
    Fields Searched (in order):
        1. "type" - Finding type (e.g., "Open Port", "CMS")
        2. "message" - Human-readable message
        3. "proof" - Raw tool output or evidence
        4. "evidence" - Additional evidence text
    
    Used By:
        Most matcher functions use this to search finding text for keywords.
    """
    parts = []
    # Loop over items.
    for key in ("type", "message", "proof", "evidence"):
        val = finding.get(key)
        if isinstance(val, str):
            parts.append(val)
    return " ".join(parts).lower()


def _build_content_string(evidence: List[dict]) -> str:
    """Concatenate all text fields from evidence findings for content inspection."""
    parts = []
    # Loop over items.
    for item in evidence:
        for key in ("type", "message", "proof", "evidence", "value", "description", "technical_details"):
            val = item.get(key)
            if isinstance(val, str):
                parts.append(val)
        # Also check nested metadata
        meta = item.get("metadata", {})
        if isinstance(meta, dict):
            for val in meta.values():
                if isinstance(val, str):
                    parts.append(val)
    return " ".join(parts).lower()


def _derive_issue_confirmation(evidence: List[dict]) -> str:
    """
    Derive the confirmation level of an issue from its supporting findings.

    Uses the LOWEST confirmation level among supporting findings
    (conservative: an issue is only as confirmed as its weakest evidence).

    Falls back to "confirmed" if no confirmation data exists on any finding.
    """
    level_order = {"confirmed": 2, "probable": 1, "hypothesized": 0}
    min_level = 2  # Start at highest (confirmed)
    has_any = False

    # Loop over items.
    for item in evidence:
        cl = item.get("confirmation_level")
        if cl and cl in level_order:
            has_any = True
            min_level = min(min_level, level_order[cl])

    if not has_any:
        # OPTION A (locked in): Default to "confirmed" when no confirmation data
        # exists on any supporting finding. This guarantees zero regression for
        # legacy data that predates Phase 1 — pre-existing issues keep their
        # original effective scores (multiplier = 1.0). Do not change this to
        # "probable" without verifying the full scan corpus still ranks correctly.
        return "confirmed"

    reverse = {2: "confirmed", 1: "probable", 0: "hypothesized"}
    return reverse[min_level]


def _extract_paths(text: str) -> List[str]:
    """
    Extract URL paths from text for evidence summarization.
    
    Finds paths like "/admin", "/wp-admin", "/api/v1/users" in finding text.
    Used to create concise evidence summaries (e.g., "Admin interface at /admin").
    
    Args:
        text: Text to search for paths
    
    Returns:
        List of unique paths found (max 5, deduplicated, preserving order)
    
    Example:
        text = "Found /admin endpoint and /wp-admin/login"
        Result: ["/admin", "/wp-admin"]
    
    Pattern:
        Matches: / followed by 3+ alphanumeric, underscore, dash, or dot characters
        Examples: "/admin", "/api/v1", "/wp-admin", "/.git/config"
        Does NOT match: "//", "/ab" (too short), "/path with spaces"
    
    Why Limit to 5:
        Evidence summaries should be concise. Too many paths clutter the UI.
    """
    matches = re.findall(r"(/[A-Za-z0-9_\-\.]{3,})", text)
    # Deduplicate while preserving order
    seen = set()
    ordered = []
    # Loop over items.
    for path in matches:
        if path not in seen:
            seen.add(path)
            ordered.append(path)
    return ordered[:5]


def _parse_version(raw: str) -> Tuple[int, ...]:
    """
    Parse a version string into a tuple of integers.
    
    Extracts up to 3 version components (major, minor, patch) from a string.
    Handles various formats: "1.2.3", "v2.4", "5.0.1-beta", etc.
    
    Args:
        raw: Version string (e.g., "WordPress 5.2.3", "nginx/1.18.0")
    
    Returns:
        Tuple of integers (major, minor, patch) or empty tuple if no numbers found
    
    Examples:
        >>> _parse_version("WordPress 5.2.3")
        (5, 2, 3)
        
        >>> _parse_version("nginx/1.18.0")
        (1, 18, 0)
        
        >>> _parse_version("v2.4")
        (2, 4)
        
        >>> _parse_version("unknown")
        ()
        
        >>> _parse_version("PHP/7.4.3-4ubuntu2.1")
        (7, 4, 3)  # Only first 3 components
    
    Edge Cases:
        - Missing components: "2.3" → (2, 3) [no patch version]
        - Extra components: "1.2.3.4" → (1, 2, 3) [only first 3]
        - Non-numeric: "beta" → () [empty tuple]
        - Empty string: "" → () [empty tuple]
    
    Why This Matters:
        Version parsing errors lead to:
        - False negatives: Missing real vulnerabilities (e.g., "5.2" parsed as (5, 2) 
          compared to minimum (5, 2, 1) might incorrectly pass)
        - False positives: Flagging safe versions as vulnerable
    """
    nums = re.findall(r"\d+", raw)
    # Conditional branch.
    if not nums:
        return tuple()
    return tuple(int(n) for n in nums[:3])


def _version_lt(current: Tuple[int, ...], minimum: Tuple[int, ...]) -> bool:
    """
    Check if a detected version is OLDER than a minimum required version.
    
    This function determines if a software version is vulnerable by comparing
    it to a known safe minimum version. Used extensively in CVE detection.
    
    Args:
        current: Detected version as tuple, e.g. (2, 3, 1) for "2.3.1"
        minimum: Required safe version, e.g. (2, 4, 0) for "2.4.0"
    
    Returns:
        True if current < minimum (VULNERABLE), False otherwise (SAFE)
    
    Examples:
        >>> _version_lt((2, 3, 1), (2, 4, 0))  # 2.3.1 < 2.4.0
        True  # VULNERABLE
        
        >>> _version_lt((2, 4, 0), (2, 4, 0))  # 2.4.0 == 2.4.0
        False  # SAFE (equal is not less-than)
        
        >>> _version_lt((3, 0), (2, 4, 0))  # 3.0 vs 2.4.0
        False  # SAFE (major version is higher)
        
        >>> _version_lt((2, 3), (2, 3, 5))  # 2.3 vs 2.3.5
        True  # VULNERABLE (missing patch version treated as 0)
    
    Edge Cases:
        - Missing patch version: (2, 3) vs (2, 3, 5) → pads to (2, 3, 0) → True
        - Empty current: () vs (1, 0) → returns False (unknown is not vulnerable)
        - Different lengths: (2, 3) vs (2, 3, 1, 0) → pads both to same length
    
    Algorithm:
        1. If current is empty (unknown version), return False (can't determine vulnerability)
        2. Pad shorter tuple with zeros so both have same length
        3. Compare lexicographically (Python tuple comparison)
        4. (2, 3, 0) < (2, 3, 1) = True (vulnerable)
    
    Why This Matters:
        Incorrect comparisons lead to:
        - False negatives: Missing real vulnerabilities (users stay at risk)
        - False positives: Flagging safe versions (wasted time investigating)
    
    Real-World Example:
        WordPress 5.2.3 detected, minimum safe is 6.4.0:
        - current = (5, 2, 3)
        - minimum = (6, 4, 0)
        - (5, 2, 3) < (6, 4, 0) = True → VULNERABLE
        - Issue created: "Outdated Public CMS" (MEDIUM severity)
    """
    # Conditional branch.
    if not current:
        return False  # Can't determine if unknown version is vulnerable
    length = max(len(current), len(minimum))
    current += (0,) * (length - len(current))
    minimum += (0,) * (length - len(minimum))
    return current < minimum  # Tuple comparison is lexicographic


def _gather_findings(findings: Iterable[dict], predicate: Callable[[dict], bool]) -> Dict[str, List[dict]]:
    """
    Group findings by target that match a predicate function.
    
    This is a helper function used by most matchers to organize findings
    by target (IP/domain) before creating issues.
    
    Args:
        findings: Iterable of finding dictionaries
        predicate: Function that returns True if finding matches pattern
    
    Returns:
        Dictionary mapping target -> list of matching findings
    
    Example:
        findings = [
            {"target": "example.com", "tags": ["admin"]},
            {"target": "example.com", "tags": ["login"]},
            {"target": "other.com", "tags": ["admin"]}
        ]
        predicate = lambda f: "admin" in f.get("tags", [])
        
        Result:
        {
            "example.com": [{"target": "example.com", "tags": ["admin"]}],
            "other.com": [{"target": "other.com", "tags": ["admin"]}]
        }
    
    Why Group by Target:
        - Issues are scoped to a specific target (one issue per target)
        - Multiple findings for same target = stronger evidence
        - Evidence chains are built from all findings for that target
    """
    buckets: Dict[str, List[dict]] = {}
    # Loop over items.
    for item in findings:
        if predicate(item):
            target = item.get("target", "unknown")
            buckets.setdefault(target, []).append(item)
    return buckets


@dataclass
class VulnRule:
    """
    A vulnerability correlation rule that transforms findings into issues.
    
    A VulnRule defines:
    - What pattern to look for (via matcher function)
    - How to classify it (severity, score, tags)
    - What to tell the user (description, impact, remediation)
    
    Attributes:
        id: Unique rule identifier (e.g., "OUTDATED_CMS")
        title: Human-readable issue title (e.g., "Outdated Public CMS")
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        description: Brief explanation of the vulnerability
        tags: List of tags for filtering/grouping (e.g., ["cms", "patching"])
        families: Vulnerability families (e.g., ["patching", "supply-chain"])
        base_score: CVSS-like base score (0.0-10.0)
        remediation: Guidance on how to fix the issue
        matcher: Function that identifies matching findings (TextAccumulator)
    
    Example Rule:
        VulnRule(
            id="OUTDATED_CMS",
            title="Outdated Public CMS",
            severity="MEDIUM",
            description="WordPress 5.2.3 detected (minimum safe: 6.4.0)",
            tags=["cms", "patching"],
            families=["patching", "supply-chain"],
            base_score=6.5,
            remediation="Upgrade to WordPress 6.4.0+",
            matcher=_match_outdated_cms
        )
    """
    id: str
    title: str
    severity: str
    description: str
    tags: List[str]
    families: List[str]
    base_score: float
    remediation: str
    matcher: TextAccumulator = field(repr=False)
    capability_types: List[str] = field(default_factory=lambda: ["execution"])

    def apply(self, findings: List[dict]) -> List[dict]:
        """
        Apply this rule to a list of findings, returning enriched issues.
        
        Process:
        1. Call matcher function to find matching findings
        2. For each match, create an enriched issue dictionary
        3. Include evidence chain (supporting findings)
        4. Add severity, impact, remediation
        
        Args:
            findings: List of raw findings from classifiers
        
        Returns:
            List of enriched issue dictionaries ready for issues_store
        
        Example Output:
            [{
                "id": "OUTDATED_CMS:example.com:1",
                "rule_id": "OUTDATED_CMS",
                "title": "Outdated Public CMS",
                "severity": "MEDIUM",
                "score": 6.5,
                "target": "example.com",
                "description": "WordPress 5.2.3 detected",
                "impact": "Running WordPress 5.2.3 exposes dozens of public exploits",
                "remediation": "Upgrade to WordPress 6.4.0+",
                "tags": ["cms", "patching", "wordpress"],
                "supporting_findings": [finding_dict_1, finding_dict_2],
                "evidence_summary": "WordPress 5.2.3 detected | Port 80 open"
            }]
        """
        matches = self.matcher(findings)
        enriched = []
        # Loop over items.
        for idx, match in enumerate(matches, start=1):
            target = match.get("target", "unknown")
            evidence = match.get("evidence", [])
            issue_id = match.get("id") or f"{self.id}:{target}:{idx}"
            confirmation = _derive_issue_confirmation(evidence)
            multiplier = CONFIRMATION_MULTIPLIERS.get(confirmation, 0.7)
            raw_score = match.get("score", self.base_score)
            effective_score = round(raw_score * multiplier, 2)

            # COMPOUND MULTIPLIER NOTE:
            # This multiplier applies to ISSUE-LEVEL ranking (which issue outranks which).
            # RiskEngine.recalculate() applies a SEPARATE multiplier to ASSET-LEVEL
            # ranking (which target needs attention first). These serve different
            # consumers and are intentionally independent.
            # Do not remove one thinking the other covers it.
            issue = {
                "id": issue_id,
                "rule_id": self.id,
                "title": self.title,
                "severity": match.get("severity", self.severity),
                "score": effective_score,
                "raw_score": raw_score,
                "confirmation_level": confirmation,
                "confirmation_multiplier": multiplier,
                "capability_types": self.capability_types,
                "target": target,
                "description": match.get("description", self.description),
                "impact": match.get("impact", ""),
                "remediation": match.get("remediation", self.remediation),
                "tags": sorted(set(self.tags + match.get("tags", []))),
                "supporting_findings": evidence,
                "families": sorted(set(self.families + match.get("families", []))),
                "evidence_summary": match.get("evidence_summary") or self._summarize_evidence(evidence),
            }

            # Attach three-axis priority scores when feature is enabled.
            # This makes the composite score available to AI chat, reports,
            # and the pressure graph without a second pass.
            try:
                from core.base.config import get_config
                if get_config().capability_model.three_axis_enabled:
                    from core.data.risk import risk_engine
                    issue["three_axis"] = risk_engine.compute_three_axis_priority(issue)
            except Exception:
                pass  # Non-critical — scoring degrades gracefully

            enriched.append(issue)
        return enriched

    @staticmethod
    def _summarize_evidence(evidence: List[dict]) -> str:
        """Function _summarize_evidence."""
        # Conditional branch.
        if not evidence:
            return ""
        samples = []
        # Loop over items.
        for item in evidence[:3]:
            msg = item.get("message") or item.get("proof") or item.get("type")
            if msg:
                samples.append(str(msg))
        return " | ".join(samples)


# ============================================================================
# Rule Matchers - Pattern Detection Functions
# ============================================================================
#
# Each matcher function follows this pattern:
# 1. Takes a list of findings
# 2. Searches for specific patterns (keywords, tags, versions, etc.)
# 3. Groups matching findings by target
# 4. Returns list of issue dictionaries with evidence chains
#
# Matcher functions are passed to VulnRule.matcher and called by rule.apply()
#
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
    """
    Match findings that indicate exposed administrative interfaces.
    
    Detects when admin/login/management interfaces are publicly accessible.
    This is a HIGH severity issue because admin panels are prime targets for
    brute-force attacks, default credential exploitation, and auth bypass attempts.
    
    Detection Logic:
        - Finding has "admin-exposure" tag, OR
        - Finding text contains admin keywords (/wp-admin, /admin, /login, etc.)
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        List of issue dictionaries (one per target with admin interface)
    
    Example:
        Finding: {"target": "example.com", "message": "Found /wp-admin endpoint"}
        Keyword match: "/wp-admin" in ADMIN_KEYWORDS → True
        
        Returns:
        [{
            "target": "example.com",
            "evidence": [finding_dict],
            "evidence_summary": "/wp-admin",
            "tags": ["admin-exposure"],
            "impact": "Attackers can directly attempt password spraying..."
        }]
    
    Admin Keywords Detected:
        - /wp-admin (WordPress)
        - /admin, /administrator
        - /login, /console
        - phpmyadmin, jenkins, grafana, kibana, splunk
    
    Why This Matters:
        Exposed admin interfaces are low-hanging fruit for attackers:
        - Default credentials (admin/admin, root/password)
        - Known vulnerabilities in admin panels
        - Password spraying attacks
        - Session hijacking if cookies are weak
    """
    buckets = _gather_findings(
        findings,
        lambda f: "admin-exposure" in f.get("tags", [])
        or any(key in _pluck_text(f) for key in ADMIN_KEYWORDS),
    )
    results: List[dict] = []
    # Loop over items.
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
    """Function _match_weak_ssl_on_login."""
    def predicate(item: dict) -> bool:
        """Function predicate."""
        text = _pluck_text(item)
        # Conditional branch.
        if not any(token in text for token in SSL_KEYWORDS):
            return False
        return any(token in text for token in LOGIN_KEYWORDS) or any(
            token in item.get("target", "").lower() for token in LOGIN_KEYWORDS
        )

    buckets = _gather_findings(findings, predicate)
    results = []
    # Loop over items.
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
    """
    Match findings that indicate outdated CMS versions.
    
    This matcher identifies when a Content Management System (WordPress, Joomla,
    Drupal, etc.) is running an outdated version with known vulnerabilities.
    
    Detection Process:
    1. Search finding text for CMS name + version pattern
    2. Parse version string to tuple (e.g., "5.2.3" → (5, 2, 3))
    3. Compare against CMS_MINIMUMS (known safe versions)
    4. If detected < minimum, create issue
    
    Args:
        findings: List of finding dictionaries from classifiers
    
    Returns:
        List of issue dictionaries (one per vulnerable CMS instance)
    
    Example:
        Finding: {"target": "example.com", "message": "WordPress 5.2.3 detected"}
        CMS_MINIMUMS["wordpress"] = (6, 4)  # Minimum safe version
        _parse_version("5.2.3") = (5, 2, 3)
        _version_lt((5, 2, 3), (6, 4)) = True  # Vulnerable!
        
        Returns:
        [{
            "target": "example.com",
            "evidence": [finding_dict],
            "tags": ["cms", "wordpress"],
            "evidence_summary": "WordPress 5.2.3 detected",
            "impact": "Running WordPress 5.2.3 exposes dozens of public exploits; upgrade to 6.4+."
        }]
    
    Supported CMS:
        - WordPress (minimum: 6.4)
        - Joomla (minimum: 4.0)
        - Drupal (minimum: 10.0)
        - Magento, PrestaShop, OpenCart, Typo3, Ghost, Concrete5
    
    Why This Matters:
        Outdated CMS versions are prime targets for automated exploitation.
        Public exploits exist for old versions, making them low-hanging fruit
        for attackers. This rule helps prioritize patching.
    """
    hits = []
    # Loop over items.
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
    """Function _match_management_ports."""
    buckets: Dict[Tuple[str, int], List[dict]] = {}
    # Loop over items.
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
    # Loop over items.
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
    """Function _match_by_tag."""
    def matcher(findings: List[dict]) -> List[dict]:
        """Function matcher."""
        results = []
        # Loop over items.
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
    """Function _match_api_exposure."""
    matcher = _match_by_tag(["api", "exposure", "no-auth"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Attackers can interact with backend APIs without authentication, enabling data harvesting or account takeover chaining.",
        )
        match.setdefault("tags", []).append("api-exposure")
    return matches


def _match_cors(findings: List[dict]) -> List[dict]:
    """Function _match_cors."""
    matcher = _match_by_tag(["cors", "misconfiguration"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Permissive CORS combined with credentialed requests allows malicious websites to read authenticated responses.",
        )
    return matches


def _match_dev_surfaces(findings: List[dict]) -> List[dict]:
    """Function _match_dev_surfaces."""
    matcher = _match_by_tag(["dev-surface", "exposure"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Developer utilities leak internal API schemas and promote attack surface discovery.",
        )
    return matches


def _match_user_enum(findings: List[dict]) -> List[dict]:
    """Function _match_user_enum."""
    matcher = _match_by_tag(["auth", "user-enum"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Usernames can be harvested to enable credential stuffing and password spraying attacks.",
        )
    return matches


def _match_metadata(findings: List[dict]) -> List[dict]:
    """Function _match_metadata."""
    matcher = _match_by_tag(["cloud", "ssrf"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Cloud metadata endpoints reveal credentials or tokens that unlock cloud services.",
        )
        match.setdefault("severity", "CRITICAL")
        match.setdefault("score", 9.0)
    return matches


def _match_dangerous_http(findings: List[dict]) -> List[dict]:
    """Function _match_dangerous_http."""
    matcher = _match_by_tag(["surface-expansion"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Unsafe HTTP verbs may permit unauthorized writes, deletes, or diagnostic queries.",
        )
    return matches


def _match_uploads(findings: List[dict]) -> List[dict]:
    """Function _match_uploads."""
    matcher = _match_by_tag(["upload"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Unauthenticated upload endpoints can be weaponized for malware hosting or stored XSS.",
        )
    return matches


def _match_private_ip(findings: List[dict]) -> List[dict]:
    """Function _match_private_ip."""
    matcher = _match_by_tag(["private-ip"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Internal addressing hints accelerate SSRF chaining and lateral movement.",
        )
    return matches


def _match_verbose_errors(findings: List[dict]) -> List[dict]:
    """Function _match_verbose_errors."""
    matcher = _match_by_tag(["error-leakage"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Detailed stack traces reveal software versions, stack components, and exploitable code paths.",
        )
    return matches


def _match_graphql(findings: List[dict]) -> List[dict]:
    """Function _match_graphql."""
    matcher = _match_by_tag(["graphql"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Introspection reveals the entire GraphQL schema, simplifying logic abuse.",
        )
    return matches


def _match_business_logic(findings: List[dict]) -> List[dict]:
    """Function _match_business_logic."""
    matcher = _match_by_tag(["business-logic"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Endpoints reference business logic identifiers. Review for IDOR, RBAC bypass, or mass-assignment.",
        )
        match.setdefault("severity", "INFO")
        match.setdefault("score", 4.0)
    return matches


def _match_session_header_chain(findings: List[dict]) -> List[dict]:
    """Function _match_session_header_chain."""
    results = []
    targets = _gather_target_tag_map(findings)
    # Loop over items.
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
    """Function _match_api_rate_limit_gap."""
    results = []
    targets = _gather_target_tag_map(findings)
    # Loop over items.
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
    """Function _match_cloud_storage_chain."""
    results = []
    targets = _gather_target_tag_map(findings)
    # Loop over items.
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
    """Function _match_waf_param_combo."""
    results = []
    targets = _gather_target_tag_map(findings)
    # Loop over items.
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
    """Function _match_timing_debug_combo."""
    results = []
    targets = _gather_target_tag_map(findings)
    # Loop over items.
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
    """Function _match_tls_timing."""
    results = []
    targets = _gather_target_tag_map(findings)
    # Loop over items.
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
    """Function _match_secret_exposure."""
    matcher = _match_by_tag(["secret-leak"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault("severity", "CRITICAL")
        match.setdefault("score", 9.5)
        match.setdefault(
            "impact",
            "Leaked credentials allow attackers to hijack infrastructure or pivot across environments.",
        )
    return matches


def _match_session_weakness(findings: List[dict]) -> List[dict]:
    """Function _match_session_weakness."""
    matcher = _match_by_tag(["session", "cookie"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Session cookies lack essential flags, enabling hijacking via XSS, MitM, or CSRF.",
        )
        match.setdefault("tags", []).append("session-hardening")
    return matches


def _gather_target_tag_map(findings: List[dict]) -> Dict[str, set]:
    """Function _gather_target_tag_map."""
    tag_map: Dict[str, set] = {}
    # Loop over items.
    for item in findings:
        target = item.get("target", "unknown")
        for tag in item.get("tags", []):
            tag_map.setdefault(target, set()).add(tag)
    return tag_map


def _match_auth_chain(findings: List[dict]) -> List[dict]:
    """Function _match_auth_chain."""
    tag_map = _gather_target_tag_map(findings)
    results = []
    # Loop over items.
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
    """Function _match_directory_upload_chain."""
    tag_map = _gather_target_tag_map(findings)
    results = []
    # Loop over items.
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
    """Function _match_ssrf_chain."""
    tag_map = _gather_target_tag_map(findings)
    results = []
    # Loop over items.
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
    """Function _match_cloud_storage_rule."""
    matcher = _match_by_tag(["cloud-storage"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        match.setdefault(
            "impact",
            "Public cloud storage buckets may host sensitive data or enable malware distribution.",
        )
        match.setdefault("severity", "MEDIUM")
    return matches


def _match_outdated_frameworks(findings: List[dict]) -> List[dict]:
    """Function _match_outdated_frameworks."""
    hits = []
    # Loop over items.
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
    """Function _match_header_chain."""
    tag_map = _gather_target_tag_map(findings)
    results = []
    # Loop over items.
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
    """Function _match_backup_rule."""
    matcher = _match_by_tag(["backup-leak"])
    matches = matcher(findings)
    # Loop over items.
    for match in matches:
        # Content-aware escalation: inspect evidence for credential indicators
        content = _build_content_string(match.get("evidence", []))
        has_credentials = any(ind in content for ind in CREDENTIAL_INDICATORS)

        if has_credentials:
            match["severity"] = "CRITICAL"
            match["score"] = 9.5
            match["impact"] = (
                "Backup or source artifacts expose credentials or secrets, "
                "enabling direct unauthorized access to backend systems."
            )
            match.setdefault("tags", []).append("credential-in-backup")
        else:
            match.setdefault("severity", "HIGH")
            match.setdefault("score", 7.7)
            match.setdefault(
                "impact",
                "Backup or source artifacts exposed publicly provide full application source and secrets.",
            )
    return matches


# ============================================================================
# Public API - Rule Registry
# ============================================================================
#
# RULES is the global registry of all vulnerability correlation rules.
# Each rule defines:
# - What pattern to detect (via matcher function)
# - How severe it is (severity, base_score)
# - What to tell users (description, impact, remediation)
#
# Rule Execution Order:
# Rules are applied in the order listed here. Later rules can build on
# earlier rule results (e.g., chain detection rules).
#
# Adding a New Rule:
# 1. Write a matcher function (e.g., _match_my_vulnerability)
# 2. Add VulnRule entry to RULES list below
# 3. Test with sample findings
# 4. Verify evidence chains are correct
#
# Rule Categories:
# - Exposure Rules: Admin interfaces, management ports, dev surfaces
# - Crypto Rules: Weak TLS, missing security headers
# - Auth Rules: User enumeration, session weaknesses, CORS misconfig
# - Chain Rules: Multiple findings that combine for higher severity
# - Supply Chain: Outdated CMS/frameworks, backup leaks, secret exposure
#
# ----------------------------------------------------------------------

_LEGACY_RULES: List[VulnRule] = [
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
        capability_types=["execution", "access"],
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
        capability_types=["information", "execution"],
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
        capability_types=["information"],
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
        capability_types=["information"],
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
        capability_types=["information"],
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
        capability_types=["access"],
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
        capability_types=["execution"],
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
        capability_types=["information", "access"],
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


def load_rules_from_yaml() -> List[VulnRule]:
    """
    Load external rules from rules.yaml and hydrate them with matcher functions.
    """
    # Conditional branch.
    if not RULES_FILE.exists():
        return []

    # Error handling block.
    try:
        with open(RULES_FILE, "r") as f:
            data = yaml.safe_load(f)
            
        loaded = []
        raw_rules = data.get("rules", [])
        
        # Registry of available matchers in this module
        # Dynamic lookup from globals()
        available_matchers = globals()
        
        for rule_def in raw_rules:
            matcher_name = rule_def.get("matcher_func")
            matcher = available_matchers.get(matcher_name)
            
            if not matcher:
                # Fallback or error logging could go here
                print(f"Warning: Matcher '{matcher_name}' not found for rule {rule_def.get('id')}")
                continue
                
            loaded.append(VulnRule(
                id=rule_def["id"],
                title=rule_def["title"],
                severity=rule_def["severity"],
                description=rule_def["description"],
                tags=rule_def.get("tags", []),
                families=rule_def.get("families", []),
                base_score=float(rule_def.get("base_score", 5.0)),
                remediation=rule_def.get("remediation", ""),
                matcher=matcher
            ))
            
        return loaded
    except Exception as e:
        print(f"Error loading rules.yaml: {e}")
        return []

# Hybrid Rule Set: Merge Legacy with YAML (YAML wins)
def _merge_rules() -> List[VulnRule]:
    # Rule ID -> VulnRule
    """Function _merge_rules."""
    registry = {r.id: r for r in _LEGACY_RULES}
    
    # Overlay YAML rules
    for r in load_rules_from_yaml():
        registry[r.id] = r
        
    return list(registry.values())

RULES = _merge_rules()


def apply_rules(findings: List[dict]):
    """
    Apply all vulnerability correlation rules to transform findings into issues.
    
    This is the main entry point for the correlation engine. It:
    1. Runs all VulnRule matchers against the findings
    2. Groups issues by target (asset)
    3. Generates killchain edges for attack path visualization
    
    Args:
        findings: List of raw findings from classifiers (raw_classifier.py)
    
    Returns:
        Tuple of:
        - enriched_issues: List of issue dictionaries (ready for issues_store)
        - grouped_by_asset: Dict mapping target -> list of issues for that target
        - killchain_edges: List of edge dictionaries for graph visualization
    
    Example:
        findings = [
            {"target": "example.com", "type": "Open Port", "message": "Port 22 open"},
            {"target": "example.com", "type": "CMS", "message": "WordPress 5.2.3"}
        ]
        
        Returns:
        (
            [
                {
                    "id": "OUTDATED_CMS:example.com:1",
                    "title": "Outdated Public CMS",
                    "severity": "MEDIUM",
                    "target": "example.com",
                    ...
                }
            ],
            {
                "example.com": [issue_dict]
            },
            [
                {
                    "source": "example.com",
                    "target": "OUTDATED_CMS:example.com:1",
                    "label": "Outdated Public CMS",
                    "severity": "MEDIUM"
                }
            ]
        )
    
    Usage:
        from core.toolkit.vuln_rules import apply_rules
        
        issues, grouped, edges = apply_rules(findings)
        
        # Store issues
        for issue in issues:
            issues_store.add_issue(issue)
        
        # Store killchain edges
        for edge in edges:
            killchain_store.add_edge(edge)
    
    Performance:
        - O(n * m) where n = findings, m = rules
        - Typically runs in <100ms for 1000 findings and 30 rules
        - Consider caching if findings list is very large (>10k)
    """
    enriched: List[dict] = []
    # Loop over items.
    for rule in RULES:
        enriched.extend(rule.apply(findings))

    grouped: Dict[str, List[dict]] = {}
    # Loop over items.
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
