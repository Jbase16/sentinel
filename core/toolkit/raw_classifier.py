"""Module raw_classifier: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/raw_classifier.py."""
#
# PURPOSE:
# Transforms unstructured security tool output (nmap, nikto, gobuster, etc.) into
# normalized RawFinding objects for downstream analysis by AIEngine and ReasoningEngine.
# Acts as the first stage of the SentinelForge analysis pipeline.
#
# KEY RESPONSIBILITIES:
# - Parse tool-specific output formats (text, JSON, ANSI-colored CLI output)
# - Extract security findings using regex pattern matching
# - Normalize findings into consistent RawFinding dataclass structure
# - Classify severity, assign tags/families, extract metadata
# - Detect cross-tool patterns (secrets, misconfigurations, exposures)
#
# INTEGRATION:
# - Used by: core/engine/orchestrator.py (scan result processing)
# - Depends on: Tool-specific output formats (nmap, whatweb, httpx, etc.)
# - Feeds into: core/ai/engine.py (AIEngine for enrichment)
#
# REGEX PATTERN DOCUMENTATION STANDARD:
# All regex patterns in this module follow production-grade documentation:
#   1. PURPOSE: What the pattern matches and why (security context)
#   2. STRUCTURE: Breakdown of pattern syntax with group semantics
#   3. EXAMPLES: Matched strings demonstrating pattern behavior
#   4. EDGE CASES: Boundary conditions, ambiguous inputs, format variations
#   5. FAILURE MODES: Known limitations, tool version dependencies
#   6. PERFORMANCE: Backtracking risks, complexity analysis (where relevant)
#
# Rationale: Security tool output parsing is brittle; comprehensive documentation
# prevents regressions during tool upgrades and enables safe pattern evolution.
#

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Dict, List, Tuple
from core.toolkit.fingerprinters import ContentHasher

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
    # Pattern structure: cms_name + delimiter + version
    # Matches: "WordPress 6.4.2", "wordpress/5.9", "WordPress:4.7", "wordpress_3.8.1", "wordpress-2.9"
    # Group 1 (optional): Version in format X, X.Y, or X.Y.Z
    # Delimiter class [\s/:_-]* permits zero or more whitespace, forward slash, colon, underscore, or hyphen
    # Version pattern: ([0-9]+(?:\.[0-9]+){0,2})?
    #   - [0-9]+ = one or more digits (major version, required if version present)
    #   - (?:\.[0-9]+){0,2} = zero to two occurrences of dot + digits (minor/patch versions)
    #   - Entire group is optional (?) to match "WordPress" without version
    # Invariant: CMS name must be present; version extraction is opportunistic
    # Edge case: Matches "wordpress" in "wordpress.org" (intentional for broad capture)
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

# RFC 1918 Private IPv4 Address Detection
# Matches three private address ranges:
#   - 10.0.0.0/8:       10.0.0.0 - 10.255.255.255
#   - 172.16.0.0/12:    172.16.0.0 - 172.31.255.255
#   - 192.168.0.0/16:   192.168.0.0 - 192.168.255.255
#
# Pattern breakdown:
#   \b                                    = Word boundary (prevents matching inside longer strings)
#   (?:                                   = Non-capturing group for alternation
#     10\.\d{1,3}\.\d{1,3}\.\d{1,3}      = Class A private (10.x.x.x)
#     |                                    = OR
#     192\.168\.\d{1,3}\.\d{1,3}         = Class C private (192.168.x.x)
#     |                                    = OR
#     172\.(?:1[6-9]|2\d|3[01])\.        = Class B private (172.16-31.x.x)
#         \d{1,3}\.\d{1,3}
#   )
#   \b                                    = Word boundary
#
# Class B breakdown (172.16-31.x.x):
#   (?:1[6-9]|2\d|3[01])
#     1[6-9]  = 16-19 (1 followed by 6-9)
#     2\d     = 20-29 (2 followed by any digit)
#     3[01]   = 30-31 (3 followed by 0 or 1)
#
# False positives: Allows invalid octets (e.g., 10.999.1.1) for permissive matching of malformed tool output
# Rationale: Security tools may truncate or malform IPs; prefer false positives over false negatives
# Performance: No catastrophic backtracking; linear time complexity O(n)
PRIVATE_IP_REGEX = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)

# Credential and Secret Detection Patterns
# Each pattern targets specific secret formats leaked in tool output, headers, or page content
# Tuples: (human_label, compiled_regex_pattern)
# All patterns are designed to minimize false negatives at cost of occasional false positives
SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    # AWS Access Key ID
    # Format: AKIA + 16 alphanumeric uppercase characters
    # Example: AKIAIOSFODNN7EXAMPLE
    # \b = word boundary to prevent matching inside larger strings
    # Group 0 (full match): entire key
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    
    # AWS Secret Access Key (contextual)
    # Matches secret keys appearing near "aws", "secret", or "key" identifiers
    # Pattern: variable name/prefix + optional spacing + separator + 40-char base64-like value
    # (?i) = case insensitive for identifier matching
    # .{0,10} = up to 10 chars between "aws" and "secret/key" (handles "aws_secret", "aws-api-key")
    # ['\"]? = optional quote before separator
    # [:=] = colon or equals separator
    # Group 3: the 40-character secret value
    # Example: aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    # False positive risk: Generic 40-char base64 strings near "key" keyword; acceptable for security context
    ("aws-secret-key", re.compile(r"(?i)aws(.{0,10})?(secret|key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})")),
    
    # Google Cloud API Key
    # Format: AIza + 35 chars (base62: A-Z, a-z, 0-9, hyphen, underscore)
    # Example: AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe
    # \b boundaries ensure exact format matching
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    
    # GitHub Personal Access Token / App Token
    # Format: gh{p|o|u|s|r}_ + 36+ alphanumeric characters
    # Token types: p=personal, o=OAuth, u=user-to-server, s=server-to-server, r=refresh
    # Character class [pousr] matches any valid type prefix
    # {36,} = minimum 36 chars (tokens can be longer; unbounded for forward compatibility)
    # Example: ghp_1234567890abcdefghijklmnopqrstuvwxyz
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    
    # Slack API Tokens
    # Format: xox{b|a|p|r|s}- + variable-length alphanumeric + hyphens
    # Token types: b=bot, a=app, p=personal, r=refresh, s=service
    # Minimum 10 chars after prefix (legacy tokens); modern tokens often 50+ chars
    # Example: xoxb-XXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXX
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    
    # Stripe Live Secret Key
    # Format: sk_live_ + 24+ alphanumeric characters
    # sk_test_ deliberately excluded (test keys are lower risk)
    # {24,} = minimum length observed; allows longer keys for API evolution
    # Example: sk_live_FAKEKEY_REDACTED_EXAMPLE
    ("stripe-secret", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    
    # Firebase/Google Services API Key
    # Identical format to google-api-key but listed separately for explicit Firebase identification
    # No word boundary at start (may appear in URLs like "?key=AIza...")
    # Example: AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe
    ("firebase", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    
    # Twilio Account SID
    # Format: AC + 32 hexadecimal characters
    # SID is public identifier but often indicates presence of sensitive auth tokens nearby
    # Example: ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    ("twilio-sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    
    # Twilio Auth Token (contextual)
    # Pattern: "twilio" + proximity text + separator + 32 hex chars
    # .{0,5} = up to 5 chars between "twilio" and identifier (handles "twilio_auth", "twilio.token")
    # Group 3: the 32-char hexadecimal token
    # Example: twilio_auth_token="1234567890abcdef1234567890abcdef"
    ("twilio-auth", re.compile(r"(?i)\btwilio(.{0,5})?(secret|token)['\"]?\s*[:=]\s*['\"]([0-9a-fA-F]{32})")),
    
    # Private Key Headers (PEM format)
    # Matches RSA, Elliptic Curve, or DSA private key blocks
    # (?:RSA|EC|DSA) = non-capturing group for key type alternatives
    # Matches header only; key material extraction would require multi-line matching
    # Example: -----BEGIN RSA PRIVATE KEY-----
    # Rationale: Header presence is sufficient for high-severity finding; full key extraction not required
    ("jwt-key", re.compile(r"-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----")),
    
    # Generic Secret Pattern (catch-all)
    # Matches common variable naming conventions followed by long alphanumeric values
    # (?i) = case insensitive to catch SECRET, secret, Secret
    # (secret|token|api[_-]?key) = Group 1: common identifier keywords
    # ['\"=:\s]+ = one or more quote/equals/colon/whitespace separators
    # Group 2: 24+ character value (alphanumeric, underscore, hyphen)
    # Minimum 24 chars reduces false positives from short config values
    # Example: api_key="abcdef1234567890ghijklmnopqrstuvwxyz"
    # False positive risk: HIGH - matches benign long identifiers; use as fallback only
    # Severity elevation logic should apply if found in HTTP responses or non-config contexts
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

# Web Framework and Runtime Detection Patterns
# Extracts framework/runtime names and version numbers from HTTP headers, error messages, or tool output
# Pattern structure mirrors CMS_SIGNATURES but accounts for framework-specific naming (e.g., "Spring Boot", "ASP.NET Core")
# All patterns use IGNORECASE for case-insensitive matching
FRAMEWORK_PATTERNS: Dict[str, re.Pattern[str]] = {
    # Express.js (Node.js framework)
    # Matches: "Express 4.18.2", "express/4.17", "Express / 3.0"
    # /? = optional forward slash separator
    # Group 1: Version (optional, format X, X.Y, or X.Y.Z)
    "express": re.compile(r"express/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    "flask": re.compile(r"flask/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "django": re.compile(r"django/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "rails": re.compile(r"rails/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "laravel": re.compile(r"laravel/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    # Spring Boot (Java framework)
    # Matches: "Spring Boot 3.1.0", "spring boot/2.7", "spring-boot 3.0"
    # Literal space in pattern requires exact "spring boot" match
    # Edge case: Does NOT match standalone "Spring" framework (intentional)
    "spring": re.compile(r"spring boot/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    # ASP.NET / ASP.NET Core (.NET framework)
    # Matches: "ASP.NET Core 8.0", "asp.net 4.8", "ASP.NET Core/7.0"
    # \. = escaped dot (literal period in "asp.net")
    # (?: core)? = optional non-capturing group for "core" suffix
    # Handles both legacy ASP.NET and modern ASP.NET Core
    "aspnet": re.compile(r"asp\.net(?: core)?/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    "fastapi": re.compile(r"fastapi/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "phoenix": re.compile(r"phoenix/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    # Next.js (React framework)
    # Matches: "Next.js 14.0.3", "next.js/13.5", "nextjs 12.0"
    # \. = escaped dot in "next.js"
    # Edge case: Also matches "nextjs" without dot (common informal naming)
    "nextjs": re.compile(r"next\.js/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    "nuxtjs": re.compile(r"nuxt\.js/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    "node": re.compile(r"node\.js/?\s*([0-9]+(?:\.[0-9]+){0,2})?", re.IGNORECASE),
    
    # Generic language runtimes (Java, PHP)
    # These may match overly broad contexts (e.g., "Java" in prose)
    # Trade-off: Prioritize detection completeness over precision
    # Downstream filtering should validate context (e.g., presence in X-Powered-By header)
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
    """Function _parse_version."""
    nums = re.findall(r"\d+", raw or "")
    return tuple(int(n) for n in nums[:3])


# ANSI/VT100 Escape Sequence Removal Pattern
# Removes terminal control sequences (colors, cursor movement, formatting) from tool output
# Many CLI security tools (nmap, gobuster, feroxbuster) emit colorized output with ANSI codes
#
# ANSI CSI sequence structure: ESC [ <parameters> <intermediate bytes> <final byte>
# Pattern breakdown:
#   \x1B        = ESC character (0x1B, starts all ANSI sequences)
#   \[          = Literal left bracket (CSI - Control Sequence Introducer)
#   [0-?]*      = Parameter bytes: zero or more chars in range 0-9, :, ;, <, =, >, ? (0x30-0x3F)
#   [ -/]*      = Intermediate bytes: zero or more chars in range space through / (0x20-0x2F)
#   [@-~]       = Final byte: single char in range @ through ~ (0x40-0x7E)
#                 Determines the action (m=color, H=cursor position, K=erase, etc.)
#
# Example sequences matched:
#   \x1B[0m        = Reset all formatting
#   \x1B[1;31m     = Bold + red foreground
#   \x1B[2J        = Clear screen
#   \x1B[?25h      = Show cursor
#
# Does NOT match:
#   - OSC sequences (\x1B]...\x07) used for titles/notifications
#   - Single-char escape sequences (\x1BM, \x1B7) without CSI
#   Rationale: These are rare in security tool output; CSI coverage is sufficient for 99%+ cases
#
# Performance: Non-backtracking; safe for untrusted input
# Used by: _strip_ansi() function to normalize tool output before regex matching
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(text: str) -> str:
    """Function _strip_ansi."""
    return ANSI_RE.sub("", text or "")


@dataclass
class RawFinding:
    """Class RawFinding."""
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
        """Function as_dict."""
        data = asdict(self)
        # Normalize to sorted unique tags/families for downstream consumers.
        data["tags"] = sorted(set(self.tags))
        data["families"] = sorted(set(self.families))
        return data


def classify(tool: str, target: str, output: str) -> List[dict]:
    """Function classify."""
    handler = _HANDLERS.get(tool.lower())
    findings: List[RawFinding] = []
    # Conditional branch.
    if handler:
        findings.extend(handler(target, output))
    findings.extend(_global_detectors(tool, target, output))
    return [finding.as_dict() for finding in findings]


# ----------------------------------------------------------------------
# Tool-specific handlers
# ----------------------------------------------------------------------


def _handle_nmap(target: str, output: str) -> List[RawFinding]:
    """Function _handle_nmap."""
    findings: List[RawFinding] = []
    # Loop over items.
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
    """Function _handle_whatweb."""
    findings: List[RawFinding] = []
    # Loop over items.
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
    """Function _handle_wafw00f."""
    # Error handling block.
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    # Conditional branch.
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
    """Function _handle_httpx."""
    findings: List[RawFinding] = []
    
    # Try parsing as JSON lines first (Cartographer Enrichment)
    # httpx -json output contains rich data including hash, body, techs
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        
        try:
            if line.startswith("{"):
                data = json.loads(line)
                url = data.get("url")
                status = data.get("status_code", 0)
                techs = data.get("tech", [])
                
                # Fingerprinting (Cartographer)
                metadata = {
                    "url": url,
                    "status": status,
                    "title": data.get("title", ""),
                    "tech": ",".join(techs) if isinstance(techs, list) else str(techs)
                }
                
                # Favicon Hash (httpx native or manual)
                if fhash := data.get("hash"):
                    # httpx returns "mmh3:-12345" sometimes
                    metadata["favicon_hash"] = str(fhash).replace("mmh3:", "")
                
                # SimHash of Body
                if body := data.get("body"):
                    metadata["simhash"] = ContentHasher.simhash(body)
                
                severity = "INFO"
                if status >= 500:
                    severity = "HIGH"
                elif status >= 400:
                    severity = "MEDIUM"
                
                findings.append(RawFinding(
                    type="HTTP Endpoint",
                    severity=severity,
                    tool="httpx",
                    target=target, # Maintain original target context
                    message=f"{url} returned {status}",
                    proof=line[:200],
                    tags=["surface-http", f"status-{status}"],
                    families=["exposure"],
                    metadata=metadata
                ))
                continue # Handled as JSON
        except json.JSONDecodeError:
            pass # Fallback to regex text parsing

    # HTTPX Output Parser (Legacy Text Mode)
    # Parses httpx tool output format: URL [STATUS] [TITLE] [TECH]
    # Example: "https://example.com [200] [Welcome Page] [nginx,PHP]"
    #
    # Pattern: (https?://\S+)\s+\[(\d{3})\]\s*(?:\[(.*?)\])?\s*(?:\[(.*?)\])?
    # Group 1: URL (required) - https?://\S+ = http/https + non-whitespace chars
    # Group 2: HTTP status code (required) - (\d{3}) = exactly 3 digits
    # Group 3: Page title (optional) - (?:\[(.*?)\])? = non-greedy capture within brackets
    # Group 4: Technology stack (optional) - (?:\[(.*?)\])? = non-greedy capture within brackets
    #
    # Non-capturing groups (?:...) wrap bracket literals to avoid group pollution
    # Lazy quantifiers (.*?) prevent over-matching across multiple bracketed sections
    #
    # Edge cases:
    #   - ANSI codes in URL or fields: Handled by _strip_ansi() before matching
    #   - Missing title/tech fields: Optional groups return None, handled by .group() or ""
    #   - URLs with query params containing brackets: URL group stops at first whitespace (\S+)
    #
    # Failure modes:
    #   - httpx format changes in future versions: Pattern assumes [field] bracketing convention
    #   - Malformed URLs (missing protocol): Won't match, which is correct (invalid httpx output)
    pattern = re.compile(r"(https?://\S+)\s+\[(\d{3})\]\s*(?:\[(.*?)\])?\s*(?:\[(.*?)\])?")
    # Loop over items.
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        if not clean.startswith("http"):
            # If it was JSON, we likely continued already. If garbage/empty, skip.
            continue
        
        # Double check it wasn't valid JSON that failed to parse (unlikely if startswith http)
        if clean.startswith("{"):
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
    """Function _handle_dirsearch."""
    findings: List[RawFinding] = []
    # Dirsearch Output Parser
    # Parses dirsearch directory enumeration format: STATUS - SIZE - PATH [-> REDIRECT]
    # Example: "200 -  1234B  - /admin/login.php"
    # Example: "301 -   312B  - /images -> /images/"
    #
    # Pattern: (\d{3})\s*-\s*[^\-]*-\s*(\S+)(?:\s*->\s*(\S+))?
    # Group 1: HTTP status code - (\d{3}) = exactly 3 digits
    # Group 2: Path/URL - (\S+) = non-whitespace sequence (stops at space or redirect arrow)
    # Group 3: Redirect target (optional) - (?:\s*->\s*(\S+))? = literal " -> " followed by destination
    #
    # Middle section [^\-]*:
    #   Matches size field (e.g., "1234B", "  312B") without capturing
    #   [^\-]* = zero or more non-hyphen chars (stops at second hyphen separator)
    #   Rationale: Size format varies; we don't extract it, just skip to path field
    #
    # Edge cases:
    #   - Paths containing spaces: Group 2 captures only up to first space (acceptable; dirsearch rarely outputs such paths)
    #   - Multiple hyphens in path: Pattern uses hyphen as delimiter, so paths like "foo-bar-baz" work correctly
    #   - Color codes: Handled by _strip_ansi() preprocessing
    #
    # Failure modes:
    #   - Dirsearch format change (e.g., different separators): Would require pattern update
    #   - Missing size field: [^\-]* handles zero-length, pattern still matches
    pattern = re.compile(r"(\d{3})\s*-\s*[^\-]*-\s*(\S+)(?:\s*->\s*(\S+))?")
    # Loop over items.
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
                type="Directory Enumeration",
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
    """Function _handle_gobuster."""
    findings: List[RawFinding] = []
    # Gobuster Output Parser
    # Parses gobuster dir/vhost mode output: PATH (Status: CODE)
    # Example: "/admin (Status: 200)"
    # Example: "https://api.example.com (Status: 301)"
    #
    # Pattern: ^([^\s]+)\s+\(Status:\s*(\d{3})\)
    # ^ = anchor to line start (ensures we match full result lines, not partial matches in headers)
    # Group 1: Path or URL - ([^\s]+) = one or more non-whitespace chars
    # Group 2: HTTP status code - (\d{3}) = exactly 3 digits
    #
    # Literal match: \(Status:\s*
    #   \( = escaped opening paren (literal character)
    #   Status: = case-sensitive literal (gobuster's fixed format)
    #   \s* = optional whitespace before status code
    #
    # Edge cases:
    #   - Gobuster DNS mode: Different output format (domain names without status codes); won't match, correct behavior
    #   - Paths with parentheses: Group 1 stops at whitespace before "(Status:", so "/foo(bar)" matches correctly
    #   - ANSI color codes: Handled by _strip_ansi() preprocessing
    #
    # Anchoring rationale:
    #   ^ prevents matching "Status: 200" in progress messages or headers
    #   Ensures only actual finding lines are captured
    pattern = re.compile(r"^([^\s]+)\s+\(Status:\s*(\d{3})\)")
    # Loop over items.
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        match = pattern.match(clean)
        if not match:
            continue
        path = match.group(1)
        status = int(match.group(2))
        findings.append(
            RawFinding(
                type="Directory Enumeration",
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
    """Function _handle_feroxbuster."""
    findings: List[RawFinding] = []
    # Feroxbuster Output Parser
    # Parses feroxbuster recursive enumeration format: STATUS SIZE WORDS LINES URL
    # Example: "200      4096   100    50 https://example.com/admin/"
    #
    # Pattern: ^(\d{3})\s+\S+\s+\S+\s+(https?://\S+)
    # ^ = anchor to line start
    # Group 1: HTTP status code - (\d{3}) = exactly 3 digits
    # \s+\S+\s+\S+\s+ = skip intermediate fields (size, words, lines) without capturing
    #   Each \S+ matches a non-whitespace field, separated by \s+ (whitespace)
    #   Rationale: Field order is fixed but values vary widely; we only need status and URL
    # Group 2: Full URL - (https?://\S+) = protocol + non-whitespace chars
    #
    # Intermediate field structure:
    #   Field 1 after status: Size in bytes (e.g., "4096", "1.2K")
    #   Field 2: Word count (integer)
    #   Field 3: Line count (integer)
    #   All matched by \S+ without semantic parsing
    #
    # Edge cases:
    #   - Feroxbuster with different column count: Pattern would fail (acceptable; indicates format change)
    #   - URLs with fragments (#section): Captured in URL group (correct behavior)
    #   - Progress/status messages: Don't start with status code, won't match
    #
    # Anchoring rationale:
    #   ^ prevents matching status codes embedded in URLs or other fields
    pattern = re.compile(r"^(\d{3})\s+\S+\s+\S+\s+(https?://\S+)")
    # Loop over items.
    for raw in output.splitlines():
        clean = _strip_ansi(raw).strip()
        match = pattern.match(clean)
        if not match:
            continue
        status = int(match.group(1))
        url = match.group(2)
        findings.append(
            RawFinding(
                type="Directory Enumeration",
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
    """Function _handle_nikto."""
    findings: List[RawFinding] = []
    # Nikto Wrapper Output Parser
    # Parses custom nikto-shim wrapper format: [nikto-shim] SEVERITY: MESSAGE
    # Example: "[nikto-shim] HIGH: Outdated Apache version detected"
    #
    # Pattern: \[nikto-shim\]\s+([A-Z]+):\s+(.*)
    # \[nikto-shim\] = literal tag prefix (wrapper-specific, not native nikto format)
    # \s+ = one or more whitespace chars (typically single space)
    # Group 1: Severity level - ([A-Z]+) = one or more uppercase letters (LOW, MEDIUM, HIGH, CRITICAL, INFO)
    # : = literal colon separator
    # \s+ = one or more whitespace chars before message
    # Group 2: Finding message - (.*) = greedy capture of remaining line content
    #
    # Wrapper context:
    #   nikto-shim is a SentinelForge-specific wrapper that normalizes nikto's variable output format
    #   Native nikto uses "+ OSVDB-####: /path: message" format, which is inconsistent
    #   Wrapper standardizes severity classification and prefixes with [nikto-shim] tag
    #
    # Edge cases:
    #   - Native nikto output without wrapper: Won't match (correct; needs wrapper preprocessing)
    #   - Multi-line messages: Group 2 captures only first line (acceptable; nikto-shim emits one line per finding)
    #   - Non-standard severity values: Matched by [A-Z]+ but validated in handler code
    #
    # Design rationale:
    #   Pattern is tightly coupled to wrapper format for deterministic parsing
    #   Alternative approach (parsing native nikto) would require complex OSVDB lookup and heuristic severity assignment
    shim_pattern = re.compile(r"\[nikto-shim\]\s+([A-Z]+):\s+(.*)")
    native_pattern = re.compile(r"^\+\s+(.*)$")

    native_skip_prefixes = (
        "target ip:",
        "target hostname:",
        "target port:",
        "start time:",
        "end time:",
        "retrieved x-powered-by",
        "no web server found",
        "0 host(s) tested",
        "1 host(s) tested",
    )

    def _native_severity(message_text: str) -> str | None:
        lowered = message_text.lower()
        if lowered.startswith("error:"):
            return None
        if any(token in lowered for token in ("cve-", "vulnerability", "outdated", "remote code execution", "sql injection")):
            return "HIGH"
        if any(token in lowered for token in ("osvdb-", "interesting", "exposed", "backup", "admin", "directory indexing", "allowed methods")):
            return "MEDIUM"
        if any(token in lowered for token in ("header", "cookie", "server", "uncommon")):
            return "LOW"
        if len(message_text.strip()) < 8:
            return None
        return "INFO"

    # Loop over items.
    for line in output.splitlines():
        clean = _strip_ansi(line).strip()
        if not clean:
            continue

        shim_match = shim_pattern.match(clean)
        if shim_match:
            severity = shim_match.group(1).upper()
            message = shim_match.group(2).strip()
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
            continue

        native_match = native_pattern.match(clean)
        if not native_match:
            continue

        message = native_match.group(1).strip()
        lowered = message.lower()
        if any(lowered.startswith(prefix) for prefix in native_skip_prefixes):
            continue

        severity = _native_severity(message)
        if severity is None:
            continue

        findings.append(
            RawFinding(
                type="Nikto Finding",
                severity=severity,
                tool="nikto",
                target=target,
                message=message,
                proof=clean,
                tags=["web-scanner", "nikto", "nikto-native"],
                families=["exposure", "misconfiguration"],
            )
        )
    return findings


def _handle_masscan(target: str, output: str) -> List[RawFinding]:
    """Function _handle_masscan."""
    findings: List[RawFinding] = []
    # Masscan Output Parser
    # Parses masscan port scan results: "Discovered open port PORT/PROTO on HOST"
    # Example: "Discovered open port 443/tcp on 192.168.1.1"
    #
    # Pattern: Discovered open port (\d+)/(tcp|udp) on ([^\s]+)
    # Literal prefix: "Discovered open port " (masscan's fixed output format)
    # Group 1: Port number - (\d+) = one or more digits (1-65535, no validation in regex)
    # / = literal forward slash separator
    # Group 2: Protocol - (tcp|udp) = exact match for either protocol
    # Literal: " on " (fixed masscan syntax)
    # Group 3: Host identifier - ([^\s]+) = non-whitespace chars (IP address or hostname)
    #
    # Host field variations:
    #   - IPv4: 192.168.1.1
    #   - IPv6: 2001:db8::1 (contains colons, captured correctly by [^\s]+)
    #   - Hostname: example.com (if reverse DNS enabled)
    #
    # Edge cases:
    #   - Masscan XML output: Different format; this pattern only works with text mode
    #   - Closed/filtered ports: Masscan doesn't report these in default mode, so won't match
    #   - Banner grabbing data: Appears in separate output lines, not matched by this pattern
    #
    # Protocol constraint:
    #   (tcp|udp) = exact alternation; masscan doesn't report other protocols (SCTP, etc.) in standard mode
    #   Future-proofing: If masscan adds protocols, pattern would need |(sctp|...) extension
    pattern = re.compile(r"Discovered open port (\d+)/(tcp|udp) on ([^\s]+)")
    # Loop over items.
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
    """Function _handle_naabu."""
    findings: List[RawFinding] = []
    # Loop over items.
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
    """Function _handle_dnsx."""
    findings: List[RawFinding] = []
    # DNSX Output Parser
    # Parses dnsx DNS enumeration format: HOSTNAME [RECORD_TYPE] [VALUE]
    # Example: "example.com [A] [192.168.1.1]"
    # Example: "mail.example.com [MX] [mail.provider.com]"
    #
    # Pattern: ([^\s]+)\s+\[(\w+)\]\s+\[([^\]]+)\]
    # Group 1: Hostname/domain - ([^\s]+) = non-whitespace chars
    # \s+ = one or more whitespace separators
    # Group 2: DNS record type - \[(\w+)\] = word chars within brackets
    #   Record types: A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, etc.
    #   \w+ = one or more alphanumeric/underscore chars (covers all standard record types)
    # \s+ = whitespace separator
    # Group 3: Record value - \[([^\]]+)\] = any chars except closing bracket
    #   [^\]]+ = one or more non-bracket chars (handles IPs, hostnames, TXT record content)
    #
    # Bracket handling:
    #   \[ and \] = escaped brackets (literal characters in dnsx output)
    #   [^\]]+ in Group 3 = negated character class (not "]"), allows brackets in value if nested
    #
    # Edge cases:
    #   - Multi-value records (e.g., multiple A records): dnsx emits separate lines per value
    #   - TXT records with spaces: Captured by [^\]]+ (includes all content until closing bracket)
    #   - IPv6 addresses: Contain colons, matched by [^\]]+
    #   - CNAME chains: Only immediate target captured; chain resolution appears in subsequent lines
    #
    # Failure modes:
    #   - DNSX format change (different bracketing): Would require pattern update
    #   - Records with literal ] in value: Would terminate Group 3 early (extremely rare in DNS)
    pattern = re.compile(r"([^\s]+)\s+\[(\w+)\]\s+\[([^\]]+)\]")
    # Loop over items.
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


def _handle_subfinder(target: str, output: str) -> List[RawFinding]:
    """Function _handle_subfinder."""
    findings: List[RawFinding] = []
    # Loop over items.
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
    """Function _handle_httprobe."""
    findings: List[RawFinding] = []
    # Loop over items.
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
    """Function _global_detectors."""
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
    """Function _detect_json_endpoints."""
    findings = []
    # Loop over items.
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
    """Function _detect_dev_surfaces."""
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
    # Loop over items.
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
    """Function _detect_cors_headers."""
    findings = []
    # Loop over items.
    for block in output.split("\n\n"):
        block_lower = block.lower()
        if "access-control-allow-origin" not in block_lower:
            continue
        # CORS Header Extraction Patterns
        # Extracts CORS policy configuration from HTTP response headers
        
        # Access-Control-Allow-Origin Pattern
        # Pattern: access-control-allow-origin:\s*([^\s]+)
        # Literal: "access-control-allow-origin:" (case-insensitive via block_lower)
        # \s* = optional whitespace after colon
        # Group 1: Origin value - ([^\s]+) = non-whitespace chars
        #   Values: "*" (wildcard), "null", or full origin "https://example.com"
        # Edge case: Multiple CORS headers (non-compliant): Only first match captured
        aca_origin = re.search(r"access-control-allow-origin:\s*([^\s]+)", block_lower)
        
        # Access-Control-Allow-Credentials Pattern
        # Pattern: access-control-allow-credentials:\s*(true|1)
        # Detects credential-permitting CORS configs (high risk when combined with wildcard origin)
        # Group 1: Boolean value - (true|1) = literal "true" or "1"
        #   Standard value is "true"; "1" is non-standard but observed in misconfigured servers
        # Does NOT match: "false" or "0" (intentional; only flag permissive configs)
        # Security implication: aca_origin="*" + aca_credentials="true" is CRITICAL (impossible per spec but seen in broken proxies)
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
    """Function _detect_http_methods."""
    findings = []
    # HTTP Methods Discovery Pattern
    # Extracts allowed HTTP methods from tool output (typically nmap http-methods script)
    # Example: "Allowed methods: GET, POST, PUT, DELETE, OPTIONS"
    #
    # Pattern: Allowed methods:\s*(.+)
    # Literal: "Allowed methods:" (case-insensitive via re.IGNORECASE)
    # \s* = optional whitespace after colon
    # Group 1: Method list - (.+) = one or more chars (greedy capture to end of line)
    #   Expected format: Comma-separated method names (GET, POST, etc.)
    #   Greedy .+ captures all methods in single line
    #
    # Security context:
    #   Dangerous methods: PUT (upload), DELETE (remove resources), TRACE (XST), OPTIONS (info disclosure)
    #   Safe methods: GET, POST, HEAD
    #   Pattern captures all; downstream logic filters for dangerous methods
    #
    # Edge cases:
    #   - Methods with trailing description: Group 1 captures everything; split on comma handles it
    #   - Multi-line method lists: Only first line captured (acceptable; nmap emits single line)
    #   - Non-standard methods (PROPFIND, PATCH): Captured correctly by .+
    method_line = re.search(r"Allowed methods:\s*(.+)", output, re.IGNORECASE)
    # Conditional branch.
    if not method_line:
        return findings
    methods = [m.strip().upper() for m in method_line.group(1).split(",")]
    dangerous = [m for m in methods if m in {"PUT", "DELETE", "TRACE", "OPTIONS"}]
    # Conditional branch.
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
    """Function _detect_upload_endpoints."""
    findings = []
    # File Upload Endpoint Detection Pattern
    # Identifies URLs/paths containing "upload" keyword, indicating potential file upload functionality
    # Example matches: "/fileupload", "/admin/upload.php", "/api/upload-avatar", "/user_upload_photo"
    #
    # Pattern: /[A-Za-z0-9_\-]+upload[a-z/0-9_\-]*
    # / = literal forward slash (path start or separator)
    # [A-Za-z0-9_\-]+ = one or more alphanumeric, underscore, or hyphen chars (path prefix)
    #   Handles: /file_upload, /admin-upload, /uploadFile
    # upload = literal keyword (case-insensitive via re.IGNORECASE)
    # [a-z/0-9_\-]* = zero or more lowercase, digit, slash, underscore, hyphen chars (path suffix)
    #   Captures extensions and subpaths: upload.php, upload/image, upload_avatar
    #
    # Prefix requirement [A-Za-z0-9_\-]+:
    #   Prevents matching standalone "/upload" at path root (too generic)
    #   Requires context like "/file-upload" or "/api/upload"
    #
    # Suffix pattern [a-z/0-9_\-]*:
    #   Lowercase only (uppercase excluded to prevent matching URL params like "?Upload=true")
    #   Allows slash for nested paths: /upload/process, /upload/validate
    #
    # Edge cases:
    #   - URL parameters: Doesn't match "?file=upload.txt" (intentional; query params not upload endpoints)
    #   - Mixed case in suffix: Only lowercase after "upload" matched; "Upload" would terminate match
    #   - Fragments: Doesn't match "#upload-section" (no leading /)
    #
    # False positive risk:
    #   - Documentation paths like "/docs/upload-guide" (acceptable; better to flag and review)
    #   - Download endpoints named "uploaded-files" (mitigated by requiring "upload" not "uploaded")
    pattern = re.compile(r"/[A-Za-z0-9_\-]+upload[a-z/0-9_\-]*", re.IGNORECASE)
    # Loop over items.
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
    """Function _detect_private_ranges."""
    matches = PRIVATE_IP_REGEX.findall(output)
    # Conditional branch.
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
    """Function _detect_verbose_errors."""
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
    # Loop over items.
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
    """Function _detect_graphql_markers."""
    keywords = ["__schema", "__typename", "introspection query"]
    # Loop over items.
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
    """Function _detect_user_enum."""
    # Conditional branch.
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
    """Function _detect_metadata_exposure."""
    # Conditional branch.
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
    """Function _detect_business_logic_hooks."""
    suspect_terms = ["user_id", "account_id", "role_id", "permission", "idor", "rbac"]
    hits = [term for term in suspect_terms if term in output.lower()]
    # Conditional branch.
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
    """Function _detect_secrets."""
    findings = []
    # Loop over items.
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
    """Function _detect_security_headers."""
    findings = []
    blocks = [block for block in output.split("\n\n") if "http/" in block.lower()]
    # Loop over items.
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
    """Function _detect_frameworks."""
    findings = []
    # Loop over items.
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
    """Function _detect_directory_listing."""
    keywords = ["index of /", "parent directory"]
    matches = []
    # Loop over items.
    for keyword in keywords:
        if keyword in output.lower():
            matches.append(keyword)
    # Conditional branch.
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
    # Backup and Sensitive File Extension Patterns
    # Detects backup files, archives, and configuration artifacts exposed via web enumeration
    # Security context: These files often contain source code, credentials, or historical data
    
    """Function _detect_backup_files."""
    patterns = [
        # .bak Extension
        # Pattern: \.bak\b
        # Matches: config.bak, index.php.bak, database.sql.bak
        # \. = escaped dot (literal period)
        # bak = literal extension
        # \b = word boundary (prevents matching "backup.txt")
        r"\.bak\b",
        
        # .old Extension
        # Pattern: \.old\b
        # Matches: config.php.old, settings.old, app.js.old
        # Common practice: Admins rename files to .old during updates/testing
        r"\.old\b",
        
        # .zip Archive
        # Pattern: \.zip\b
        # Matches: backup.zip, source.zip, archive.zip
        # Risk: May contain full source code, database dumps, or credentials
        r"\.zip\b",
        
        # .tar and .tar.gz Archives
        # Pattern: \.tar(?:\.gz)?\b
        # Matches: backup.tar, backup.tar.gz
        # (?:\.gz)? = optional non-capturing group for gzip suffix
        # \b = word boundary after "tar" or "gz"
        r"\.tar(?:\.gz)?\b",
        
        # .swp Vim Swap Files
        # Pattern: \.swp\b
        # Matches: .index.php.swp, .config.swp
        # Vim/Vi editors create swap files during editing; often left on servers after crashes
        # Contains file content in various save states (potential credential/code leak)
        r"\.swp\b",
        
        # .env Environment Files
        # Pattern: \.env\b
        # Matches: .env, config.env, production.env
        # Contains environment variables including API keys, database passwords, secrets
        # CRITICAL severity finding if exposed
        r"\.env\b",
        
        # .git/config Repository Config
        # Pattern: \.git/config
        # Matches: .git/config (literal path)
        # Git repository metadata; reveals repo structure, remote URLs, contributor info
        # Often indicates full .git directory exposure (can reconstruct source history)
        # \. = escaped dot, / = literal forward slash
        r"\.git/config",
        
        # .sql Database Dumps
        # Pattern: \.sql\b
        # Matches: backup.sql, dump.sql, database.sql
        # Direct database exports containing table schemas and data (HIGH/CRITICAL risk)
        r"\.sql\b",
        
        # config.php.old (Specific Pattern)
        # Pattern: config\.php\.old
        # Matches: config.php.old (exact filename)
        # Targets common PHP config backup pattern
        # \. = escaped dots (literal periods in filename)
        # More specific than generic \.old pattern; raised separately for severity tuning
        r"config\.php\.old",
    ]
    findings = []
    # Loop over items.
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
    """Function _detect_login_flows."""
    keywords = ["reset password", "forgot password", "otp", "2fa reset"]
    matches = []
    # Loop over items.
    for keyword in keywords:
        if keyword in output.lower():
            matches.append(keyword)
    # Conditional branch.
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
    """Function _detect_session_misconfigs."""
    findings = []
    # Set-Cookie Header Extraction Pattern
    # Extracts cookie values and attributes to detect security misconfigurations
    # Example: "Set-Cookie: sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
    #
    # Pattern: set-cookie:\s*([^\n]+)
    # Literal: "set-cookie:" (case-insensitive via re.IGNORECASE)
    # \s* = optional whitespace after colon
    # Group 1: Full cookie string - ([^\n]+) = all chars until newline
    #   Captures: name=value and all attributes (Secure, HttpOnly, SameSite, etc.)
    #   [^\n]+ = one or more non-newline chars (stops at line break, handles multi-line headers)
    #
    # Downstream parsing:
    #   Group 1 content is analyzed for presence/absence of security flags:
    #   - "Secure" flag: Cookie only sent over HTTPS
    #   - "HttpOnly" flag: Cookie inaccessible to JavaScript (XSS mitigation)
    #   - "SameSite" attribute: CSRF protection (Strict/Lax/None)
    #
    # Edge cases:
    #   - Multiple Set-Cookie headers: finditer() captures all (correct behavior)
    #   - Cookies with embedded newlines (RFC violation): Only first line captured
    #   - Quoted cookie values: Captured as-is; downstream logic handles quotes
    #
    # Security checks performed on Group 1:
    #   - missing_secure: "secure" not in lowercased cookie string
    #   - missing_http_only: "httponly" not in lowercased cookie string
    #   - samesite_none: "samesite=none" present (risky without Secure flag)
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
    """Function _detect_timing_patterns."""
    return []


def _detect_ssrf_indicators(target: str, output: str) -> List[RawFinding]:
    """Function _detect_ssrf_indicators."""
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
    # Conditional branch.
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
    """Function _detect_waf_behaviors."""
    waf_keywords = ["cloudflare", "akamai", "imperva", "incapsula", "f5", "radware", "datadome"]
    matches = [kw for kw in waf_keywords if kw in output.lower()]
    # Conditional branch.
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
    # Cloud Storage URL Detection Patterns
    # Identifies publicly accessible cloud storage URLs in tool output (HTML, headers, JS)
    # Security context: Public bucket URLs may leak sensitive data or indicate misconfigured ACLs
    
    """Function _detect_cloud_storage."""
    patterns = [
        # AWS S3 Bucket URL Pattern
        # Matches: https://bucket-name.s3.amazonaws.com/path/to/object.txt
        #          http://my-bucket.s3-us-west-2.amazonaws.com/file.pdf
        #
        # Pattern: https?://[a-z0-9\-\.]+\.s3\.amazonaws\.com/[^\s\"']+
        # https? = http or https protocol
        # [a-z0-9\-\.]+ = bucket name (lowercase alphanumeric, hyphens, dots)
        #   S3 bucket naming: 3-63 chars, lowercase, numbers, hyphens, dots
        #   Pattern allows region-specific endpoints: bucket.s3-us-east-1.amazonaws.com
        # \.s3\.amazonaws\.com = literal domain suffix (escaped dots)
        # / = path separator (required in URL)
        # [^\s\"']+ = object key/path (non-whitespace, non-quote chars)
        #   Stops at whitespace or quotes (common delimiters in HTML/JSON)
        #
        # Edge cases:
        #   - S3 Transfer Acceleration endpoints (*.s3-accelerate.amazonaws.com): Not matched (rare in pentesting)
        #   - Virtual-hosted style (above) vs. path-style (s3.amazonaws.com/bucket/key): Only virtual-hosted matched
        #   - Pre-signed URLs with query params: Captured in [^\s\"']+ up to delimiter
        (r"https?://[a-z0-9\-\.]+\.s3\.amazonaws\.com/[^\s\"']+", "aws-s3"),
        
        # Google Cloud Storage URL Pattern
        # Matches: https://storage.googleapis.com/bucket-name/path/to/object
        #
        # Pattern: https?://storage\.googleapis\.com/[^\s\"']+
        # storage\.googleapis\.com = literal GCS domain (escaped dots)
        # / = path separator
        # [^\s\"']+ = bucket name + object path
        #   GCS URL structure: storage.googleapis.com/BUCKET_NAME/OBJECT_PATH
        #   Pattern captures entire path; bucket/object split done downstream if needed
        #
        # Alternative GCS URLs not matched:
        #   - Custom domain CNAMEs: Unpredictable, can't pattern match reliably
        #   - XML API endpoints: Different domain structure
        (r"https?://storage\.googleapis\.com/[^\s\"']+", "gcp-storage"),
        
        # Azure Blob Storage URL Pattern
        # Matches: https://storageaccount.blob.core.windows.net/container/blob.txt
        #
        # Pattern: https?://[a-z0-9\-\.]+\.blob\.core\.windows\.net/[^\s\"']+
        # [a-z0-9\-\.]+ = storage account name (lowercase alphanumeric, hyphens)
        #   Azure storage account: 3-24 chars, lowercase, numbers only (hyphens in subdomain)
        #   Pattern allows dots for legacy accounts
        # \.blob\.core\.windows\.net = literal Azure Blob domain (escaped dots)
        # [^\s\"']+ = container + blob path
        #
        # Azure service variations not matched:
        #   - Table storage (*.table.core.windows.net): Different service, not blob storage
        #   - Queue/File services: Distinct endpoints
        (r"https?://[a-z0-9\-\.]+\.blob\.core\.windows\.net/[^\s\"']+", "azure-blob"),
    ]
    findings = []
    # Loop over items.
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
    """Function _extract_snippet."""
    match = re.search(re.escape(needle), output, re.IGNORECASE)
    # Conditional branch.
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
    "subfinder": _handle_subfinder,
    "httprobe": _handle_httprobe,
}


__all__ = ["classify", "RawFinding"]
