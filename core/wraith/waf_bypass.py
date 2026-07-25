"""
WAF Fingerprint-to-Bypass Matrix with Adaptive Selection

This module provides deterministic WAF detection and bypass technique selection
using an adaptive multi-armed bandit approach. No random mutations — structured,
feedback-driven bypass selection.

Author: SentinelForge
License: Apache 2.0
"""

import logging
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests


logger = logging.getLogger(__name__)


class VulnerabilityClass(Enum):
    """Vulnerability classes that require WAF bypass."""
    SQLi = "sqli"
    XXE = "xxe"
    SSRF = "ssrf"
    RCE = "rce"
    XSS = "xss"
    LDAP = "ldap"
    XPATH = "xpath"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"


class EncodingType(Enum):
    """Types of encoding transformations."""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    HTML = "html"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    CASE_VARIATION = "case_variation"
    MIXED_CASE = "mixed_case"


@dataclass
class WAFFingerprint:
    """Represents identified WAF characteristics."""
    name: str
    version: Optional[str]
    confidence: float  # 0.0 to 1.0
    detection_source: str  # "header", "body_pattern", "status_code", etc.
    detected_at: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        return (
            f"WAFFingerprint(name={self.name}, version={self.version}, "
            f"confidence={self.confidence:.2f}, source={self.detection_source})"
        )


@dataclass
class BypassTechnique:
    """Represents a WAF bypass technique."""
    id: str  # Unique identifier (e.g., "modsecurity_case_variation")
    name: str  # Human-readable name
    description: str
    encoder_func: Optional[Callable[[str], str]]  # None means pass-through
    applicable_wafs: List[str]  # ["ModSecurity", "Cloudflare", "*"]
    applicable_vulns: List[VulnerabilityClass]
    encoding_type: EncodingType
    complexity: int  # 1-10, higher = more complex transformation

    def encode(self, payload: str) -> str:
        """Apply encoding transformation to payload."""
        if self.encoder_func:
            return self.encoder_func(payload)
        return payload

    def is_applicable(self, waf_name: str, vuln_class: VulnerabilityClass) -> bool:
        """Check if technique is applicable to WAF and vulnerability type."""
        waf_matches = "*" in self.applicable_wafs or waf_name in self.applicable_wafs
        vuln_matches = vuln_class in self.applicable_vulns
        return waf_matches and vuln_matches


@dataclass
class BanditArm:
    """Represents a single arm in the multi-armed bandit."""
    technique_id: str
    attempts: int = 0
    successes: int = 0
    last_attempt: Optional[float] = None
    success_history: List[bool] = field(default_factory=list)  # Last N attempts
    confidence: float = 0.5

    def update_result(self, success: bool, max_history: int = 100) -> None:
        """Update arm with new result."""
        self.attempts += 1
        if success:
            self.successes += 1
        self.last_attempt = time.time()
        self.success_history.append(success)

        # Keep sliding window of recent attempts
        if len(self.success_history) > max_history:
            self.success_history.pop(0)

        # Update confidence with sliding window average
        if self.success_history:
            self.confidence = sum(self.success_history) / len(self.success_history)

    def get_success_rate(self) -> float:
        """Get recent success rate (sliding window)."""
        if not self.success_history:
            return 0.0
        return sum(self.success_history) / len(self.success_history)

    def get_ucb1_score(self, total_attempts: int, exploration_param: float = 1.41) -> float:
        """Calculate Upper Confidence Bound (UCB1) score for this arm."""
        if self.attempts == 0:
            return float("inf")  # Unexplored arms have highest priority

        exploitation = self.confidence
        exploration = exploration_param * math.sqrt(math.log(total_attempts) / self.attempts)
        return exploitation + exploration


class WAFDetector:
    """Detects WAF from HTTP responses."""

    # Fingerprinting patterns: (pattern, waf_name, confidence, detection_source)
    DETECTION_PATTERNS = [
        # ModSecurity patterns
        (
            re.compile(r"modsecurity|mod_security", re.IGNORECASE),
            "ModSecurity",
            0.95,
            "header",
        ),
        (
            re.compile(r"Your request has been blocked", re.IGNORECASE),
            "ModSecurity",
            0.70,
            "body",
        ),
        # Cloudflare patterns
        (
            re.compile(r"Cloudflare", re.IGNORECASE),
            "Cloudflare",
            0.99,
            "header",
        ),
        (
            re.compile(r"error code: \d{3,4}", re.IGNORECASE),
            "Cloudflare",
            0.75,
            "body",
        ),
        # AWS WAF patterns
        (
            re.compile(r"AWS WAF|waf-token", re.IGNORECASE),
            "AWS WAF",
            0.95,
            "header",
        ),
        # Akamai patterns
        (
            re.compile(r"akamai", re.IGNORECASE),
            "Akamai",
            0.85,
            "header",
        ),
        # Imperva/Distil patterns
        (
            re.compile(r"imperva|distil", re.IGNORECASE),
            "Imperva",
            0.80,
            "header",
        ),
        # F5 patterns
        (
            re.compile(r"f5|big-ip", re.IGNORECASE),
            "F5 BIG-IP",
            0.85,
            "header",
        ),
        # Barracuda patterns
        (
            re.compile(r"barracuda", re.IGNORECASE),
            "Barracuda",
            0.80,
            "header",
        ),
        # Fortinet patterns
        (
            re.compile(r"fortinet|fortigate", re.IGNORECASE),
            "Fortinet FortiWAF",
            0.80,
            "header",
        ),
    ]

    # Status code patterns
    STATUS_CODE_PATTERNS = {
        403: ("Generic WAF", 0.60, "403 Forbidden"),
        406: ("Generic WAF", 0.65, "406 Not Acceptable"),
        419: ("Generic WAF", 0.60, "419 (suspicious status)"),
        429: ("Rate Limiter", 0.70, "429 Too Many Requests"),
        444: ("Generic WAF", 0.55, "444 (closed connection)"),
    }

    def __init__(self):
        """Initialize WAF detector."""
        self.fingerprints_cache: Dict[str, WAFFingerprint] = {}

    def detect_from_response(
        self,
        response: requests.Response,
        body_content: Optional[str] = None,
    ) -> Optional[WAFFingerprint]:
        """
        Detect WAF from HTTP response.

        Args:
            response: requests.Response object
            body_content: Optional response body content

        Returns:
            WAFFingerprint if detected, None otherwise
        """
        candidates = []

        # Check headers
        headers_text = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        for pattern, waf_name, confidence, source in self.DETECTION_PATTERNS:
            if pattern.search(headers_text):
                candidates.append((waf_name, confidence, source))

        # Check body
        if body_content:
            for pattern, waf_name, confidence, source in self.DETECTION_PATTERNS:
                if pattern.search(body_content):
                    candidates.append((waf_name, confidence, source))

        # Check status code
        if response.status_code in self.STATUS_CODE_PATTERNS:
            waf_name, confidence, source = self.STATUS_CODE_PATTERNS[response.status_code]
            candidates.append((waf_name, confidence, source))

        if not candidates:
            return None

        # Select highest confidence match
        best = max(candidates, key=lambda x: x[1])
        waf_name, confidence, source = best

        fingerprint = WAFFingerprint(
            name=waf_name,
            version=self._extract_version(headers_text),
            confidence=confidence,
            detection_source=source,
        )

        logger.info(f"Detected WAF: {fingerprint}")
        self.fingerprints_cache[waf_name] = fingerprint
        return fingerprint

    @staticmethod
    def _extract_version(text: str) -> Optional[str]:
        """Extract version information from response."""
        version_pattern = r"(?:modsecurity|cloudflare|aws.*?waf).*?(?:v|version|/)\s*(\d+\.\d+)"
        match = re.search(version_pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None


class BypassMatrix:
    """Maps (WAF type, vulnerability class) to applicable bypass techniques."""

    # Encoder functions
    @staticmethod
    def _url_encode(payload: str) -> str:
        """URL encode the payload."""
        from urllib.parse import quote
        return quote(payload, safe="")

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Double URL encode the payload."""
        from urllib.parse import quote
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def _html_encode(payload: str) -> str:
        """HTML entity encode the payload."""
        import html
        return html.escape(payload)

    @staticmethod
    def _hex_encode(payload: str) -> str:
        """Hex encode the payload."""
        return "0x" + payload.encode().hex()

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        """Unicode normalization (NFD)."""
        import unicodedata
        return unicodedata.normalize("NFKD", payload)

    @staticmethod
    def _base64_encode(payload: str) -> str:
        """Base64 encode the payload."""
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def _case_variation(payload: str) -> str:
        """Random case variation."""
        import random
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    @staticmethod
    def _mixed_case(payload: str) -> str:
        """Alternate case pattern."""
        return "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)
        )

    @staticmethod
    def _comment_injection(payload: str) -> str:
        """Insert comments in payload (SQL context)."""
        parts = payload.split(" ")
        return "/**/".join(parts)

    @staticmethod
    def _whitespace_variation(payload: str) -> str:
        """Replace spaces with tabs/newlines."""
        return payload.replace(" ", "\t")

    def __init__(self):
        """Initialize bypass matrix with built-in techniques."""
        self.techniques = self._build_techniques()

    def _build_techniques(self) -> List[BypassTechnique]:
        """Build comprehensive bypass technique list."""
        techniques = [
            # ModSecurity-specific techniques
            BypassTechnique(
                id="modsecurity_case_variation",
                name="Case Variation",
                description="Vary keyword casing (e.g., SELECT vs SeLeCt)",
                encoder_func=self._case_variation,
                applicable_wafs=["ModSecurity", "*"],
                applicable_vulns=[VulnerabilityClass.SQLi, VulnerabilityClass.XPATH],
                encoding_type=EncodingType.CASE_VARIATION,
                complexity=2,
            ),
            BypassTechnique(
                id="modsecurity_comment_injection",
                name="Comment Injection",
                description="Insert SQL comments between keywords",
                encoder_func=self._comment_injection,
                applicable_wafs=["ModSecurity", "*"],
                applicable_vulns=[VulnerabilityClass.SQLi],
                encoding_type=EncodingType.NONE,
                complexity=3,
            ),
            BypassTechnique(
                id="modsecurity_whitespace_variation",
                name="Whitespace Variation",
                description="Use tabs/newlines instead of spaces",
                encoder_func=self._whitespace_variation,
                applicable_wafs=["ModSecurity", "*"],
                applicable_vulns=[VulnerabilityClass.SQLi],
                encoding_type=EncodingType.NONE,
                complexity=2,
            ),
            # Cloudflare-specific techniques
            BypassTechnique(
                id="cloudflare_unicode_normalization",
                name="Unicode Normalization",
                description="Use NFD Unicode normalization for parsing bypass",
                encoder_func=self._unicode_normalize,
                applicable_wafs=["Cloudflare", "*"],
                applicable_vulns=[
                    VulnerabilityClass.XSS,
                    VulnerabilityClass.SQLi,
                    VulnerabilityClass.COMMAND_INJECTION,
                ],
                encoding_type=EncodingType.UNICODE,
                complexity=4,
            ),
            BypassTechnique(
                id="cloudflare_double_encoding",
                name="Double URL Encoding",
                description="Double URL encode special characters",
                encoder_func=self._double_url_encode,
                applicable_wafs=["Cloudflare", "AWS WAF"],
                applicable_vulns=[
                    VulnerabilityClass.XSS,
                    VulnerabilityClass.PATH_TRAVERSAL,
                ],
                encoding_type=EncodingType.DOUBLE_URL,
                complexity=3,
            ),
            # AWS WAF techniques
            BypassTechnique(
                id="aws_json_body_parsing",
                name="JSON Body Encoding",
                description="Encode payload in JSON body instead of query string",
                encoder_func=None,  # Requires context-aware encoding
                applicable_wafs=["AWS WAF", "*"],
                applicable_vulns=[VulnerabilityClass.SQLi, VulnerabilityClass.XSS],
                encoding_type=EncodingType.NONE,
                complexity=5,
            ),
            BypassTechnique(
                id="aws_url_encoding",
                name="URL Encoding",
                description="Standard URL encoding",
                encoder_func=self._url_encode,
                applicable_wafs=["AWS WAF", "*"],
                applicable_vulns=[VulnerabilityClass.XSS, VulnerabilityClass.SSRF],
                encoding_type=EncodingType.URL,
                complexity=1,
            ),
            # Generic techniques
            BypassTechnique(
                id="generic_html_encoding",
                name="HTML Entity Encoding",
                description="HTML entity encode special characters",
                encoder_func=self._html_encode,
                applicable_wafs=["*"],
                applicable_vulns=[VulnerabilityClass.XSS],
                encoding_type=EncodingType.HTML,
                complexity=2,
            ),
            BypassTechnique(
                id="generic_hex_encoding",
                name="Hex Encoding",
                description="Hex encode the payload",
                encoder_func=self._hex_encode,
                applicable_wafs=["*"],
                applicable_vulns=[VulnerabilityClass.SQLi, VulnerabilityClass.COMMAND_INJECTION],
                encoding_type=EncodingType.HEX,
                complexity=4,
            ),
            BypassTechnique(
                id="generic_base64",
                name="Base64 Encoding",
                description="Base64 encode for RCE payloads",
                encoder_func=self._base64_encode,
                applicable_wafs=["*"],
                applicable_vulns=[VulnerabilityClass.RCE, VulnerabilityClass.COMMAND_INJECTION],
                encoding_type=EncodingType.BASE64,
                complexity=3,
            ),
            BypassTechnique(
                id="generic_mixed_case",
                name="Alternating Case",
                description="Alternate upper/lower case characters",
                encoder_func=self._mixed_case,
                applicable_wafs=["*"],
                applicable_vulns=[VulnerabilityClass.SQLi, VulnerabilityClass.XSS],
                encoding_type=EncodingType.MIXED_CASE,
                complexity=2,
            ),
        ]
        return techniques

    def get_techniques_for(
        self,
        waf_name: str,
        vuln_class: VulnerabilityClass,
    ) -> List[BypassTechnique]:
        """
        Get applicable bypass techniques for a WAF and vulnerability class.

        Args:
            waf_name: Name of detected WAF
            vuln_class: Vulnerability class

        Returns:
            List of applicable techniques, sorted by complexity
        """
        applicable = [
            t for t in self.techniques if t.is_applicable(waf_name, vuln_class)
        ]
        return sorted(applicable, key=lambda t: t.complexity)


class AdaptiveBandit:
    """Multi-armed bandit for adaptive bypass technique selection."""

    def __init__(self, max_history: int = 100, exploration_param: float = 1.41):
        """
        Initialize adaptive bandit.

        Args:
            max_history: Maximum number of historical attempts to keep per arm
            exploration_param: Exploration parameter for UCB1 calculation
        """
        self.max_history = max_history
        self.exploration_param = exploration_param
        self.arms: Dict[str, BanditArm] = {}
        self.total_pulls = 0

    def initialize_arm(self, technique_id: str) -> None:
        """Initialize a new arm for a bypass technique."""
        if technique_id not in self.arms:
            self.arms[technique_id] = BanditArm(technique_id=technique_id)

    def select_next(self, available_techniques: List[str]) -> Optional[str]:
        """
        Select next technique to try using UCB1 algorithm.

        Args:
            available_techniques: List of technique IDs to choose from

        Returns:
            Selected technique ID, or None if list is empty
        """
        if not available_techniques:
            return None

        # Initialize any unknown techniques
        for technique_id in available_techniques:
            self.initialize_arm(technique_id)

        # Calculate UCB1 scores
        scores = {
            tid: self.arms[tid].get_ucb1_score(
                self.total_pulls,
                self.exploration_param,
            )
            for tid in available_techniques
        }

        # Select technique with highest score
        selected = max(scores.items(), key=lambda x: x[1])[0]
        logger.debug(
            f"Bandit selected {selected} (score={scores[selected]:.3f}) "
            f"from {len(available_techniques)} options"
        )
        return selected

    def record_result(self, technique_id: str, success: bool) -> None:
        """
        Record result of a bypass attempt.

        Args:
            technique_id: ID of the technique that was attempted
            success: Whether the bypass was successful
        """
        self.initialize_arm(technique_id)
        self.arms[technique_id].update_result(success, self.max_history)
        self.total_pulls += 1
        logger.debug(f"Recorded {technique_id}: success={success}")

    def get_arm_stats(self, technique_id: str) -> Dict[str, Any]:
        """Get statistics for a specific arm."""
        if technique_id not in self.arms:
            return {}

        arm = self.arms[technique_id]
        return {
            "technique_id": technique_id,
            "attempts": arm.attempts,
            "successes": arm.successes,
            "success_rate": arm.get_success_rate(),
            "confidence": arm.confidence,
        }

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all arms."""
        return {tid: self.get_arm_stats(tid) for tid in self.arms}

    def reset(self) -> None:
        """Reset all arm statistics."""
        self.arms.clear()
        self.total_pulls = 0


class WAFBypassEngine:
    """
    Coordinates WAF detection, bypass matrix lookup, and adaptive selection.

    This is the main interface for WAF fingerprinting and bypass technique selection.
    """

    def __init__(self):
        """Initialize WAF bypass engine."""
        self.detector = WAFDetector()
        self.matrix = BypassMatrix()
        self.bandits: Dict[str, AdaptiveBandit] = {}  # Per-WAF bandit instances
        logger.info("WAFBypassEngine initialized")

    def _get_bandit_for_waf(self, waf_name: str) -> AdaptiveBandit:
        """Get or create bandit instance for a WAF."""
        if waf_name not in self.bandits:
            self.bandits[waf_name] = AdaptiveBandit()
            logger.debug(f"Created new bandit for WAF: {waf_name}")
        return self.bandits[waf_name]

    def detect_waf(
        self,
        response: requests.Response,
        body_content: Optional[str] = None,
    ) -> Optional[WAFFingerprint]:
        """
        Detect WAF from HTTP response.

        Args:
            response: HTTP response object
            body_content: Optional response body

        Returns:
            WAFFingerprint if detected, None otherwise
        """
        fingerprint = self.detector.detect_from_response(response, body_content)
        if fingerprint:
            logger.info(f"WAF detected: {fingerprint.name} ({fingerprint.confidence:.0%})")
        return fingerprint

    def get_bypass_techniques(
        self,
        waf_name: str,
        vuln_class: VulnerabilityClass,
    ) -> List[BypassTechnique]:
        """
        Get bypass techniques applicable to a WAF and vulnerability class.

        Args:
            waf_name: Name of the WAF
            vuln_class: Vulnerability class

        Returns:
            List of applicable techniques
        """
        techniques = self.matrix.get_techniques_for(waf_name, vuln_class)
        logger.debug(f"Found {len(techniques)} bypass techniques for {waf_name}/{vuln_class.value}")
        return techniques

    def select_bypass_technique(
        self,
        waf_name: str,
        vuln_class: VulnerabilityClass,
    ) -> Optional[BypassTechnique]:
        """
        Select next bypass technique to try for a WAF/vulnerability pair.

        Uses adaptive selection based on historical success rates.

        Args:
            waf_name: Name of the WAF
            vuln_class: Vulnerability class

        Returns:
            Selected BypassTechnique or None if no techniques available
        """
        techniques = self.get_bypass_techniques(waf_name, vuln_class)
        if not techniques:
            logger.warning(f"No bypass techniques available for {waf_name}/{vuln_class.value}")
            return None

        bandit = self._get_bandit_for_waf(waf_name)
        technique_ids = [t.id for t in techniques]
        selected_id = bandit.select_next(technique_ids)

        if selected_id:
            selected_technique = next(t for t in techniques if t.id == selected_id)
            logger.info(f"Selected bypass: {selected_technique.name}")
            return selected_technique

        return techniques[0] if techniques else None

    def record_bypass_result(
        self,
        waf_name: str,
        technique_id: str,
        success: bool,
    ) -> None:
        """
        Record result of a bypass attempt for adaptive feedback.

        Args:
            waf_name: Name of the WAF
            technique_id: ID of the technique that was attempted
            success: Whether the bypass succeeded
        """
        bandit = self._get_bandit_for_waf(waf_name)
        bandit.record_result(technique_id, success)
        logger.info(f"Recorded bypass result: {technique_id} = {success}")

    def get_waf_stats(self, waf_name: str) -> Dict[str, Dict[str, Any]]:
        """
        Get adaptive bandit statistics for a WAF.

        Args:
            waf_name: Name of the WAF

        Returns:
            Dictionary of technique statistics
        """
        bandit = self._get_bandit_for_waf(waf_name)
        return bandit.get_all_stats()

    def apply_bypass_to_payload(
        self,
        payload: str,
        technique: BypassTechnique,
    ) -> str:
        """
        Apply bypass technique to a payload.

        Args:
            payload: Original payload string
            technique: BypassTechnique to apply

        Returns:
            Transformed payload
        """
        transformed = technique.encode(payload)
        logger.debug(f"Applied {technique.name} to payload (length: {len(payload)} -> {len(transformed)})")
        return transformed

    def reset_stats(self, waf_name: Optional[str] = None) -> None:
        """
        Reset adaptive statistics.

        Args:
            waf_name: If provided, reset only this WAF's stats; otherwise reset all
        """
        if waf_name:
            if waf_name in self.bandits:
                self.bandits[waf_name].reset()
                logger.info(f"Reset stats for WAF: {waf_name}")
        else:
            self.bandits.clear()
            logger.info("Reset stats for all WAFs")


__all__ = [
    "VulnerabilityClass",
    "EncodingType",
    "WAFFingerprint",
    "BypassTechnique",
    "WAFDetector",
    "BypassMatrix",
    "AdaptiveBandit",
    "WAFBypassEngine",
]
