"""
Persona-Based Differential Analysis System for SentinelForge.

This module implements differential authentication testing by replaying requests
across multiple privilege levels (Admin, User, Anonymous) and comparing responses
to detect:
- Insecure Direct Object References (IDOR)
- Authentication bypass
- Privilege escalation
- Access control violations

The system uses semantic response diffing (not just status codes) to identify
vulnerabilities where responses have the same status but different content or
record counts.

Design:
- Persona: represents a user privilege level (Admin, User, Anonymous, Custom)
- PersonaSession: httpx.AsyncClient wrapper with persona-specific auth
- PersonaManager: creates/manages parallel sessions for all personas
- DifferentialAnalyzer: replays requests across personas and compares responses
- DifferentialFinding: captures detected access control violations
"""

from __future__ import annotations

import asyncio
import enum
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from core.cortex.capability_tiers import CapabilityTier
from .execution_policy import ExecutionPolicyRuntime, PolicyViolation
from .mutation_engine import (
    ActionOutcome,
    MutationRequest,
    MutationResponse,
    ResponseDiff,
    diff_responses,
    Evidence,
    EvidenceType,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums and Constants
# ---------------------------------------------------------------------------

class PersonaType(str, enum.Enum):
    """Privilege levels for differential testing."""
    ADMIN = "admin"
    USER = "user"
    ANONYMOUS = "anonymous"
    CUSTOM = "custom"


class DifferentialIssueType(str, enum.Enum):
    """Types of access control vulnerabilities detected."""
    IDOR = "idor"                          # Different users access same data
    AUTH_BYPASS = "auth_bypass"            # Unauthenticated access to protected resource
    PRIVILEGE_ESCALATION = "privilege_escalation"  # User accesses admin resource
    INCONSISTENT_ACCESS = "inconsistent_access"    # User access differs unexpectedly
    DATA_LEAK = "data_leak"                # Sensitive data visible at different auth levels
    RECORD_COUNT_DIVERGENCE = "record_count_divergence"  # Different counts = different data


# ---------------------------------------------------------------------------
# Authentication Configuration
# ---------------------------------------------------------------------------

@dataclass
class LoginFlow:
    """Configuration for a login flow (POST to endpoint with credentials).
    
    Example:
        LoginFlow(
            endpoint="/api/login",
            method="POST",
            username_param="email",
            password_param="password",
            username_value="admin@test.com",
            password_value="admin123",
            token_extract_path="data.token",
            cookie_extract=None
        )
    """
    endpoint: str                          # Path or full URL to login endpoint
    method: str = "POST"                   # HTTP method (POST, PATCH, etc.)
    username_param: str = "username"       # Form/JSON param for username
    password_param: str = "password"       # Form/JSON param for password
    username_value: str = ""               # Actual username/email
    password_value: str = ""               # Actual password
    token_extract_path: Optional[str] = None  # JSON path to extract token (e.g., "data.token")
    cookie_extract: Optional[str] = None   # Cookie name to extract (e.g., "session_id")
    headers: Dict[str, str] = field(default_factory=dict)  # Additional headers
    content_type: str = "application/json" # Form data or JSON


@dataclass
class Persona:
    """Represents a user with specific privilege level and authentication.
    
    Auth methods (in priority order):
    1. cookie_jar: Dict[str, str] of cookies (most direct)
    2. bearer_token: Bearer token string
    3. login_flow: LoginFlow to execute
    """
    name: str                              # Human name (e.g., "Admin User", "Guest")
    persona_type: PersonaType             # ADMIN, USER, ANONYMOUS, CUSTOM
    
    # Authentication (choose one)
    cookie_jar: Optional[Dict[str, str]] = None  # Direct cookies
    bearer_token: Optional[str] = None           # Bearer token
    login_flow: Optional[LoginFlow] = None       # Login endpoint + creds
    
    # Optional: custom headers per persona (e.g., User-Agent, X-API-Key)
    extra_headers: Dict[str, str] = field(default_factory=dict)
    
    # Base URL for login flow
    base_url: str = "http://localhost:8000"
    
    def __post_init__(self):
        """Validate persona configuration."""
        auth_count = sum([
            self.cookie_jar is not None,
            self.bearer_token is not None,
            self.login_flow is not None,
        ])
        if auth_count == 0 and self.persona_type != PersonaType.ANONYMOUS:
            logger.warning(f"Persona '{self.name}' has no auth method; will be treated as ANONYMOUS")
        elif auth_count > 1:
            logger.warning(f"Persona '{self.name}' has multiple auth methods; using first available")


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

@dataclass
class PersonaSession:
    """Wraps httpx.AsyncClient with persona-specific authentication.
    
    Automatically injects cookies, Bearer tokens, or login flows into requests.
    Maintains separate session state per persona.
    """
    persona: Persona
    client: httpx.AsyncClient
    policy_runtime: Optional[ExecutionPolicyRuntime] = None
    _authenticated: bool = False
    
    async def authenticate(self) -> bool:
        """Execute login flow if configured.
        
        Returns:
            True if authentication successful or not required, False otherwise.
        """
        if self.persona.persona_type == PersonaType.ANONYMOUS:
            self._authenticated = True
            return True
        
        if self.persona.cookie_jar or self.persona.bearer_token:
            self._authenticated = True
            return True
        
        if self.persona.login_flow:
            return await self._execute_login_flow()
        
        self._authenticated = True
        return True
    
    async def _execute_login_flow(self) -> bool:
        """Execute POST login flow and extract token/cookie.
        
        Returns:
            True if login succeeded and token/cookie extracted.
        """
        try:
            flow = self.persona.login_flow
            assert flow is not None
            
            # Build login endpoint URL
            login_url = flow.endpoint
            if not login_url.startswith("http"):
                login_url = urljoin(self.persona.base_url, login_url)
            
            # Build request body
            body: Dict[str, str] | str
            if flow.content_type == "application/json":
                body = {
                    flow.username_param: flow.username_value,
                    flow.password_param: flow.password_value,
                }
            else:
                body = {
                    flow.username_param: flow.username_value,
                    flow.password_param: flow.password_value,
                }
            
            headers = dict(flow.headers)
            if "Content-Type" not in headers:
                headers["Content-Type"] = flow.content_type
            
            # Execute login request
            if self.policy_runtime is not None:
                try:
                    resp = await self.policy_runtime.execute_http(
                        client=self.client,
                        method=flow.method,
                        url=login_url,
                        request_kwargs={
                            "json": body if flow.content_type == "application/json" else None,
                            "data": body if flow.content_type != "application/json" else None,
                            "headers": headers,
                            "timeout": 10.0,
                        },
                        tier_hint=CapabilityTier.T2a_SAFE_VERIFY,
                    )
                except PolicyViolation as e:
                    logger.error(f"Login flow blocked by policy for '{self.persona.name}': {e}")
                    return False
            else:
                resp = await self.client.request(
                    flow.method,
                    login_url,
                    json=body if flow.content_type == "application/json" else None,
                    data=body if flow.content_type != "application/json" else None,
                    headers=headers,
                    timeout=10.0,
                )
            
            if resp.status_code >= 400:
                logger.error(
                    f"Login failed for '{self.persona.name}': "
                    f"{resp.status_code} {resp.text[:200]}"
                )
                return False
            
            # Extract token if configured
            if flow.token_extract_path:
                try:
                    data = resp.json()
                    token = self._extract_json_path(data, flow.token_extract_path)
                    if token:
                        self.persona.bearer_token = token
                        self._authenticated = True
                        logger.info(f"Extracted token for persona '{self.persona.name}'")
                        return True
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    logger.error(f"Failed to extract token: {e}")
            
            # Extract cookie if configured
            if flow.cookie_extract:
                if flow.cookie_extract in resp.cookies:
                    self.persona.cookie_jar = dict(resp.cookies)
                    self._authenticated = True
                    logger.info(f"Extracted cookies for persona '{self.persona.name}'")
                    return True
            
            self._authenticated = True
            return True
            
        except Exception as e:
            logger.error(f"Login flow failed for '{self.persona.name}': {e}")
            return False
    
    @staticmethod
    def _extract_json_path(data: Any, path: str) -> Optional[str]:
        """Extract value from JSON using dotted path notation.
        
        Args:
            data: JSON data (dict or list)
            path: Dotted path (e.g., "data.token" or "data[0].id")
        
        Returns:
            Extracted value as string, or None if not found.
        """
        keys = path.split(".")
        current = data
        
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list):
                try:
                    idx = int(key)
                    current = current[idx]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            
            if current is None:
                return None
        
        return str(current) if current is not None else None
    
    async def request(
        self,
        mutation_request: MutationRequest,
    ) -> MutationResponse:
        """Execute a request with persona-specific authentication.
        
        Injects cookies, Bearer token, or other auth headers based on persona config.
        
        Args:
            mutation_request: Request to execute
        
        Returns:
            MutationResponse with captured response
        """
        if not self._authenticated:
            await self.authenticate()
        
        # Build request headers with persona's auth
        headers = dict(mutation_request.headers)
        headers.update(self.persona.extra_headers)
        
        # Inject Bearer token if available
        if self.persona.bearer_token:
            headers["Authorization"] = f"Bearer {self.persona.bearer_token}"
        
        # Inject cookies
        cookies = dict(mutation_request.cookies)
        if self.persona.cookie_jar:
            cookies.update(self.persona.cookie_jar)

        request_kwargs = {
            "headers": headers,
            "cookies": cookies,
            "params": mutation_request.query_params or None,
            "json": mutation_request.body if isinstance(mutation_request.body, dict) else None,
            "content": mutation_request.body if isinstance(mutation_request.body, str) else None,
            "timeout": mutation_request.timeout,
            "follow_redirects": True,
        }

        # Execute request via centralized policy runtime when configured.
        try:
            start = asyncio.get_event_loop().time()
            if self.policy_runtime is not None:
                resp = await self.policy_runtime.execute_http(
                    client=self.client,
                    method=mutation_request.method.value,
                    url=mutation_request.url,
                    request_kwargs=request_kwargs,
                    tier_hint=CapabilityTier.T2a_SAFE_VERIFY,
                )
            else:
                resp = await self.client.request(
                    mutation_request.method.value,
                    mutation_request.url,
                    **request_kwargs,
                )
            elapsed_ms = (asyncio.get_event_loop().time() - start) * 1000
            return MutationResponse.from_httpx(resp, elapsed_ms)

        except PolicyViolation as e:
            logger.warning(f"Request blocked by policy for persona '{self.persona.name}': {e}")
            return MutationResponse(
                status_code=0,
                headers={},
                body=f"Policy blocked request: {e}",
                body_length=len(str(e)),
                elapsed_ms=0.0,
                url=mutation_request.url,
                outcome=ActionOutcome.BLOCKED,
            )
        except httpx.TimeoutException:
            logger.warning(f"Request timeout for persona '{self.persona.name}'")
            return MutationResponse(
                status_code=0,
                headers={},
                body="",
                body_length=0,
                elapsed_ms=mutation_request.timeout * 1000,
                url=mutation_request.url,
                outcome=ActionOutcome.TIMEOUT,
            )
        except Exception as e:
            logger.error(f"Request failed for persona '{self.persona.name}': {e}")
            return MutationResponse(
                status_code=0,
                headers={},
                body=f"Error: {str(e)}",
                body_length=len(str(e)),
                elapsed_ms=0.0,
                url=mutation_request.url,
                outcome=ActionOutcome.ERROR,
            )
    
    async def close(self):
        """Close the httpx client."""
        await self.client.aclose()


# ---------------------------------------------------------------------------
# Persona Manager
# ---------------------------------------------------------------------------

class PersonaManager:
    """Creates and manages parallel httpx sessions for all personas.
    
    Handles authentication setup and provides convenient request replay
    across multiple personas.
    """
    
    def __init__(
        self,
        personas: Optional[List[Persona]] = None,
        policy_runtime: Optional[ExecutionPolicyRuntime] = None,
    ):
        """Initialize PersonaManager.
        
        Args:
            personas: List of Persona objects. If None, creates ANONYMOUS only.
        """
        self.personas = personas or [
            Persona(
                name="Anonymous",
                persona_type=PersonaType.ANONYMOUS,
            )
        ]
        self.sessions: Dict[str, PersonaSession] = {}
        self._policy_runtime = policy_runtime
    
    async def initialize(self) -> bool:
        """Create httpx clients and authenticate all personas.
        
        Should be called before using the manager.
        
        Returns:
            True if all personas initialized successfully.
        """
        all_ok = True
        
        for persona in self.personas:
            try:
                client = httpx.AsyncClient(follow_redirects=True)
                session = PersonaSession(
                    persona=persona,
                    client=client,
                    policy_runtime=self._policy_runtime,
                )
                
                if not await session.authenticate():
                    logger.error(f"Failed to authenticate persona '{persona.name}'")
                    all_ok = False
                
                self.sessions[persona.name] = session
                logger.info(f"Initialized persona '{persona.name}' ({persona.persona_type.value})")
            
            except Exception as e:
                logger.error(f"Failed to initialize persona '{persona.name}': {e}")
                all_ok = False
        
        return all_ok
    
    async def replay_across_personas(
        self,
        mutation_request: MutationRequest,
    ) -> Dict[str, MutationResponse]:
        """Replay a single request across all personas.
        
        Executes in parallel for performance.
        
        Args:
            mutation_request: Request to replay
        
        Returns:
            Dict mapping persona name to MutationResponse.
        """
        tasks = {
            name: session.request(mutation_request)
            for name, session in self.sessions.items()
        }
        
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        responses = {}
        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"Request failed for persona '{name}': {result}")
                responses[name] = MutationResponse(
                    status_code=0,
                    headers={},
                    body=f"Error: {str(result)}",
                    body_length=0,
                    elapsed_ms=0.0,
                    url=mutation_request.url,
                )
            else:
                responses[name] = result
        
        return responses
    
    async def close(self):
        """Close all sessions."""
        for session in self.sessions.values():
            await session.close()
    
    def get_session(self, persona_name: str) -> Optional[PersonaSession]:
        """Get a specific persona's session.
        
        Args:
            persona_name: Name of persona
        
        Returns:
            PersonaSession or None if not found.
        """
        return self.sessions.get(persona_name)


# ---------------------------------------------------------------------------
# Differential Finding
# ---------------------------------------------------------------------------

@dataclass
class DifferentialFinding:
    """Access control vulnerability detected via differential analysis.
    
    Represents one detected issue from comparing responses across personas.
    """
    issue_type: DifferentialIssueType
    url: str
    method: str
    
    # Personas compared
    baseline_persona: str                  # Persona baseline (usually Admin)
    test_persona: str                      # Persona being tested
    
    # Evidence
    response_diff: ResponseDiff            # Semantic diff of responses
    evidence: List[Evidence] = field(default_factory=list)
    
    # Severity/confidence
    confidence: float = 0.8                # 0.0-1.0
    severity: str = "medium"               # critical, high, medium, low
    
    # Details for report
    description: str = ""
    remediation: str = ""
    
    def __post_init__(self):
        """Auto-populate description and remediation based on issue type."""
        if not self.description:
            self.description = self._generate_description()
        if not self.remediation:
            self.remediation = self._generate_remediation()
    
    def _generate_description(self) -> str:
        """Generate human-readable description."""
        if self.issue_type == DifferentialIssueType.IDOR:
            return (
                f"Potential IDOR: {self.test_persona} received different "
                f"data shape/count than {self.baseline_persona} on {self.method} {self.url}"
            )
        elif self.issue_type == DifferentialIssueType.AUTH_BYPASS:
            return (
                f"Potential auth bypass: Anonymous user received status "
                f"{self.response_diff.status_differs} response on {self.method} {self.url}"
            )
        elif self.issue_type == DifferentialIssueType.PRIVILEGE_ESCALATION:
            return (
                f"Potential privilege escalation: {self.test_persona} accessed "
                f"admin-only resource {self.method} {self.url}"
            )
        elif self.issue_type == DifferentialIssueType.DATA_LEAK:
            return (
                f"Potential data leak: Sensitive data visible to {self.test_persona} "
                f"on {self.method} {self.url}"
            )
        elif self.issue_type == DifferentialIssueType.RECORD_COUNT_DIVERGENCE:
            return (
                f"Record count divergence: {self.baseline_persona} got "
                f"{self.response_diff.record_count_a} records, "
                f"{self.test_persona} got {self.response_diff.record_count_b} records"
            )
        else:
            return (
                f"{self.issue_type.value} detected: "
                f"{self.test_persona} vs {self.baseline_persona} on {self.method} {self.url}"
            )
    
    def _generate_remediation(self) -> str:
        """Generate remediation advice."""
        if self.issue_type == DifferentialIssueType.IDOR:
            return (
                "Verify authorization checks: ensure users can only access "
                "resources they own. Implement proper access control (ACL, RBAC)."
            )
        elif self.issue_type == DifferentialIssueType.AUTH_BYPASS:
            return (
                "Implement proper authentication on all protected endpoints. "
                "Use framework auth middleware and verify before processing requests."
            )
        elif self.issue_type == DifferentialIssueType.PRIVILEGE_ESCALATION:
            return (
                "Verify role-based access control. Ensure endpoints check "
                "user role before allowing admin operations."
            )
        elif self.issue_type == DifferentialIssueType.DATA_LEAK:
            return (
                "Remove sensitive fields from responses based on user role. "
                "Implement output filtering/sanitization."
            )
        elif self.issue_type == DifferentialIssueType.RECORD_COUNT_DIVERGENCE:
            return (
                "Verify data filtering: ensure each user sees only their own records. "
                "Check WHERE clauses in database queries."
            )
        else:
            return "Investigate access control implementation."
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dict."""
        return {
            "issue_type": self.issue_type.value,
            "url": self.url,
            "method": self.method,
            "baseline_persona": self.baseline_persona,
            "test_persona": self.test_persona,
            "confidence": self.confidence,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "response_diff": {
                "status_differs": self.response_diff.status_differs,
                "body_length_delta": self.response_diff.body_length_delta,
                "body_hash_differs": self.response_diff.body_hash_differs,
                "record_count_a": self.response_diff.record_count_a,
                "record_count_b": self.response_diff.record_count_b,
                "description": self.response_diff.description,
                "confidence": self.response_diff.confidence,
            },
            "evidence_count": len(self.evidence),
        }


# ---------------------------------------------------------------------------
# Differential Analyzer
# ---------------------------------------------------------------------------

class DifferentialAnalyzer:
    """Performs differential analysis across personas to detect access control issues.
    
    Algorithm:
    1. Replay request across all personas
    2. Compare responses pairwise or against baseline
    3. Apply heuristics to classify issue type
    4. Generate evidence chain for causal graph
    
    Detects:
    - IDOR: same response structure but different record counts
    - Auth bypass: anonymous gets 200 OK with meaningful data
    - Privilege escalation: low-privilege user accesses high-privilege resource
    - Data leaks: different data visible at different privilege levels
    """
    
    def __init__(
        self,
        manager: PersonaManager,
        baseline_persona: str = "Admin",
        skip_anonymous: bool = False,
    ):
        """Initialize DifferentialAnalyzer.
        
        Args:
            manager: PersonaManager with initialized personas
            baseline_persona: Name of baseline persona (usually admin)
            skip_anonymous: If True, don't test against anonymous
        """
        self.manager = manager
        self.baseline_persona = baseline_persona
        self.skip_anonymous = skip_anonymous
    
    async def analyze(
        self,
        mutation_request: MutationRequest,
    ) -> List[DifferentialFinding]:
        """Analyze a single request for access control issues.
        
        Replays across all personas, compares responses, and generates findings.
        
        Args:
            mutation_request: Request to analyze
        
        Returns:
            List of DifferentialFinding objects (may be empty).
        """
        findings: List[DifferentialFinding] = []
        
        # Replay request across all personas
        responses = await self.manager.replay_across_personas(mutation_request)
        
        if len(responses) < 2:
            logger.warning("Need at least 2 personas to perform differential analysis")
            return findings
        
        # Get baseline response
        baseline_resp = responses.get(self.baseline_persona)
        if not baseline_resp:
            logger.warning(f"Baseline persona '{self.baseline_persona}' not found")
            return findings
        
        # Compare each persona's response against baseline
        for persona_name, test_resp in responses.items():
            if persona_name == self.baseline_persona:
                continue
            
            if self.skip_anonymous and persona_name == "Anonymous":
                continue
            
            # Perform semantic diff
            resp_diff = diff_responses(baseline_resp, test_resp)
            
            # Classify issue type based on diff
            issue_type = self._classify_issue(
                baseline_persona=self.baseline_persona,
                test_persona=persona_name,
                baseline_resp=baseline_resp,
                test_resp=test_resp,
                diff=resp_diff,
            )
            
            if issue_type:
                evidence = self._extract_evidence(
                    baseline_resp=baseline_resp,
                    test_resp=test_resp,
                    diff=resp_diff,
                    issue_type=issue_type,
                )
                
                confidence = self._compute_confidence(diff=resp_diff, issue_type=issue_type)
                severity = self._classify_severity(issue_type=issue_type, confidence=confidence)
                
                finding = DifferentialFinding(
                    issue_type=issue_type,
                    url=mutation_request.url,
                    method=mutation_request.method.value,
                    baseline_persona=self.baseline_persona,
                    test_persona=persona_name,
                    response_diff=resp_diff,
                    evidence=evidence,
                    confidence=confidence,
                    severity=severity,
                )
                
                findings.append(finding)
                logger.info(
                    f"Found {issue_type.value}: {persona_name} vs {self.baseline_persona} "
                    f"on {mutation_request.method.value} {mutation_request.url}"
                )
        
        return findings
    
    def _classify_issue(
        self,
        baseline_persona: str,
        test_persona: str,
        baseline_resp: MutationResponse,
        test_resp: MutationResponse,
        diff: ResponseDiff,
    ) -> Optional[DifferentialIssueType]:
        """Classify the type of access control issue.
        
        Returns:
            DifferentialIssueType or None if no issue detected.
        """
        # Auth bypass: anonymous gets 200 OK with substantial content
        if test_persona == "Anonymous" or "anonymous" in test_persona.lower():
            if test_resp.status_code == 200 and baseline_resp.status_code == 200:
                if test_resp.body_length > 100 and abs(diff.body_length_delta) < 100:
                    return DifferentialIssueType.AUTH_BYPASS
        
        # Record count divergence: same status but different record counts
        if (diff.record_count_a is not None and diff.record_count_b is not None 
            and diff.record_count_a != diff.record_count_b):
            return DifferentialIssueType.RECORD_COUNT_DIVERGENCE
        
        # Privilege escalation: low-privilege user gets 200 OK for admin resource
        if (test_persona.lower() in ("user", "guest", "test")
            and baseline_persona.lower() == "admin"
            and test_resp.status_code == 200
            and baseline_resp.status_code == 200):
            # If responses are very similar, likely privilege escalation
            if diff.body_length_delta > -100 and diff.body_length_delta < 100:
                if not diff.unique_keys_a and not diff.unique_keys_b:
                    return DifferentialIssueType.PRIVILEGE_ESCALATION
        
        # IDOR: same response structure but different data
        if (baseline_resp.status_code == 200 and test_resp.status_code == 200
            and diff.body_hash_differs
            and (diff.unique_keys_a or diff.unique_keys_b)):
            return DifferentialIssueType.IDOR
        
        # Data leak: user-accessible data visible at unexpected privilege level
        if (baseline_resp.status_code == 200 and test_resp.status_code == 200
            and diff.unique_keys_b and not diff.unique_keys_a):
            return DifferentialIssueType.DATA_LEAK
        
        # Inconsistent access: mixed signals
        if diff.is_significant and diff.status_differs:
            return DifferentialIssueType.INCONSISTENT_ACCESS
        
        return None
    
    def _extract_evidence(
        self,
        baseline_resp: MutationResponse,
        test_resp: MutationResponse,
        diff: ResponseDiff,
        issue_type: DifferentialIssueType,
    ) -> List[Evidence]:
        """Extract evidence items from responses for causal graph.
        
        Args:
            baseline_resp: Response from baseline (admin) persona
            test_resp: Response from test persona
            diff: ResponseDiff from comparison
            issue_type: Classified issue type
        
        Returns:
            List of Evidence objects.
        """
        evidence: List[Evidence] = []
        
        # Evidence 1: Status code difference
        if diff.status_differs:
            evidence.append(Evidence(
                type=EvidenceType.STATUS_DIFF,
                description=(
                    f"Status code differs: baseline={baseline_resp.status_code}, "
                    f"test={test_resp.status_code}"
                ),
                confidence=0.85,
                response_snippet=f"Status: {test_resp.status_code}",
            ))
        
        # Evidence 2: Content difference
        if diff.body_hash_differs:
            evidence.append(Evidence(
                type=EvidenceType.CONTENT_DIFF,
                description=(
                    f"Response content differs (hash mismatch). "
                    f"Delta: {diff.body_length_delta} bytes"
                ),
                confidence=0.75,
                response_snippet=test_resp.body[:200],
            ))
        
        # Evidence 3: Record count difference
        if (diff.record_count_a is not None and diff.record_count_b is not None 
            and diff.record_count_a != diff.record_count_b):
            evidence.append(Evidence(
                type=EvidenceType.DATA_EXTRACTION,
                description=(
                    f"Record count differs: baseline={diff.record_count_a}, "
                    f"test={diff.record_count_b}"
                ),
                confidence=0.90,
                extracted_data=f"{diff.record_count_b} records",
            ))
        
        # Evidence 4: Unique keys (indicates different data structure)
        if diff.unique_keys_a or diff.unique_keys_b:
            keys_str = ", ".join((diff.unique_keys_a + diff.unique_keys_b)[:5])
            evidence.append(Evidence(
                type=EvidenceType.DATA_EXTRACTION,
                description=f"Unique JSON keys found: {keys_str}",
                confidence=0.80,
                extracted_data=keys_str,
            ))
        
        return evidence
    
    def _compute_confidence(
        self,
        diff: ResponseDiff,
        issue_type: DifferentialIssueType,
    ) -> float:
        """Compute confidence score (0.0-1.0) for the finding.
        
        Args:
            diff: ResponseDiff with semantic analysis
            issue_type: Classified issue type
        
        Returns:
            Confidence score.
        """
        confidence = diff.confidence
        
        # Boost confidence for specific issue types
        if issue_type == DifferentialIssueType.RECORD_COUNT_DIVERGENCE:
            confidence = min(1.0, confidence + 0.15)
        elif issue_type == DifferentialIssueType.AUTH_BYPASS:
            confidence = min(1.0, confidence + 0.10)
        elif issue_type == DifferentialIssueType.PRIVILEGE_ESCALATION:
            confidence = min(1.0, confidence + 0.05)
        
        return confidence
    
    def _classify_severity(
        self,
        issue_type: DifferentialIssueType,
        confidence: float,
    ) -> str:
        """Classify severity (critical, high, medium, low).
        
        Args:
            issue_type: Type of issue detected
            confidence: Confidence score (0.0-1.0)
        
        Returns:
            Severity string.
        """
        is_high_confidence = confidence >= 0.80
        
        if issue_type == DifferentialIssueType.AUTH_BYPASS:
            return "critical" if is_high_confidence else "high"
        elif issue_type == DifferentialIssueType.PRIVILEGE_ESCALATION:
            return "critical" if is_high_confidence else "high"
        elif issue_type == DifferentialIssueType.IDOR:
            return "high" if is_high_confidence else "medium"
        elif issue_type == DifferentialIssueType.DATA_LEAK:
            return "high" if is_high_confidence else "medium"
        elif issue_type == DifferentialIssueType.RECORD_COUNT_DIVERGENCE:
            return "medium" if is_high_confidence else "low"
        else:
            return "medium"


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

async def run_differential_analysis(
    personas: List[Persona],
    mutation_request: MutationRequest,
    baseline_persona: str = "Admin",
) -> List[DifferentialFinding]:
    """Convenience function to run full differential analysis.
    
    Handles setup, execution, and cleanup.
    
    Args:
        personas: List of Persona objects
        mutation_request: Request to analyze
        baseline_persona: Name of baseline persona
    
    Returns:
        List of DifferentialFinding objects.
    """
    manager = PersonaManager(personas)
    
    try:
        # Initialize personas
        if not await manager.initialize():
            logger.error("Failed to initialize personas")
            return []
        
        # Run analysis
        analyzer = DifferentialAnalyzer(
            manager=manager,
            baseline_persona=baseline_persona,
        )
        findings = await analyzer.analyze(mutation_request)
        
        return findings
    
    finally:
        await manager.close()
