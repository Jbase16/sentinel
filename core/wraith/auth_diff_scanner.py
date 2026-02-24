"""
core/wraith/auth_diff_scanner.py

Authenticated Differential Scanner (T2a).

Replays discovered endpoints across multiple Persona privilege levels to detect:
- IDOR (Insecure Direct Object Reference)
- Authentication Bypasses
- Broken Access Control
- Privilege Escalation

Leverages the `PersonaManager` (and the `SessionBridge` initialized Auth Session material)
alongside the `DifferentialAnalyzer` to semantically compare HTTP responses.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from core.base.session import ScanSession
from core.wraith.personas import PersonaManager, DifferentialAnalyzer, DifferentialFinding
from core.wraith.session_manager import AuthSessionManager
from core.wraith.mutation_engine import MutationRequest, HttpMethod

logger = logging.getLogger(__name__)


class AuthDiffScanner:
    """
    Authenticated Differential Scanner.
    Executes T2a Safe Verification across known attack surface endpoints.
    """

    def __init__(self, session: ScanSession):
        self.session = session
        self.manager: Optional[PersonaManager] = None
        self.analyzer: Optional[DifferentialAnalyzer] = None
        
        # Pull baseline persona name from config, default 'Admin'
        self.baseline_persona = self.session.knowledge.get("persona_baseline", "Admin")

    async def initialize(self) -> bool:
        """
        Initialize the Scanner by loading the AuthSessionManager material
        and instantiating the DifferentialAnalyzer.
        """
        auth_bridge = self.session.knowledge.get("session_bridge")
        
        if not isinstance(auth_bridge, AuthSessionManager):
            logger.warning("[AuthDiffScanner] No AuthSessionManager found. Cannot run differential analysis.")
            return False
            
        # Ensure session bridge is initialized
        if not getattr(auth_bridge, "_initialized", False):
            await auth_bridge.initialize()
            
        # Initialize PersonaManager using the personas from the bridge
        self.manager = PersonaManager(
            personas=auth_bridge.personas,
            policy_runtime=self.session.scope_context.policy if hasattr(self.session, "scope_context") else None
        )
        
        # Populate session material straight from the bridge
        for p in self.manager.personas:
            auth_mat = await auth_bridge.get_auth(p.name)
            if auth_mat:
                if auth_mat.cookies:
                    p.cookie_jar = dict(auth_mat.cookies)
                if auth_mat.bearer_token:
                    p.bearer_token = auth_mat.bearer_token
                    
        # Verify PersonaManager boots correctly
        if not await self.manager.initialize():
            logger.error("[AuthDiffScanner] Failed to initialize PersonaManager sessions.")
            return False
            
        self.analyzer = DifferentialAnalyzer(
            manager=self.manager,
            baseline_persona=self.baseline_persona,
            skip_anonymous=False
        )
        
        logger.info(f"[AuthDiffScanner] Initialized with baseline persona: {self.baseline_persona}")
        return True

    async def scan_endpoint(self, url: str, method: str = "GET", params: Optional[Dict[str, Any]] = None, body: Optional[str] = None) -> List[DifferentialFinding]:
        """
        Run differential analysis against a specific endpoint.
        """
        if not self.analyzer:
            logger.error("[AuthDiffScanner] Scanner not initialized.")
            return []
            
        try:
            http_method = HttpMethod(method.upper())
        except ValueError:
            http_method = HttpMethod.GET
            
        request = MutationRequest(
            method=http_method,
            url=url,
            query_params=params,
            body=body,
            headers={}, 
            timeout=10.0
        )
        
        logger.info(f"[AuthDiffScanner] Replaying across personas: {method} {url}")
        findings = await self.analyzer.analyze(request)
        
        # Register findings into the central repository
        for f in findings:
            self.session.findings.add_finding({
                "tool": "auth_diff_scanner",
                "type": f.issue_type.value,
                "severity": f.severity.upper(),
                "target": urlparse(f.url).netloc,
                "metadata": {
                    "url": f.url,
                    "method": f.method,
                    "test_persona": f.test_persona,
                    "baseline_persona": f.baseline_persona,
                    "diff_description": f.response_diff.description,
                    "confidence": f.confidence
                },
                "title": f"Access Control Violation: {f.issue_type.value.upper()} on {f.method} {urlparse(f.url).path}",
                "description": f.description,
                "remediation": f.remediation
            })
            
        return findings

    async def close(self):
        """Clean up HTTP client sessions."""
        if self.manager:
            await self.manager.close()
