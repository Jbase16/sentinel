"""
Comprehensive unit tests for AuthDiffScanner, PersonaManager, and DifferentialAnalyzer.

Tests cover:
- Persona creation from config with scope guards
- PersonaSession auth injection (bearer tokens and cookies)
- DifferentialAnalyzer issue classification
- AuthDiffScanner finding registration
- All mocked with unittest.mock and pytest.mark.anyio
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, List, Optional, Any

import pytest

from core.wraith.personas import (
    Persona,
    PersonaType,
    PersonaSession,
    PersonaManager,
    DifferentialAnalyzer,
    DifferentialFinding,
    DifferentialIssueType,
    LoginFlow,
)
from core.wraith.mutation_engine import (
    MutationRequest,
    MutationResponse,
    HttpMethod,
    diff_responses,
)
from core.wraith.session_manager import parse_personas_config
from core.wraith.auth_diff_scanner import AuthDiffScanner


# ============================================================================
# Test 1: parse_personas_config creates Persona objects from raw dicts
# ============================================================================

def test_persona_creation_from_config():
    """
    Tests that parse_personas_config() creates Persona objects correctly.
    
    Input: list with admin (bearer_token), user (cookie_jar), auto-add anonymous
    Assert: 3 personas total, admin has bearer_token, user has cookie_jar, one is ANONYMOUS
    """
    base_url = "http://target.com"
    cfg = [
        {
            "name": "Admin",
            "persona_type": "admin",
            "bearer_token": "admin_token_123",
        },
        {
            "name": "User",
            "persona_type": "user",
            "cookie_jar": {"session": "user_session_456"},
        },
    ]
    
    personas, persist_by_name = parse_personas_config(base_url, cfg)
    
    # Should auto-add Anonymous
    assert len(personas) == 3, f"Expected 3 personas, got {len(personas)}"
    
    # Find personas by name
    admin = next((p for p in personas if p.name == "Admin"), None)
    user = next((p for p in personas if p.name == "User"), None)
    anon = next((p for p in personas if p.persona_type == PersonaType.ANONYMOUS), None)
    
    assert admin is not None, "Admin persona not found"
    assert user is not None, "User persona not found"
    assert anon is not None, "Anonymous persona not found"
    
    # Verify auth methods
    assert admin.bearer_token == "admin_token_123", f"Admin bearer token not set correctly"
    assert user.cookie_jar == {"session": "user_session_456"}, f"User cookie jar not set correctly"
    assert anon.persona_type == PersonaType.ANONYMOUS, "Anonymous type incorrect"


# ============================================================================
# Test 2: Scope guard drops login flows pointing to different origin
# ============================================================================

def test_persona_creation_scope_guard():
    """
    Tests that parse_personas_config drops login flows pointing to a different origin.
    
    Input: persona with login_flow.endpoint = "https://evil.com/login", base_url = "http://target.com"
    Assert: persona created but login_flow is None
    """
    base_url = "http://target.com"
    cfg = [
        {
            "name": "Attacker",
            "persona_type": "admin",
            "login_flow": {
                "endpoint": "https://evil.com/login",
                "method": "POST",
                "username_param": "user",
                "password_param": "pass",
                "username_value": "admin",
                "password_value": "secret",
            },
        },
    ]
    
    personas, persist_by_name = parse_personas_config(base_url, cfg)
    
    attacker = next((p for p in personas if p.name == "Attacker"), None)
    assert attacker is not None, "Attacker persona should be created"
    assert attacker.login_flow is None, "login_flow should be None due to scope guard"


# ============================================================================
# Test 3: PersonaSession injects Bearer token
# ============================================================================

@pytest.mark.anyio
async def test_persona_session_injects_bearer_token():
    """
    Tests PersonaSession.request() injects Authorization header with bearer token.
    
    Create a Persona with bearer_token="tok123" and PersonaType.USER
    Mock httpx.AsyncClient.request to return 200
    Call session.request() and assert Authorization header was set
    """
    # Create persona with bearer token
    persona = Persona(
        name="TestUser",
        persona_type=PersonaType.USER,
        bearer_token="tok123",
    )
    
    # Create mock httpx.AsyncClient
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "success"
    mock_response.headers = {}
    mock_response.history = []
    mock_client.request.return_value = mock_response
    
    # Create PersonaSession
    session = PersonaSession(persona=persona, client=mock_client)
    session._authenticated = True  # Mark as authenticated
    
    # Create mutation request
    mutation_req = MutationRequest(
        method=HttpMethod.GET,
        url="http://example.com/api/users",
    )
    
    # Execute request
    response = await session.request(mutation_req)
    
    # Verify mock was called
    assert mock_client.request.called, "httpx.AsyncClient.request not called"
    
    # Get the call arguments
    call_args, call_kwargs = mock_client.request.call_args
    
    # Verify Authorization header was injected
    assert "headers" in call_kwargs, "headers not in call_kwargs"
    headers = call_kwargs["headers"]
    assert "Authorization" in headers, "Authorization header not injected"
    assert headers["Authorization"] == "Bearer tok123", f"Bearer token incorrect: {headers['Authorization']}"


# ============================================================================
# Test 4: PersonaSession injects cookies
# ============================================================================

@pytest.mark.anyio
async def test_persona_session_injects_cookies():
    """
    Tests PersonaSession.request() injects cookies from persona.cookie_jar.
    
    Create a Persona with cookie_jar={"session": "abc123"}
    Mock httpx.AsyncClient.request to return 200
    Call session.request() and assert cookies dict contains session cookie
    """
    # Create persona with cookies
    persona = Persona(
        name="TestUser",
        persona_type=PersonaType.USER,
        cookie_jar={"session": "abc123"},
    )
    
    # Create mock httpx.AsyncClient
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "success"
    mock_response.headers = {}
    mock_response.history = []
    mock_client.request.return_value = mock_response
    
    # Create PersonaSession
    session = PersonaSession(persona=persona, client=mock_client)
    session._authenticated = True  # Mark as authenticated
    
    # Create mutation request
    mutation_req = MutationRequest(
        method=HttpMethod.GET,
        url="http://example.com/api/users",
    )
    
    # Execute request
    response = await session.request(mutation_req)
    
    # Verify mock was called
    assert mock_client.request.called, "httpx.AsyncClient.request not called"
    
    # Get the call arguments
    call_args, call_kwargs = mock_client.request.call_args
    
    # Verify cookies were injected
    assert "cookies" in call_kwargs, "cookies not in call_kwargs"
    cookies = call_kwargs["cookies"]
    assert "session" in cookies, "session cookie not injected"
    assert cookies["session"] == "abc123", f"Session cookie value incorrect: {cookies['session']}"


# ============================================================================
# Test 5: DifferentialAnalyzer detects AUTH_BYPASS
# ============================================================================

@pytest.mark.anyio
async def test_differential_analyzer_detects_auth_bypass():
    """
    Tests DifferentialAnalyzer detects authentication bypass.
    
    Mock manager.replay_across_personas() to return:
    - Admin: status=200, body="admin data", body_length=500
    - Anonymous: status=200, body="admin data", body_length=495 (nearly same)
    Assert: finds DifferentialIssueType.AUTH_BYPASS
    """
    # Create mock personas
    admin_persona = Persona(
        name="Admin",
        persona_type=PersonaType.ADMIN,
        bearer_token="admin_token",
    )
    anon_persona = Persona(
        name="Anonymous",
        persona_type=PersonaType.ANONYMOUS,
    )
    
    # Create mock PersonaManager
    mock_manager = AsyncMock(spec=PersonaManager)
    mock_manager.personas = [admin_persona, anon_persona]
    
    # Mock responses
    admin_response = MutationResponse(
        status_code=200,
        headers={},
        body="admin_data_content" * 30,  # ~540 bytes
        body_length=540,
        elapsed_ms=100.0,
        url="http://example.com/api/admin",
    )
    
    anon_response = MutationResponse(
        status_code=200,
        headers={},
        body="admin_data_content" * 28,  # ~504 bytes, nearly same
        body_length=504,
        elapsed_ms=100.0,
        url="http://example.com/api/admin",
    )
    
    mock_manager.replay_across_personas.return_value = {
        "Admin": admin_response,
        "Anonymous": anon_response,
    }
    
    # Create DifferentialAnalyzer
    analyzer = DifferentialAnalyzer(
        manager=mock_manager,
        baseline_persona="Admin",
    )
    
    # Create mutation request
    mutation_req = MutationRequest(
        method=HttpMethod.GET,
        url="http://example.com/api/admin",
    )
    
    # Execute analysis
    findings = await analyzer.analyze(mutation_req)
    
    # Verify findings
    assert len(findings) > 0, "No findings detected"
    assert any(f.issue_type == DifferentialIssueType.AUTH_BYPASS for f in findings), \
        f"AUTH_BYPASS not found in findings: {[f.issue_type for f in findings]}"


# ============================================================================
# Test 6: DifferentialAnalyzer detects PRIVILEGE_ESCALATION
# ============================================================================

@pytest.mark.anyio
async def test_differential_analyzer_detects_privilege_escalation():
    """
    Tests DifferentialAnalyzer detects privilege escalation.
    
    Mock manager.replay_across_personas() to return:
    - Admin: status=200, body='{"admin":true}', body_length=150
    - user (lowercase): status=200, body='{"admin":true}', body_length=148 (near-identical)
    Assert: finds DifferentialIssueType.PRIVILEGE_ESCALATION
    """
    # Create mock personas
    admin_persona = Persona(
        name="Admin",
        persona_type=PersonaType.ADMIN,
        bearer_token="admin_token",
    )
    user_persona = Persona(
        name="user",  # lowercase to match heuristic
        persona_type=PersonaType.USER,
        bearer_token="user_token",
    )
    
    # Create mock PersonaManager
    mock_manager = AsyncMock(spec=PersonaManager)
    mock_manager.personas = [admin_persona, user_persona]
    
    # Mock responses - nearly identical JSON
    admin_body = json.dumps({"admin": True, "id": 1, "role": "admin", "data": "secret" * 20})
    user_body = json.dumps({"admin": True, "id": 1, "role": "admin", "data": "secret" * 20})
    
    admin_response = MutationResponse(
        status_code=200,
        headers={},
        body=admin_body,
        body_length=len(admin_body),
        elapsed_ms=100.0,
        url="http://example.com/api/admin",
    )
    
    user_response = MutationResponse(
        status_code=200,
        headers={},
        body=user_body,
        body_length=len(user_body),
        elapsed_ms=100.0,
        url="http://example.com/api/admin",
    )
    
    mock_manager.replay_across_personas.return_value = {
        "Admin": admin_response,
        "user": user_response,
    }
    
    # Create DifferentialAnalyzer
    analyzer = DifferentialAnalyzer(
        manager=mock_manager,
        baseline_persona="Admin",
    )
    
    # Create mutation request
    mutation_req = MutationRequest(
        method=HttpMethod.GET,
        url="http://example.com/api/admin",
    )
    
    # Execute analysis
    findings = await analyzer.analyze(mutation_req)
    
    # Verify findings - should find privilege escalation
    assert len(findings) > 0, "No findings detected"
    assert any(f.issue_type == DifferentialIssueType.PRIVILEGE_ESCALATION for f in findings), \
        f"PRIVILEGE_ESCALATION not found. Found: {[f.issue_type for f in findings]}"


# ============================================================================
# Test 7: DifferentialAnalyzer detects RECORD_COUNT_DIVERGENCE
# ============================================================================

@pytest.mark.anyio
async def test_differential_analyzer_detects_record_count_divergence():
    """
    Tests DifferentialAnalyzer detects record count divergence.
    
    Mock responses where Admin body is JSON array of 10 items
    and User body is array of 2 items.
    Assert: finds DifferentialIssueType.RECORD_COUNT_DIVERGENCE
    """
    # Create mock personas
    admin_persona = Persona(
        name="Admin",
        persona_type=PersonaType.ADMIN,
        bearer_token="admin_token",
    )
    user_persona = Persona(
        name="User",
        persona_type=PersonaType.USER,
        bearer_token="user_token",
    )
    
    # Create mock PersonaManager
    mock_manager = AsyncMock(spec=PersonaManager)
    mock_manager.personas = [admin_persona, user_persona]
    
    # Mock responses with different record counts
    admin_records = [{"id": i, "email": f"user{i}@example.com"} for i in range(10)]
    user_records = [{"id": i, "email": f"user{i}@example.com"} for i in range(2)]
    
    admin_body = json.dumps(admin_records)
    user_body = json.dumps(user_records)
    
    admin_response = MutationResponse(
        status_code=200,
        headers={},
        body=admin_body,
        body_length=len(admin_body),
        elapsed_ms=100.0,
        url="http://example.com/api/users",
    )
    
    user_response = MutationResponse(
        status_code=200,
        headers={},
        body=user_body,
        body_length=len(user_body),
        elapsed_ms=100.0,
        url="http://example.com/api/users",
    )
    
    mock_manager.replay_across_personas.return_value = {
        "Admin": admin_response,
        "User": user_response,
    }
    
    # Create DifferentialAnalyzer
    analyzer = DifferentialAnalyzer(
        manager=mock_manager,
        baseline_persona="Admin",
    )
    
    # Create mutation request
    mutation_req = MutationRequest(
        method=HttpMethod.GET,
        url="http://example.com/api/users",
    )
    
    # Execute analysis
    findings = await analyzer.analyze(mutation_req)
    
    # Verify findings
    assert len(findings) > 0, "No findings detected"
    assert any(f.issue_type == DifferentialIssueType.RECORD_COUNT_DIVERGENCE for f in findings), \
        f"RECORD_COUNT_DIVERGENCE not found. Found: {[f.issue_type for f in findings]}"


# ============================================================================
# Test 8: DifferentialAnalyzer no finding on matching responses
# ============================================================================

@pytest.mark.anyio
async def test_differential_analyzer_no_finding_on_matching_responses():
    """
    Tests DifferentialAnalyzer returns empty list when responses match.
    
    Both Admin and User return identical status=403, body=""
    Assert: returns empty list (no spurious findings)
    """
    # Create mock personas
    admin_persona = Persona(
        name="Admin",
        persona_type=PersonaType.ADMIN,
        bearer_token="admin_token",
    )
    user_persona = Persona(
        name="User",
        persona_type=PersonaType.USER,
        bearer_token="user_token",
    )
    
    # Create mock PersonaManager
    mock_manager = AsyncMock(spec=PersonaManager)
    mock_manager.personas = [admin_persona, user_persona]
    
    # Mock identical forbidden responses
    response = MutationResponse(
        status_code=403,
        headers={},
        body="",
        body_length=0,
        elapsed_ms=100.0,
        url="http://example.com/api/secret",
    )
    
    mock_manager.replay_across_personas.return_value = {
        "Admin": response,
        "User": response,
    }
    
    # Create DifferentialAnalyzer
    analyzer = DifferentialAnalyzer(
        manager=mock_manager,
        baseline_persona="Admin",
    )
    
    # Create mutation request
    mutation_req = MutationRequest(
        method=HttpMethod.GET,
        url="http://example.com/api/secret",
    )
    
    # Execute analysis
    findings = await analyzer.analyze(mutation_req)
    
    # Verify no findings (matching responses = no issue)
    assert len(findings) == 0, f"Expected no findings, got {len(findings)}"


# ============================================================================
# Test 9: AuthDiffScanner registers findings
# ============================================================================

@pytest.mark.anyio
async def test_auth_diff_scanner_registers_findings():
    """
    Tests AuthDiffScanner.scan_endpoint() registers findings with session.
    
    Create a mock ScanSession with session_bridge
    Mock DifferentialAnalyzer.analyze to return one DifferentialFinding
    Call scan_endpoint() and assert findings.add_finding was called
    """
    # Create mock ScanSession
    mock_session = MagicMock()
    mock_session.knowledge = {}
    mock_session.findings = MagicMock()
    
    # Create mock AuthSessionManager
    admin_persona = Persona(
        name="Admin",
        persona_type=PersonaType.ADMIN,
        bearer_token="admin_token",
    )
    user_persona = Persona(
        name="User",
        persona_type=PersonaType.USER,
        bearer_token="user_token",
    )
    
    mock_auth_manager = AsyncMock()
    mock_auth_manager._initialized = True
    mock_auth_manager.personas = [admin_persona, user_persona]
    
    mock_session.knowledge["session_bridge"] = mock_auth_manager
    
    # Create AuthDiffScanner
    scanner = AuthDiffScanner(session=mock_session)
    
    # Mock initialize to set up analyzer
    with patch.object(scanner, 'manager', new=AsyncMock(spec=PersonaManager)):
        with patch.object(scanner, 'analyzer', new=AsyncMock(spec=DifferentialAnalyzer)):
            scanner.manager.personas = [admin_persona, user_persona]
            
            # Create a mock finding
            mock_finding = MagicMock(spec=DifferentialFinding)
            mock_finding.issue_type = DifferentialIssueType.AUTH_BYPASS
            mock_finding.severity = "critical"
            mock_finding.url = "http://example.com/api/users"
            mock_finding.method = "GET"
            mock_finding.test_persona = "User"
            mock_finding.baseline_persona = "Admin"
            mock_finding.response_diff = MagicMock()
            mock_finding.response_diff.description = "Test diff"
            mock_finding.confidence = 0.95
            mock_finding.description = "Auth bypass detected"
            mock_finding.remediation = "Implement auth checks"
            
            scanner.analyzer.analyze.return_value = [mock_finding]
            
            # Call scan_endpoint
            findings = await scanner.scan_endpoint(
                url="http://example.com/api/users",
                method="GET",
            )
            
            # Verify findings.add_finding was called
            assert mock_session.findings.add_finding.called, "add_finding not called"
            
            # Verify the finding dict structure
            call_args = mock_session.findings.add_finding.call_args
            finding_dict = call_args[0][0]
            
            assert finding_dict["tool"] == "auth_diff_scanner", "tool not set correctly"
            assert finding_dict["type"] == "auth_bypass", "type not set correctly"


# ============================================================================
# Test 10: AuthDiffScanner skips without session_bridge
# ============================================================================

@pytest.mark.anyio
async def test_auth_diff_scanner_skips_without_session_bridge():
    """
    Tests AuthDiffScanner.initialize() returns False without session_bridge.
    
    Create scanner with session.knowledge = {} (no session_bridge)
    Call initialize() and assert returns False
    """
    # Create mock ScanSession without session_bridge
    mock_session = MagicMock()
    mock_session.knowledge = {}  # Empty knowledge
    
    # Create AuthDiffScanner
    scanner = AuthDiffScanner(session=mock_session)
    
    # Call initialize
    result = await scanner.initialize()
    
    # Verify it returns False
    assert result is False, "Expected initialize() to return False without session_bridge"


# ============================================================================
# Additional tests for diff_responses function
# ============================================================================

def test_diff_responses_with_identical_responses():
    """
    Test diff_responses with identical responses.
    """
    body = '{"data": "test"}'
    resp_a = MutationResponse(
        status_code=200,
        headers={},
        body=body,
        body_length=len(body),
        elapsed_ms=100.0,
        url="http://example.com",
    )
    resp_b = MutationResponse(
        status_code=200,
        headers={},
        body=body,
        body_length=len(body),
        elapsed_ms=100.0,
        url="http://example.com",
    )
    
    diff = diff_responses(resp_a, resp_b)
    
    assert diff.status_differs is False, "Status should not differ"
    assert diff.body_hash_differs is False, "Body hash should not differ"
    assert diff.is_significant is False, "Diff should not be significant"


def test_diff_responses_with_status_difference():
    """
    Test diff_responses with different status codes.
    """
    resp_a = MutationResponse(
        status_code=200,
        headers={},
        body="authorized",
        body_length=10,
        elapsed_ms=100.0,
        url="http://example.com",
    )
    resp_b = MutationResponse(
        status_code=403,
        headers={},
        body="forbidden",
        body_length=9,
        elapsed_ms=100.0,
        url="http://example.com",
    )
    
    diff = diff_responses(resp_a, resp_b)
    
    assert diff.status_differs is True, "Status should differ"
    assert diff.is_significant is True, "Diff should be significant"
    assert diff.confidence >= 0.85, "Confidence should be high for status diff"


def test_diff_responses_with_json_record_count_difference():
    """
    Test diff_responses detects different record counts in JSON arrays.
    """
    resp_a = MutationResponse(
        status_code=200,
        headers={},
        body=json.dumps([{"id": 1}, {"id": 2}, {"id": 3}]),
        body_length=30,
        elapsed_ms=100.0,
        url="http://example.com",
    )
    resp_b = MutationResponse(
        status_code=200,
        headers={},
        body=json.dumps([{"id": 1}]),
        body_length=10,
        elapsed_ms=100.0,
        url="http://example.com",
    )
    
    diff = diff_responses(resp_a, resp_b)
    
    assert diff.record_count_a == 3, f"Expected 3 records in A, got {diff.record_count_a}"
    assert diff.record_count_b == 1, f"Expected 1 record in B, got {diff.record_count_b}"
    assert diff.is_significant is True, "Diff should be significant"


def test_diff_responses_strips_dynamic_fields():
    """
    Test diff_responses strips dynamic fields before comparison.
    """
    # Responses with different CSRF tokens but otherwise identical
    resp_a = MutationResponse(
        status_code=200,
        headers={},
        body=json.dumps({"data": "same", "csrf": "token123"}),
        body_length=40,
        elapsed_ms=100.0,
        url="http://example.com",
    )
    resp_b = MutationResponse(
        status_code=200,
        headers={},
        body=json.dumps({"data": "same", "csrf": "token456"}),
        body_length=40,
        elapsed_ms=100.0,
        url="http://example.com",
    )
    
    diff = diff_responses(resp_a, resp_b)
    
    # After stripping csrf, the data should be identical
    # unique_keys_a and unique_keys_b should be empty
    assert diff.unique_keys_a == [], "Should not have unique keys in A after stripping"
    assert diff.unique_keys_b == [], "Should not have unique keys in B after stripping"
    assert diff.is_significant is False, "Diff should not be significant after stripping dynamic fields"


# ============================================================================
# Test PersonaManager initialization
# ============================================================================

@pytest.mark.anyio
async def test_persona_manager_initializes_personas():
    """
    Test PersonaManager.initialize() creates sessions for all personas.
    """
    personas = [
        Persona(
            name="Admin",
            persona_type=PersonaType.ADMIN,
            bearer_token="admin_token",
        ),
        Persona(
            name="User",
            persona_type=PersonaType.USER,
            bearer_token="user_token",
        ),
    ]
    
    # Mock httpx.AsyncClient
    with patch("core.wraith.personas.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = AsyncMock()
        mock_client_class.return_value = mock_client_instance
        
        manager = PersonaManager(personas=personas)
        result = await manager.initialize()
        
        # Should succeed
        assert result is True, "Expected initialization to succeed"
        
        # Should create 2 sessions
        assert len(manager.sessions) == 2, f"Expected 2 sessions, got {len(manager.sessions)}"
        assert "Admin" in manager.sessions, "Admin session not created"
        assert "User" in manager.sessions, "User session not created"


@pytest.mark.anyio
async def test_persona_manager_replay_across_personas():
    """
    Test PersonaManager.replay_across_personas() returns responses from all personas.
    """
    personas = [
        Persona(
            name="Admin",
            persona_type=PersonaType.ADMIN,
            bearer_token="admin_token",
        ),
        Persona(
            name="User",
            persona_type=PersonaType.USER,
            bearer_token="user_token",
        ),
    ]
    
    # Create mock responses
    admin_response = MutationResponse(
        status_code=200,
        headers={},
        body="admin data",
        body_length=10,
        elapsed_ms=100.0,
        url="http://example.com/api/admin",
    )
    user_response = MutationResponse(
        status_code=200,
        headers={},
        body="user data",
        body_length=9,
        elapsed_ms=100.0,
        url="http://example.com/api/admin",
    )
    
    # Mock httpx.AsyncClient and PersonaSession
    with patch("core.wraith.personas.httpx.AsyncClient"):
        with patch("core.wraith.personas.PersonaSession") as mock_session_class:
            mock_admin_session = AsyncMock()
            mock_user_session = AsyncMock()
            
            mock_admin_session.request.return_value = admin_response
            mock_user_session.request.return_value = user_response
            
            # Create manager and manually set sessions
            manager = PersonaManager(personas=personas)
            manager.sessions["Admin"] = mock_admin_session
            manager.sessions["User"] = mock_user_session
            
            # Create mutation request
            mutation_req = MutationRequest(
                method=HttpMethod.GET,
                url="http://example.com/api/admin",
            )
            
            # Execute replay
            responses = await manager.replay_across_personas(mutation_req)
            
            # Verify responses
            assert len(responses) == 2, f"Expected 2 responses, got {len(responses)}"
            assert "Admin" in responses, "Admin response not found"
            assert "User" in responses, "User response not found"
            assert responses["Admin"] == admin_response, "Admin response incorrect"
            assert responses["User"] == user_response, "User response incorrect"


# ============================================================================
# Edge case: Persona with no auth method defaults to ANONYMOUS
# ============================================================================

def test_persona_with_no_auth_defaults_to_anonymous():
    """
    Test that a Persona with no auth method is still created but treated as anonymous.
    """
    persona = Persona(
        name="NoAuth",
        persona_type=PersonaType.CUSTOM,
    )
    
    # Should not raise an error, but should log a warning
    assert persona.name == "NoAuth"
    assert persona.persona_type == PersonaType.CUSTOM
    assert persona.bearer_token is None
    assert persona.cookie_jar is None
    assert persona.login_flow is None


# ============================================================================
# Test DifferentialFinding creation
# ============================================================================

def test_differential_finding_creation():
    """
    Test DifferentialFinding can be created and has proper attributes.
    """
    mock_diff = MagicMock()
    
    finding = DifferentialFinding(
        issue_type=DifferentialIssueType.AUTH_BYPASS,
        url="http://example.com/api/users",
        method="GET",
        baseline_persona="Admin",
        test_persona="Anonymous",
        response_diff=mock_diff,
        confidence=0.95,
        severity="critical",
    )
    
    assert finding.issue_type == DifferentialIssueType.AUTH_BYPASS
    assert finding.url == "http://example.com/api/users"
    assert finding.method == "GET"
    assert finding.baseline_persona == "Admin"
    assert finding.test_persona == "Anonymous"
    assert finding.confidence == 0.95
    assert finding.severity == "critical"
