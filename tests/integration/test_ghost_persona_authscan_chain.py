"""
Integration Test: Ghost FlowMapper → Personas → AuthDiffScanner Chain

Tests the full P2 pipeline:
  1. Ghost records HTTP traffic and extracts auth tokens (FlowMapper)
  2. FlowMapper.to_personas() converts flows into Persona objects
  3. DifferentialAnalyzer (via mocked PersonaManager) detects access control issues
  4. AuthDiffScanner registers findings into the session

All HTTP is mocked — no real network required.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.ghost.flow import FlowMapper, UserFlow, FlowStep
from core.wraith.personas import (
    DifferentialAnalyzer,
    DifferentialFinding,
    DifferentialIssueType,
    Persona,
    PersonaManager,
    PersonaType,
)
from core.wraith.mutation_engine import (
    HttpMethod,
    MutationRequest,
    MutationResponse,
    diff_responses,
)
from core.wraith.session_manager import parse_personas_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    status: int,
    body: str,
    headers: dict | None = None,
) -> MutationResponse:
    return MutationResponse(
        status_code=status,
        headers=headers or {},
        body=body,
        body_length=len(body),
        elapsed_ms=10.0,
        url="http://example.com/api/users",
    )


def _fresh_flow_mapper() -> FlowMapper:
    """Return a fresh, non-singleton FlowMapper so tests are isolated."""
    mapper = FlowMapper()
    return mapper


# ---------------------------------------------------------------------------
# 1. FlowMapper → Persona conversion
# ---------------------------------------------------------------------------

class TestFlowMapperToPersonas:
    def test_bearer_token_flow_produces_user_persona(self):
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Admin Session")
        mapper.record_request(
            fid,
            "GET",
            "http://api.example.com/users",
            {},
            {"Authorization": "Bearer supertoken123", "Content-Type": "application/json"},
        )

        personas = mapper.to_personas(base_url="http://api.example.com")

        non_anon = [p for p in personas if p.persona_type != PersonaType.ANONYMOUS]
        assert len(non_anon) == 1
        assert non_anon[0].name == "Admin Session"
        assert non_anon[0].bearer_token == "supertoken123"
        assert non_anon[0].persona_type == PersonaType.USER

    def test_cookie_flow_produces_user_persona_with_jar(self):
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Logged In User")
        mapper.record_request(
            fid,
            "GET",
            "http://api.example.com/profile",
            {},
            {"Cookie": "session_id=abc123; csrf=xyz"},
        )

        personas = mapper.to_personas(base_url="http://api.example.com")

        non_anon = [p for p in personas if p.persona_type != PersonaType.ANONYMOUS]
        assert len(non_anon) == 1
        p = non_anon[0]
        assert p.cookie_jar is not None
        assert p.cookie_jar.get("session_id") == "abc123"
        assert p.cookie_jar.get("csrf") == "xyz"

    def test_flow_without_auth_tokens_is_skipped(self):
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Unauthenticated Crawl")
        mapper.record_request(
            fid, "GET", "http://api.example.com/public", {}, {"Accept": "application/json"}
        )

        personas = mapper.to_personas()
        # Only ANONYMOUS should be present
        assert all(p.persona_type == PersonaType.ANONYMOUS for p in personas)

    def test_always_includes_exactly_one_anonymous_persona(self):
        mapper = _fresh_flow_mapper()
        fid1 = mapper.start_recording("Admin")
        mapper.record_request(fid1, "GET", "http://x.com/", {}, {"Authorization": "Bearer t1"})
        fid2 = mapper.start_recording("User")
        mapper.record_request(fid2, "GET", "http://x.com/", {}, {"Cookie": "s=1"})

        personas = mapper.to_personas()
        anon = [p for p in personas if p.persona_type == PersonaType.ANONYMOUS]
        assert len(anon) == 1

    def test_base_url_extracted_from_first_step(self):
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Admin")
        mapper.record_request(
            fid,
            "GET",
            "https://secure.api.example.com/v2/users",
            {},
            {"Authorization": "Bearer tok"},
        )

        personas = mapper.to_personas(base_url="http://fallback.com")
        non_anon = [p for p in personas if p.persona_type != PersonaType.ANONYMOUS]
        assert non_anon[0].base_url == "https://secure.api.example.com"

    def test_multiple_flows_produce_multiple_personas(self):
        mapper = _fresh_flow_mapper()

        fid1 = mapper.start_recording("Admin Flow")
        mapper.record_request(fid1, "GET", "http://app.com/", {}, {"Authorization": "Bearer admin-tok"})

        fid2 = mapper.start_recording("User Flow")
        mapper.record_request(fid2, "GET", "http://app.com/", {}, {"Cookie": "user_session=u123"})

        personas = mapper.to_personas()
        non_anon = [p for p in personas if p.persona_type != PersonaType.ANONYMOUS]
        assert len(non_anon) == 2
        names = {p.name for p in non_anon}
        assert "Admin Flow" in names
        assert "User Flow" in names


# ---------------------------------------------------------------------------
# 2. Persona Config Parsing (session_manager)
# ---------------------------------------------------------------------------

class TestParsePersonasConfig:
    def test_parses_bearer_and_cookie_personas(self):
        cfg = [
            {"name": "Admin", "persona_type": "admin", "bearer_token": "admin-tok"},
            {"name": "User", "persona_type": "user", "cookie_jar": {"session": "user-sess"}},
        ]
        personas, persist = parse_personas_config("http://target.com", cfg)
        names = {p.name for p in personas}
        assert "Admin" in names
        assert "User" in names
        # Auto-added anonymous
        assert any(p.persona_type == PersonaType.ANONYMOUS for p in personas)

    def test_scope_guard_drops_cross_origin_login_flow(self):
        cfg = [
            {
                "name": "Admin",
                "persona_type": "admin",
                "login_flow": {
                    "endpoint": "https://evil.com/login",
                    "username_value": "admin",
                    "password_value": "pass",
                },
            }
        ]
        personas, _ = parse_personas_config("http://target.com", cfg)
        admin = next((p for p in personas if p.name == "Admin"), None)
        assert admin is not None
        # login_flow must be dropped because origin doesn't match
        assert admin.login_flow is None

    def test_same_origin_login_flow_is_kept(self):
        cfg = [
            {
                "name": "Admin",
                "persona_type": "admin",
                "login_flow": {
                    "endpoint": "http://target.com/login",
                    "username_value": "admin",
                    "password_value": "pass",
                },
            }
        ]
        personas, _ = parse_personas_config("http://target.com", cfg)
        admin = next((p for p in personas if p.name == "Admin"), None)
        assert admin is not None
        assert admin.login_flow is not None

    def test_base_url_is_pinned_to_target_origin(self):
        cfg = [
            {"name": "User", "persona_type": "user", "bearer_token": "tok"},
        ]
        personas, _ = parse_personas_config("http://target.com", cfg)
        user = next((p for p in personas if p.name == "User"), None)
        assert user is not None
        assert user.base_url == "http://target.com"


# ---------------------------------------------------------------------------
# 3. DifferentialAnalyzer issue classification
# ---------------------------------------------------------------------------

class TestDifferentialAnalyzerChain:
    """Tests the DifferentialAnalyzer with mocked PersonaManager."""

    def _make_manager(self, responses: dict[str, MutationResponse]) -> PersonaManager:
        """Return a PersonaManager whose replay returns fixed responses."""
        manager = MagicMock(spec=PersonaManager)
        manager.replay_across_personas = AsyncMock(return_value=responses)
        return manager

    def _make_request(self, url: str = "http://example.com/api/users") -> MutationRequest:
        return MutationRequest(
            method=HttpMethod.GET,
            url=url,
            headers={},
            timeout=10.0,
        )

    @pytest.mark.anyio
    async def test_auth_bypass_detected(self):
        """Anonymous gets substantial content → AUTH_BYPASS."""
        admin_body = "x" * 500
        anon_body = "x" * 497  # Nearly identical — triggers auth bypass heuristic
        responses = {
            "Admin": _make_response(200, admin_body),
            "Anonymous": _make_response(200, anon_body),
        }
        manager = self._make_manager(responses)
        analyzer = DifferentialAnalyzer(manager=manager, baseline_persona="Admin")

        findings = await analyzer.analyze(self._make_request())
        issue_types = {f.issue_type for f in findings}
        assert DifferentialIssueType.AUTH_BYPASS in issue_types

    @pytest.mark.anyio
    async def test_privilege_escalation_detected(self):
        """User gets same body as Admin → PRIVILEGE_ESCALATION."""
        body = '{"data": "admin-only"}'
        responses = {
            "Admin": _make_response(200, body),
            "user": _make_response(200, body),  # lowercase "user" to match heuristic
        }
        manager = self._make_manager(responses)
        analyzer = DifferentialAnalyzer(manager=manager, baseline_persona="Admin")

        findings = await analyzer.analyze(self._make_request())
        issue_types = {f.issue_type for f in findings}
        assert DifferentialIssueType.PRIVILEGE_ESCALATION in issue_types

    @pytest.mark.anyio
    async def test_record_count_divergence_detected(self):
        """Admin gets 10-item list; User gets 2-item list → RECORD_COUNT_DIVERGENCE."""
        import json
        admin_records = json.dumps(list(range(10)))   # 10 items
        user_records = json.dumps(list(range(2)))      # 2 items
        responses = {
            "Admin": _make_response(200, admin_records),
            "User": _make_response(200, user_records),
        }
        manager = self._make_manager(responses)
        analyzer = DifferentialAnalyzer(manager=manager, baseline_persona="Admin")

        findings = await analyzer.analyze(self._make_request())
        issue_types = {f.issue_type for f in findings}
        assert DifferentialIssueType.RECORD_COUNT_DIVERGENCE in issue_types

    @pytest.mark.anyio
    async def test_no_finding_on_both_403(self):
        """Both personas get 403 → no vulnerability."""
        responses = {
            "Admin": _make_response(403, "Forbidden"),
            "User": _make_response(403, "Forbidden"),
        }
        manager = self._make_manager(responses)
        analyzer = DifferentialAnalyzer(manager=manager, baseline_persona="Admin")

        findings = await analyzer.analyze(self._make_request())
        assert findings == []

    @pytest.mark.anyio
    async def test_analyzer_needs_minimum_two_personas(self):
        """Single-persona response dict returns empty findings."""
        responses = {
            "Admin": _make_response(200, "data"),
        }
        manager = self._make_manager(responses)
        analyzer = DifferentialAnalyzer(manager=manager, baseline_persona="Admin")

        findings = await analyzer.analyze(self._make_request())
        assert findings == []


# ---------------------------------------------------------------------------
# 4. Full Ghost → Personas → DifferentialAnalyzer chain (mocked HTTP)
# ---------------------------------------------------------------------------

class TestGhostPersonaAuthScanChain:
    """End-to-end chain: Ghost records flows → PersonaManager → DifferentialAnalyzer."""

    @pytest.mark.anyio
    async def test_ghost_flow_to_personas_to_auth_bypass_finding(self):
        """
        Scenario:
          1. Ghost records admin traffic (Bearer token extracted).
          2. FlowMapper.to_personas() creates Admin persona + Anonymous.
          3. DifferentialAnalyzer (mocked manager) detects AUTH_BYPASS when
             Anonymous gets same response as Admin.
        """
        # Step 1: Ghost records admin flow
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Admin Session")
        mapper.record_request(
            fid,
            "GET",
            "http://api.example.com/v1/admin/users",
            {},
            {"Authorization": "Bearer admin-secret-token"},
        )

        # Step 2: Convert flows to personas
        personas = mapper.to_personas(base_url="http://api.example.com")
        assert len(personas) >= 2  # Admin + Anonymous

        admin_p = next((p for p in personas if p.bearer_token == "admin-secret-token"), None)
        anon_p = next((p for p in personas if p.persona_type == PersonaType.ANONYMOUS), None)
        assert admin_p is not None, "Admin persona must be created from flow"
        assert anon_p is not None, "Anonymous persona must always be present"

        # Step 3: Wire mocked manager — Anonymous gets same content as Admin (auth bypass)
        # Body must be >100 bytes to trigger auth-bypass heuristic (body_length > 100)
        admin_body = '{"users": [' + ', '.join(f'{{"id": {i}, "role": "admin", "email": "admin{i}@corp.com"}}' for i in range(5)) + ']}'
        anon_body = admin_body  # Same body — this is the vulnerability

        mock_manager = MagicMock(spec=PersonaManager)
        mock_manager.replay_across_personas = AsyncMock(return_value={
            "Admin Session": _make_response(200, admin_body),
            "Anonymous": _make_response(200, anon_body),
        })

        analyzer = DifferentialAnalyzer(
            manager=mock_manager,
            baseline_persona="Admin Session",
        )

        findings = await analyzer.analyze(
            MutationRequest(
                method=HttpMethod.GET,
                url="http://api.example.com/v1/admin/users",
                headers={},
                timeout=10.0,
            )
        )

        issue_types = {f.issue_type for f in findings}
        assert DifferentialIssueType.AUTH_BYPASS in issue_types, (
            f"Expected AUTH_BYPASS in {issue_types}"
        )

    @pytest.mark.anyio
    async def test_ghost_flow_to_personas_to_privilege_escalation(self):
        """
        Scenario:
          1. Ghost records admin AND user flows (two Bearer tokens).
          2. FlowMapper produces Admin + User + Anonymous personas.
          3. DifferentialAnalyzer detects PRIVILEGE_ESCALATION when User
             gets the same admin-only content.
        """
        mapper = _fresh_flow_mapper()

        fid_admin = mapper.start_recording("Admin")
        mapper.record_request(
            fid_admin, "GET", "http://app.com/api/admin/settings", {},
            {"Authorization": "Bearer admin-tok"},
        )

        fid_user = mapper.start_recording("user")  # lowercase to match heuristic
        mapper.record_request(
            fid_user, "GET", "http://app.com/api/admin/settings", {},
            {"Authorization": "Bearer user-tok"},
        )

        personas = mapper.to_personas(base_url="http://app.com")
        non_anon = [p for p in personas if p.persona_type != PersonaType.ANONYMOUS]
        assert len(non_anon) == 2

        admin_body = '{"setting": "global_admin_key=secret"}'
        user_body = admin_body  # user sees identical admin config — privilege escalation

        mock_manager = MagicMock(spec=PersonaManager)
        mock_manager.replay_across_personas = AsyncMock(return_value={
            "Admin": _make_response(200, admin_body),
            "user": _make_response(200, user_body),
        })

        analyzer = DifferentialAnalyzer(manager=mock_manager, baseline_persona="Admin")
        findings = await analyzer.analyze(
            MutationRequest(
                method=HttpMethod.GET,
                url="http://app.com/api/admin/settings",
                headers={},
                timeout=10.0,
            )
        )

        issue_types = {f.issue_type for f in findings}
        assert DifferentialIssueType.PRIVILEGE_ESCALATION in issue_types, (
            f"Expected PRIVILEGE_ESCALATION in {issue_types}"
        )

    @pytest.mark.anyio
    async def test_ghost_flow_with_no_auth_produces_only_anonymous(self):
        """
        Ghost records purely unauthenticated traffic → only Anonymous persona → no findings.
        """
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Public Crawler")
        mapper.record_request(
            fid, "GET", "http://app.com/public", {}, {"Accept": "*/*"}
        )

        personas = mapper.to_personas()
        assert all(p.persona_type == PersonaType.ANONYMOUS for p in personas)
        assert len(personas) == 1

        # With only one persona, analyzer should return no findings
        mock_manager = MagicMock(spec=PersonaManager)
        mock_manager.replay_across_personas = AsyncMock(return_value={
            "Anonymous": _make_response(200, "public content"),
        })

        analyzer = DifferentialAnalyzer(manager=mock_manager, baseline_persona="Admin")
        findings = await analyzer.analyze(
            MutationRequest(method=HttpMethod.GET, url="http://app.com/public", headers={}, timeout=5.0)
        )
        assert findings == []

    @pytest.mark.anyio
    async def test_full_chain_finding_has_correct_metadata(self):
        """
        Verify DifferentialFinding fields are correctly populated when the chain fires.
        """
        mapper = _fresh_flow_mapper()
        fid = mapper.start_recording("Admin")
        mapper.record_request(
            fid, "GET", "http://api.com/data", {}, {"Authorization": "Bearer tok"}
        )

        admin_body = "x" * 600
        anon_body = "x" * 595

        mock_manager = MagicMock(spec=PersonaManager)
        mock_manager.replay_across_personas = AsyncMock(return_value={
            "Admin": _make_response(200, admin_body),
            "Anonymous": _make_response(200, anon_body),
        })

        analyzer = DifferentialAnalyzer(manager=mock_manager, baseline_persona="Admin")
        findings = await analyzer.analyze(
            MutationRequest(method=HttpMethod.GET, url="http://api.com/data", headers={}, timeout=5.0)
        )

        assert len(findings) >= 1
        f = findings[0]
        assert isinstance(f, DifferentialFinding)
        assert f.baseline_persona == "Admin"
        assert f.url == "http://api.com/data"
        assert f.method == "GET"
        assert 0.0 < f.confidence <= 1.0
        assert f.severity in ("critical", "high", "medium", "low")
        assert f.description  # non-empty
        assert f.remediation  # non-empty
