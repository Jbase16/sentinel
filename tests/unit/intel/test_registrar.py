"""
Tests for the auto-registration registrar (Phase 2D).

The critical contracts are the THREE GATES — all three must block when
they should block. We test each gate independently and in combination.

Other tested behavior:
  - Credentials generated are unguessable (different on each call)
  - Default email domain is example.com (sinkhole, no real-user spam)
  - Generated Persona has source=AUTO_REGISTERED and confidence=0.8
  - Successful signup → verifier called → persona.verified set
  - Network errors return a report with the failure reason set
  - The registrar reuses an existing persona's login_flow shape when possible
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

import pytest

from core.intel.program_scope import (
    CredentialSource,
    LoginFlow,
    Persona,
    Platform,
    ProgramScope,
    Restriction,
    RestrictionKind,
    ScopeRule,
    ScopeRuleType,
    VerificationStatus,
)
from core.intel.registrar import (
    RegistrationFlow,
    RegistrationReport,
    _check_policy_authorization,
    _find_blocking_restriction,
    _infer_base_url,
    auto_register,
)


# ─────────────────────────── Helpers ───────────────────────────────

class _FakeResponse:
    def __init__(self, *, status_code=200, json_body=None, cookies=None):
        self.status_code = status_code
        self._json_body = json_body or {}
        self.cookies = cookies or {}

    def json(self):
        return self._json_body


class _FakeClient:
    """Programmable async client that returns the next response from
    a queue. Records every request for inspection.

    Why a queue: auto-register makes TWO requests in the happy path —
    POST /signup and POST /login (the verifier). Tests need to script
    both responses independently.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("FakeClient: no programmed response left")
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _make_factory(*responses):
    """Return a factory callable that yields the same _FakeClient
    (so it sees both signup and verify-login requests)."""
    client = _FakeClient(list(responses))

    def factory():
        return client

    factory.client = client
    return factory


def _scope_with_authorization(*personas, restrictions=None, signup_endpoint=None) -> ProgramScope:
    """Build a scope that has an authorization keyword in its text so
    gate 3 passes by default."""
    base_restrictions = list(restrictions or [])
    if not any(r for r in base_restrictions if "researchers may create" in (r.description or "").lower()):
        # Synthesize one so policy gate passes.
        base_restrictions.append(Restriction(
            kind=RestrictionKind.OTHER,
            severity="soft",
            description="Researchers may create accounts for differential testing.",
        ))
    return ProgramScope(
        handle="test",
        platform=Platform.HACKERONE,
        name="Test",
        source_url="https://hackerone.com/test/policy",
        fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        personas=list(personas),
        scope_rules=[
            ScopeRule(pattern="app.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        ],
        signup_endpoint=signup_endpoint,
        restrictions=base_restrictions,
    )


# ─────────────────────────── Gate 1: opt-in ────────────────────────

class TestGate1OperatorOptIn:
    async def test_default_off_blocks_registration(self):
        scope = _scope_with_authorization()
        report = await auto_register(scope, http_factory=_make_factory())
        assert report.attempted is False
        assert report.succeeded is False
        assert report.blocked_reason == "not_authorized_by_operator"

    async def test_explicit_false_blocks_registration(self):
        scope = _scope_with_authorization()
        report = await auto_register(
            scope, allow_auto_register=False, http_factory=_make_factory(),
        )
        assert report.attempted is False
        assert report.blocked_reason == "not_authorized_by_operator"


# ─────────────────────────── Gate 2: hard restriction ──────────────

class TestGate2HardRestriction:
    async def test_no_automated_scan_hard_blocks(self):
        scope = _scope_with_authorization(restrictions=[
            Restriction(
                kind=RestrictionKind.NO_AUTOMATED_SCAN, severity="hard",
                description="No automated scanning.",
                raw_quote="Automated scanning is prohibited.",
            ),
        ])
        report = await auto_register(
            scope, allow_auto_register=True, http_factory=_make_factory(),
        )
        assert report.attempted is False
        assert report.blocked_reason == "hard_restriction_blocks"
        assert report.raw_quote == "Automated scanning is prohibited."

    async def test_no_automated_scan_soft_does_not_block(self):
        # Soft restrictions warn but proceed.
        scope = _scope_with_authorization(restrictions=[
            Restriction(
                kind=RestrictionKind.NO_AUTOMATED_SCAN, severity="soft",
                description="Please limit automated scanning.",
            ),
        ])
        report = await auto_register(
            scope, allow_auto_register=True,
            force_policy_check=False,  # bypass gate 3 for this test
            http_factory=_make_factory(
                _FakeResponse(status_code=201),  # signup OK
                _FakeResponse(status_code=200, json_body={"token": "abc"}),  # verify OK
            ),
        )
        assert report.succeeded is True

    async def test_other_hard_restrictions_dont_block_signup(self):
        # NO_DOS, NO_BRUTEFORCE, etc. are hard restrictions but they
        # don't bar signup specifically — only NO_AUTOMATED_SCAN does.
        scope = _scope_with_authorization(restrictions=[
            Restriction(kind=RestrictionKind.NO_DOS, severity="hard", description="No DoS"),
            Restriction(kind=RestrictionKind.NO_BRUTEFORCE, severity="hard", description="No BF"),
        ])
        report = await auto_register(
            scope, allow_auto_register=True,
            force_policy_check=False,
            http_factory=_make_factory(
                _FakeResponse(status_code=201),
                _FakeResponse(status_code=200, json_body={"token": "x"}),
            ),
        )
        assert report.succeeded is True


# ─────────────────────────── Gate 3: policy authorization ──────────

class TestGate3PolicyAuthorization:
    async def test_blocks_when_no_authorization_keyword(self):
        # Policy text mentions nothing about signup — should block.
        scope = ProgramScope(
            handle="test", platform=Platform.HACKERONE,
            name="Test", source_url="https://x.com",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
            scope_rules=[
                ScopeRule(pattern="x.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ],
            restrictions=[
                Restriction(
                    kind=RestrictionKind.OTHER, severity="soft",
                    description="some other text with nothing about signup",
                ),
            ],
        )
        report = await auto_register(
            scope, allow_auto_register=True, http_factory=_make_factory(),
        )
        assert report.attempted is False
        assert report.blocked_reason == "no_explicit_authorization"

    async def test_force_policy_check_false_bypasses_gate3(self):
        # Operator who's manually confirmed authorization can override.
        scope = ProgramScope(
            handle="test", platform=Platform.HACKERONE,
            name="Test", source_url="https://x.com",
            fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
            scope_rules=[
                ScopeRule(pattern="x.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
            ],
        )
        report = await auto_register(
            scope, allow_auto_register=True,
            force_policy_check=False,
            http_factory=_make_factory(
                _FakeResponse(status_code=201),
                _FakeResponse(status_code=200, json_body={"token": "x"}),
            ),
        )
        assert report.succeeded is True

    async def test_authorization_keyword_in_description_passes(self):
        scope = _scope_with_authorization()  # has the keyword baked in
        report = await auto_register(
            scope, allow_auto_register=True,
            http_factory=_make_factory(
                _FakeResponse(status_code=201),
                _FakeResponse(status_code=200, json_body={"token": "x"}),
            ),
        )
        assert report.succeeded is True


# ─────────────────────────── Successful registration ───────────────

class TestSuccessfulRegistration:
    async def test_creates_persona_with_auto_registered_source(self):
        scope = _scope_with_authorization()
        report = await auto_register(
            scope, allow_auto_register=True,
            http_factory=_make_factory(
                _FakeResponse(status_code=201),
                _FakeResponse(status_code=200, json_body={"token": "abc123"}),
            ),
        )
        assert report.persona is not None
        assert report.persona.source == CredentialSource.AUTO_REGISTERED
        assert report.persona.persona_type == "user"
        # The verifier should have run — token at 'token' path returned a
        # value, so login is verified.
        assert report.persona.verified == VerificationStatus.VERIFIED

    async def test_signup_endpoint_from_scope_is_used(self):
        scope = _scope_with_authorization(signup_endpoint="/custom/register")
        factory = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        await auto_register(scope, allow_auto_register=True, http_factory=factory)
        signup_call = factory.client.calls[0]
        assert "/custom/register" in signup_call["url"]

    async def test_signup_endpoint_defaults_when_none_in_scope(self):
        scope = _scope_with_authorization()  # no signup_endpoint set
        factory = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        await auto_register(scope, allow_auto_register=True, http_factory=factory)
        signup_call = factory.client.calls[0]
        # First candidate is /api/signup.
        assert "/api/signup" in signup_call["url"]

    async def test_login_flow_reuses_existing_persona_shape(self):
        existing = Persona(
            name="existing",
            persona_type="user",
            base_url="https://app.example.com",
            username="existing@x.com",
            password="x",
            login_flow=LoginFlow(
                endpoint="/auth/v2/login",
                method="POST",
                username_param="user_email",  # nonstandard
                password_param="user_pw",     # nonstandard
                content_type="application/json",
                token_extract_path="data.session.token",
            ),
        )
        scope = _scope_with_authorization(existing)
        report = await auto_register(
            scope, allow_auto_register=True,
            http_factory=_make_factory(
                _FakeResponse(status_code=201),
                _FakeResponse(status_code=200, json_body={
                    "data": {"session": {"token": "abc"}},
                }),
            ),
        )
        assert report.persona is not None
        # The new persona's login_flow mirrors the existing one.
        assert report.persona.login_flow.endpoint == "/auth/v2/login"
        assert report.persona.login_flow.username_param == "user_email"
        assert report.persona.login_flow.token_extract_path == "data.session.token"

    async def test_signup_failure_marks_report_unsucceeded(self):
        scope = _scope_with_authorization()
        report = await auto_register(
            scope, allow_auto_register=True,
            http_factory=_make_factory(_FakeResponse(status_code=409)),  # email taken / conflict
        )
        assert report.succeeded is False
        assert report.attempted is True
        assert "http_409" in (report.blocked_reason or "")

    async def test_verify_failure_marks_persona_failed(self):
        scope = _scope_with_authorization()
        report = await auto_register(
            scope, allow_auto_register=True,
            http_factory=_make_factory(
                _FakeResponse(status_code=201),                              # signup OK
                _FakeResponse(status_code=401, json_body={"error": "nope"}),  # login fails
            ),
        )
        # Signup succeeded but verify did not.
        assert report.succeeded is True  # signup itself worked
        assert report.persona is not None
        assert report.persona.verified == VerificationStatus.FAILED

    async def test_network_error_during_signup_returns_report(self):
        import httpx
        scope = _scope_with_authorization()
        report = await auto_register(
            scope, allow_auto_register=True,
            http_factory=_make_factory(httpx.ConnectError("dns")),
        )
        assert report.succeeded is False
        assert "network_error" in (report.blocked_reason or "")


# ─────────────────────────── Credential generation ─────────────────

class TestCredentialGeneration:
    """The two cred properties that matter for security/safety:

      1. Email defaults to example.com — won't bounce-spam real users.
      2. Passwords are cryptographically random — unguessable.
    """

    async def test_email_defaults_to_example_com_sinkhole(self):
        scope = _scope_with_authorization()
        factory = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        await auto_register(scope, allow_auto_register=True, http_factory=factory)
        signup_call = factory.client.calls[0]
        sent_email = signup_call["json"]["email"]
        assert sent_email.endswith("@example.com")

    async def test_custom_email_domain_used_when_set(self):
        scope = _scope_with_authorization()
        factory = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        await auto_register(
            scope, allow_auto_register=True,
            email_domain="my-disposable-mailbox.test",
            http_factory=factory,
        )
        sent_email = factory.client.calls[0]["json"]["email"]
        assert sent_email.endswith("@my-disposable-mailbox.test")

    async def test_passwords_are_different_each_call(self):
        scope = _scope_with_authorization()
        factory1 = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        factory2 = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        report1 = await auto_register(scope, allow_auto_register=True, http_factory=factory1)
        report2 = await auto_register(scope, allow_auto_register=True, http_factory=factory2)
        assert report1.persona.password != report2.persona.password
        assert report1.persona.username != report2.persona.username

    async def test_passwords_are_long_enough_to_be_unguessable(self):
        scope = _scope_with_authorization()
        factory = _make_factory(
            _FakeResponse(status_code=201),
            _FakeResponse(status_code=200, json_body={"token": "x"}),
        )
        report = await auto_register(scope, allow_auto_register=True, http_factory=factory)
        # At least 20 chars — 32-char secrets.token_urlsafe(24) is the spec.
        assert len(report.persona.password) >= 20


# ─────────────────────────── _check_policy_authorization ───────────

class TestPolicyAuthorizationCheck:
    """Lock in the conservative keyword behavior."""

    def _scope_with_text(self, text: str) -> ProgramScope:
        return ProgramScope(
            handle="t", platform=Platform.HACKERONE, name="Test",
            source_url="https://x", fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            restrictions=[Restriction(
                kind=RestrictionKind.OTHER, severity="soft", description=text,
            )],
        )

    def test_authorization_phrases_match_case_insensitively(self):
        scope = self._scope_with_text(
            "Researchers MAY CREATE accounts for differential testing."
        )
        ok, phrase = _check_policy_authorization(scope)
        assert ok is True

    def test_silence_blocks(self):
        scope = self._scope_with_text("This is some other policy text.")
        ok, _ = _check_policy_authorization(scope)
        assert ok is False

    def test_each_phrase_matches_independently(self):
        for phrase in (
            "Create a test account on app.example.com.",
            "You may create accounts for testing.",
            "Researchers may create their own accounts.",
            "Sign up to test the API.",
        ):
            scope = self._scope_with_text(phrase)
            ok, _ = _check_policy_authorization(scope)
            assert ok, f"Expected authorization for: {phrase!r}"


# ─────────────────────────── _find_blocking_restriction ────────────

class TestFindBlockingRestriction:
    def test_returns_none_for_empty_list(self):
        assert _find_blocking_restriction([]) is None

    def test_returns_no_automated_scan_hard(self):
        r = Restriction(
            kind=RestrictionKind.NO_AUTOMATED_SCAN, severity="hard", description="x",
        )
        assert _find_blocking_restriction([r]) is r

    def test_ignores_no_automated_scan_soft(self):
        r = Restriction(
            kind=RestrictionKind.NO_AUTOMATED_SCAN, severity="soft", description="x",
        )
        assert _find_blocking_restriction([r]) is None

    def test_ignores_other_hard_restrictions(self):
        for kind in (
            RestrictionKind.NO_DOS, RestrictionKind.NO_BRUTEFORCE,
            RestrictionKind.NO_SOCIAL_ENG, RestrictionKind.RATE_LIMITED,
        ):
            r = Restriction(kind=kind, severity="hard", description="x")
            assert _find_blocking_restriction([r]) is None


# ─────────────────────────── _infer_base_url ───────────────────────

class TestInferBaseUrl:
    def _scope_with(self, *, scope_rules=None, personas=None, source_url="https://h1.com/x"):
        return ProgramScope(
            handle="t", platform=Platform.HACKERONE, name="Test",
            source_url=source_url,
            fetched_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            scope_rules=scope_rules or [],
            personas=personas or [],
        )

    def test_in_scope_domain_wins(self):
        scope = self._scope_with(scope_rules=[
            ScopeRule(pattern="app.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        ])
        assert _infer_base_url(scope) == "https://app.example.com"

    def test_wildcard_does_not_count_as_base_url(self):
        # *.example.com is not a single concrete host to register against.
        scope = self._scope_with(scope_rules=[
            ScopeRule(pattern="*.example.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        ])
        # Falls through to source_url fallback.
        assert _infer_base_url(scope) == "https://h1.com"

    def test_persona_base_url_used_when_no_scope_domain(self):
        scope = self._scope_with(personas=[
            Persona(name="u", persona_type="user", base_url="https://app.example.com"),
        ])
        assert _infer_base_url(scope) == "https://app.example.com"

    def test_source_url_fallback(self):
        scope = self._scope_with(source_url="https://example.com/security/policy")
        assert _infer_base_url(scope) == "https://example.com"
