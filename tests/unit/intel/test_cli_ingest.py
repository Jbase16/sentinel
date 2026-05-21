"""
Integration tests for scripts/sentinel_ingest.py (Phase 2F).

These tests exercise the full pipeline end-to-end with mocked HTTP and
LLM. They lock in the contracts the operator depends on:

  1. Unresolved identifier → exit 4
  2. Failed extraction → exit 1
  3. Hard NO_AUTOMATED_SCAN restriction → exit 2
  4. Required attestation without --accept-attestations → exit 3
  5. Successful happy path → exit 0, all four files written
  6. Output files are parseable by their downstream consumers
     (round-trip with engine parsers, same as Phase 2C contract tests)
  7. --skip-verify actually skips the verifier (no login HTTP)
  8. --allow-auto-register triggers the registrar path
"""
from __future__ import annotations

import importlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from unittest.mock import AsyncMock, patch

import pytest

# Import the script as a module so we can call its functions directly.
# This is the same pattern the existing test_command_validation suite
# uses to test pysentinel.
_REPO = Path(__file__).resolve().parents[3]
if str(_REPO / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO / "scripts"))

sentinel_ingest = importlib.import_module("sentinel_ingest")
from core.intel.program_scope import (
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


# ─────────────────────────── Builder helpers ───────────────────────

def _program_scope(
    *,
    handle: str = "test",
    platform: Platform = Platform.HACKERONE,
    restrictions: Optional[List[Restriction]] = None,
    personas: Optional[List[Persona]] = None,
) -> ProgramScope:
    return ProgramScope(
        handle=handle,
        platform=platform,
        name="Test Program",
        source_url=f"https://hackerone.com/{handle}/policy",
        fetched_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        scope_rules=[
            ScopeRule(pattern="*.test.com", rule_type=ScopeRuleType.DOMAIN, in_scope=True),
        ],
        personas=personas or [],
        restrictions=restrictions or [],
        raw_content_hash="0" * 64,
        extractor_version="test@1.0",
        extraction_confidence=0.85,
    )


class _FakeExtractor:
    """Stand-in extractor that returns a programmed scope."""

    name = "test-fake"
    version = "1.0"
    version_stamp = "test-fake@1.0"

    def __init__(self, returns: Optional[ProgramScope]):
        self.returns = returns

    def can_handle(self, identifier: str) -> bool:
        return identifier.startswith("fake:")

    async def extract(self, identifier: str) -> Optional[ProgramScope]:
        return self.returns


# ─────────────────────────── Exit-code contracts ───────────────────

class TestExitCodes:
    """Lock in the documented exit-code contract — shell wrappers depend
    on these values being stable."""

    def test_constants_are_stable(self):
        # If any of these values change, every wrapper script that branches
        # on the exit code breaks. Bumping them is a contract break.
        assert sentinel_ingest.EXIT_OK == 0
        assert sentinel_ingest.EXIT_GENERIC_ERROR == 1
        assert sentinel_ingest.EXIT_BLOCKED_BY_RESTRICTION == 2
        assert sentinel_ingest.EXIT_OPERATOR_CANCELLED == 3
        assert sentinel_ingest.EXIT_UNRESOLVED == 4


# ─────────────────────────── Unresolved identifier ─────────────────

class TestUnresolved:
    async def test_returns_exit_4_when_no_extractor_matches(self, tmp_path, capsys):
        """A bare handle with no platform prefix matches no extractor."""
        args = _make_args(program="not-a-real-identifier", out_dir=tmp_path)
        code = await sentinel_ingest.run(args)
        assert code == sentinel_ingest.EXIT_UNRESOLVED


# ─────────────────────────── Extraction failure ────────────────────

class TestExtractionFailure:
    async def test_returns_exit_1_when_extractor_returns_none(self, tmp_path):
        # Patch the resolver to return our fake extractor that yields None.
        fake = _FakeExtractor(returns=None)
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([fake]),
        ):
            args = _make_args(program="fake:foo", out_dir=tmp_path)
            code = await sentinel_ingest.run(args)
        assert code == sentinel_ingest.EXIT_GENERIC_ERROR


# ─────────────────────────── Hard restriction blocks ───────────────

class TestHardRestrictionBlocks:
    async def test_no_automated_scan_hard_returns_exit_2(self, tmp_path):
        scope = _program_scope(restrictions=[
            Restriction(
                kind=RestrictionKind.NO_AUTOMATED_SCAN, severity="hard",
                description="Automated scanning prohibited.",
            ),
        ])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path)
            code = await sentinel_ingest.run(args)
        assert code == sentinel_ingest.EXIT_BLOCKED_BY_RESTRICTION

    async def test_no_dos_hard_does_NOT_block_scan_just_disables_tools(self, tmp_path):
        scope = _program_scope(restrictions=[
            Restriction(
                kind=RestrictionKind.NO_DOS, severity="hard",
                description="No DoS testing.",
            ),
        ])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path)
            code = await sentinel_ingest.run(args)
        # Exit OK — NO_DOS disables certain tools but doesn't block scan.
        assert code == sentinel_ingest.EXIT_OK


# ─────────────────────────── Attestation gate ──────────────────────

class TestAttestationGate:
    async def test_requires_prior_approval_blocks_without_accept_flag(self, tmp_path):
        scope = _program_scope(restrictions=[
            Restriction(
                kind=RestrictionKind.REQUIRES_PRIOR_APPROVAL, severity="hard",
                description="Contact the program manager before scanning.",
            ),
        ])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path)
            code = await sentinel_ingest.run(args)
        assert code == sentinel_ingest.EXIT_OPERATOR_CANCELLED

    async def test_accept_attestations_flag_unblocks(self, tmp_path):
        scope = _program_scope(restrictions=[
            Restriction(
                kind=RestrictionKind.REQUIRES_PRIOR_APPROVAL, severity="hard",
                description="Contact PM.",
            ),
        ])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path, accept_attestations=True)
            code = await sentinel_ingest.run(args)
        assert code == sentinel_ingest.EXIT_OK


# ─────────────────────────── Happy path: files written ─────────────

class TestSuccessfulIngest:
    async def test_writes_all_four_files(self, tmp_path):
        scope = _program_scope(handle="example")
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path, skip_verify=True)
            code = await sentinel_ingest.run(args)
        assert code == sentinel_ingest.EXIT_OK
        # All four expected files exist.
        assert (tmp_path / "example-program-scope.json").exists()
        assert (tmp_path / "example-scope.txt").exists()
        assert (tmp_path / "example-personas.json").exists()
        assert (tmp_path / "example-restrictions.json").exists()

    async def test_program_scope_json_is_valid(self, tmp_path):
        scope = _program_scope(handle="rt")
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path, skip_verify=True)
            await sentinel_ingest.run(args)

        # Round-trip: load and reconstruct.
        text = (tmp_path / "rt-program-scope.json").read_text()
        loaded = ProgramScope.from_json(text)
        assert loaded.handle == "rt"
        assert loaded.name == scope.name

    async def test_personas_json_loads_with_pysentinel_loader(self, tmp_path):
        # Persona with credentials so it survives the compiler's filter.
        persona = Persona(
            name="researcher",
            persona_type="user",
            base_url="https://test.com",
            username="t@t.com",
            password="x",
            login_flow=LoginFlow(endpoint="/login"),
            verified=VerificationStatus.VERIFIED,
        )
        scope = _program_scope(handle="ld", personas=[persona])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ):
            args = _make_args(program="fake:x", out_dir=tmp_path, skip_verify=True)
            await sentinel_ingest.run(args)

        # Load it the way pysentinel actually loads personas.
        from pysentinel import _load_personas_file
        loaded = _load_personas_file(str(tmp_path / "ld-personas.json"))
        assert isinstance(loaded, list)
        names = [p["name"] for p in loaded]
        # researcher is in there, plus the auto-synthesized anonymous.
        assert "researcher" in names
        assert "anonymous" in names


# ─────────────────────────── Verification skipping ─────────────────

class TestSkipVerify:
    async def test_skip_verify_does_not_call_verifier(self, tmp_path):
        scope = _program_scope(handle="sv", personas=[
            Persona(
                name="u", persona_type="user", base_url="https://x",
                username="a@b.c", password="x",
                login_flow=LoginFlow(endpoint="/login"),
            ),
        ])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ), patch.object(sentinel_ingest, "verify", new_callable=AsyncMock) as mock_verify:
            args = _make_args(program="fake:x", out_dir=tmp_path, skip_verify=True)
            await sentinel_ingest.run(args)
            assert mock_verify.called is False

    async def test_default_calls_verifier(self, tmp_path):
        scope = _program_scope(handle="dv", personas=[
            Persona(
                name="u", persona_type="user", base_url="https://x",
                username="a@b.c", password="x",
                login_flow=LoginFlow(endpoint="/login"),
            ),
        ])
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ), patch.object(sentinel_ingest, "verify", new_callable=AsyncMock) as mock_verify:
            args = _make_args(program="fake:x", out_dir=tmp_path)
            await sentinel_ingest.run(args)
            assert mock_verify.called is True


# ─────────────────────────── Auto-register flag ────────────────────

class TestAllowAutoRegister:
    async def test_registrar_called_when_flag_set(self, tmp_path):
        scope = _program_scope(handle="ar")
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ), patch.object(
            sentinel_ingest, "auto_register", new_callable=AsyncMock,
        ) as mock_register:
            # Return a "blocked" report so we don't actually mutate.
            from core.intel.registrar import RegistrationReport
            mock_register.return_value = RegistrationReport(
                attempted=False, succeeded=False,
                blocked_reason="no_explicit_authorization",
            )
            args = _make_args(
                program="fake:x", out_dir=tmp_path, skip_verify=True,
                allow_auto_register=True,
            )
            await sentinel_ingest.run(args)
            assert mock_register.called is True

    async def test_registrar_not_called_by_default(self, tmp_path):
        scope = _program_scope(handle="nr")
        with patch.object(
            sentinel_ingest, "default_resolver",
            return_value=_FakeResolver([_FakeExtractor(returns=scope)]),
        ), patch.object(
            sentinel_ingest, "auto_register", new_callable=AsyncMock,
        ) as mock_register:
            args = _make_args(program="fake:x", out_dir=tmp_path, skip_verify=True)
            await sentinel_ingest.run(args)
            assert mock_register.called is False


# ─────────────────────────── argparse / main ───────────────────────

class TestArgparse:
    def test_main_returns_exit_code_via_asyncio_run(self):
        # main() shells out to asyncio.run(run(args)) — just check it
        # doesn't crash on a valid argv. Use an unresolved identifier
        # so we get exit 4 quickly without any external dependencies.
        code = sentinel_ingest.main([
            "--program", "no-such-identifier",
            "--out-dir", tempfile.mkdtemp(),
        ])
        assert code == sentinel_ingest.EXIT_UNRESOLVED

    def test_missing_program_arg_errors(self):
        with pytest.raises(SystemExit):
            sentinel_ingest.main([])


# ─────────────────────────── Plumbing ──────────────────────────────

class _FakeResolver:
    def __init__(self, extractors):
        self._extractors = list(extractors)

    def resolve(self, identifier):
        for e in self._extractors:
            if e.can_handle(identifier):
                return e
        return None


def _make_args(
    *,
    program: str,
    out_dir,
    skip_verify: bool = False,
    allow_auto_register: bool = False,
    register_as: str = "user",
    email_domain: str = "example.com",
    force: bool = False,
    accept_attestations: bool = False,
    verbose: bool = False,
):
    """Build an args namespace matching the argparse parser's defaults."""
    import argparse
    return argparse.Namespace(
        program=program,
        out_dir=str(out_dir),
        skip_verify=skip_verify,
        allow_auto_register=allow_auto_register,
        register_as=register_as,
        email_domain=email_domain,
        force=force,
        accept_attestations=accept_attestations,
        verbose=verbose,
    )
