#!/usr/bin/env python3
"""
sentinel-ingest — Phase 2F CLI for program scope ingestion.

Resolves a bug bounty program identifier (HackerOne handle, Bugcrowd
handle, or arbitrary policy URL) and produces:

    <out-dir>/<handle>-program-scope.json    # full ProgramScope (cache)
    <out-dir>/<handle>-scope.txt             # text scope rules
    <out-dir>/<handle>-personas.json         # wraith-compatible personas
    <out-dir>/<handle>-restrictions.json     # restrictions + enforcement

Usage:

    sentinel-ingest --program hackerone:gitlab
    sentinel-ingest --program bugcrowd:tesla --out-dir ./scopes/
    sentinel-ingest --program https://example.com/security
    sentinel-ingest --program hackerone:foo --allow-auto-register

Exit codes:

    0   Success — config files produced
    1   Generic error (network, parse, etc.)
    2   Blocked by a hard restriction (downstream scan should not run)
    3   Operator cancelled / missing attestation
    4   Could not resolve identifier (no extractor matched)

Design — see ``docs/PHASE_2_DESIGN.md``.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Path setup so this works whether run from repo root or as installed script.
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from core.intel import (
    Persona,
    ProgramScope,
    VerificationStatus,
    default_resolver,
    verify,
)
from core.intel.compilers import (
    compile_personas_json,
    compile_restrictions_json,
    compile_scope_file,
)
from core.intel.extractors.base import ExtractorError
from core.intel.policy_enforcer import enforce_from_file
from core.intel.registrar import RegistrationReport, auto_register

logger = logging.getLogger(__name__)


# Exit-code constants — referenced in the module docstring and in
# shell-level wrappers. Bumping any of these is a contract break.
EXIT_OK = 0
EXIT_GENERIC_ERROR = 1
EXIT_BLOCKED_BY_RESTRICTION = 2
EXIT_OPERATOR_CANCELLED = 3
EXIT_UNRESOLVED = 4


async def run(args: argparse.Namespace) -> int:
    """Run the ingest pipeline. Returns the exit code."""
    _configure_logging(args.verbose)

    # ─── 1. Resolve identifier → extractor ────────────────────────────
    resolver = default_resolver()
    extractor = resolver.resolve(args.program)
    if extractor is None:
        print(
            f"❌ No extractor matched identifier {args.program!r}.\n"
            f"   Use one of:\n"
            f"     hackerone:<handle>\n"
            f"     bugcrowd:<handle>\n"
            f"     https://hackerone.com/<handle>\n"
            f"     https://bugcrowd.com/<handle>\n"
            f"     https://<any-policy-url>",
            file=sys.stderr,
        )
        return EXIT_UNRESOLVED

    print(f"→ Resolved {args.program!r} → {extractor.version_stamp}", file=sys.stderr)

    # ─── 2. Extract ───────────────────────────────────────────────────
    try:
        scope = await extractor.extract(args.program)
    except ExtractorError as e:
        print(f"❌ Extractor rejected input: {e}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    if scope is None:
        print(
            f"❌ Extraction failed (network error, LLM unavailable, or empty page). "
            f"See logs for detail.",
            file=sys.stderr,
        )
        return EXIT_GENERIC_ERROR

    print(
        f"✓ Extracted ProgramScope: "
        f"name={scope.name!r} "
        f"scope_rules={len(scope.scope_rules)} "
        f"personas={len(scope.personas)} "
        f"restrictions={len(scope.restrictions)} "
        f"confidence={scope.extraction_confidence:.2f}",
        file=sys.stderr,
    )

    # ─── 3. Verify extracted personas (best-effort) ───────────────────
    if scope.personas and not args.skip_verify:
        print("→ Verifying extracted credentials...", file=sys.stderr)
        await verify(scope)
        verified = [p for p in scope.personas if p.verified == VerificationStatus.VERIFIED]
        failed = [p for p in scope.personas if p.verified == VerificationStatus.FAILED]
        print(f"  verified={len(verified)} failed={len(failed)}", file=sys.stderr)

    # ─── 4. Auto-register if requested ────────────────────────────────
    registration_report: Optional[RegistrationReport] = None
    if args.allow_auto_register:
        print("→ Attempting auto-registration...", file=sys.stderr)
        registration_report = await auto_register(
            scope,
            allow_auto_register=True,
            persona_type=args.register_as,
            email_domain=args.email_domain,
            force_policy_check=not args.force,
        )
        if registration_report.persona is not None:
            scope.personas.append(registration_report.persona)
            print(
                f"  ✓ Registered {registration_report.persona.name} "
                f"({registration_report.persona.username}) → "
                f"{registration_report.persona.verified.value}",
                file=sys.stderr,
            )
        else:
            print(
                f"  ⚠ Registration did not produce a persona: "
                f"{registration_report.blocked_reason}",
                file=sys.stderr,
            )

    # ─── 5. Compile + write the config files ──────────────────────────
    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)

    handle = scope.handle or "program"
    files_written: List[Path] = []

    # 5a. Full ProgramScope (for cache / replay).
    program_scope_path = out_dir / f"{handle}-program-scope.json"
    program_scope_path.write_text(scope.to_json())
    files_written.append(program_scope_path)

    # 5b. Scope file.
    scope_path = out_dir / f"{handle}-scope.txt"
    scope_path.write_text(compile_scope_file(scope))
    files_written.append(scope_path)

    # 5c. Personas file.
    personas_path = out_dir / f"{handle}-personas.json"
    personas_path.write_text(compile_personas_json(scope))
    files_written.append(personas_path)

    # 5d. Restrictions file.
    restrictions_path = out_dir / f"{handle}-restrictions.json"
    restrictions_path.write_text(compile_restrictions_json(scope))
    files_written.append(restrictions_path)

    # ─── 6. Read back the restrictions and surface enforcement preview ──
    enforcement = enforce_from_file(restrictions_path)

    # ─── 7. Q2 silence-policy + automated-scan policy warning ─────────
    if not _has_authorization_signal(scope):
        print(
            "⚠ Policy did not explicitly authorize automated scanning. "
            "Proceeding — but review the policy text before running the scan.",
            file=sys.stderr,
        )

    # ─── 8. Print summary report ──────────────────────────────────────
    print()  # blank line on stdout
    print("=" * 70)
    print(f"INGEST SUMMARY — {scope.name}")
    print("=" * 70)
    print(f"  Program:       {scope.name}")
    print(f"  Platform:      {scope.platform.value}")
    print(f"  Handle:        {scope.handle or '(none)'}")
    print(f"  Source URL:    {scope.source_url}")
    print(f"  Confidence:    {scope.extraction_confidence:.2f}")
    print(f"  Extractor:     {scope.extractor_version}")
    print()
    _print_scope_summary(scope)
    print()
    _print_persona_summary(scope)
    print()
    _print_restriction_summary(scope, enforcement, registration_report)
    print()
    print("Files written:")
    for p in files_written:
        print(f"  {p}")
    print()

    # ─── 9. Decide final exit code ────────────────────────────────────
    if enforcement.scan_blocked:
        print(
            f"⛔ Scanning is BLOCKED by hard restriction: "
            f"{enforcement.scan_blocked_reason}",
            file=sys.stderr,
        )
        return EXIT_BLOCKED_BY_RESTRICTION

    if enforcement.required_attestations and not args.accept_attestations:
        print(
            "⛔ This program requires operator attestations before scanning:",
            file=sys.stderr,
        )
        for a in enforcement.required_attestations:
            print(f"  - {a}", file=sys.stderr)
        print(
            "   Re-run with --accept-attestations to confirm you've done these.",
            file=sys.stderr,
        )
        return EXIT_OPERATOR_CANCELLED

    return EXIT_OK


# ─────────────────────────── Summary helpers ───────────────────────

def _print_scope_summary(scope: ProgramScope) -> None:
    in_scope = [r for r in scope.scope_rules if r.in_scope]
    out_scope = [r for r in scope.scope_rules if not r.in_scope]
    print(f"  SCOPE: {len(in_scope)} in-scope, {len(out_scope)} out-of-scope")
    for r in in_scope[:5]:
        print(f"    + {r.pattern}")
    if len(in_scope) > 5:
        print(f"    ... +{len(in_scope) - 5} more in-scope")
    for r in out_scope[:5]:
        print(f"    - {r.pattern}")
    if len(out_scope) > 5:
        print(f"    ... -{len(out_scope) - 5} more out-of-scope")


def _print_persona_summary(scope: ProgramScope) -> None:
    verified = [p for p in scope.personas if p.verified == VerificationStatus.VERIFIED]
    failed = [p for p in scope.personas if p.verified == VerificationStatus.FAILED]
    other = [p for p in scope.personas if p.verified == VerificationStatus.UNVERIFIED]
    print(
        f"  PERSONAS: {len(verified)} verified, "
        f"{len(failed)} failed, {len(other)} unverified"
    )
    for p in scope.personas:
        marker = {
            VerificationStatus.VERIFIED: "✓",
            VerificationStatus.FAILED: "✗",
            VerificationStatus.UNVERIFIED: "?",
        }[p.verified]
        username = p.username or "(no creds)"
        print(f"    {marker} {p.name} [{p.persona_type}] — {username}")


def _print_restriction_summary(
    scope: ProgramScope,
    enforcement,
    registration: Optional[RegistrationReport],
) -> None:
    print(f"  RESTRICTIONS: {len(scope.restrictions)}")
    for r in scope.restrictions:
        sev = {"hard": "■", "soft": "▢"}.get(r.severity, "?")
        print(f"    {sev} [{r.severity}] {r.kind.value}: {r.description}")

    if not enforcement.is_empty():
        print()
        print("  ENFORCEMENT (applied at scan-time):")
        if enforcement.disabled_tools:
            print(f"    disabled tools: {sorted(enforcement.disabled_tools)}")
        if enforcement.max_capability_tier:
            print(f"    max capability tier: {enforcement.max_capability_tier}")
        if enforcement.rate_limit_rps is not None:
            print(f"    rate limit: {enforcement.rate_limit_rps} rps")
        if enforcement.scope_strict:
            print(f"    scope_strict: enabled")
        if enforcement.scan_blocked:
            print(f"    ⛔ scan_blocked: {enforcement.scan_blocked_reason}")

    if registration is not None:
        print()
        print(f"  AUTO-REGISTRATION:")
        if registration.persona is not None:
            print(f"    ✓ Created persona {registration.persona.name}")
        else:
            print(f"    ✗ Not created — {registration.blocked_reason}")


def _has_authorization_signal(scope: ProgramScope) -> bool:
    """Q2 — silent-policy detection. Returns True if the policy text
    explicitly mentions automated testing in any form (allow or deny)."""
    haystack = " ".join(filter(None, [
        scope.name,
        *(r.description or "" for r in scope.restrictions),
        *(r.raw_quote or "" for r in scope.restrictions),
    ])).lower()
    keywords = ("automated", "scanner", "scanning", "scan", "test", "research")
    return any(kw in haystack for kw in keywords)


# ─────────────────────────── CLI plumbing ──────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-ingest",
        description="Ingest a bug bounty program's scope, credentials, "
                    "and restrictions; produce config files Sentinel can scan with.",
    )
    p.add_argument(
        "--program",
        required=True,
        help="Program identifier: hackerone:<handle>, bugcrowd:<handle>, or a URL.",
    )
    p.add_argument(
        "--out-dir",
        default="~/.sentinelforge/intel",
        help="Directory to write config files into. Default: ~/.sentinelforge/intel/",
    )
    p.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip credential verification (don't attempt logins). Faster but the "
             "personas file will only have UNVERIFIED entries.",
    )
    p.add_argument(
        "--allow-auto-register",
        action="store_true",
        help="Authorize the registrar to create test accounts via the target's "
             "signup endpoint. Default off (creates account state on someone "
             "else's system, only do if policy authorizes).",
    )
    p.add_argument(
        "--register-as",
        choices=("user", "admin"),
        default="user",
        help="Role label for the auto-registered account.",
    )
    p.add_argument(
        "--email-domain",
        default="example.com",
        help="Domain for the generated test-account email. Default example.com "
             "(IANA sinkhole). Use a disposable inbox domain if email "
             "verification is required.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Bypass the policy-text authorization keyword check for "
             "auto-registration. Use ONLY if you've manually confirmed the "
             "program authorizes test-account creation.",
    )
    p.add_argument(
        "--accept-attestations",
        action="store_true",
        help="Acknowledge all required-attestation prompts. Without this, "
             "the script exits 3 if any are present.",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging.",
    )
    return p


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n⛔ Cancelled by operator.", file=sys.stderr)
        return EXIT_OPERATOR_CANCELLED
    except Exception as e:  # noqa: BLE001 - top-level catch
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return EXIT_GENERIC_ERROR


if __name__ == "__main__":
    sys.exit(main())
