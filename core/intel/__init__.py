"""
Program scope ingestion (Phase 2).

Takes a bug bounty program identifier (HackerOne handle, Bugcrowd handle,
or direct policy URL) and autonomously produces a working scope file,
personas file, and restrictions config.

Public surface:
    from core.intel import ProgramScope, Persona, ScopeRule, Restriction
    from core.intel import Platform, RestrictionKind, VerificationStatus
    from core.intel import Resolver, default_resolver
    from core.intel import verify  # CredentialVerifier entry point

Layers:
    extractors/   — fetch + parse (policy URL → ProgramScope)
    resolver      — dispatch identifier → correct extractor
    verifier      — login-attempt verification of extracted creds
    registrar     — auto-signup when policy authorizes (opt-in)
    compilers/    — ProgramScope → CAL scope, personas.json, policy gates
    token_store   — keychain-first secure storage for platform API tokens

See docs/PHASE_2_DESIGN.md for full architecture.
"""
from __future__ import annotations

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
from core.intel.resolver import Resolver, default_resolver
from core.intel.verifier import verify

__all__ = [
    "CredentialSource",
    "LoginFlow",
    "Persona",
    "Platform",
    "ProgramScope",
    "Resolver",
    "Restriction",
    "RestrictionKind",
    "ScopeRule",
    "ScopeRuleType",
    "VerificationStatus",
    "default_resolver",
    "verify",
]
