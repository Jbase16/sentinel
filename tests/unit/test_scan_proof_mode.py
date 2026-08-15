"""Regression tests for sealed-request business-logic proof posture."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from core.safety.proof_mode import ProofMode, rules_for
from core.server.routers.scans import (
    ScanRequest,
    _resolve_business_logic_proof_mode,
)


def test_bug_bounty_without_environment_is_bounty_safe(monkeypatch):
    monkeypatch.delenv("SENTINEL_PROOF_MODE", raising=False)
    req = ScanRequest(target="https://example.test", mode="bug_bounty")

    resolved = _resolve_business_logic_proof_mode(
        req,
        environment_limit=os.getenv("SENTINEL_PROOF_MODE"),
    )
    allowed, budget = rules_for(resolved)

    assert resolved == ProofMode.BOUNTY_SAFE
    assert allowed is not None
    assert budget.max_total_requests == 400
    assert budget.max_requests_per_endpoint == 5
    assert budget.max_cross_object_reads == 1
    assert budget.allow_delete is False
    assert budget.allow_real_user_data_access is False


def test_environment_lab_cannot_loosen_bug_bounty():
    req = ScanRequest(target="https://example.test", mode="bug_bounty")

    assert (
        _resolve_business_logic_proof_mode(
            req,
            environment_limit="lab",
        )
        == ProofMode.BOUNTY_SAFE
    )


def test_environment_can_tighten_bug_bounty_to_passive():
    req = ScanRequest(target="https://example.test", mode="bug_bounty")

    assert (
        _resolve_business_logic_proof_mode(
            req,
            environment_limit="passive",
        )
        == ProofMode.PASSIVE
    )


@pytest.mark.parametrize("mode", ["passive", "recon"])
def test_passive_and_recon_resolve_to_passive(mode):
    req = ScanRequest(target="https://example.test", mode=mode)

    assert req.mode == "passive"
    assert (
        _resolve_business_logic_proof_mode(
            req,
            environment_limit="lab",
        )
        == ProofMode.PASSIVE
    )


@pytest.mark.parametrize("mode", ["standard", "stealth"])
def test_non_lab_active_modes_default_to_bounty_safe(mode):
    req = ScanRequest(target="https://example.test", mode=mode)

    assert _resolve_business_logic_proof_mode(req) == ProofMode.BOUNTY_SAFE


def test_owned_lab_request_is_the_only_scan_mode_that_grants_lab():
    req = ScanRequest(target="http://127.0.0.1:3002", mode="owned_lab")

    assert _resolve_business_logic_proof_mode(req) == ProofMode.LAB
    with pytest.raises(ValidationError, match="(?i)allowed modes"):
        ScanRequest(target="http://127.0.0.1:3002", mode="lab")


def test_environment_can_tighten_owned_lab():
    req = ScanRequest(target="http://127.0.0.1:3002", mode="owned_lab")

    assert (
        _resolve_business_logic_proof_mode(
            req,
            environment_limit="bounty_safe",
        )
        == ProofMode.BOUNTY_SAFE
    )
    assert (
        _resolve_business_logic_proof_mode(
            req,
            environment_limit="passive",
        )
        == ProofMode.PASSIVE
    )


def test_missing_or_unknown_proof_configuration_fails_closed():
    assert ProofMode.normalize(None) == ProofMode.PASSIVE
    assert ProofMode.normalize("not-a-mode") == ProofMode.PASSIVE
    allowed, budget = rules_for(None)
    assert allowed is not None
    assert budget.allow_delete is False
    assert budget.allow_real_user_data_access is False


def test_bug_bounty_has_independent_lab_refusal_invariant(monkeypatch):
    req = ScanRequest(target="https://example.test", mode="bug_bounty")

    def unsafe_resolver(cls, scan_mode, *, environment_limit=None):
        return cls.LAB

    monkeypatch.setattr(ProofMode, "for_scan_mode", classmethod(unsafe_resolver))
    with pytest.raises(RuntimeError, match="refusing bug_bounty"):
        _resolve_business_logic_proof_mode(req)
