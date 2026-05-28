"""
Phase 4-G4 tests for core/ghost/mutations.py.

Each mutation in the semantic library is tested with two pinned cases:
  1. applies_to() returns True for the right kind of step + False for
     a step where the hypothesis doesn't make sense.
  2. apply() produces the right mutated step shape — verified against
     specific bytes/headers/body fields, not just "different from input."

The proposer (propose_mutations) is tested against a synthetic multi-step
flow to confirm it surfaces the right mutations at the right step indices.
"""
from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from core.ghost.flow import FlowStep, UserFlow
from core.ghost.mutations import (
    ALL_MUTATIONS,
    CSRFTokenStrip,
    HeaderInject,
    JWTAlgNone,
    MutationProposal,
    NegativeQuantity,
    OAuthStateStrip,
    PrivilegeDowngrade,
    VerbTampering,
    propose_mutations,
)


# ─────────────────────────── helpers ───────────────────────────


def _mk_jwt(alg: str, payload: dict, sig: bytes = b"sig") -> str:
    """Build a synthetic JWT with the given alg + payload."""
    def b64(d):
        return base64.urlsafe_b64encode(d).decode("ascii").rstrip("=")
    h = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = b64(json.dumps(payload).encode())
    s = b64(sig)
    return f"{h}.{p}.{s}"


# ─────────────────────────── JWTAlgNone ───────────────────────────


class TestJWTAlgNone:
    def test_applies_to_hs256_jwt(self):
        token = _mk_jwt("HS256", {"sub": "alice", "role": "user"})
        step = FlowStep(method="GET", url="http://h/me",
                        headers={"Authorization": f"Bearer {token}"})
        assert JWTAlgNone().applies_to(step) is True

    def test_does_not_apply_to_non_bearer(self):
        step = FlowStep(method="GET", url="http://h/",
                        headers={"Authorization": "Basic Zm9vOmJhcg=="})
        assert JWTAlgNone().applies_to(step) is False

    def test_does_not_apply_to_already_alg_none(self):
        token = _mk_jwt("none", {"sub": "x"})
        step = FlowStep(method="GET", url="http://h/",
                        headers={"Authorization": f"Bearer {token}"})
        assert JWTAlgNone().applies_to(step) is False

    def test_apply_produces_alg_none_jwt_with_empty_sig(self):
        original_payload = {"sub": "alice", "role": "user", "iat": 1234567890}
        token = _mk_jwt("HS256", original_payload)
        step = FlowStep(method="GET", url="http://h/me",
                        headers={"Authorization": f"Bearer {token}"})

        mut = JWTAlgNone().apply(step)
        new_auth = mut.headers["authorization"]
        assert new_auth.startswith("Bearer ")
        new_token = new_auth[7:]
        # Three parts (header.payload.empty-sig).
        h_b64, p_b64, s_b64 = new_token.split(".")
        # Decode the header — must be alg=none.
        padded_h = h_b64 + "=" * (-len(h_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded_h))
        assert header["alg"] == "none"
        # Payload preserved byte-for-byte.
        padded_p = p_b64 + "=" * (-len(p_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded_p))
        assert payload == original_payload
        # Signature stripped to empty.
        assert s_b64 == ""


# ─────────────────────────── OAuthStateStrip ───────────────────────────


class TestOAuthStateStrip:
    def test_applies_when_state_param_present(self):
        step = FlowStep(method="GET",
                        url="http://h/callback?code=abc&state=xyz")
        assert OAuthStateStrip().applies_to(step) is True

    def test_does_not_apply_without_state(self):
        step = FlowStep(method="GET", url="http://h/login")
        assert OAuthStateStrip().applies_to(step) is False

    def test_apply_removes_state_keeps_other_params(self):
        step = FlowStep(method="GET",
                        url="http://h/callback?code=abc&state=xyz&scope=read")
        mut = OAuthStateStrip().apply(step)
        assert "state" not in mut.url
        # Other params survive.
        assert "code=abc" in mut.url
        assert "scope=read" in mut.url


# ─────────────────────────── PrivilegeDowngrade ───────────────────────────


class TestPrivilegeDowngrade:
    def test_applies_to_json_body(self):
        step = FlowStep(method="POST", url="http://h/profile",
                        request_body='{"name": "alice", "email": "a@b"}',
                        request_content_type="application/json")
        assert PrivilegeDowngrade().applies_to(step) is True

    def test_does_not_apply_to_non_json(self):
        step = FlowStep(method="POST", url="http://h/",
                        request_body="not json",
                        request_content_type="text/plain")
        assert PrivilegeDowngrade().applies_to(step) is False

    def test_apply_injects_admin_fields(self):
        step = FlowStep(method="PUT", url="http://h/users/42",
                        request_body='{"name": "alice", "email": "a@b"}',
                        request_content_type="application/json")
        mut = PrivilegeDowngrade().apply(step)
        body = json.loads(mut.request_body)
        assert body["is_admin"] is True
        assert body["role"] == "admin"
        # Original fields preserved.
        assert body["name"] == "alice"
        assert body["email"] == "a@b"


# ─────────────────────────── NegativeQuantity ───────────────────────────


class TestNegativeQuantity:
    def test_applies_when_quantity_field_present(self):
        step = FlowStep(method="POST", url="http://h/cart",
                        request_body='{"product": 1, "quantity": 3}',
                        request_content_type="application/json")
        assert NegativeQuantity().applies_to(step) is True

    def test_applies_for_price_field(self):
        step = FlowStep(method="POST", url="http://h/checkout",
                        request_body='{"price": 10.5}',
                        request_content_type="application/json")
        assert NegativeQuantity().applies_to(step) is True

    def test_does_not_apply_for_string_quantity(self):
        # "3" as string isn't a numeric invariant target.
        step = FlowStep(method="POST", url="http://h/",
                        request_body='{"quantity": "three"}',
                        request_content_type="application/json")
        assert NegativeQuantity().applies_to(step) is False

    def test_apply_negates_numeric_fields(self):
        step = FlowStep(method="POST", url="http://h/cart",
                        request_body='{"quantity": 5, "price": 10, "name": "x"}',
                        request_content_type="application/json")
        mut = NegativeQuantity().apply(step)
        body = json.loads(mut.request_body)
        assert body["quantity"] == -1
        assert body["price"] == -1
        # Non-target fields unchanged.
        assert body["name"] == "x"


# ─────────────────────────── HeaderInject ───────────────────────────


class TestHeaderInject:
    def test_applies_to_any_step(self):
        step = FlowStep(method="GET", url="http://h/")
        assert HeaderInject().applies_to(step) is True

    def test_apply_adds_trust_boundary_headers(self):
        step = FlowStep(method="GET", url="http://h/admin")
        mut = HeaderInject().apply(step)
        # Headers stored lowercased, so check lowercase.
        assert mut.headers.get("x-forwarded-for") == "127.0.0.1"
        assert mut.headers.get("x-real-ip") == "127.0.0.1"
        assert mut.headers.get("x-original-url") == "/admin"


# ─────────────────────────── VerbTampering ───────────────────────────


class TestVerbTampering:
    def test_applies_for_get(self):
        step = FlowStep(method="GET", url="http://h/")
        assert VerbTampering().applies_to(step) is True

    def test_apply_swaps_method(self):
        step = FlowStep(method="GET", url="http://h/admin")
        mut = VerbTampering().apply(step)
        assert mut.method != "GET"
        assert mut.method == "POST"


# ─────────────────────────── CSRFTokenStrip ───────────────────────────


class TestCSRFTokenStrip:
    def test_applies_when_csrf_header_present(self):
        step = FlowStep(method="POST", url="http://h/",
                        headers={"X-CSRF-Token": "abc123"})
        assert CSRFTokenStrip().applies_to(step) is True

    def test_applies_when_csrf_in_body(self):
        step = FlowStep(method="POST", url="http://h/",
                        request_body='{"name": "x", "csrf_token": "tok"}',
                        request_content_type="application/json")
        assert CSRFTokenStrip().applies_to(step) is True

    def test_does_not_apply_without_csrf(self):
        step = FlowStep(method="POST", url="http://h/",
                        request_body='{"name": "x"}',
                        request_content_type="application/json")
        assert CSRFTokenStrip().applies_to(step) is False

    def test_apply_strips_header_and_body_token(self):
        step = FlowStep(
            method="POST", url="http://h/",
            headers={"X-CSRF-Token": "abc", "Content-Type": "application/json"},
            request_body='{"name": "x", "csrf_token": "tok", "authenticity_token": "tok2"}',
            request_content_type="application/json",
        )
        mut = CSRFTokenStrip().apply(step)
        assert "x-csrf-token" not in mut.headers
        body = json.loads(mut.request_body)
        assert "csrf_token" not in body
        assert "authenticity_token" not in body
        # Non-CSRF field preserved.
        assert body["name"] == "x"


# ─────────────────────────── propose_mutations ───────────────────────────


class TestProposeMutations:
    def test_empty_flow_returns_no_proposals(self):
        flow = UserFlow(name="empty")
        assert propose_mutations(flow) == []

    def test_proposer_surfaces_relevant_mutations(self):
        """A multi-step flow with each step exercising a different
        mutation hypothesis. The proposer must emit one proposal per
        match — and ONLY for the relevant mutations on each step."""
        flow = UserFlow(name="rich")
        # Step 0: OAuth callback with state.
        flow.add_step(FlowStep(method="GET",
                               url="http://h/oauth/callback?code=c&state=s"))
        # Step 1: JWT-authenticated request.
        token = _mk_jwt("HS256", {"sub": "alice"})
        flow.add_step(FlowStep(method="GET", url="http://h/me",
                               headers={"Authorization": f"Bearer {token}"}))
        # Step 2: JSON body with quantity.
        flow.add_step(FlowStep(method="POST", url="http://h/cart",
                               request_body='{"quantity": 3, "product": 1}',
                               request_content_type="application/json"))

        proposals = propose_mutations(flow)
        # We expect: step 0 → OAuthStateStrip + HeaderInject + VerbTamper
        #            step 1 → JWTAlgNone + HeaderInject + VerbTamper
        #            step 2 → PrivilegeDowngrade + NegativeQuantity + HeaderInject + VerbTamper
        by_step = {}
        for p in proposals:
            by_step.setdefault(p.step_index, []).append(p.mutation_label)

        # Step 0 had state= → OAuth strip applies.
        assert "oauth-state-strip" in by_step[0]
        assert "jwt-alg-none" not in by_step[0]  # no JWT here
        # Step 1 had HS256 JWT → alg-none applies.
        assert "jwt-alg-none" in by_step[1]
        assert "oauth-state-strip" not in by_step[1]  # no ?state=
        assert "negative-quantity" not in by_step[1]  # no body
        # Step 2 had quantity → negative-quantity + privilege-downgrade apply.
        assert "negative-quantity" in by_step[2]
        assert "privilege-downgrade" in by_step[2]
        assert "jwt-alg-none" not in by_step[2]  # no JWT

        # HeaderInject + VerbTampering apply to every step (always-on
        # hypotheses).
        for step_idx in (0, 1, 2):
            assert "header-inject-localhost" in by_step[step_idx]
            assert "verb-tamper" in by_step[step_idx]

    def test_proposals_are_serializable(self):
        flow = UserFlow(name="serial-test")
        flow.add_step(FlowStep(method="GET", url="http://h/?state=x"))
        proposals = propose_mutations(flow)
        # Must round-trip through json.dumps.
        for p in proposals:
            d = p.to_dict()
            json.dumps(d)  # raises on bad serialization
            assert "step_index" in d
            assert "mutation_label" in d
            assert "rationale" in d

    def test_proposer_is_deterministic(self):
        """Same flow + same catalog → same proposal order."""
        flow = UserFlow(name="determinism")
        flow.add_step(FlowStep(method="GET", url="http://h/?state=x"))
        flow.add_step(FlowStep(method="POST", url="http://h/",
                               request_body='{"quantity": 1}',
                               request_content_type="application/json"))

        a = propose_mutations(flow)
        b = propose_mutations(flow)
        assert [(p.step_index, p.mutation_label) for p in a] == \
               [(p.step_index, p.mutation_label) for p in b]


class TestCatalogSurface:
    def test_all_mutations_exposes_seven_classes(self):
        """Coverage tripwire — if someone adds a mutation class but
        forgets to register it, this test fails. If they REMOVE one,
        same."""
        assert len(ALL_MUTATIONS) == 7
        labels = {cls().label for cls in ALL_MUTATIONS}
        assert labels == {
            "jwt-alg-none",
            "oauth-state-strip",
            "privilege-downgrade",
            "negative-quantity",
            "header-inject-localhost",
            "verb-tamper",
            "csrf-token-strip",
        }
