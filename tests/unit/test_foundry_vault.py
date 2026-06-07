"""
Phase 7-PF2 tests for core/foundry/vault.py.

The vault is the Foundry's ethical backbone. Tests pin the three
non-negotiable properties:

  1. AUDITABILITY — every account creation is logged + queryable.
  2. RATE LIMITING — per (persona, service) cap refuses signups that
     would resemble account-farming.
  3. SECRET HYGIENE — persona files are written 0600; password is
     redacted in repr.

Plus persona CRUD, readiness checks, and round-trip serialization.
"""
from __future__ import annotations

import os
import stat

import pytest

from core.foundry.vault import (
    AccountCreationRecord,
    PersonaVault,
    RateLimitExceeded,
    ResearchPersona,
)


@pytest.fixture
def vault(monkeypatch, tmp_path):
    """A PersonaVault rooted at a tmp dir (no touching real ~/.sentinelforge)."""
    monkeypatch.setenv("SENTINELFORGE_PERSONA_VAULT", str(tmp_path / "personas"))
    return PersonaVault(max_accounts_per_service=3, window_seconds=30 * 86400)


# ───────────────────────── persona CRUD ─────────────────────────


class TestPersonaCRUD:
    def test_add_and_get(self, vault):
        p = vault.add_persona(
            label="research-alice",
            email="alice@research.example",
            password="s3cr3t-pw",
            first_name="Alice",
            last_name="Researcher",
        )
        loaded = vault.get_persona(p.persona_id)
        assert loaded is not None
        assert loaded.email == "alice@research.example"
        assert loaded.first_name == "Alice"
        # Password persisted (it's a secret the replay engine needs).
        assert loaded.password == "s3cr3t-pw"

    def test_list(self, vault):
        vault.add_persona(label="a", email="a@x")
        vault.add_persona(label="b", email="b@x")
        personas = vault.list_personas()
        assert {p.label for p in personas} == {"a", "b"}

    def test_remove(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        assert vault.remove_persona(p.persona_id) is True
        assert vault.get_persona(p.persona_id) is None
        # Removing again returns False (idempotent-ish).
        assert vault.remove_persona(p.persona_id) is False

    def test_get_unknown_returns_none(self, vault):
        assert vault.get_persona("no-such-id") is None


# ───────────────────────── secret hygiene ─────────────────────────


class TestSecretHygiene:
    def test_password_redacted_in_repr(self):
        p = ResearchPersona(
            persona_id="x", label="a", email="a@x", password="TOPSECRET",
        )
        assert "TOPSECRET" not in repr(p)
        assert "redacted" in repr(p).lower()

    def test_persona_file_is_0600(self, vault, tmp_path):
        p = vault.add_persona(label="a", email="a@x", password="pw")
        path = (tmp_path / "personas") / f"persona-{p.persona_id}.json"
        assert path.exists()
        mode = stat.S_IMODE(os.stat(path).st_mode)
        # Owner read/write only — no group/other access.
        assert mode == 0o600, f"persona file mode is {oct(mode)}, expected 0600"

    def test_to_dict_can_exclude_secrets(self):
        p = ResearchPersona(
            persona_id="x", label="a", email="a@x", password="pw",
        )
        d = p.to_dict(include_secrets=False)
        assert "password" not in d
        d2 = p.to_dict(include_secrets=True)
        assert d2["password"] == "pw"


# ───────────────────────── audit ─────────────────────────


class TestAudit:
    def test_record_and_query(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        vault.record_account_creation(
            persona_id=p.persona_id, service_handle="airtable",
            recipe_id="r1", outcome="success",
        )
        records = vault.audit_records(persona_id=p.persona_id)
        assert len(records) == 1
        assert records[0].service_handle == "airtable"
        assert records[0].outcome == "success"

    def test_audit_filtered_by_service(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        vault.record_account_creation(persona_id=p.persona_id, service_handle="airtable")
        vault.record_account_creation(persona_id=p.persona_id, service_handle="affirm")
        airtable = vault.audit_records(service_handle="airtable")
        assert len(airtable) == 1
        assert airtable[0].service_handle == "airtable"

    def test_audit_survives_reload(self, vault, monkeypatch, tmp_path):
        p = vault.add_persona(label="a", email="a@x")
        vault.record_account_creation(persona_id=p.persona_id, service_handle="airtable")
        # New vault instance, same dir — audit log persists.
        v2 = PersonaVault()
        assert len(v2.audit_records(persona_id=p.persona_id)) == 1


# ───────────────────────── rate limiting ─────────────────────────


class TestRateLimiting:
    def test_under_cap_passes(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        # 2 successful accounts; cap is 3 → next is still allowed.
        vault.record_account_creation(persona_id=p.persona_id, service_handle="airtable")
        vault.record_account_creation(persona_id=p.persona_id, service_handle="airtable")
        # Should NOT raise.
        vault.check_rate_limit(p.persona_id, "airtable")

    def test_at_cap_refuses(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        for _ in range(3):
            vault.record_account_creation(persona_id=p.persona_id, service_handle="airtable")
        with pytest.raises(RateLimitExceeded, match="account-farm guardrail"):
            vault.check_rate_limit(p.persona_id, "airtable")

    def test_failed_accounts_dont_count(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        # 5 FAILED attempts — none count toward the cap.
        for _ in range(5):
            vault.record_account_creation(
                persona_id=p.persona_id, service_handle="airtable",
                outcome="failed",
            )
        # Still allowed — only successes count.
        vault.check_rate_limit(p.persona_id, "airtable")
        assert vault.account_count_in_window(p.persona_id, "airtable") == 0

    def test_window_expiry(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        # 3 successes but all OUTSIDE the window (40 days ago).
        old = __import__("time").time() - 40 * 86400
        for _ in range(3):
            rec = vault.record_account_creation(
                persona_id=p.persona_id, service_handle="airtable",
            )
            # Backdate by rewriting the audit file directly is messy;
            # instead query with a `now` far in the future so the
            # 30-day window excludes them.
        future = __import__("time").time() + 40 * 86400
        # At `future`, the just-now records are >30 days old → 0 count.
        assert vault.account_count_in_window(p.persona_id, "airtable", now=future) == 0
        vault.check_rate_limit(p.persona_id, "airtable", now=future)  # no raise

    def test_different_service_independent_cap(self, vault):
        p = vault.add_persona(label="a", email="a@x")
        # Fill airtable to cap.
        for _ in range(3):
            vault.record_account_creation(persona_id=p.persona_id, service_handle="airtable")
        # A DIFFERENT service is unaffected.
        vault.check_rate_limit(p.persona_id, "affirm")  # no raise


# ───────────────────────── readiness ─────────────────────────


class TestReadiness:
    def test_persona_ready_when_all_fields_present(self, vault):
        p = vault.add_persona(
            label="a", email="a@x", password="pw",
            first_name="A", last_name="B",
        )
        missing = vault.persona_ready_for(
            p.persona_id, ["email", "password", "first_name"]
        )
        assert missing == []

    def test_persona_missing_fields_reported(self, vault):
        p = vault.add_persona(label="a", email="a@x")  # no phone
        missing = vault.persona_ready_for(p.persona_id, ["email", "phone"])
        assert missing == ["phone"]

    def test_unknown_persona_all_fields_missing(self, vault):
        missing = vault.persona_ready_for("nope", ["email", "phone"])
        assert set(missing) == {"email", "phone"}

    def test_empty_string_counts_as_missing(self, vault):
        p = vault.add_persona(label="a", email="a@x", phone="")
        missing = vault.persona_ready_for(p.persona_id, ["phone"])
        assert missing == ["phone"]


# ───────────────────────── binding dict ─────────────────────────


class TestBindingDict:
    def test_as_binding_dict_includes_secrets(self):
        p = ResearchPersona(
            persona_id="x", label="a", email="a@x", password="pw",
            first_name="A", extra={"org": "acme"},
        )
        b = p.as_binding_dict()
        assert b["email"] == "a@x"
        assert b["password"] == "pw"  # replay engine needs it
        assert b["first_name"] == "A"
        # extra fields prefixed.
        assert b["extra_org"] == "acme"

    def test_serialization_round_trip(self):
        p = ResearchPersona(
            persona_id="x", label="research-a", email="a@x",
            password="pw", phone="+15551234",
            verification={"email_imap": "alice-mailbox"},
            extra={"org": "acme"},
        )
        restored = ResearchPersona.from_dict(p.to_dict(include_secrets=True))
        assert restored.email == p.email
        assert restored.password == p.password
        assert restored.verification == {"email_imap": "alice-mailbox"}
        assert restored.extra == {"org": "acme"}
