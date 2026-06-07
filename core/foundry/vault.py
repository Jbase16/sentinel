"""
core/foundry/vault.py — Phase 7-PF2: the Persona Vault.

The ethical backbone of the Foundry. Stores "research personas" — real
legal identities the researcher uses ONLY for security testing — and
makes every account creation auditable + rate-limited.

Three non-negotiable properties:

  1. AUDITABILITY. Every account the Foundry creates is logged with
     (persona_id, service_handle, recipe_id, timestamp, outcome). The
     researcher can answer "what did Sentinel create, where, and when"
     at any moment. This is what keeps the system defensible: it's not
     an account farm, it's a logged tool operated by an accountable
     human.

  2. RATE LIMITING. Per (persona, service) caps so the Foundry never
     resembles abusive automation. Default: at most N accounts on the
     same service per persona per rolling window. A signup that would
     exceed the cap is REFUSED before any network action.

  3. SECRET HYGIENE. Persona records contain real PII + passwords.
     Stored under ~/.sentinelforge/personas/ with 0600 perms. Secret
     fields (password) are flagged; a future hardening moves them to
     Keychain (the token_store pattern). For V1 they're inline with a
     clear security note + restrictive file mode.

A persona is NOT a throwaway. It's a durable identity the researcher
owns and is accountable for — a real name, a real (dedicated) email,
optionally a real (dedicated) phone + payment method. The Foundry's
whole legitimacy rests on this being a real, owned, accountable
identity rather than a fabricated one.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Where personas + audit live. Override via env for tests.
_VAULT_ENV = "SENTINELFORGE_PERSONA_VAULT"
_DEFAULT_VAULT_DIR = Path.home() / ".sentinelforge" / "personas"


def _vault_dir() -> Path:
    override = os.environ.get(_VAULT_ENV)
    if override:
        return Path(override)
    return _DEFAULT_VAULT_DIR


# Default rate-limit policy: at most this many accounts per
# (persona, service) within the rolling window.
DEFAULT_MAX_ACCOUNTS_PER_SERVICE = 3
DEFAULT_WINDOW_SECONDS = 30 * 24 * 3600  # 30 days


# ─────────────────────────── persona ───────────────────────────


# Field names treated as secret — redacted in repr, flagged for future
# Keychain migration.
_SECRET_FIELDS = {"password"}


@dataclass
class ResearchPersona:
    """A real, owned, accountable identity used for security testing.

    `verification` declares where email/SMS verification artifacts can
    be fetched from — e.g. {"email_imap": "imap_handle",
    "sms_webhook": "twilio_handle"}. The actual fetch is a bridge
    concern (PF5); the persona just declares the source so the replay
    engine knows where to look (or whether to hand off to the human).
    """
    persona_id: str
    label: str                         # human name: "research-alice"
    email: str
    first_name: str = ""
    last_name: str = ""
    password: str = field(default="", repr=False)  # secret — redacted
    phone: str = ""
    date_of_birth: str = ""            # "YYYY-MM-DD" if a signup needs it
    # Verification source handles (resolved by PF5 bridges).
    verification: Dict[str, str] = field(default_factory=dict)
    # Free-form: payment-card vault handle, org name, etc.
    extra: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    notes: str = ""

    def __repr__(self) -> str:
        return (
            f"ResearchPersona(persona_id={self.persona_id!r}, "
            f"label={self.label!r}, email={self.email!r}, "
            f"password=<redacted>)"
        )

    def as_binding_dict(self) -> Dict[str, Any]:
        """The flat dict a recipe's persona: bindings resolve against.

        Includes secret fields (the replay engine needs the password to
        fill the form) — callers MUST NOT log this dict."""
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "password": self.password,
            "phone": self.phone,
            "date_of_birth": self.date_of_birth,
            **{f"extra_{k}": v for k, v in self.extra.items()},
        }

    def missing_fields_for(self, required: List[str]) -> List[str]:
        """Return the persona: fields a recipe needs that this persona
        lacks (empty string counts as missing)."""
        binding = self.as_binding_dict()
        return [f for f in required if not str(binding.get(f, "")).strip()]

    def to_dict(self, *, include_secrets: bool = True) -> Dict[str, Any]:
        d = {
            "persona_id": self.persona_id,
            "label": self.label,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone": self.phone,
            "date_of_birth": self.date_of_birth,
            "verification": dict(self.verification),
            "extra": dict(self.extra),
            "created_at": self.created_at,
            "notes": self.notes,
        }
        if include_secrets:
            d["password"] = self.password
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ResearchPersona":
        return cls(
            persona_id=d["persona_id"],
            label=d["label"],
            email=d["email"],
            first_name=d.get("first_name", ""),
            last_name=d.get("last_name", ""),
            password=d.get("password", ""),
            phone=d.get("phone", ""),
            date_of_birth=d.get("date_of_birth", ""),
            verification=dict(d.get("verification", {})),
            extra=dict(d.get("extra", {})),
            created_at=float(d.get("created_at", time.time())),
            notes=d.get("notes", ""),
        )


# ─────────────────────────── audit ───────────────────────────


@dataclass
class AccountCreationRecord:
    """One audit-log entry: the Foundry created (or attempted) an
    account using `persona_id` on `service_handle`."""
    record_id: str
    persona_id: str
    service_handle: str
    recipe_id: Optional[str]
    outcome: str           # "success" | "failed" | "abandoned"
    created_at: float = field(default_factory=time.time)
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "persona_id": self.persona_id,
            "service_handle": self.service_handle,
            "recipe_id": self.recipe_id,
            "outcome": self.outcome,
            "created_at": self.created_at,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AccountCreationRecord":
        return cls(
            record_id=d["record_id"],
            persona_id=d["persona_id"],
            service_handle=d["service_handle"],
            recipe_id=d.get("recipe_id"),
            outcome=d.get("outcome", "success"),
            created_at=float(d.get("created_at", time.time())),
            detail=d.get("detail", ""),
        )


class RateLimitExceeded(Exception):
    """Raised when a signup would exceed the per-(persona, service)
    account cap. The caller must NOT proceed with the signup."""


# ─────────────────────────── vault ───────────────────────────


class PersonaVault:
    """File-backed store of personas + the account-creation audit log.

    Thread-safe (RLock). Persona records live in
    {vault}/persona-{id}.json (0600). The audit log is an append-only
    JSONL file {vault}/audit.jsonl.

    The vault is instantiated per-use rather than a global singleton so
    tests can point it at a tmp dir cleanly.
    """

    def __init__(
        self,
        *,
        max_accounts_per_service: int = DEFAULT_MAX_ACCOUNTS_PER_SERVICE,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ):
        self._lock = threading.RLock()
        self._max = max_accounts_per_service
        self._window = window_seconds
        self._dir = _vault_dir()

    # ── persona CRUD ──

    def _persona_path(self, persona_id: str) -> Path:
        return self._dir / f"persona-{persona_id}.json"

    def add_persona(
        self,
        *,
        label: str,
        email: str,
        password: str = "",
        first_name: str = "",
        last_name: str = "",
        phone: str = "",
        date_of_birth: str = "",
        verification: Optional[Dict[str, str]] = None,
        extra: Optional[Dict[str, Any]] = None,
        notes: str = "",
    ) -> ResearchPersona:
        """Create + persist a new persona. Returns it."""
        persona = ResearchPersona(
            persona_id=uuid.uuid4().hex,
            label=label,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            date_of_birth=date_of_birth,
            verification=verification or {},
            extra=extra or {},
            notes=notes,
        )
        self._save_persona(persona)
        logger.info(
            "[vault] added persona %s (label=%r, email=%r)",
            persona.persona_id, label, email,
        )
        return persona

    def _save_persona(self, persona: ResearchPersona) -> Path:
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            path = self._persona_path(persona.persona_id)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(persona.to_dict(include_secrets=True), indent=2))
            # Restrictive perms BEFORE the rename so the final file never
            # exists world-readable even momentarily.
            os.chmod(tmp, 0o600)
            tmp.replace(path)
            return path

    def get_persona(self, persona_id: str) -> Optional[ResearchPersona]:
        with self._lock:
            path = self._persona_path(persona_id)
            if not path.exists():
                return None
            try:
                return ResearchPersona.from_dict(json.loads(path.read_text()))
            except Exception as e:
                logger.error("[vault] failed to load persona %s: %s", persona_id, e)
                return None

    def list_personas(self) -> List[ResearchPersona]:
        with self._lock:
            if not self._dir.exists():
                return []
            out: List[ResearchPersona] = []
            for p in sorted(self._dir.glob("persona-*.json")):
                try:
                    out.append(ResearchPersona.from_dict(json.loads(p.read_text())))
                except Exception as e:
                    logger.warning("[vault] skipping unreadable %s: %s", p, e)
            return out

    def remove_persona(self, persona_id: str) -> bool:
        with self._lock:
            path = self._persona_path(persona_id)
            if path.exists():
                path.unlink()
                return True
            return False

    # ── audit ──

    def _audit_path(self) -> Path:
        return self._dir / "audit.jsonl"

    def _append_audit(self, record: AccountCreationRecord) -> None:
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            path = self._audit_path()
            with path.open("a") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def audit_records(
        self,
        *,
        persona_id: Optional[str] = None,
        service_handle: Optional[str] = None,
    ) -> List[AccountCreationRecord]:
        """Read the audit log, optionally filtered by persona/service."""
        with self._lock:
            path = self._audit_path()
            if not path.exists():
                return []
            out: List[AccountCreationRecord] = []
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = AccountCreationRecord.from_dict(json.loads(line))
                except Exception:
                    continue
                if persona_id and rec.persona_id != persona_id:
                    continue
                if service_handle and rec.service_handle != service_handle:
                    continue
                out.append(rec)
            return out

    # ── rate limiting ──

    def account_count_in_window(
        self, persona_id: str, service_handle: str, *, now: Optional[float] = None
    ) -> int:
        """How many SUCCESSFUL accounts this persona created on this
        service within the rolling window."""
        now = now if now is not None else time.time()
        cutoff = now - self._window
        records = self.audit_records(
            persona_id=persona_id, service_handle=service_handle
        )
        return sum(
            1 for r in records
            if r.outcome == "success" and r.created_at >= cutoff
        )

    def check_rate_limit(
        self, persona_id: str, service_handle: str, *, now: Optional[float] = None
    ) -> None:
        """Raise RateLimitExceeded if creating another account would
        breach the per-(persona, service) cap. Call this BEFORE any
        signup network action."""
        count = self.account_count_in_window(persona_id, service_handle, now=now)
        if count >= self._max:
            raise RateLimitExceeded(
                f"persona {persona_id} already has {count} account(s) on "
                f"{service_handle!r} within the {self._window / 86400:.0f}-day "
                f"window (cap: {self._max}). Refusing to create another — "
                f"this is the account-farm guardrail."
            )

    def record_account_creation(
        self,
        *,
        persona_id: str,
        service_handle: str,
        recipe_id: Optional[str] = None,
        outcome: str = "success",
        detail: str = "",
    ) -> AccountCreationRecord:
        """Append an audit record. Called by the replay engine after a
        signup completes (or fails / is abandoned)."""
        record = AccountCreationRecord(
            record_id=uuid.uuid4().hex,
            persona_id=persona_id,
            service_handle=service_handle,
            recipe_id=recipe_id,
            outcome=outcome,
            detail=detail,
        )
        self._append_audit(record)
        logger.info(
            "[vault] audit: persona=%s service=%s outcome=%s",
            persona_id, service_handle, outcome,
        )
        return record

    # ── readiness check ──

    def persona_ready_for(
        self, persona_id: str, required_persona_fields: List[str]
    ) -> List[str]:
        """Return the list of persona fields a recipe needs that this
        persona is MISSING. Empty list = ready. Used to fail-fast
        before starting a replay with an incomplete persona."""
        persona = self.get_persona(persona_id)
        if persona is None:
            return list(required_persona_fields)  # everything missing
        return persona.missing_fields_for(required_persona_fields)
