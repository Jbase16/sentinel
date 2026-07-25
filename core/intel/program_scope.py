"""
Data model for bug bounty program scope.

The ``ProgramScope`` dataclass is the canonical representation of everything
Sentinel learned from a bounty program's policy page: in/out-of-scope
domains, test credentials (personas), restrictions, payout tier, and
provenance.

It flows through every Phase 2 layer:

    Extractor → ProgramScope → Verifier → ProgramScope (creds annotated)
                                       → Compiler  → scope file + personas.json

The model is intentionally serializable to plain JSON (no pickle, no
Pydantic) so that:

  * Each layer's output can be cached on disk for replay / debug.
  * The model can cross process boundaries (CLI ↔ daemon ↔ tests).
  * Stale ``ProgramScope`` files from old extractor versions are easy
    to detect via ``extractor_version`` + ``raw_content_hash``.

Schema-version-bumping policy:
  Bumping any field in this file should bump ``ProgramScope.SCHEMA_VERSION``
  so cached files from prior versions are rejected (and re-extracted)
  rather than silently mis-parsed.
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────
# Enums — kept as ``str`` mixins so JSON serialization is automatic
# (json.dumps(VerificationStatus.VERIFIED) writes "verified", not the
# enum's repr).
# ─────────────────────────────────────────────────────────────────────────

class Platform(str, enum.Enum):
    """Which bug bounty platform hosts this program."""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    GITHUB_SECURITY_LAB = "github_security_lab"
    SELF_HOSTED = "self_hosted"           # Program runs its own VRP page
    DIRECT_URL = "direct_url"             # No platform — operator gave us a URL
    UNKNOWN = "unknown"


class CredentialSource(str, enum.Enum):
    """Where this credential pair came from — for audit and trust scoring."""
    POLICY_EXPLICIT = "policy_explicit"   # Listed verbatim in policy page
    POLICY_INFERRED = "policy_inferred"   # LLM extracted from prose
    AUTO_REGISTERED = "auto_registered"   # We created the account via signup
    OPERATOR_PROVIDED = "operator_provided"  # Operator put it in config manually
    PLATFORM_API = "platform_api"         # Fetched via H1/Bugcrowd API
    UNKNOWN = "unknown"


class VerificationStatus(str, enum.Enum):
    """Has Sentinel confirmed this credential pair actually works?"""
    VERIFIED = "verified"       # Login succeeded; auth token / cookie obtained
    FAILED = "failed"           # Login attempted, did not succeed
    UNVERIFIED = "unverified"   # Not yet attempted (or unable to attempt — no login flow)


class ScopeRuleType(str, enum.Enum):
    """Granularity of a scope rule."""
    DOMAIN = "domain"           # "*.gitlab.com"
    URL = "url"                 # "https://example.com/admin/*"
    IP_CIDR = "ip_cidr"         # "192.168.0.0/16"
    MOBILE_APP = "mobile_app"   # iOS / Android bundle id
    SOURCE_CODE = "source_code" # GitHub repo
    OTHER = "other"


class RestrictionKind(str, enum.Enum):
    """Categories of restriction that programs commonly impose.

    These map 1:1 to enforcement actions in the Strategos policy gate
    (Phase 2E). A new restriction kind here MUST be paired with a
    handler there, or it will silently be ignored at scan time.
    """
    NO_DOS = "no_dos"
    NO_AUTOMATED_SCAN = "no_automated_scan"
    NO_SOCIAL_ENG = "no_social_engineering"
    NO_DATA_DESTRUCTION = "no_data_destruction"
    NO_BRUTEFORCE = "no_bruteforce"
    NO_THIRD_PARTY = "no_third_party_services"
    RATE_LIMITED = "rate_limited"
    BUSINESS_HOURS_ONLY = "business_hours_only"
    REGION_RESTRICTED = "region_restricted"
    REQUIRES_PRIOR_APPROVAL = "requires_prior_approval"
    OTHER = "other"


# ─────────────────────────────────────────────────────────────────────────
# Leaf dataclasses
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class LoginFlow:
    """How to perform a login against this program's auth endpoint.

    Captures only the information needed to programmatically authenticate.
    CSRF tokens that must be fetched first are represented in
    ``additional_fields`` with values like ``"$CSRF_FROM:/login"`` —
    a small DSL the verifier interprets.
    """
    endpoint: str                                    # "/api/login"
    method: str = "POST"                             # "POST" | "GET"
    username_param: str = "email"                    # form/JSON key for username
    password_param: str = "password"                 # form/JSON key for password
    content_type: str = "application/json"           # "application/json" | "application/x-www-form-urlencoded"
    token_extract_path: Optional[str] = None         # JSONPath-lite: "data.token"
    cookie_extract_name: Optional[str] = None        # Cookie name to capture as session token
    additional_fields: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return _asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoginFlow":
        return cls(**data)


@dataclass
class Persona:
    """A named credential pair for IDOR / persona-diff testing.

    ``persona_type`` is a free-text role descriptor: ``"user"``,
    ``"admin"``, ``"merchant"``, ``"anonymous"``, etc. The persona
    *type* determines how the persona-diff scanner uses it — for
    example, two ``user`` personas with different ids are the input
    for cross-user IDOR; one ``user`` + one ``admin`` is the input
    for privilege-escalation diffs.

    A persona with ``persona_type == "anonymous"`` carries no creds
    and no login flow — it represents an unauthenticated baseline.
    """
    name: str
    persona_type: str
    base_url: str
    login_flow: Optional[LoginFlow] = None
    username: Optional[str] = None
    password: Optional[str] = None
    role_hint: Optional[str] = None
    source: CredentialSource = CredentialSource.UNKNOWN
    verified: VerificationStatus = VerificationStatus.UNVERIFIED
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return _asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Persona":
        data = dict(data)  # don't mutate caller
        if "login_flow" in data and data["login_flow"] is not None:
            data["login_flow"] = LoginFlow.from_dict(data["login_flow"])
        if "source" in data:
            data["source"] = CredentialSource(data["source"])
        if "verified" in data:
            data["verified"] = VerificationStatus(data["verified"])
        return cls(**data)


@dataclass
class ScopeRule:
    """A single in-scope or out-of-scope assertion."""
    pattern: str
    rule_type: ScopeRuleType
    in_scope: bool
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopeRule":
        data = dict(data)
        if "rule_type" in data:
            data["rule_type"] = ScopeRuleType(data["rule_type"])
        return cls(**data)


@dataclass
class Restriction:
    """A constraint the program imposes on testing.

    ``severity == "hard"`` means scan execution must respect it (e.g.
    NO_DOS hard ⇒ refuse to run nuclei DoS templates). ``"soft"`` means
    surface it as a warning but proceed.

    ``applies_to`` is the **scope** of the rule — which category of
    testing it governs. This is the field that prevents a rule from a
    program's DoS-testing subsection from being mis-enforced as a
    program-wide activity ban (Calibration Run #17 finding):

      ["all"]           — global: governs all testing on the program
      ["dos"]           — only DoS / load testing
      ["bruteforce"]    — only brute-force / enumeration
      ["social_eng"]    — only social engineering
      ["automated"]     — only automated/scanner traffic (vs manual)
      [...multiple...]  — governs several specific categories

    The policy_enforcer only hard-blocks a scan when ``"all"`` is in
    ``applies_to``. A ``no_automated_scan`` rule scoped to ``["dos"]``
    disables DoS tooling but lets the rest of the scan proceed.
    Defaults to ``["all"]`` when the extractor can't determine scope —
    conservative, but the extraction prompt is tuned to scope correctly.
    """
    kind: RestrictionKind
    severity: str        # "hard" | "soft"
    description: str
    raw_quote: Optional[str] = None  # Verbatim policy quote, for audit
    applies_to: List[str] = field(default_factory=lambda: ["all"])

    def to_dict(self) -> Dict[str, Any]:
        return _asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Restriction":
        data = dict(data)
        if "kind" in data:
            data["kind"] = RestrictionKind(data["kind"])
        # Backfill applies_to for any pre-1.1 dict that lacks it.
        if "applies_to" not in data or not data["applies_to"]:
            data["applies_to"] = ["all"]
        return cls(**data)


# ─────────────────────────────────────────────────────────────────────────
# Top-level ProgramScope
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class ProgramScope:
    """Everything Sentinel knows about a bug bounty program.

    Each Phase 2 layer reads and/or writes this object. It's the
    serializable unit of caching, audit, and replay.

    Lifecycle (typical):

        1. Resolver maps handle → source_url
        2. Extractor fetches source_url → ProgramScope(
               scope_rules=[...], personas=[Persona(verified=UNVERIFIED, ...)],
               restrictions=[...], raw_content_hash=sha256(page),
           )
        3. Verifier attempts each persona's login_flow, mutates
           Persona.verified in place.
        4. (Optional) Registrar creates new personas via signup endpoint.
        5. Compilers consume ProgramScope and emit Sentinel's existing
           config files (CAL scope DSL, personas.json, restrictions).
    """

    # Bumped any time the field layout changes. Loaders use this to
    # reject (and trigger re-extraction of) stale cached scopes.
    SCHEMA_VERSION: str = field(default="1.1", init=False, repr=False)

    # ── Identity ──────────────────────────────────────────────────────
    handle: Optional[str]
    platform: Platform
    name: str
    source_url: str
    fetched_at: datetime

    # ── Scope ─────────────────────────────────────────────────────────
    scope_rules: List[ScopeRule] = field(default_factory=list)

    # ── Credentials ───────────────────────────────────────────────────
    personas: List[Persona] = field(default_factory=list)
    signup_endpoint: Optional[str] = None

    # ── Constraints ───────────────────────────────────────────────────
    restrictions: List[Restriction] = field(default_factory=list)
    rate_limit_rps: Optional[float] = None
    payout_max_usd: Optional[int] = None

    # ── Provenance ────────────────────────────────────────────────────
    raw_content_hash: str = ""
    extractor_version: str = "unknown"
    extraction_confidence: float = 0.0

    # ─── Helpers ──────────────────────────────────────────────────────

    def in_scope_domains(self) -> List[str]:
        """Convenience: just the in-scope DOMAIN patterns."""
        return [
            r.pattern for r in self.scope_rules
            if r.in_scope and r.rule_type == ScopeRuleType.DOMAIN
        ]

    def verified_personas(self) -> List[Persona]:
        """Convenience: only personas whose login was confirmed."""
        return [p for p in self.personas if p.verified == VerificationStatus.VERIFIED]

    def hard_restrictions(self) -> List[Restriction]:
        """Convenience: only restrictions that block scan execution."""
        return [r for r in self.restrictions if r.severity == "hard"]

    # ─── Serialization ────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """JSON-ready dict. Round-trips with ``from_dict``."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "handle": self.handle,
            "platform": self.platform.value,
            "name": self.name,
            "source_url": self.source_url,
            "fetched_at": self.fetched_at.isoformat(),
            "scope_rules": [r.to_dict() for r in self.scope_rules],
            "personas": [p.to_dict() for p in self.personas],
            "signup_endpoint": self.signup_endpoint,
            "restrictions": [r.to_dict() for r in self.restrictions],
            "rate_limit_rps": self.rate_limit_rps,
            "payout_max_usd": self.payout_max_usd,
            "raw_content_hash": self.raw_content_hash,
            "extractor_version": self.extractor_version,
            "extraction_confidence": self.extraction_confidence,
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProgramScope":
        """Re-hydrate from a dict produced by ``to_dict``.

        Raises ValueError if the schema_version doesn't match — callers
        should treat that as "cache miss, re-extract."
        """
        schema = data.get("schema_version", "0")
        if schema != cls.SCHEMA_VERSION:
            raise ValueError(
                f"ProgramScope schema mismatch: cached={schema!r} "
                f"current={cls.SCHEMA_VERSION!r}. Re-extract required."
            )
        return cls(
            handle=data.get("handle"),
            platform=Platform(data["platform"]),
            name=data["name"],
            source_url=data["source_url"],
            fetched_at=_parse_iso(data["fetched_at"]),
            scope_rules=[ScopeRule.from_dict(r) for r in data.get("scope_rules", [])],
            personas=[Persona.from_dict(p) for p in data.get("personas", [])],
            signup_endpoint=data.get("signup_endpoint"),
            restrictions=[Restriction.from_dict(r) for r in data.get("restrictions", [])],
            rate_limit_rps=data.get("rate_limit_rps"),
            payout_max_usd=data.get("payout_max_usd"),
            raw_content_hash=data.get("raw_content_hash", ""),
            extractor_version=data.get("extractor_version", "unknown"),
            extraction_confidence=data.get("extraction_confidence", 0.0),
        )

    @classmethod
    def from_json(cls, text: str) -> "ProgramScope":
        return cls.from_dict(json.loads(text))


# ─────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────

def content_hash(text: str) -> str:
    """SHA-256 of UTF-8 text, hex-encoded. Used for cache invalidation
    when a remote policy page changes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _asdict(obj: Any) -> Dict[str, Any]:
    """Custom dataclass-to-dict that respects enum-string serialization.

    The stdlib ``dataclasses.asdict`` recursion calls ``copy.deepcopy``
    which mangles enum subclasses in some edge cases; this is simpler
    and avoids that.
    """
    if not is_dataclass(obj):
        raise TypeError(f"_asdict expects a dataclass, got {type(obj).__name__}")
    out: Dict[str, Any] = {}
    for f in fields(obj):
        value = getattr(obj, f.name)
        out[f.name] = _serialize_value(value)
    return out


def _serialize_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return _asdict(value)
    if isinstance(value, (list, tuple)):
        return [_serialize_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize_value(v) for k, v in value.items()}
    return value


def _parse_iso(text: str) -> datetime:
    """Parse an ISO 8601 timestamp string. Always returns tz-aware UTC."""
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
