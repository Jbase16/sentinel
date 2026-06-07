"""
core/foundry/recipe.py — Phase 7-PF1: the SignupRecipe artifact.

A SignupRecipe is a declarative, serializable, PARAMETERIZABLE
description of how to sign up to a service. The key word is
parameterizable: a recipe binds form fields to *persona fields*
(persona:email) rather than literals, so ONE recorded recipe replayed
with N personas creates N accounts.

A recipe is also DRIVER-AGNOSTIC. The steps describe *what* to do
("fill the field that looks like an email input with the persona's
email"), not *how* a specific browser does it. The replay engine
(PF3) binds a concrete driver (real browser automation, or a mock for
tests).

────────────────────────────────────────────────────────────────────
Step kinds
────────────────────────────────────────────────────────────────────
  NAVIGATE    — go to a URL.
  FILL        — type a value into a field (selector + value_binding).
  CLICK       — click an element (button, link, checkbox).
  WAIT_FOR    — wait until an element/condition is present.
  EXTRACT     — pull a value off the page into a named variable
                (e.g. capture the API token shown after signup).
  CHALLENGE   — a KNOWN anti-bot wall (CAPTCHA / email-link / SMS /
                payment-3DS / ToS-scroll). The replay engine emits a
                challenge event here and BLOCKS for the human. We
                never try to solve these.

────────────────────────────────────────────────────────────────────
Value bindings (what a FILL puts into a field)
────────────────────────────────────────────────────────────────────
  literal:<text>          — a fixed string.
  persona:<field>         — pull persona.field (email, password,
                            first_name, last_name, phone, …).
  generated:<kind>        — generate at replay time (password,
                            username). Keeps recorded recipes free of
                            real secrets.
  verification:<source>   — block until a verification artifact is
                            available, then use it (email_link,
                            sms_code). The actual fetch is a
                            CHALLENGE-or-bridge concern; the binding
                            just declares the dependency.
  extracted:<var>         — a value EXTRACTed earlier in this recipe
                            (e.g. a CSRF token read off the page).

Binding strings use a `kind:arg` shape so recipes stay plain JSON.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class StepKind(str, Enum):
    NAVIGATE = "navigate"
    FILL = "fill"
    CLICK = "click"
    WAIT_FOR = "wait_for"
    EXTRACT = "extract"
    CHALLENGE = "challenge"


class BindingKind(str, Enum):
    LITERAL = "literal"
    PERSONA = "persona"
    GENERATED = "generated"
    VERIFICATION = "verification"
    EXTRACTED = "extracted"


class ChallengeKind(str, Enum):
    """The anti-bot wall types we recognize. Each maps to a distinct
    human-handoff prompt in PF4."""
    CAPTCHA = "captcha"
    EMAIL_LINK = "email_link"
    EMAIL_CODE = "email_code"
    SMS_CODE = "sms_code"
    PAYMENT_3DS = "payment_3ds"
    TOS_SCROLL = "tos_scroll"
    MANUAL = "manual"  # catch-all: "a human needs to look at this"


# ─────────────────────────── bindings ───────────────────────────


def resolve_binding(
    binding: str,
    *,
    persona: Optional[Dict[str, Any]] = None,
    extracted: Optional[Dict[str, Any]] = None,
    generator=None,
) -> str:
    """Resolve a `kind:arg` value binding into a concrete string.

    Args:
      binding: "literal:foo", "persona:email", "generated:password",
               "extracted:csrf", "verification:email_link".
      persona: dict of persona fields (for persona: bindings).
      extracted: dict of values EXTRACTed earlier (for extracted:).
      generator: optional callable(kind:str) -> str for generated:
                 bindings. Defaults to a built-in generator.

    Returns the resolved string.

    Raises:
      ValueError on malformed binding or missing source.

    Note: `verification:*` bindings can NOT be resolved here — they
    require a runtime verification fetch (email poll / SMS bridge /
    challenge). The replay engine handles those specially; calling
    resolve_binding on one raises so a misuse is loud.
    """
    if ":" not in binding:
        raise ValueError(
            f"binding {binding!r} missing ':' — expected 'kind:arg'"
        )
    kind_raw, _, arg = binding.partition(":")
    try:
        kind = BindingKind(kind_raw)
    except ValueError:
        raise ValueError(
            f"unknown binding kind {kind_raw!r} in {binding!r}; "
            f"known: {[k.value for k in BindingKind]}"
        )

    if kind is BindingKind.LITERAL:
        return arg
    if kind is BindingKind.PERSONA:
        if not persona or arg not in persona:
            raise ValueError(
                f"persona binding {binding!r} but persona has no "
                f"field {arg!r} (have: {list((persona or {}).keys())})"
            )
        return str(persona[arg])
    if kind is BindingKind.EXTRACTED:
        if not extracted or arg not in extracted:
            raise ValueError(
                f"extracted binding {binding!r} but no variable "
                f"{arg!r} was extracted yet "
                f"(have: {list((extracted or {}).keys())})"
            )
        return str(extracted[arg])
    if kind is BindingKind.GENERATED:
        gen = generator or _default_generator
        return gen(arg)
    if kind is BindingKind.VERIFICATION:
        raise ValueError(
            f"verification binding {binding!r} cannot be resolved "
            f"synchronously — it requires a runtime verification fetch "
            f"(handled by the replay engine, not resolve_binding)."
        )
    raise ValueError(f"unhandled binding kind {kind}")  # pragma: no cover


def _default_generator(kind: str) -> str:
    """Built-in generators for `generated:*` bindings.

    password — a strong random password meeting common policies
               (upper, lower, digit, symbol, length 20).
    username — a pronounceable-ish random handle.
    uuid     — a bare uuid4 hex.
    """
    import secrets
    import string

    if kind == "password":
        # Guarantee one of each class, then fill to length 20.
        alpha_l = secrets.choice(string.ascii_lowercase)
        alpha_u = secrets.choice(string.ascii_uppercase)
        digit = secrets.choice(string.digits)
        symbol = secrets.choice("!@#$%^&*-_=+")
        pool = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        rest = "".join(secrets.choice(pool) for _ in range(16))
        chars = list(alpha_l + alpha_u + digit + symbol + rest)
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)
    if kind == "username":
        return "sf_" + secrets.token_hex(6)
    if kind == "uuid":
        return uuid.uuid4().hex
    raise ValueError(f"unknown generated kind {kind!r}")


# ─────────────────────────── steps ───────────────────────────


@dataclass
class RecipeStep:
    """One declarative action in a signup recipe.

    Not every field applies to every kind — selectors apply to
    FILL/CLICK/WAIT_FOR/EXTRACT, value_binding only to FILL,
    extract_as only to EXTRACT, challenge_kind only to CHALLENGE,
    url only to NAVIGATE. Validation in `validate()` enforces the
    per-kind requirements.
    """
    kind: StepKind
    # Human-readable label for logs + the recorder UI ("fill email").
    label: str = ""
    # NAVIGATE
    url: Optional[str] = None
    # FILL / CLICK / WAIT_FOR / EXTRACT — how to locate the element.
    # A driver-agnostic selector spec: {"by": "css"|"label"|"name"|
    # "placeholder"|"role", "value": "..."}. The replay driver maps
    # this to its own locator API.
    selector: Optional[Dict[str, str]] = None
    # FILL — the value binding string ("persona:email").
    value_binding: Optional[str] = None
    # EXTRACT — the variable name to store the extracted value under.
    extract_as: Optional[str] = None
    # EXTRACT — how to read the value: "text" | "value" | "attr:href" | "json:path".
    extract_mode: str = "text"
    # CHALLENGE — which anti-bot wall this is.
    challenge_kind: Optional[ChallengeKind] = None
    # CHALLENGE — a human-facing prompt ("Solve the CAPTCHA shown.").
    challenge_prompt: Optional[str] = None
    # WAIT_FOR — max seconds to wait before the step fails.
    timeout_s: float = 15.0
    # Optional free-form metadata (recorder annotations, retries, …).
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Raise ValueError if the step's fields are inconsistent with
        its kind. Called by SignupRecipe.validate()."""
        k = self.kind
        if k is StepKind.NAVIGATE:
            if not self.url:
                raise ValueError("NAVIGATE step requires a url")
        elif k is StepKind.FILL:
            if not self.selector:
                raise ValueError("FILL step requires a selector")
            if not self.value_binding:
                raise ValueError("FILL step requires a value_binding")
        elif k in (StepKind.CLICK, StepKind.WAIT_FOR):
            if not self.selector:
                raise ValueError(f"{k.value.upper()} step requires a selector")
        elif k is StepKind.EXTRACT:
            if not self.selector:
                raise ValueError("EXTRACT step requires a selector")
            if not self.extract_as:
                raise ValueError("EXTRACT step requires extract_as")
        elif k is StepKind.CHALLENGE:
            if not self.challenge_kind:
                raise ValueError("CHALLENGE step requires a challenge_kind")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "label": self.label,
            "url": self.url,
            "selector": dict(self.selector) if self.selector else None,
            "value_binding": self.value_binding,
            "extract_as": self.extract_as,
            "extract_mode": self.extract_mode,
            "challenge_kind": self.challenge_kind.value if self.challenge_kind else None,
            "challenge_prompt": self.challenge_prompt,
            "timeout_s": self.timeout_s,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RecipeStep":
        return cls(
            kind=StepKind(d["kind"]),
            label=d.get("label", ""),
            url=d.get("url"),
            selector=d.get("selector"),
            value_binding=d.get("value_binding"),
            extract_as=d.get("extract_as"),
            extract_mode=d.get("extract_mode", "text"),
            challenge_kind=(
                ChallengeKind(d["challenge_kind"])
                if d.get("challenge_kind") else None
            ),
            challenge_prompt=d.get("challenge_prompt"),
            timeout_s=float(d.get("timeout_s", 15.0)),
            metadata=dict(d.get("metadata", {})),
        )


# ─────────────────────────── recipe ───────────────────────────


@dataclass
class SignupRecipe:
    """A named, versioned, parameterizable signup flow for one service.

    The `service_handle` ties the recipe to a program (e.g. "airtable")
    so the vault's per-service rate limiting and audit can correlate
    "which recipe created which account where". `origin` is the
    base URL the recipe operates against — used by the replay engine's
    scope gate to refuse navigating off-origin mid-flow.
    """
    service_handle: str
    name: str
    origin: str
    steps: List[RecipeStep] = field(default_factory=list)
    recipe_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    version: int = 1
    created_at: float = field(default_factory=time.time)
    # Which persona fields this recipe consumes — derived from the
    # persona: bindings. Lets the vault validate "this persona has
    # everything this recipe needs" before a replay starts.
    required_persona_fields: List[str] = field(default_factory=list)
    # Provenance: "recorded" (PF1 recorder) | "inferred" (PF2 LLM) |
    # "hand-written".
    source: str = "recorded"
    notes: str = ""

    def validate(self) -> None:
        """Validate the whole recipe. Raises ValueError on the first
        problem found."""
        if not self.service_handle:
            raise ValueError("recipe requires a service_handle")
        if not self.origin:
            raise ValueError("recipe requires an origin")
        if not self.steps:
            raise ValueError("recipe has no steps")
        for i, step in enumerate(self.steps):
            try:
                step.validate()
            except ValueError as e:
                raise ValueError(f"step {i} ({step.kind.value}): {e}")

    def derive_required_persona_fields(self) -> List[str]:
        """Scan FILL steps for persona: bindings and return the sorted
        set of persona field names this recipe needs. Also updates
        self.required_persona_fields in place."""
        needed: set[str] = set()
        for step in self.steps:
            if step.kind is StepKind.FILL and step.value_binding:
                if step.value_binding.startswith("persona:"):
                    needed.add(step.value_binding.split(":", 1)[1])
        self.required_persona_fields = sorted(needed)
        return self.required_persona_fields

    def challenge_steps(self) -> List[RecipeStep]:
        """All CHALLENGE steps — useful for previewing 'this signup
        will require N human handoffs' before starting."""
        return [s for s in self.steps if s.kind is StepKind.CHALLENGE]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipe_id": self.recipe_id,
            "service_handle": self.service_handle,
            "name": self.name,
            "origin": self.origin,
            "version": self.version,
            "created_at": self.created_at,
            "required_persona_fields": list(self.required_persona_fields),
            "source": self.source,
            "notes": self.notes,
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignupRecipe":
        recipe = cls(
            service_handle=d["service_handle"],
            name=d.get("name", d["service_handle"]),
            origin=d["origin"],
            steps=[RecipeStep.from_dict(s) for s in d.get("steps", [])],
            recipe_id=d.get("recipe_id", uuid.uuid4().hex),
            version=int(d.get("version", 1)),
            created_at=float(d.get("created_at", time.time())),
            required_persona_fields=list(d.get("required_persona_fields", [])),
            source=d.get("source", "recorded"),
            notes=d.get("notes", ""),
        )
        return recipe
