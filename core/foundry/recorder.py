"""
core/foundry/recorder.py — Phase 7-PF8: the Recipe Recorder.

Turns a captured browser action log into a SignupRecipe — and, crucially,
INFERS the right binding for each field from its semantics. A fill into a
field that looks like an email becomes `persona:email`; a password field
becomes `generated:password`; a recaptcha iframe becomes a
`CHALLENGE(captcha)` step. The researcher records a signup once (manually,
through a real browser); the recorder produces a parameterized recipe
that replays for any persona.

The substantive, novel, testable logic is `infer_binding()`: the "look at
the signup field and figure out what it MEANS" intelligence. Production
action logs come from a Playwright codegen / injected-recorder session;
tests feed synthetic logs. Either way, the inference is the same.

────────────────────────────────────────────────────────────────────
The action log
────────────────────────────────────────────────────────────────────
A list of RecordedAction. Each is one thing the human did (or the
recorder observed):

  navigate   — page changed to a URL.
  fill       — typed into a field. Carries `field` metadata (name, id,
               type, label, placeholder, autocomplete) — NOT the value
               typed (we infer the binding, we don't store secrets).
  click      — clicked an element.
  challenge  — the recorder detected an anti-bot wall (a captcha iframe,
               a verification redirect). Carries challenge_kind.

The recorder maps each action to a RecipeStep, inferring FILL bindings.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional

from core.foundry.recipe import (
    ChallengeKind,
    RecipeStep,
    SignupRecipe,
    StepKind,
)

logger = logging.getLogger(__name__)


# ─────────────────────────── recorded action ───────────────────────────


@dataclass
class RecordedAction:
    """One captured browser event."""
    action: str                                # navigate | fill | click | challenge
    url: Optional[str] = None                  # navigate
    selector: Optional[Dict[str, str]] = None  # fill | click — how to locate
    field: Dict[str, str] = dc_field(default_factory=dict)  # fill metadata
    challenge_kind: Optional[str] = None       # challenge
    label: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RecordedAction":
        return cls(
            action=d["action"],
            url=d.get("url"),
            selector=d.get("selector"),
            field=dict(d.get("field", {})),
            challenge_kind=d.get("challenge_kind"),
            label=d.get("label", ""),
        )


# ─────────────────────────── binding inference ───────────────────────────


# The "stash key" the replay engine remembers a generated password under,
# so a confirm-password field can reference the SAME value.
_GENERATED_PASSWORD_REF = "extracted:generated_password"


def _field_signal(field: Dict[str, str]) -> str:
    """Concatenate the field's identifying attributes into one lowercase
    haystack for substring matching."""
    parts = [
        field.get("name", ""),
        field.get("id", ""),
        field.get("label", ""),
        field.get("placeholder", ""),
        field.get("autocomplete", ""),
        field.get("aria-label", ""),
    ]
    return " ".join(p for p in parts if p).lower()


def infer_binding(
    field: Dict[str, str], *, password_seen: bool = False
) -> str:
    """Infer the value binding for a FILL from the field's semantics.

    Args:
      field: the field metadata (name, id, type, label, placeholder,
             autocomplete, aria-label).
      password_seen: True if a password field was already filled earlier
             in this recipe — so a SECOND password field is treated as a
             confirm-password and bound to the SAME generated value.

    Returns a binding string ("persona:email", "generated:password", …).

    The order of checks matters: more-specific signals (autocomplete,
    type) win over fuzzy name matching.
    """
    ftype = (field.get("type") or "").lower()
    autocomplete = (field.get("autocomplete") or "").lower()
    signal = _field_signal(field)

    # Password fields — strongest signal is type=password.
    if ftype == "password" or "password" in signal or "passwd" in signal:
        # A second password field is a confirm — reuse the generated one.
        if password_seen or "confirm" in signal or "repeat" in signal or "verify" in signal:
            return _GENERATED_PASSWORD_REF
        return "generated:password"

    # Email — autocomplete=email, type=email, or "email" in the signal.
    if autocomplete == "email" or ftype == "email" or "email" in signal or "e-mail" in signal:
        return "persona:email"

    # Phone — autocomplete=tel, type=tel, or phone-ish words.
    if autocomplete in ("tel", "tel-national") or ftype == "tel" or \
       any(w in signal for w in ("phone", "mobile", "telephone")):
        return "persona:phone"

    # Names. autocomplete is the cleanest: given-name / family-name.
    if autocomplete == "given-name" or any(
        w in signal for w in ("first name", "firstname", "fname", "given name")
    ):
        return "persona:first_name"
    if autocomplete == "family-name" or any(
        w in signal for w in ("last name", "lastname", "lname", "surname", "family name")
    ):
        return "persona:last_name"

    # A generic "name" / "full name" / "your name" → a generated username
    # (signup "name" fields are usually display names, not legal names).
    if any(w in signal for w in ("username", "user name", "handle", "screen name")):
        return "generated:username"
    if "name" in signal:
        # Ambiguous full-name field — prefer first_name (most common
        # mapping); operator can adjust. Mark in the step metadata.
        return "persona:first_name"

    # Date of birth.
    if any(w in signal for w in ("birth", "dob", "birthday")):
        return "persona:date_of_birth"

    # Fallback — an unrecognized field. Bind to a literal placeholder so
    # the recipe is valid but the operator knows to review it.
    return "literal:REVIEW_THIS_FIELD"


_CHALLENGE_KIND_MAP = {
    "captcha": ChallengeKind.CAPTCHA,
    "recaptcha": ChallengeKind.CAPTCHA,
    "hcaptcha": ChallengeKind.CAPTCHA,
    "turnstile": ChallengeKind.CAPTCHA,
    "email_link": ChallengeKind.EMAIL_LINK,
    "email_code": ChallengeKind.EMAIL_CODE,
    "sms_code": ChallengeKind.SMS_CODE,
    "payment_3ds": ChallengeKind.PAYMENT_3DS,
    "tos_scroll": ChallengeKind.TOS_SCROLL,
}


# ─────────────────────────── the recorder ───────────────────────────


def record_to_recipe(
    *,
    service_handle: str,
    origin: str,
    name: str,
    actions: List[RecordedAction],
) -> SignupRecipe:
    """Convert a captured action log into a parameterized SignupRecipe.

    FILL steps get their bindings inferred from field semantics. CHALLENGE
    actions become CHALLENGE steps. The result is validated before return
    so a malformed capture surfaces immediately.
    """
    steps: List[RecipeStep] = []
    password_seen = False
    review_flags: List[str] = []

    for i, act in enumerate(actions):
        if act.action == "navigate":
            steps.append(RecipeStep(
                kind=StepKind.NAVIGATE, url=act.url,
                label=act.label or f"navigate to {act.url}",
            ))

        elif act.action == "fill":
            binding = infer_binding(act.field, password_seen=password_seen)
            if binding in ("generated:password",):
                password_seen = True
            if binding == "literal:REVIEW_THIS_FIELD":
                review_flags.append(
                    f"step {len(steps)}: field "
                    f"{act.field.get('name') or act.field.get('id') or '?'} "
                    f"could not be inferred — review the binding"
                )
            label = act.label or _label_for_binding(binding)
            steps.append(RecipeStep(
                kind=StepKind.FILL, label=label,
                selector=act.selector,
                value_binding=binding,
                metadata={"inferred_from": _field_signal(act.field)} if act.field else {},
            ))

        elif act.action == "click":
            steps.append(RecipeStep(
                kind=StepKind.CLICK, label=act.label or "click",
                selector=act.selector,
            ))

        elif act.action == "challenge":
            kind = _CHALLENGE_KIND_MAP.get(
                (act.challenge_kind or "").lower(), ChallengeKind.MANUAL
            )
            steps.append(RecipeStep(
                kind=StepKind.CHALLENGE, label=act.label or f"{kind.value} challenge",
                challenge_kind=kind,
            ))

        else:
            logger.warning(
                "[recorder] skipping unknown action %r at index %d",
                act.action, i,
            )

    recipe = SignupRecipe(
        service_handle=service_handle,
        name=name,
        origin=origin,
        steps=steps,
        source="recorded",
        notes=(
            "Auto-recorded. " + (
                "Review needed: " + "; ".join(review_flags)
                if review_flags else "All fields inferred."
            )
        ),
    )
    recipe.validate()
    recipe.derive_required_persona_fields()
    logger.info(
        "[recorder] recorded %s: %d steps, %d challenge(s), %d field(s) "
        "needing review",
        service_handle, len(steps), len(recipe.challenge_steps()),
        len(review_flags),
    )
    return recipe


def _label_for_binding(binding: str) -> str:
    mapping = {
        "persona:email": "fill email",
        "persona:phone": "fill phone",
        "persona:first_name": "fill first name",
        "persona:last_name": "fill last name",
        "persona:date_of_birth": "fill date of birth",
        "generated:password": "fill password",
        "generated:username": "fill username",
        _GENERATED_PASSWORD_REF: "confirm password",
        "literal:REVIEW_THIS_FIELD": "fill (REVIEW)",
    }
    return mapping.get(binding, "fill field")
