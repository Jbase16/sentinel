"""
core/foundry/recorder.py — Phase 7-PF8: the Recipe Recorder.

Turns a captured browser action log into a SignupRecipe — and, crucially,
INFERS the right binding for each field from its semantics. A fill into a
field that looks like an email becomes `persona:email`; a password field
becomes `persona:password`; a recaptcha iframe becomes a
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
import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

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
    correlation_id: Optional[str] = None       # response provenance, never a secret
    response_status: Optional[int] = None      # terminal navigation health

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RecordedAction":
        return cls(
            action=d["action"],
            url=d.get("url"),
            selector=d.get("selector"),
            field=dict(d.get("field", {})),
            challenge_kind=d.get("challenge_kind"),
            label=d.get("label", ""),
            correlation_id=d.get("correlation_id"),
            response_status=(
                int(d["response_status"])
                if d.get("response_status") is not None else None
            ),
        )


def recording_rejection_reason(actions: List[RecordedAction]) -> Optional[str]:
    """Return why a human-visible recording is unsafe to persist.

    Closing the native window is the operator's completion signal. This check
    deliberately avoids assuming a site-specific success URL, while still
    rejecting captures that cannot reproduce an interaction or that visibly
    ended on an HTTP failure page.
    """
    if not any(action.action in {"fill", "click", "challenge"} for action in actions):
        return "recording contains no reproducible interaction"

    navigations = [action for action in actions if action.action == "navigate"]
    if not navigations:
        return "recording contains no navigation"

    terminal = navigations[-1]
    if terminal.response_status is not None and terminal.response_status >= 400:
        return (
            "recording ended on an HTTP error "
            f"({terminal.response_status}) at "
            f"{_redact_url(terminal.url) or 'unknown URL'}"
        )
    return None


# ─────────────────────────── binding inference ───────────────────────────


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
        field.get("help_text", ""),
    ]
    return " ".join(p for p in parts if p).lower()


def infer_semantic_key(field: Dict[str, str]) -> str:
    """Return the stable meaning of one captured control.

    The semantic key is deliberately independent of DOM position and selector.
    It distinguishes fields that share a value (password/password_confirm) and
    records non-text controls such as terms acceptance.
    """
    ftype = (field.get("type") or "").lower()
    autocomplete = (field.get("autocomplete") or "").lower()
    signal = _field_signal(field)

    if autocomplete == "one-time-code" or any(
        word in signal
        for word in ("verification code", "email code", "one-time code", "one-time-code", "otp")
    ):
        return "verification_code"
    if (
        ftype == "password"
        or autocomplete == "new-password"
        or "password" in signal
        or "passwd" in signal
    ):
        if any(word in signal for word in ("confirm", "confirmation", "repeat", "match")):
            return "password_confirm"
        return "password"
    if autocomplete == "email" or ftype == "email" or "email" in signal or "e-mail" in signal:
        return "email"
    if ftype == "checkbox" and any(
        word in signal for word in ("terms", "agree", "agreed", "consent")
    ):
        return "accept_terms"
    if autocomplete in ("tel", "tel-national") or ftype == "tel" or any(
        word in signal for word in ("phone", "mobile", "telephone")
    ):
        return "phone"
    if autocomplete == "name" or any(
        word in signal for word in ("full name", "display name", "your name")
    ):
        return "display_name"
    if autocomplete == "given-name" or any(
        word in signal for word in ("first name", "firstname", "fname", "given name")
    ):
        return "first_name"
    if autocomplete == "family-name" or any(
        word in signal for word in ("last name", "lastname", "lname", "surname", "family name")
    ):
        return "last_name"
    if autocomplete == "username" or any(
        word in signal for word in ("username", "user name", "handle", "screen name")
    ):
        return "username"
    if autocomplete == "bday" or any(word in signal for word in ("birth", "dob", "birthday")):
        return "date_of_birth"
    if "name" in signal:
        return "display_name"
    return "unknown"


def infer_binding(
    field: Dict[str, str], *, password_seen: bool = False
) -> str:
    """Infer the value binding for a FILL from the field's semantics.

    Args:
      field: the field metadata (name, id, type, label, placeholder,
             autocomplete, aria-label).
      password_seen: Retained for caller compatibility. Password and confirmation
             fields both bind to the persona's vault-backed password, so this flag
             does not alter the returned binding.

    Returns a binding string ("persona:email", "persona:password", …).

    The order of checks matters: more-specific signals (autocomplete,
    type) win over fuzzy name matching.
    """
    semantic_key = infer_semantic_key(field)

    if semantic_key in {"password", "password_confirm"}:
        return "persona:password"
    if semantic_key == "email":
        return "persona:email"
    if semantic_key == "phone":
        return "persona:phone"
    if semantic_key == "display_name":
        return "persona:full_name"
    if semantic_key == "first_name":
        return "persona:first_name"
    if semantic_key == "last_name":
        return "persona:last_name"
    if semantic_key == "username":
        return "generated:username"
    if semantic_key == "date_of_birth":
        return "persona:date_of_birth"
    if semantic_key == "accept_terms":
        return "literal:true"
    if semantic_key == "verification_code":
        return "extracted:challenge_email_code"

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
    visual_variant: Optional[str] = None,
    provenance: Optional[Dict[str, Any]] = None,
) -> SignupRecipe:
    """Convert a captured action log into a parameterized SignupRecipe.

    FILL steps get their bindings inferred from field semantics. CHALLENGE
    actions become CHALLENGE steps. The result is validated before return
    so a malformed capture surfaces immediately.
    """
    steps: List[RecipeStep] = []
    review_flags: List[str] = []
    challenge_boundaries: set[str] = set()
    correlation_ids = {
        action.correlation_id
        for action in actions
        if action.correlation_id
    }

    for i, act in enumerate(actions):
        if act.action == "navigate":
            safe_url = _redact_url(act.url)
            navigation_role = (
                "observe"
                if i > 0 and actions[i - 1].action == "click"
                else "drive"
            )
            steps.append(RecipeStep(
                kind=StepKind.NAVIGATE, url=safe_url,
                label=act.label or f"navigate to {safe_url}",
                metadata={"navigation_role": navigation_role},
            ))
            if _is_email_verification_url(safe_url) and "email_code" not in challenge_boundaries:
                challenge_boundaries.add("email_code")
                steps.append(RecipeStep(
                    kind=StepKind.CHALLENGE,
                    label="email verification challenge",
                    challenge_kind=ChallengeKind.EMAIL_CODE,
                    challenge_prompt="Provide the email verification code to continue.",
                    metadata={"boundary_url": safe_url},
                ))

        elif act.action == "fill":
            binding = infer_binding(act.field)
            semantic_key = infer_semantic_key(act.field)
            if (act.field.get("type") or "").lower() == "checkbox":
                steps.append(RecipeStep(
                    kind=StepKind.CLICK,
                    label=act.label or (
                        "accept terms"
                        if semantic_key == "accept_terms"
                        else "toggle checkbox"
                    ),
                    selector=act.selector,
                    semantic_key=semantic_key,
                    metadata={
                        "control_type": "checkbox",
                        "recorded_checked": act.field.get("checked", "true"),
                    },
                ))
                continue
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
                semantic_key=semantic_key,
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
        visual_variant=visual_variant,
        provenance={
            **dict(provenance or {}),
            "correlation_ids": sorted(correlation_ids),
            "recorded_navigation_count": sum(
                1 for action in actions if action.action == "navigate"
            ),
        },
        notes=(
            "Auto-recorded. " + (
                "Review needed: " + "; ".join(review_flags)
                if review_flags else "All fields inferred."
            )
        ),
    )
    recipe.validate()
    recipe.derive_required_persona_fields()
    recipe.secret_audit = _secret_audit(recipe)
    if recipe.secret_audit["status"] != "pass":
        raise ValueError("recorded recipe failed secret audit")
    logger.info(
        "[recorder] recorded %s: %d steps, %d challenge(s), %d field(s) "
        "needing review",
        service_handle, len(steps), len(recipe.challenge_steps()),
        len(review_flags),
    )
    return recipe


def _redact_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return url
    parts = urlsplit(url)
    # Query parameters and fragments frequently contain verification artifacts.
    # A signup recipe needs the route, not the one-time values from this run.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _is_email_verification_url(url: Optional[str]) -> bool:
    if not url:
        return False
    return urlsplit(url).path.rstrip("/") == "/verify"


_SECRET_SHAPED = re.compile(r"(?:labsess_|labtok_|\b\d{6}\b)", re.IGNORECASE)


def _secret_audit(recipe: SignupRecipe) -> Dict[str, Any]:
    """Audit persisted recipe fields without ever returning matched values."""
    violations: List[str] = []
    for index, step in enumerate(recipe.steps):
        binding = step.value_binding or ""
        if binding.startswith("literal:") and binding not in {
            "literal:true",
            "literal:REVIEW_THIS_FIELD",
        }:
            violations.append(f"step_{index}_literal_binding")
        for candidate in (step.url, step.label, step.challenge_prompt):
            if candidate and _SECRET_SHAPED.search(candidate):
                violations.append(f"step_{index}_secret_shaped_text")
    return {
        "status": "pass" if not violations else "fail",
        "scanner": "foundry_recipe_v1",
        "violations": sorted(set(violations)),
    }


def _label_for_binding(binding: str) -> str:
    mapping = {
        "persona:email": "fill email",
        "persona:phone": "fill phone",
        "persona:first_name": "fill first name",
        "persona:last_name": "fill last name",
        "persona:full_name": "fill full name",
        "persona:date_of_birth": "fill date of birth",
        "persona:password": "fill password",
        "generated:username": "fill username",
        "literal:true": "accept terms",
        "extracted:challenge_email_code": "fill email verification code",
        "literal:REVIEW_THIS_FIELD": "fill (REVIEW)",
    }
    return mapping.get(binding, "fill field")
