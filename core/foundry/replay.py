"""
core/foundry/replay.py — Phase 7-PF3: the Recipe Replay engine.

Executes a SignupRecipe with a ResearchPersona's values bound in. The
engine walks the recipe's steps, driving a concrete `Driver` (real
browser automation in production, a mock in tests — driver-agnostic
exactly like the Phase 4-G3 replay engine).

The crucial property: when the engine reaches an anti-bot wall — either
a standalone CHALLENGE step or a FILL whose value is a `verification:`
binding — it does NOT try to solve it. It packages a `Challenge`,
hands it to the caller's `challenge_handler`, and AWAITS the human's
`ChallengeResolution`. Then it continues. The engine is the boring-95%
automator; the handler (PF4) is the rare-5% human handoff.

State machine:
    PENDING → RUNNING → (AWAITING_CHALLENGE → RUNNING)* → COMPLETED
                                                        ↘ FAILED
                                                        ↘ ABORTED

The engine is async so a challenge can block for minutes (a human
solving a CAPTCHA) without burning a thread — the handler awaits a
resolution future internally.

Safety:
  * NAVIGATE steps are scope-gated to the recipe's origin (+ optional
    allowlist). A recipe cannot drive the browser to an arbitrary
    off-origin site mid-flow.
  * Rate limit checked BEFORE the first network action when a vault is
    provided. A signup that would breach the per-(persona, service)
    cap is refused without touching the wire.
  * Every run records an audit entry (success/failed/abandoned) when a
    vault is provided.
"""
from __future__ import annotations

import base64
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol
from urllib.parse import urlparse

from core.foundry.recipe import (
    BindingKind,
    ChallengeKind,
    RecipeStep,
    SignupRecipe,
    StepKind,
    resolve_binding,
)

logger = logging.getLogger(__name__)


# ─────────────────────────── driver ───────────────────────────


class Driver(Protocol):
    """The concrete automation surface the engine drives.

    Production implementations wrap a real browser (Chrome MCP,
    Playwright, etc.). Tests inject a mock that records calls + returns
    scripted values. All methods are async so a real browser's I/O
    doesn't block the event loop.
    """

    async def navigate(self, url: str) -> None: ...
    async def fill(self, selector: Dict[str, str], value: str) -> None: ...
    async def click(self, selector: Dict[str, str]) -> None: ...
    async def wait_for(self, selector: Dict[str, str], timeout_s: float) -> None: ...
    async def extract(self, selector: Dict[str, str], mode: str) -> str: ...
    async def screenshot(self) -> bytes: ...
    async def current_url(self) -> str: ...


# ─────────────────────────── challenge types ───────────────────────────


@dataclass
class Challenge:
    """An anti-bot wall the engine cannot (and must not) auto-solve.

    Carries everything the human needs to resolve it in one action:
    the kind, a prompt, the page URL, and a screenshot. For
    verification challenges (email/SMS), the resolution is expected to
    carry the extracted artifact (the link or code)."""
    challenge_id: str
    kind: ChallengeKind
    prompt: str
    context_url: str
    recipe_id: str
    persona_id: str
    service_handle: str
    screenshot_b64: Optional[str] = None
    # For verification challenges: the binding that needs a value
    # (e.g. "verification:email_link") so the handler knows what to
    # return in resolution.extracted_value.
    needs_value_for: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "kind": self.kind.value,
            "prompt": self.prompt,
            "context_url": self.context_url,
            "recipe_id": self.recipe_id,
            "persona_id": self.persona_id,
            "service_handle": self.service_handle,
            "screenshot_b64": self.screenshot_b64,
            "needs_value_for": self.needs_value_for,
            "created_at": self.created_at,
        }


@dataclass
class ChallengeResolution:
    """The human's answer to a Challenge.

    resolved=True  → the human handled it; engine continues.
    resolved=False → abort; engine stops with state ABORTED.
    extracted_value → for verification challenges, the link/code the
                      human (or a PF5 bridge) supplied.
    """
    challenge_id: str
    resolved: bool
    extracted_value: Optional[str] = None
    note: str = ""


# `challenge_handler(challenge) -> ChallengeResolution` (awaitable).
ChallengeHandler = Callable[[Challenge], Awaitable[ChallengeResolution]]


# ─────────────────────────── outcome ───────────────────────────


class ReplayState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_CHALLENGE = "awaiting_challenge"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class ReplayOutcome:
    """Result of running a recipe."""
    recipe_id: str
    persona_id: str
    service_handle: str
    state: ReplayState
    extracted: Dict[str, str] = field(default_factory=dict)
    steps_executed: int = 0
    challenges_encountered: int = 0
    error: Optional[str] = None
    elapsed_ms: float = 0.0

    @property
    def succeeded(self) -> bool:
        return self.state is ReplayState.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipe_id": self.recipe_id,
            "persona_id": self.persona_id,
            "service_handle": self.service_handle,
            "state": self.state.value,
            # NOTE: `extracted` MAY contain sensitive values (API tokens).
            # Callers persisting this should treat it as secret.
            "extracted": dict(self.extracted),
            "steps_executed": self.steps_executed,
            "challenges_encountered": self.challenges_encountered,
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
        }


class RecipeReplayError(Exception):
    """Raised for engine-level failures the caller should see (scope
    violation, missing persona field). Step-level failures are captured
    in ReplayOutcome.error instead, not raised."""


# ─────────────────────────── engine ───────────────────────────


def _origin_of(url: str) -> Optional[str]:
    try:
        p = urlparse(url)
    except Exception:
        return None
    if not p.scheme or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


# Which ChallengeKind a verification:<source> binding maps to.
_VERIFICATION_KIND = {
    "email_link": ChallengeKind.EMAIL_LINK,
    "email_code": ChallengeKind.EMAIL_CODE,
    "sms_code": ChallengeKind.SMS_CODE,
}


class RecipeReplayer:
    """Drives a SignupRecipe to completion, handing anti-bot walls to
    the human via the supplied challenge_handler."""

    def __init__(
        self,
        driver: Driver,
        *,
        vault=None,
        extra_allowed_origins: Optional[List[str]] = None,
    ):
        self._driver = driver
        self._vault = vault
        self._extra_origins = set(extra_allowed_origins or [])

    async def run(
        self,
        recipe: SignupRecipe,
        persona,
        *,
        challenge_handler: ChallengeHandler,
        generator=None,
    ) -> ReplayOutcome:
        """Execute `recipe` with `persona`'s values, awaiting the human
        at each anti-bot wall. Returns a ReplayOutcome.

        `persona` may be a ResearchPersona or any object exposing
        `as_binding_dict()` + `persona_id` (duck-typed for tests).
        """
        started = time.time()
        recipe.validate()
        recipe.derive_required_persona_fields()

        persona_id = getattr(persona, "persona_id", "unknown")
        binding_dict = persona.as_binding_dict()

        outcome = ReplayOutcome(
            recipe_id=recipe.recipe_id,
            persona_id=persona_id,
            service_handle=recipe.service_handle,
            state=ReplayState.PENDING,
        )

        # Fail-fast: persona must have every persona: field the recipe needs.
        missing = [
            f for f in recipe.required_persona_fields
            if not str(binding_dict.get(f, "")).strip()
        ]
        if missing:
            outcome.state = ReplayState.FAILED
            outcome.error = f"persona missing required fields: {missing}"
            outcome.elapsed_ms = (time.time() - started) * 1000.0
            return outcome

        # Rate-limit gate (before any network action).
        if self._vault is not None:
            from core.foundry.vault import RateLimitExceeded
            try:
                self._vault.check_rate_limit(persona_id, recipe.service_handle)
            except RateLimitExceeded as e:
                outcome.state = ReplayState.FAILED
                outcome.error = f"rate limit: {e}"
                outcome.elapsed_ms = (time.time() - started) * 1000.0
                return outcome

        # Allowed origins: recipe origin + extras.
        allowed = {_origin_of(recipe.origin)} | self._extra_origins
        allowed.discard(None)

        extracted: Dict[str, str] = {}
        outcome.state = ReplayState.RUNNING

        try:
            for i, step in enumerate(recipe.steps):
                await self._execute_step(
                    step, i, recipe, persona_id, binding_dict, extracted,
                    allowed, challenge_handler, generator, outcome,
                )
                outcome.steps_executed += 1
                # A step may have aborted the run (challenge resolved=False).
                if outcome.state is ReplayState.ABORTED:
                    break
            else:
                # Loop completed without break → success.
                outcome.state = ReplayState.COMPLETED
        except _AbortReplay as ab:
            outcome.state = ReplayState.ABORTED
            outcome.error = str(ab)
        except Exception as e:
            outcome.state = ReplayState.FAILED
            outcome.error = f"{type(e).__name__}: {e}"
            logger.warning(
                "[replay] recipe %s failed at step %d: %s",
                recipe.recipe_id, outcome.steps_executed, e,
            )

        outcome.extracted = extracted
        outcome.elapsed_ms = (time.time() - started) * 1000.0

        # Audit.
        if self._vault is not None:
            audit_outcome = {
                ReplayState.COMPLETED: "success",
                ReplayState.ABORTED: "abandoned",
            }.get(outcome.state, "failed")
            try:
                self._vault.record_account_creation(
                    persona_id=persona_id,
                    service_handle=recipe.service_handle,
                    recipe_id=recipe.recipe_id,
                    outcome=audit_outcome,
                    detail=outcome.error or "",
                )
            except Exception as e:
                logger.warning("[replay] audit write failed: %s", e)

        return outcome

    async def _execute_step(
        self, step: RecipeStep, index: int, recipe: SignupRecipe,
        persona_id: str, binding_dict: Dict[str, Any],
        extracted: Dict[str, str], allowed_origins: set,
        challenge_handler: ChallengeHandler, generator, outcome: ReplayOutcome,
    ) -> None:
        k = step.kind

        if k is StepKind.NAVIGATE:
            origin = _origin_of(step.url or "")
            if origin not in allowed_origins:
                raise RecipeReplayError(
                    f"step {index} NAVIGATE to {step.url!r} is off-origin "
                    f"(allowed: {sorted(allowed_origins)}) — refusing to "
                    f"drive the browser off the recipe's scope."
                )
            await self._driver.navigate(step.url)

        elif k is StepKind.FILL:
            value = await self._resolve_fill_value(
                step, recipe, persona_id, binding_dict, extracted,
                challenge_handler, generator, outcome,
            )
            if value is None:
                # A verification challenge was aborted → abort run.
                raise _AbortReplay(
                    f"step {index} FILL aborted: verification challenge "
                    f"not resolved"
                )
            await self._driver.fill(step.selector, value)

        elif k is StepKind.CLICK:
            await self._driver.click(step.selector)

        elif k is StepKind.WAIT_FOR:
            await self._driver.wait_for(step.selector, step.timeout_s)

        elif k is StepKind.EXTRACT:
            val = await self._driver.extract(step.selector, step.extract_mode)
            extracted[step.extract_as] = val

        elif k is StepKind.CHALLENGE:
            outcome.challenges_encountered += 1
            outcome.state = ReplayState.AWAITING_CHALLENGE
            resolution = await self._emit_challenge(
                kind=step.challenge_kind,
                prompt=step.challenge_prompt or _default_prompt(step.challenge_kind),
                recipe=recipe,
                persona_id=persona_id,
                challenge_handler=challenge_handler,
                needs_value_for=None,
            )
            outcome.state = ReplayState.RUNNING
            if not resolution.resolved:
                raise _AbortReplay(
                    f"step {index} CHALLENGE ({step.challenge_kind.value}) "
                    f"not resolved by operator"
                )
            # A challenge MAY carry an extracted value (e.g. a code the
            # human typed) — stash it under the challenge kind so a
            # later step can reference it via extracted:.
            if resolution.extracted_value is not None:
                extracted[f"challenge_{step.challenge_kind.value}"] = resolution.extracted_value

    async def _resolve_fill_value(
        self, step: RecipeStep, recipe: SignupRecipe, persona_id: str,
        binding_dict: Dict[str, Any], extracted: Dict[str, str],
        challenge_handler: ChallengeHandler, generator, outcome: ReplayOutcome,
    ) -> Optional[str]:
        """Resolve a FILL step's value. verification: bindings emit a
        challenge and use the human-supplied value; everything else
        resolves synchronously."""
        binding = step.value_binding or ""
        if binding.startswith("verification:"):
            source = binding.split(":", 1)[1]
            kind = _VERIFICATION_KIND.get(source, ChallengeKind.MANUAL)
            outcome.challenges_encountered += 1
            outcome.state = ReplayState.AWAITING_CHALLENGE
            resolution = await self._emit_challenge(
                kind=kind,
                prompt=(
                    f"Provide the {source.replace('_', ' ')} for the "
                    f"{recipe.service_handle} signup."
                ),
                recipe=recipe,
                persona_id=persona_id,
                challenge_handler=challenge_handler,
                needs_value_for=binding,
            )
            outcome.state = ReplayState.RUNNING
            if not resolution.resolved:
                return None
            return resolution.extracted_value or ""
        # Synchronous binding (literal/persona/generated/extracted).
        return resolve_binding(
            binding, persona=binding_dict, extracted=extracted,
            generator=generator,
        )

    async def _emit_challenge(
        self, *, kind: ChallengeKind, prompt: str, recipe: SignupRecipe,
        persona_id: str, challenge_handler: ChallengeHandler,
        needs_value_for: Optional[str],
    ) -> ChallengeResolution:
        """Build a Challenge (with a screenshot for context) and await
        the handler's resolution."""
        try:
            shot = await self._driver.screenshot()
            shot_b64 = base64.b64encode(shot).decode("ascii") if shot else None
        except Exception:
            shot_b64 = None
        try:
            ctx_url = await self._driver.current_url()
        except Exception:
            ctx_url = recipe.origin

        challenge = Challenge(
            challenge_id=uuid.uuid4().hex,
            kind=kind,
            prompt=prompt,
            context_url=ctx_url,
            recipe_id=recipe.recipe_id,
            persona_id=persona_id,
            service_handle=recipe.service_handle,
            screenshot_b64=shot_b64,
            needs_value_for=needs_value_for,
        )
        logger.info(
            "[replay] CHALLENGE %s (%s) — awaiting human handoff",
            challenge.challenge_id, kind.value,
        )
        resolution = await challenge_handler(challenge)
        if resolution.challenge_id != challenge.challenge_id:
            # Defensive: handler returned a resolution for a different
            # challenge — treat as unresolved.
            logger.warning(
                "[replay] handler returned resolution for %s but challenge "
                "was %s — treating as unresolved",
                resolution.challenge_id, challenge.challenge_id,
            )
            return ChallengeResolution(
                challenge_id=challenge.challenge_id, resolved=False,
                note="handler resolution id mismatch",
            )
        return resolution


def _default_prompt(kind: Optional[ChallengeKind]) -> str:
    return {
        ChallengeKind.CAPTCHA: "Solve the CAPTCHA shown in the browser.",
        ChallengeKind.EMAIL_LINK: "Click the verification link in the signup email.",
        ChallengeKind.EMAIL_CODE: "Enter the code from the signup email.",
        ChallengeKind.SMS_CODE: "Enter the SMS verification code.",
        ChallengeKind.PAYMENT_3DS: "Complete the 3-D Secure payment challenge.",
        ChallengeKind.TOS_SCROLL: "Scroll through and accept the terms of service.",
        ChallengeKind.MANUAL: "A manual step is needed — review the browser.",
    }.get(kind, "A human action is needed to continue.")


class _AbortReplay(Exception):
    """Internal: a challenge was not resolved → abort the run cleanly
    (distinct from a step failure)."""
