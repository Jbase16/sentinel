"""
core/foundry/signup.py — Phase 7-PF9: signup orchestration.

Ties the whole Foundry together. POST /v1/foundry/signup kicks off a
SignupJob: load the recipe + persona, launch a browser Driver, run the
RecipeReplayer with the singleton ChallengeBus as the challenge handler
— all in a background async task. The replay drives every boring step
and, at each anti-bot wall, hands off to the human via the bus. The
human resolves over HTTP (/challenges + /resolve); the replay resumes.

Why a background task: a signup can take minutes (a human solving a
CAPTCHA). The /signup POST returns immediately with a job id; the
caller polls /signup/{job_id} for progress. The challenge bus's future-
based handoff works because the background task and the /resolve
request share the one event loop + the one singleton bus.

Driver factory is injectable: production uses PlaywrightDriver.launch
(a real headful browser); tests inject a mock driver factory so the
orchestration is testable without a browser.

Secret hygiene: a completed job's `extracted` may contain API tokens
(the recipe's EXTRACT steps). The public job dict REDACTS extracted
values to length-only — the operator reads the actual token from the
job's secure detail path, not the status listing.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class SignupJobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass
class SignupJob:
    job_id: str
    recipe_id: str
    persona_id: str
    service_handle: str
    state: SignupJobState = SignupJobState.PENDING
    error: Optional[str] = None
    # Filled when the replay finishes. The raw extracted dict (may hold
    # secrets) lives here; the public to_dict() redacts it.
    _outcome: Optional[Any] = None  # ReplayOutcome
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def to_dict(self, *, include_secrets: bool = False) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "job_id": self.job_id,
            "recipe_id": self.recipe_id,
            "persona_id": self.persona_id,
            "service_handle": self.service_handle,
            "state": self.state.value,
            "error": self.error,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }
        if self._outcome is not None:
            extracted = dict(getattr(self._outcome, "extracted", {}) or {})
            if include_secrets:
                d["extracted"] = extracted
            else:
                # Redact to length-only so the listing never leaks a token.
                d["extracted_keys"] = {
                    k: f"<{len(str(v))} chars>" for k, v in extracted.items()
                }
            d["steps_executed"] = getattr(self._outcome, "steps_executed", 0)
            d["challenges_encountered"] = getattr(
                self._outcome, "challenges_encountered", 0
            )
            d["replay_state"] = getattr(
                getattr(self._outcome, "state", None), "value", None
            )
        return d


# DriverFactory: async callable () -> Driver. The orchestrator calls it
# to get a fresh driver per job, and closes the driver when done.
DriverFactory = Callable[[], Awaitable[Any]]


async def _default_driver_factory():
    """Launch a real Playwright browser (headful). Only invoked in
    production; tests inject a mock factory."""
    from core.foundry.driver_playwright import PlaywrightDriver
    return await PlaywrightDriver.launch(headless=False)


class SignupOrchestrator:
    """Runs signup jobs in the background, bridging the replayer to the
    challenge bus. Process-singleton (see get_orchestrator) so the
    router and the background tasks share job state + the bus."""

    def __init__(
        self,
        *,
        driver_factory: Optional[DriverFactory] = None,
        bus=None,
        vault=None,
    ):
        self._driver_factory = driver_factory or _default_driver_factory
        self._bus = bus
        self._vault = vault
        self._jobs: Dict[str, SignupJob] = {}
        self._tasks: Dict[str, asyncio.Task] = {}

    def _get_bus(self):
        if self._bus is not None:
            return self._bus
        from core.foundry.challenges import get_challenge_bus
        return get_challenge_bus()

    async def start(self, recipe_id: str, persona_id: str) -> SignupJob:
        """Load recipe + persona, create a job, launch the background
        replay. Returns the job immediately (state PENDING/RUNNING).

        Raises ValueError if the recipe or persona doesn't exist, or the
        persona is missing a field the recipe needs (fail fast before
        spinning up a browser)."""
        from core.foundry.recipe_store import load_recipe
        from core.foundry.vault import PersonaVault

        recipe = load_recipe(recipe_id)
        if recipe is None:
            raise ValueError(f"recipe {recipe_id!r} not found")

        vault = self._vault or PersonaVault()
        persona = vault.get_persona(persona_id)
        if persona is None:
            raise ValueError(f"persona {persona_id!r} not found")

        recipe.derive_required_persona_fields()
        missing = persona.missing_fields_for(recipe.required_persona_fields)
        if missing:
            raise ValueError(
                f"persona {persona_id!r} is missing fields the recipe "
                f"needs: {missing}"
            )

        job = SignupJob(
            job_id=uuid.uuid4().hex,
            recipe_id=recipe_id,
            persona_id=persona_id,
            service_handle=recipe.service_handle,
            state=SignupJobState.PENDING,
        )
        self._jobs[job.job_id] = job

        task = asyncio.create_task(
            self._run_job(job, recipe, persona, vault),
            name=f"signup-{job.job_id[:8]}",
        )
        self._tasks[job.job_id] = task
        return job

    async def _run_job(self, job: SignupJob, recipe, persona, vault) -> None:
        from core.foundry.replay import RecipeReplayer, ReplayState

        job.state = SignupJobState.RUNNING
        driver = None
        try:
            driver = await self._driver_factory()
            replayer = RecipeReplayer(driver, vault=vault)
            outcome = await replayer.run(
                recipe, persona, challenge_handler=self._get_bus().as_handler(),
            )
            job._outcome = outcome
            job.state = {
                ReplayState.COMPLETED: SignupJobState.COMPLETED,
                ReplayState.ABORTED: SignupJobState.ABORTED,
            }.get(outcome.state, SignupJobState.FAILED)
            job.error = outcome.error
        except Exception as e:
            job.state = SignupJobState.FAILED
            job.error = f"{type(e).__name__}: {e}"
            logger.warning("[signup] job %s failed: %s", job.job_id, e)
        finally:
            job.finished_at = time.time()
            if driver is not None:
                close = getattr(driver, "close", None)
                if callable(close):
                    try:
                        await close()
                    except Exception:
                        pass
            self._tasks.pop(job.job_id, None)

    def get_job(self, job_id: str) -> Optional[SignupJob]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list:
        return list(self._jobs.values())


# ─────────────────────────── singleton ───────────────────────────


_ORCH_SINGLETON: Optional[SignupOrchestrator] = None


def get_orchestrator(
    *, driver_factory: Optional[DriverFactory] = None,
) -> SignupOrchestrator:
    """Process-wide SignupOrchestrator. driver_factory only applies on
    first call (singleton creation)."""
    global _ORCH_SINGLETON
    if _ORCH_SINGLETON is None:
        _ORCH_SINGLETON = SignupOrchestrator(driver_factory=driver_factory)
    return _ORCH_SINGLETON


def _reset_orchestrator_for_tests(
    *, driver_factory: Optional[DriverFactory] = None,
    bus=None, vault=None,
) -> SignupOrchestrator:
    """Test-only: replace the singleton with a fresh, fully-injected
    orchestrator."""
    global _ORCH_SINGLETON
    _ORCH_SINGLETON = SignupOrchestrator(
        driver_factory=driver_factory, bus=bus, vault=vault,
    )
    return _ORCH_SINGLETON
