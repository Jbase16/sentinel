"""
core/foundry/challenges.py — Phase 7-PF4: the Challenge Handoff Bus.

THE categorical innovation. Every other account-automation tool dies
at the anti-bot wall: it either tries to BYPASS it (CAPTCHA solvers,
account farms — over the ToS line) or it gives up and dumps a "now go
do this manually" handoff on the human. The Foundry does neither. It
routes the anti-bot challenge to the human as a FRICTIONLESS HANDOFF —
a one-second click instead of a thirty-minute manual signup — and
resumes the automation the moment the human responds.

The handoff IS the innovation. The boring 95% stays automated; the
rare 5% (the parts that legitimately need a human) become a tap on a
notification.

Mechanism:
  1. The replay engine (PF3) reaches a CHALLENGE and calls
     bus.submit(challenge) — an awaitable.
  2. The bus stores the challenge, fires the notifier (desktop /
     mobile push / UI banner), and AWAITS a resolution future.
  3. The human sees the notification, solves the CAPTCHA / clicks the
     email link / reads the SMS code, and their response calls
     bus.resolve(challenge_id, ...) — which completes the future.
  4. The awaiting submit() returns the resolution; the replay engine
     continues.

Bounded wait: a challenge unanswered within `timeout_s` resolves
automatically as unresolved, so a replay never hangs forever waiting
on a human who walked away.

Process-singleton: for the cross-context handoff to work (engine
awaiting in one async task, human resolving via an HTTP POST in
another), the bus must be ONE instance shared across the process.
`get_challenge_bus()` returns the singleton.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Dict, List, Optional

from core.foundry.replay import Challenge, ChallengeResolution

logger = logging.getLogger(__name__)


# A notifier surfaces a challenge to the human. callable(challenge) -> None.
# Production: push to the realtime WebSocket / desktop notification /
# mobile push. Tests: record.
Notifier = Callable[[Challenge], None]


DEFAULT_CHALLENGE_TIMEOUT_S = 600.0  # 10 minutes for a human to respond


class ChallengeBus:
    """Routes anti-bot challenges to the human and awaits resolution.

    Thread-affinity note: submit() awaits an asyncio.Future created on
    the running loop. resolve() must be called on the SAME loop (e.g.
    a FastAPI request handler in the same process). For a single-
    process app this is automatic.
    """

    def __init__(
        self,
        *,
        notifier: Optional[Notifier] = None,
        default_timeout_s: float = DEFAULT_CHALLENGE_TIMEOUT_S,
    ):
        self._notifier = notifier or _logging_notifier
        self._timeout = default_timeout_s
        # challenge_id → (Challenge, Future[ChallengeResolution])
        self._pending: Dict[str, Challenge] = {}
        self._futures: Dict[str, "asyncio.Future[ChallengeResolution]"] = {}
        self._resolved: Dict[str, ChallengeResolution] = {}
        self._lock = asyncio.Lock()

    # ── engine side ──

    async def submit(self, challenge: Challenge) -> ChallengeResolution:
        """Called by the replay engine's challenge_handler. Notifies the
        human and awaits their resolution (or times out).

        This is the method you pass as `challenge_handler` to
        RecipeReplayer.run (via `bus.as_handler()`)."""
        loop = asyncio.get_running_loop()
        future: "asyncio.Future[ChallengeResolution]" = loop.create_future()

        async with self._lock:
            self._pending[challenge.challenge_id] = challenge
            self._futures[challenge.challenge_id] = future

        # Fire the notification. A bad notifier must NOT break the
        # handoff — log and continue; the human can still resolve via
        # the pending list / UI.
        try:
            self._notifier(challenge)
        except Exception as e:
            logger.warning(
                "[challenge-bus] notifier raised for %s: %s",
                challenge.challenge_id, e,
            )

        logger.info(
            "[challenge-bus] awaiting human for %s (%s) — timeout %.0fs",
            challenge.challenge_id, challenge.kind.value, self._timeout,
        )

        try:
            resolution = await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError:
            resolution = ChallengeResolution(
                challenge_id=challenge.challenge_id,
                resolved=False,
                note=f"timed out after {self._timeout:.0f}s waiting for human",
            )
            logger.warning(
                "[challenge-bus] challenge %s TIMED OUT", challenge.challenge_id,
            )
        finally:
            async with self._lock:
                self._pending.pop(challenge.challenge_id, None)
                self._futures.pop(challenge.challenge_id, None)
                self._resolved[challenge.challenge_id] = resolution

        return resolution

    def as_handler(self):
        """Return the submit method as a ChallengeHandler for
        RecipeReplayer.run(challenge_handler=...)."""
        return self.submit

    # ── human side ──

    def resolve(
        self,
        challenge_id: str,
        *,
        resolved: bool = True,
        extracted_value: Optional[str] = None,
        note: str = "",
    ) -> bool:
        """Called by the human's response (e.g. a FastAPI POST handler
        when the operator taps 'done' on the notification).

        Returns True if a pending challenge was resolved, False if the
        challenge_id is unknown or already resolved.

        Sets the awaiting submit()'s future. Thread/loop note: this must
        run on the same event loop the submit() awaited on.
        """
        future = self._futures.get(challenge_id)
        if future is None:
            logger.warning(
                "[challenge-bus] resolve() for unknown/expired challenge %s",
                challenge_id,
            )
            return False
        if future.done():
            return False
        resolution = ChallengeResolution(
            challenge_id=challenge_id,
            resolved=resolved,
            extracted_value=extracted_value,
            note=note,
        )
        # set_result may need to be scheduled if called from a different
        # callback context; here we set directly (same loop).
        try:
            future.set_result(resolution)
        except asyncio.InvalidStateError:
            return False
        logger.info(
            "[challenge-bus] challenge %s resolved=%s by human",
            challenge_id, resolved,
        )
        return True

    # ── introspection ──

    def pending_challenges(self) -> List[Challenge]:
        """The challenges currently awaiting a human. The UI polls/streams
        this to show 'Sentinel needs you' badges."""
        return list(self._pending.values())

    def get_pending(self, challenge_id: str) -> Optional[Challenge]:
        return self._pending.get(challenge_id)

    def resolution_for(self, challenge_id: str) -> Optional[ChallengeResolution]:
        """The recorded resolution for a (now-settled) challenge, if any."""
        return self._resolved.get(challenge_id)


def _logging_notifier(challenge: Challenge) -> None:
    """Default notifier: log the prompt. Real deployments swap in a
    desktop/mobile/UI notifier."""
    logger.info(
        "[challenge-bus] 🔔 HUMAN NEEDED: %s — %s (%s)",
        challenge.kind.value, challenge.prompt, challenge.context_url,
    )


# ─────────────────────────── process singleton ───────────────────────────


_BUS_SINGLETON: Optional[ChallengeBus] = None


def get_challenge_bus(
    *, notifier: Optional[Notifier] = None,
    default_timeout_s: float = DEFAULT_CHALLENGE_TIMEOUT_S,
) -> ChallengeBus:
    """Return the process-wide ChallengeBus, creating it on first call.

    For the cross-context handoff to work (engine awaiting in one task,
    human resolving via an HTTP POST in another), every caller in the
    process must share this instance.

    The notifier/timeout args only apply on the FIRST call (when the
    singleton is created). Subsequent calls return the existing bus.
    """
    global _BUS_SINGLETON
    if _BUS_SINGLETON is None:
        _BUS_SINGLETON = ChallengeBus(
            notifier=notifier, default_timeout_s=default_timeout_s,
        )
    return _BUS_SINGLETON


def _reset_bus_for_tests() -> None:
    """Test-only: drop the singleton so each test gets a fresh bus."""
    global _BUS_SINGLETON
    _BUS_SINGLETON = None
