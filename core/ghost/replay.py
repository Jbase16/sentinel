"""
core/ghost/replay.py — Phase 4-G3: deterministic flow replay with mutation
injection.

The captured Flow (G2) is the input. This module turns it into the
EXECUTABLE unit Phase 4 is about: take a captured user journey, replay
it step-by-step against the live target with surgical mutations injected
at any step, and diff the result against the baseline.

This is what makes Ghost categorically different from request fuzzers
(Burp Intruder, ZAP) — those operate on individual requests. Ghost
operates on whole flows. State carries forward. A mutation early in the
flow affects every downstream response. A mutation late in the flow is
tested in the context of a fully-realized session.

────────────────────────────────────────────────────────────────────────
The Mutation contract
────────────────────────────────────────────────────────────────────────

A Mutation is a small object with two methods:

    applies_to(step: FlowStep) -> bool
        Cheap predicate. Returns True if this mutation makes sense for
        this step. Used by hypothesis proposers (G4) to filter the
        library down to "what could fire here."

    apply(step: FlowStep) -> FlowStep
        Returns a NEW FlowStep representing the mutated request. The
        original step is never modified — same step can be re-used
        across multiple replays.

A Mutation MAY also expose:
    label: str       — short human-readable name for the diff report
    rationale: str   — why this mutation is interesting (for AI-driven
                       proposers to surface to the operator)

G3 ships with two trivial Mutations (NoOp + SwapAuthHeader) so the
engine + diff has something to exercise. G4 ships the real library.

────────────────────────────────────────────────────────────────────────
State isolation per replay
────────────────────────────────────────────────────────────────────────

Each `replay_flow()` call creates ONE httpx.AsyncClient with its own
cookie jar. Within that client, cookies set by step N are available to
step N+1 — that's how captured sessions actually replay. Across
replays, the clients are independent — parallel replays don't leak
state into each other.

If the operator wants to seed the jar (e.g. "start the replay already
authenticated as Alice"), they pass `initial_cookies={…}` and
`initial_headers={…}`. Most replays do NOT seed — they start from
"nothing" and let the captured login step establish the session.

────────────────────────────────────────────────────────────────────────
Divergence policy
────────────────────────────────────────────────────────────────────────

By default, the engine runs every step even after a divergence. This is
intentional: a mutation early in the flow may cause step N to diverge
without breaking the rest — we want to see how steps N+1, N+2 respond
to that divergence. Operators chasing "fragile flow" failures can pass
`stop_on_divergence=True` to bail at the first delta.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol

import httpx

from core.ghost.flow import FlowStep, UserFlow

logger = logging.getLogger(__name__)


# ─────────────────────────── Mutation protocol ──────────────────────────


class Mutation(Protocol):
    """A semantic transform applied to a FlowStep before replay.

    Implementations should be small and composable — the engine may
    apply MULTIPLE mutations to the same step. Each `apply()` returns
    a new FlowStep; the engine chains them.
    """

    label: str
    rationale: str

    def applies_to(self, step: FlowStep) -> bool: ...
    def apply(self, step: FlowStep) -> FlowStep: ...


@dataclass
class NoOpMutation:
    """Identity mutation — used as a baseline / sanity-check.

    Useful for "replay the flow as-is, see if it still works" before
    actually running with mutations. Also handy for testing the engine
    plumbing without needing to think about mutation semantics."""
    label: str = "noop"
    rationale: str = "Baseline replay — no mutation applied."

    def applies_to(self, step: FlowStep) -> bool:
        return True

    def apply(self, step: FlowStep) -> FlowStep:
        return _clone_step(step)


@dataclass
class SwapAuthHeader:
    """Replace the Authorization header with a different value (or omit it).

    The simplest interesting mutation: take a captured authenticated
    flow, replay it without auth (or with the wrong auth) and see which
    steps continue to succeed. Steps that succeed despite the swap are
    auth-bypass candidates — the original auth wasn't actually gating
    them.

    Params:
        new_value: The Authorization header value to substitute. If
            empty/None, the header is REMOVED entirely (the anonymous
            replay case).
        label / rationale: human-readable identity for the diff report.
    """
    new_value: Optional[str] = None
    label: str = "swap-auth"
    rationale: str = (
        "Substitute the Authorization header — tests whether steps "
        "succeed despite missing/wrong auth (= missing access-control gate)."
    )

    def applies_to(self, step: FlowStep) -> bool:
        # Only meaningful if the step actually had an Authorization
        # header in the capture. Otherwise the swap is a no-op.
        return "authorization" in step.headers

    def apply(self, step: FlowStep) -> FlowStep:
        new_step = _clone_step(step)
        if self.new_value:
            new_step.headers["authorization"] = self.new_value
        else:
            new_step.headers.pop("authorization", None)
        return new_step


def _clone_step(step: FlowStep) -> FlowStep:
    """Deep-copy a FlowStep for mutation. Preserves the source id so
    diff reports can correlate replay-step back to capture-step."""
    cloned = FlowStep(
        method=step.method,
        url=step.url,
        params=copy.deepcopy(step.params),
        headers=copy.deepcopy(step.headers),
        request_body=step.request_body,
        request_body_truncated=step.request_body_truncated,
        request_content_type=step.request_content_type,
    )
    cloned.id = step.id  # preserve identity so diffs can match steps
    return cloned


# ─────────────────────────── diff types ──────────────────────────────


@dataclass
class StepDiff:
    """Result of comparing one replay-step against its capture-step.

    The diff is INTENTIONALLY coarse in G3: status equality, body-hash
    equality, size delta, header presence. G4 will add semantic diffs
    (new JSON keys, parsed-token decode, etc.).
    """
    step_index: int
    step_id: str
    method: str
    url: str

    original_status: int
    replay_status: int

    original_size: int
    replay_size: int

    original_hash: str
    replay_hash: str

    status_changed: bool
    body_changed: bool
    size_delta: int        # replay - original; sign matters
    elapsed_delta_ms: float

    applied_mutations: List[str] = field(default_factory=list)

    @property
    def diverged(self) -> bool:
        """Cheap one-line: did the replay's response differ in any
        observable way from the capture's?"""
        return self.status_changed or self.body_changed


@dataclass
class ReplayResult:
    """Result of replaying one whole flow.

    Carries the source flow id, the new flow (built from replay
    responses), the per-step diffs, and a summary."""
    source_flow_id: str
    source_flow_name: str
    replay_flow: UserFlow
    step_diffs: List[StepDiff]
    total_elapsed_ms: float
    stopped_early: bool = False
    error: Optional[str] = None

    @property
    def diverged_step_count(self) -> int:
        return sum(1 for d in self.step_diffs if d.diverged)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_flow_id": self.source_flow_id,
            "source_flow_name": self.source_flow_name,
            "replay_flow": self.replay_flow.to_dict(),
            "step_diffs": [
                {
                    "step_index": d.step_index,
                    "step_id": d.step_id,
                    "method": d.method,
                    "url": d.url,
                    "original_status": d.original_status,
                    "replay_status": d.replay_status,
                    "original_size": d.original_size,
                    "replay_size": d.replay_size,
                    "original_hash": d.original_hash,
                    "replay_hash": d.replay_hash,
                    "status_changed": d.status_changed,
                    "body_changed": d.body_changed,
                    "size_delta": d.size_delta,
                    "elapsed_delta_ms": d.elapsed_delta_ms,
                    "applied_mutations": list(d.applied_mutations),
                    "diverged": d.diverged,
                }
                for d in self.step_diffs
            ],
            "total_elapsed_ms": self.total_elapsed_ms,
            "stopped_early": self.stopped_early,
            "error": self.error,
            "diverged_step_count": self.diverged_step_count,
        }


# ─────────────────────────── engine ──────────────────────────────


async def replay_flow(
    flow: UserFlow,
    mutations_by_step_index: Optional[Dict[int, List[Mutation]]] = None,
    *,
    initial_cookies: Optional[Dict[str, str]] = None,
    initial_headers: Optional[Dict[str, str]] = None,
    override_headers: Optional[Dict[str, str]] = None,
    scope_filter: Optional[Callable[[str], bool]] = None,
    stop_on_divergence: bool = False,
    per_step_timeout: float = 10.0,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> ReplayResult:
    """Replay a captured flow with optional mutations injected at any step.

    Args:
      flow: The captured UserFlow to replay.
      mutations_by_step_index: Map of step-index → list of Mutations to
        apply IN ORDER at that step. Each Mutation's `applies_to` is
        checked; non-applicable ones are silently skipped (no error).
      initial_cookies: Pre-seed the replay's cookie jar (default: empty).
      initial_headers: Headers applied to EVERY replay request UNLESS
        the step's captured headers (or a mutation) override the same
        key. Lowest precedence. Use this for ambient additions like
        custom telemetry headers (default: empty).
      override_headers: Headers applied to EVERY replay request with
        the HIGHEST precedence — overrides both captured and mutation
        headers. Used by multi-principal flow diff (G5) to inject the
        alternate persona's auth: the captured Authorization is
        REPLACED by the new persona's, not augmented. (default: empty)
      scope_filter: Optional callable; if any step's URL is out of
        scope, that step is skipped (the diff shows the original side
        only). Belt + suspenders — same authority verify_phase uses.
      stop_on_divergence: If True, halt replay at the first step whose
        response differs from the capture. Default False (keep going
        to see downstream effects).
      per_step_timeout: httpx timeout per request (default 10s).
      transport: Optional httpx transport override — used by tests to
        inject a MockTransport without spinning up a real server.

    Returns:
      ReplayResult with the new flow + per-step diffs.

    NEVER raises for ordinary failures. Network errors on a single step
    are recorded as a diverged StepDiff with replay_status=0 and the
    engine continues. Catastrophic errors (e.g. malformed UserFlow) are
    surfaced via ReplayResult.error.
    """
    mutations_by_step_index = mutations_by_step_index or {}
    replay_flow_obj = UserFlow(name=f"{flow.name} [replay]")
    diffs: List[StepDiff] = []
    started = time.time()
    stopped_early = False
    error: Optional[str] = None

    # Per-replay isolated client + cookie jar.
    client_kwargs: Dict[str, Any] = {
        "timeout": per_step_timeout,
        "follow_redirects": False,  # explicit per step
    }
    if transport is not None:
        client_kwargs["transport"] = transport

    async with httpx.AsyncClient(**client_kwargs) as client:
        # Seed cookies if provided.
        if initial_cookies:
            for k, v in initial_cookies.items():
                client.cookies.set(k, v)

        for i, source_step in enumerate(flow.steps):
            # Optional scope gate — skip out-of-scope steps. We emit a
            # diff entry marking them so the operator sees why the
            # replay went short.
            if scope_filter is not None:
                try:
                    in_scope = bool(scope_filter(source_step.url))
                except Exception:
                    in_scope = False
                if not in_scope:
                    logger.info(
                        f"[replay] step {i} {source_step.url} OUT OF SCOPE; "
                        f"skipping"
                    )
                    continue

            # Apply mutations at this step (in order).
            step_to_send = _clone_step(source_step)
            applied_labels: List[str] = []
            for mut in mutations_by_step_index.get(i, []):
                try:
                    if mut.applies_to(step_to_send):
                        step_to_send = mut.apply(step_to_send)
                        applied_labels.append(getattr(mut, "label", "?"))
                except Exception as e:
                    logger.warning(
                        f"[replay] mutation {getattr(mut, 'label', '?')} "
                        f"raised on step {i}: {type(e).__name__}: {e}"
                    )
                    continue

            # Header precedence (lowest → highest):
            #   1. initial_headers      — ambient, capture wins on collision
            #   2. captured/mutated step headers — what the flow asked for
            #   3. override_headers     — caller-injected identity (G5)
            #
            # The override_headers tier is what makes multi-principal flow
            # diff (G5) work: when replaying Alice's flow as Bob, the
            # captured `Authorization: Bearer alice-token` is REPLACED by
            # `Authorization: Bearer bob-token`, not augmented.
            merged_headers = {}
            if initial_headers:
                merged_headers.update(
                    {str(k).lower(): str(v) for k, v in initial_headers.items()}
                )
            merged_headers.update(step_to_send.headers)

            # Cross-principal replay (G5): when the caller injects a DIFFERENT
            # identity (override_headers and/or initial_cookies), the captured
            # request's own credentials must NOT leak into the replay. Strip the
            # captured Cookie and Authorization so the request authenticates
            # ONLY as the injected principal (Bob's seeded cookie jar + override
            # headers). Without this, cookie-auth targets (e.g. GitLab's
            # _gitlab_session) would still answer as the ORIGINAL principal —
            # a FALSE IDOR. (Header/JWT-auth targets like Juice Shop were fine
            # because override_headers already replaced Authorization.)
            if override_headers or initial_cookies:
                for _h in [
                    k for k in list(merged_headers)
                    if k.lower() in ("cookie", "authorization")
                ]:
                    merged_headers.pop(_h, None)

            if override_headers:
                merged_headers.update(
                    {str(k).lower(): str(v) for k, v in override_headers.items()}
                )

            # Send the request. Errors become a diverged step, not a raise.
            step_started = time.time()
            try:
                req = client.build_request(
                    method=step_to_send.method,
                    url=step_to_send.url,
                    headers=merged_headers,
                    content=(
                        step_to_send.request_body.encode("utf-8")
                        if step_to_send.request_body else None
                    ),
                )
                resp = await client.send(req)
                status = int(resp.status_code)
                body = resp.text or ""
                response_headers = {k: v for k, v in resp.headers.items()}
                elapsed_ms = (time.time() - step_started) * 1000.0
            except Exception as e:
                logger.warning(
                    f"[replay] step {i} {source_step.method} {source_step.url} "
                    f"failed: {type(e).__name__}: {e}"
                )
                status = 0
                body = f"<replay-error: {type(e).__name__}: {e}>"
                response_headers = {}
                elapsed_ms = (time.time() - step_started) * 1000.0

            # Build the replay step + finalize.
            replay_step = step_to_send  # already a clone
            # Snapshot cookies via the underlying cookielib jar, NOT
            # client.cookies.items(): the latter raises httpx.CookieConflict
            # when the jar holds same-named cookies from different domains
            # (e.g. Cloudflare's _cfuvid on gitlab.com AND a CDN/telemetry
            # host). Real multi-domain flows hit this immediately; single-
            # domain ones (Juice Shop) never did. Defensive: a cookie snapshot
            # must never 500 the whole cross-principal diff.
            try:
                _cookies_after = {c.name: c.value for c in client.cookies.jar}
            except Exception:
                _cookies_after = {}
            replay_step.set_response(
                status=status,
                headers=response_headers,
                body=body,
                content_type=response_headers.get("content-type"),
                elapsed_ms=elapsed_ms,
                cookies_after_step=_cookies_after,
            )
            replay_flow_obj.add_step(replay_step)

            # Build the diff.
            diff = _diff_step(
                step_index=i,
                source_step=source_step,
                replay_step=replay_step,
                applied_mutations=applied_labels,
            )
            diffs.append(diff)

            if stop_on_divergence and diff.diverged:
                logger.info(
                    f"[replay] step {i} diverged "
                    f"(status {diff.original_status} → {diff.replay_status}); "
                    f"stopping"
                )
                stopped_early = True
                break

    total_elapsed_ms = (time.time() - started) * 1000.0
    return ReplayResult(
        source_flow_id=flow.id,
        source_flow_name=flow.name,
        replay_flow=replay_flow_obj,
        step_diffs=diffs,
        total_elapsed_ms=total_elapsed_ms,
        stopped_early=stopped_early,
        error=error,
    )


def _diff_step(
    *,
    step_index: int,
    source_step: FlowStep,
    replay_step: FlowStep,
    applied_mutations: List[str],
) -> StepDiff:
    """Compute the structural diff between a capture-step and a replay-step."""
    orig_body = source_step.response_body or ""
    new_body = replay_step.response_body or ""
    orig_hash = (
        hashlib.sha256(orig_body.encode("utf-8", errors="replace")).hexdigest()[:16]
        if orig_body else ""
    )
    new_hash = (
        hashlib.sha256(new_body.encode("utf-8", errors="replace")).hexdigest()[:16]
        if new_body else ""
    )
    return StepDiff(
        step_index=step_index,
        step_id=source_step.id,
        method=source_step.method,
        url=source_step.url,
        original_status=source_step.response_status,
        replay_status=replay_step.response_status,
        original_size=len(orig_body),
        replay_size=len(new_body),
        original_hash=orig_hash,
        replay_hash=new_hash,
        status_changed=(source_step.response_status != replay_step.response_status),
        body_changed=(orig_hash != new_hash),
        size_delta=(len(new_body) - len(orig_body)),
        elapsed_delta_ms=(
            replay_step.response_elapsed_ms - source_step.response_elapsed_ms
        ),
        applied_mutations=applied_mutations,
    )
