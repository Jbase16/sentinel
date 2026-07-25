"""
core/ghost/flow_diff.py — Phase 4-G5: multi-principal flow diff.

The closer of Phase 4. Composes the replay engine (G3) with the persona
machinery (Phase 3 step 2) to turn a captured flow into a cross-principal
IDOR detector at the FLOW level.

The detection model:

  Alice records a flow:  login → view profile → edit settings → save.
  We replay the SAME flow under Bob's identity (Bob's auth seeded via
  override_headers). For every step:

    * If Bob's response converges with Alice's captured response
      (same status, similar body) → Bob is reading Alice's data.
      That's cross-principal IDOR — at this step.

    * If Bob's response diverges (403, different body, etc.) →
      authorization IS working at this step. Good.

The strength of this signal vs Phase 3's multi-principal pass:
  * Phase 3 compares two identities' responses for the SAME URL.
  * This compares the WHOLE captured flow under one identity vs
    the SAME captured flow replayed under another. State carries
    forward — if Alice's step 3 reveals an internal ID and Bob's
    replay shows the same ID, that's stronger than URL-level
    comparison.

What the diff catches that the request-level pass doesn't:
  * IDORs reachable only via prior-step state (e.g. /api/orders/X
    where X is only discoverable from a previous /api/me response).
  * Auth-state divergence (a flow that depends on a specific user's
    cart should show different cart contents under different users —
    if it shows the same, that's IDOR).
  * Multi-step authorization bypasses (Alice's step 4 succeeds only
    because steps 1-3 set up state; Bob shouldn't see that state).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from core.ghost.flow import UserFlow
from core.ghost.replay import ReplayResult, replay_flow

logger = logging.getLogger(__name__)


# ─────────────────────────── diff types ──────────────────────────


@dataclass
class CrossPrincipalStepFinding:
    """One step-level cross-principal IDOR finding.

    Emitted when Alice's captured response and Bob's replay response
    for the same step converge in a way that suggests Bob is reading
    Alice's data."""
    step_index: int
    step_method: str
    step_url: str
    alice_persona: str
    bob_persona: str

    alice_status: int
    bob_status: int

    alice_body_size: int
    bob_body_size: int

    alice_body_hash: str
    bob_body_hash: str

    signal: str           # "identical-json" | "distinct-json-similar-size"
                          #   | "distinct-body" | "denied"
    confidence: float     # 0.0–1.0
    rationale: str

    # Short body excerpts for triage.
    alice_excerpt: str = ""
    bob_excerpt: str = ""

    @property
    def is_idor_signal(self) -> bool:
        """Did this step indicate cross-principal leakage?"""
        return self.signal in ("identical-json", "distinct-json-similar-size")


@dataclass
class CrossPrincipalFlowDiff:
    """Result of comparing one captured flow against a replay under
    a different identity."""
    source_flow_id: str
    source_flow_name: str
    alice_persona: str
    bob_persona: str
    step_findings: List[CrossPrincipalStepFinding]
    bob_replay_result: ReplayResult
    total_elapsed_ms: float

    @property
    def idor_step_count(self) -> int:
        return sum(1 for f in self.step_findings if f.is_idor_signal)

    @property
    def denied_step_count(self) -> int:
        return sum(1 for f in self.step_findings if f.signal == "denied")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_flow_id": self.source_flow_id,
            "source_flow_name": self.source_flow_name,
            "alice_persona": self.alice_persona,
            "bob_persona": self.bob_persona,
            "total_elapsed_ms": self.total_elapsed_ms,
            "idor_step_count": self.idor_step_count,
            "denied_step_count": self.denied_step_count,
            "step_findings": [
                {
                    "step_index": f.step_index,
                    "method": f.step_method,
                    "url": f.step_url,
                    "alice_persona": f.alice_persona,
                    "bob_persona": f.bob_persona,
                    "alice_status": f.alice_status,
                    "bob_status": f.bob_status,
                    "alice_body_size": f.alice_body_size,
                    "bob_body_size": f.bob_body_size,
                    "alice_body_hash": f.alice_body_hash,
                    "bob_body_hash": f.bob_body_hash,
                    "signal": f.signal,
                    "confidence": f.confidence,
                    "rationale": f.rationale,
                    "is_idor_signal": f.is_idor_signal,
                    "alice_excerpt": f.alice_excerpt,
                    "bob_excerpt": f.bob_excerpt,
                }
                for f in self.step_findings
            ],
        }


# ─────────────────────────── engine ──────────────────────────


async def diff_flow_across_principals(
    flow: UserFlow,
    alice_persona_name: str,
    bob_persona_name: str,
    bob_headers: Dict[str, str],
    bob_cookies: Optional[Dict[str, str]] = None,
    *,
    scope_filter: Optional[Callable[[str], bool]] = None,
    per_step_timeout: float = 10.0,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> CrossPrincipalFlowDiff:
    """Replay `flow` (originally captured as Alice) under Bob's identity,
    then compare every step's response across the two principals.

    The captured flow's step responses ARE Alice's responses (we use
    those as-is — no need to replay Alice). Bob's responses come from
    a fresh replay with `override_headers=bob_headers` so the captured
    Authorization is replaced by Bob's.

    Args:
      flow: The captured flow (Alice's session).
      alice_persona_name: Name to attribute Alice's side of the diff to.
        Stored on every finding for clear reporting.
      bob_persona_name: Name to attribute Bob's side to.
      bob_headers: Bob's authenticated headers — typically returned by
        persona_auth.authenticate_persona(). Usually one entry:
        `{"Authorization": "Bearer <bob-token>"}`.
      bob_cookies: Optional cookie jar to seed Bob's replay with.
      scope_filter: Optional URL gate; out-of-scope steps are skipped
        in Bob's replay (no probe leaves; finding marks 'skipped').
      per_step_timeout: httpx timeout per request.
      transport: For testing — httpx.MockTransport injection.

    Returns:
      CrossPrincipalFlowDiff with per-step findings + Bob's full replay.
    """
    import time
    started = time.time()

    # Replay the flow as Bob — fresh client, Bob's auth, no mutations.
    bob_result = await replay_flow(
        flow,
        mutations_by_step_index=None,  # no mutations: we want to see
                                       # what Bob sees doing exactly what
                                       # Alice did
        initial_cookies=bob_cookies,
        override_headers=bob_headers,
        scope_filter=scope_filter,
        stop_on_divergence=False,  # always run the full flow
        per_step_timeout=per_step_timeout,
        transport=transport,
    )

    # Now diff each step of Alice's capture vs Bob's replay.
    step_findings: List[CrossPrincipalStepFinding] = []
    # bob_result.replay_flow.steps may be SHORTER than flow.steps if
    # scope_filter skipped some steps. Match by source step id.
    bob_steps_by_source_id = {
        s.id: s for s in bob_result.replay_flow.steps
    }
    for i, alice_step in enumerate(flow.steps):
        bob_step = bob_steps_by_source_id.get(alice_step.id)
        if bob_step is None:
            # Step skipped (scope filter, etc.); skip the diff.
            continue

        signal, confidence, rationale = _classify(
            alice_status=alice_step.response_status,
            alice_body=alice_step.response_body or "",
            bob_status=bob_step.response_status,
            bob_body=bob_step.response_body or "",
        )

        import hashlib
        a_hash = hashlib.sha256(
            (alice_step.response_body or "").encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        b_hash = hashlib.sha256(
            (bob_step.response_body or "").encode("utf-8", errors="replace")
        ).hexdigest()[:16]

        step_findings.append(CrossPrincipalStepFinding(
            step_index=i,
            step_method=alice_step.method,
            step_url=alice_step.url,
            alice_persona=alice_persona_name,
            bob_persona=bob_persona_name,
            alice_status=alice_step.response_status,
            bob_status=bob_step.response_status,
            alice_body_size=len(alice_step.response_body or ""),
            bob_body_size=len(bob_step.response_body or ""),
            alice_body_hash=a_hash,
            bob_body_hash=b_hash,
            signal=signal,
            confidence=confidence,
            rationale=rationale,
            alice_excerpt=(alice_step.response_body or "")[:200],
            bob_excerpt=(bob_step.response_body or "")[:200],
        ))

    total_elapsed_ms = (time.time() - started) * 1000.0
    logger.info(
        f"[flow-diff] {flow.name!r} as {alice_persona_name!r}↔{bob_persona_name!r}: "
        f"{sum(1 for f in step_findings if f.is_idor_signal)} IDOR step(s) "
        f"across {len(step_findings)} comparison(s)"
    )

    return CrossPrincipalFlowDiff(
        source_flow_id=flow.id,
        source_flow_name=flow.name,
        alice_persona=alice_persona_name,
        bob_persona=bob_persona_name,
        step_findings=step_findings,
        bob_replay_result=bob_result,
        total_elapsed_ms=total_elapsed_ms,
    )


def _classify(
    *,
    alice_status: int,
    alice_body: str,
    bob_status: int,
    bob_body: str,
) -> Tuple[str, float, str]:
    """Classify the cross-principal signal for one step.

    This mirrors the Phase 3 multi-principal pass taxonomy
    (identical-json is the canonical IDOR signal), but applied at the
    flow-step level — Alice's captured response vs Bob's replay
    response, not URL-level comparison."""
    # Bob got 200, Alice got 200 — the interesting case.
    if alice_status == 200 and bob_status == 200:
        if len(alice_body) < 20 or len(bob_body) < 20:
            return ("distinct-body", 0.3,
                    "Both 200 but bodies too short to compare structurally.")
        is_json_a = alice_body.lstrip().startswith(("{", "["))
        is_json_b = bob_body.lstrip().startswith(("{", "["))
        both_json = is_json_a and is_json_b

        if alice_body == bob_body:
            if both_json:
                return ("identical-json", 0.90,
                        "Both identities received BYTE-IDENTICAL JSON — "
                        "Bob is reading Alice's data via this captured URL.")
            return ("distinct-body", 0.3,
                    "Identical bodies but non-JSON — likely SPA shell, "
                    "not a per-user data leak.")

        size_ratio = min(len(alice_body), len(bob_body)) / max(
            len(alice_body), len(bob_body), 1
        )
        if both_json and size_ratio >= 0.5:
            return ("distinct-json-similar-size", 0.85,
                    "Both identities received DISTINCT JSON of similar "
                    "shape — same URL returning per-identity data with "
                    "no access-control gate.")
        return ("distinct-body", 0.5,
                "Both 200 but bodies diverge structurally — auth may "
                "still be filtering correctly.")

    # Bob got 4xx — authorization is working at this step.
    if bob_status in (401, 403, 404):
        return ("denied", 0.0,
                f"Bob received {bob_status} — auth gate is working "
                f"at this step.")

    # Mixed: Alice 200, Bob something else.
    if alice_status == 200 and bob_status != 200:
        return ("denied", 0.0,
                f"Alice 200 / Bob {bob_status} — auth differentiating "
                f"correctly.")

    # Neither 200 — uninteresting.
    return ("denied", 0.0,
            f"Alice {alice_status} / Bob {bob_status} — neither 200, "
            f"no IDOR signal possible.")
