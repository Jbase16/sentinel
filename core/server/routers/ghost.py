"""
core/server/routers/ghost.py

Ghost Protocol Router — Phase 4-G1 (real proxy lifecycle, no more stubs).

This used to be entirely a placeholder (`_ghost_process = None`, comments
saying "in production, this would..."). The real GhostInterceptor + addon
existed in core/ghost/proxy.py but were never reachable from the API,
which meant the operator could never actually USE Ghost — only the scan
engine could, and only as an internal hook.

Phase 4-G1 wires this up properly:

  * POST /v1/ghost/start  → spawn real mitmproxy with GhostAddon, return
    the ACTUAL listen port. The proxy runs in the same event loop as
    FastAPI as a long-running asyncio task.
  * POST /v1/ghost/stop   → master.shutdown() + cancel the task cleanly.
  * GET  /v1/ghost/status → real state: running flag, port, flow count,
    active recording sessions, certificate path.
  * GET  /v1/ghost/cert   → serve the mitmproxy CA cert so the operator
    can install it into their system trust store with one click.
  * POST /v1/ghost/record/{flow_name} → start a flow recording (uses
    the FlowMapper singleton; the addon already feeds it).
  * POST /v1/ghost/record/{flow_name}/stop → stop and persist the flow.
  * GET  /v1/ghost/flows  → list recorded flows.
  * GET  /v1/ghost/flows/{flow_id} → details of one flow.

Lifecycle: one global Ghost instance per FastAPI process (single-operator
model). Multiple concurrent Ghost proxies on the same process don't make
sense — mitmproxy's DumpMaster has its own loop affinity and the operator
can only point one browser at one proxy at a time anyway.

The Ghost session is its OWN ScanSession (separate from scheduler-driven
scan sessions), because Ghost is operator-driven and persists across
multiple captures. Findings emitted by the addon land in this dedicated
session.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from core.server.routers.auth import verify_sensitive_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ghost"])


# ─────────────────────────── response models ───────────────────────────


class GhostStartResponse(BaseModel):
    """Response when starting Ghost Protocol."""
    status: str
    port: Optional[int] = None
    message: Optional[str] = None
    cert_path: Optional[str] = None


class GhostStopResponse(BaseModel):
    """Response when stopping Ghost Protocol."""
    status: str
    message: Optional[str] = None


class GhostRecordResponse(BaseModel):
    """Response when starting or stopping flow recording."""
    status: str
    flow_name: str
    flow_id: Optional[str] = None
    step_count: Optional[int] = None
    message: Optional[str] = None


class GhostStatusResponse(BaseModel):
    """Current Ghost Protocol state."""
    running: bool
    port: Optional[int] = None
    session_id: Optional[str] = None
    active_recordings: List[str] = []
    flow_count: int = 0
    cert_available: bool = False
    cert_path: Optional[str] = None
    findings_so_far: int = 0


class FlowSummary(BaseModel):
    """One-line summary of a recorded flow (for list endpoints)."""
    flow_id: str
    name: str
    step_count: int
    has_auth_tokens: bool


# ─────────────────────── singleton process state ───────────────────────
#
# Globals are intentional here — one Ghost per FastAPI process. The
# alternative (per-request state) makes no sense for a long-lived proxy.

_INTERCEPTOR = None              # type: Optional["GhostInterceptor"]
_GHOST_SESSION = None            # type: Optional[Any]  # ScanSession
_RECORDING_FLOW_IDS: Dict[str, str] = {}  # human-name → flow_id


def _mitmproxy_cert_path() -> Optional[Path]:
    """Return the path to mitmproxy's CA cert, or None if not generated yet.

    mitmproxy creates ~/.mitmproxy/mitmproxy-ca-cert.pem on first run.
    Returns None if the proxy has never been started — the operator
    would see `cert_available=False` and know to run /start first.
    """
    p = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    return p if p.exists() else None


def _get_or_create_ghost_session():
    """One ScanSession per Ghost lifetime. Created lazily on first /start."""
    global _GHOST_SESSION
    if _GHOST_SESSION is None:
        # Imported lazily so this router can load even if the session
        # subsystem isn't fully initialized (test scaffolding etc.).
        from core.base.session import ScanSession
        _GHOST_SESSION = ScanSession(target="ghost://operator-driven")
        _GHOST_SESSION.knowledge = getattr(_GHOST_SESSION, "knowledge", None) or {}
        logger.info(
            f"[Ghost] created operator session id={_GHOST_SESSION.id}"
        )
    return _GHOST_SESSION


# ───────────────────────────── endpoints ─────────────────────────────


@router.post("/start", response_model=GhostStartResponse)
async def start_ghost(
    port: int = Query(
        default=0,
        description="Port for the proxy to listen on. 0 = pick a free port.",
    ),
    _: bool = Depends(verify_sensitive_token),
) -> GhostStartResponse:
    """Start the Ghost Protocol passive interception proxy.

    Spawns the real mitmproxy DumpMaster with the GhostAddon installed.
    The addon:
      * Enforces scope (drops out-of-scope requests with 403)
      * Emits CAL Evidence for every observed request
      * Feeds the MIMIC shadow_spec (auto-discovered API surface)
      * Captures auth tokens via SessionBridge
      * Async-de-obfuscates JS via Lazarus

    Returns the actual listen port (may differ from the requested port
    if 0 was passed for "find a free one"). Also returns the CA cert path
    if mitmproxy has generated it (it does so on first run).
    """
    global _INTERCEPTOR

    if _INTERCEPTOR is not None:
        # Already running — surface the existing state instead of 409.
        # Operators want idempotency on /start; nobody likes "click twice
        # → error" UX. The status endpoint can tell them more.
        return GhostStartResponse(
            status="already_running",
            port=getattr(_INTERCEPTOR, "port", None),
            message="Ghost Protocol is already running. Use /v1/ghost/status for details.",
            cert_path=str(_mitmproxy_cert_path()) if _mitmproxy_cert_path() else None,
        )

    # Lazy import — mitmproxy is heavyweight and we don't want to pay
    # the import cost just because someone hit /v1/ghost/status.
    try:
        from core.ghost.proxy import GhostInterceptor
    except ImportError as e:
        logger.error(f"[Ghost] cannot import GhostInterceptor: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Ghost Protocol unavailable (missing mitmproxy?): {e}",
        )

    session = _get_or_create_ghost_session()
    # Wire the session.ghost handle so the addon can reach back.
    session.ghost = None  # cleared until we have the interceptor

    interceptor = GhostInterceptor(session=session, port=port)
    session.ghost = interceptor  # addon's strategy proposer needs this

    try:
        await interceptor.start()
    except Exception as e:
        logger.error(
            f"[Ghost] failed to start: {type(e).__name__}: {e}",
            exc_info=True,
        )
        # Roll back partial state.
        session.ghost = None
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start Ghost Protocol: {e}",
        )

    _INTERCEPTOR = interceptor
    actual_port = interceptor.port
    cert_path = _mitmproxy_cert_path()

    logger.info(
        f"[Ghost] proxy started on port {actual_port} "
        f"(session id={session.id}, cert={'ready' if cert_path else 'pending'})"
    )
    return GhostStartResponse(
        status="running",
        port=actual_port,
        message=(
            f"Ghost Protocol started on 127.0.0.1:{actual_port}. "
            f"Configure your browser/app to use this as HTTP/HTTPS proxy."
        ),
        cert_path=str(cert_path) if cert_path else None,
    )


@router.post("/stop", response_model=GhostStopResponse)
async def stop_ghost(_: bool = Depends(verify_sensitive_token)) -> GhostStopResponse:
    """Stop the Ghost Protocol proxy gracefully."""
    global _INTERCEPTOR

    if _INTERCEPTOR is None:
        return GhostStopResponse(
            status="not_running",
            message="Ghost Protocol is not currently running.",
        )

    try:
        _INTERCEPTOR.stop()
        # Give the asyncio task a moment to actually finish cancellation
        # so subsequent /start calls don't trip over a half-dead master.
        task = getattr(_INTERCEPTOR, "_task", None)
        if task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                # Don't care — shutdown is best-effort.
                pass
    except Exception as e:
        logger.warning(f"[Ghost] stop encountered: {type(e).__name__}: {e}")

    _INTERCEPTOR = None
    # Keep the ghost_session around — flows remain accessible until
    # the operator explicitly clears them.

    logger.info("[Ghost] proxy stopped")
    return GhostStopResponse(
        status="stopped",
        message="Ghost Protocol stopped. Recorded flows are preserved.",
    )


@router.get("/status", response_model=GhostStatusResponse)
async def get_ghost_status(
    _: bool = Depends(verify_sensitive_token),
) -> GhostStatusResponse:
    """Return the current Ghost state, including how many flows + findings
    have accumulated. Safe to poll from the UI for live status indicators."""
    # Avoid touching the FlowMapper singleton unless we actually have one.
    from core.ghost.flow import FlowMapper

    fm = FlowMapper.instance()
    flow_count = len(fm.active_flows)
    cert_path = _mitmproxy_cert_path()

    findings_so_far = 0
    sess = _GHOST_SESSION
    if sess is not None:
        try:
            findings_so_far = len(sess.findings.get_all())
        except Exception:
            findings_so_far = 0

    return GhostStatusResponse(
        running=_INTERCEPTOR is not None,
        port=getattr(_INTERCEPTOR, "port", None) if _INTERCEPTOR else None,
        session_id=sess.id if sess else None,
        active_recordings=list(_RECORDING_FLOW_IDS.keys()),
        flow_count=flow_count,
        cert_available=cert_path is not None,
        cert_path=str(cert_path) if cert_path else None,
        findings_so_far=findings_so_far,
    )


@router.get("/cert")
async def get_ca_cert(_: bool = Depends(verify_sensitive_token)):
    """Serve the mitmproxy CA cert so the operator can install it in the
    system trust store. mitmproxy generates this on first proxy start;
    if Ghost has never run, returns 404.

    Security note: this cert is the operator's own MITM root — it should
    NOT be shared. Endpoint is gated by verify_sensitive_token.
    """
    cert_path = _mitmproxy_cert_path()
    if cert_path is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "MITM CA cert not found. Start Ghost Protocol at least "
                "once with POST /v1/ghost/start — mitmproxy generates "
                "the cert on first run."
            ),
        )
    return FileResponse(
        path=str(cert_path),
        media_type="application/x-pem-file",
        filename="sentinel-ghost-ca.pem",
    )


@router.post("/record/{flow_name}", response_model=GhostRecordResponse)
async def start_ghost_recording(
    flow_name: str,
    _: bool = Depends(verify_sensitive_token),
) -> GhostRecordResponse:
    """Start recording a named flow. The proxy must be running.

    The FlowMapper is fed by GhostAddon for every request; calling this
    endpoint just creates a flow ID the operator can later reference.
    Multiple flows can record concurrently — each gets its own ID.
    """
    if _INTERCEPTOR is None:
        raise HTTPException(
            status_code=409,
            detail="Ghost Protocol is not running. POST /v1/ghost/start first.",
        )

    if flow_name in _RECORDING_FLOW_IDS:
        return GhostRecordResponse(
            status="already_recording",
            flow_name=flow_name,
            flow_id=_RECORDING_FLOW_IDS[flow_name],
            message=f"Flow {flow_name!r} is already recording.",
        )

    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    flow_id = fm.start_recording(flow_name)
    _RECORDING_FLOW_IDS[flow_name] = flow_id

    logger.info(f"[Ghost] started recording flow {flow_name!r} (id={flow_id})")
    return GhostRecordResponse(
        status="recording",
        flow_name=flow_name,
        flow_id=flow_id,
        message=(
            f"Recording flow {flow_name!r}. Browse the target through the "
            f"proxy on 127.0.0.1:{_INTERCEPTOR.port}; every request lands "
            f"in this flow."
        ),
    )


@router.post("/record/{flow_name}/stop", response_model=GhostRecordResponse)
async def stop_ghost_recording(
    flow_name: str,
    _: bool = Depends(verify_sensitive_token),
) -> GhostRecordResponse:
    """Stop recording a named flow. The flow remains in FlowMapper.active_flows
    so it can be inspected, replayed, or fuzzed afterward."""
    if flow_name not in _RECORDING_FLOW_IDS:
        raise HTTPException(
            status_code=404,
            detail=f"No active recording named {flow_name!r}.",
        )
    flow_id = _RECORDING_FLOW_IDS.pop(flow_name)

    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    flow = fm.active_flows.get(flow_id)
    step_count = len(flow.steps) if flow else 0

    # Phase 4-G2: persist on stop so the flow survives proxy restart.
    persist_path = fm.persist(flow_id)
    persist_note = f" Persisted to {persist_path}." if persist_path else ""

    logger.info(
        f"[Ghost] stopped recording flow {flow_name!r} "
        f"(id={flow_id}, steps={step_count}){persist_note}"
    )
    return GhostRecordResponse(
        status="stopped",
        flow_name=flow_name,
        flow_id=flow_id,
        step_count=step_count,
        message=(
            f"Recording stopped. {step_count} step(s) captured."
            f"{persist_note}"
        ),
    )


@router.get("/flows", response_model=List[FlowSummary])
async def list_flows(
    _: bool = Depends(verify_sensitive_token),
) -> List[FlowSummary]:
    """List all recorded flows (active and stopped). Returns one-line
    summaries; use /flows/{flow_id} for full details."""
    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    out: List[FlowSummary] = []
    for fid, flow in fm.active_flows.items():
        out.append(FlowSummary(
            flow_id=fid,
            name=flow.name,
            step_count=len(flow.steps),
            has_auth_tokens=bool(flow.auth_tokens),
        ))
    return out


@router.get("/flows/{flow_id}")
async def get_flow_detail(
    flow_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    """Full details of one flow: every step's method/url/params/headers."""
    from core.ghost.flow import FlowMapper
    fm = FlowMapper.instance()
    flow = fm.active_flows.get(flow_id)
    if flow is None:
        # Phase 4-G2: try disk before declaring not-found.
        flow = fm.load_persisted(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found.")
    return {
        "flow_id": flow_id,
        "name": flow.name,
        "step_count": len(flow.steps),
        "auth_tokens": dict(flow.auth_tokens),  # full token values; gated by sensitive token
        "steps": [
            {
                "id": s.id,
                "method": s.method,
                "url": s.url,
                "params": dict(s.params) if s.params else {},
                "headers": dict(s.headers) if s.headers else {},
                "timestamp": s.timestamp,
                "response_status": s.response_status,
            }
            for s in flow.steps
        ],
    }


# ──────────────────────── Phase 4-G3: replay ────────────────────────


class ReplayMutationSpec(BaseModel):
    """One mutation request: which built-in mutation to apply, at which
    step index, with optional params."""
    step_index: int
    mutation: str  # "noop" | "swap-auth"
    params: Dict[str, Any] = {}


class ReplayRequest(BaseModel):
    """POST /v1/ghost/flows/{flow_id}/replay body."""
    mutations: List[ReplayMutationSpec] = []
    initial_cookies: Dict[str, str] = {}
    initial_headers: Dict[str, str] = {}
    stop_on_divergence: bool = False
    per_step_timeout: float = 10.0


def _build_mutation(spec: ReplayMutationSpec):
    """Resolve a mutation spec into a Mutation object.

    G3 shipped noop + swap-auth as engine-validation baselines. G4
    extends this catalog with the full semantic library:
      jwt-alg-none, oauth-state-strip, privilege-downgrade,
      negative-quantity, header-inject-localhost, verb-tamper,
      csrf-token-strip.
    """
    from core.ghost.replay import NoOpMutation, SwapAuthHeader
    from core.ghost.mutations import (
        CSRFTokenStrip,
        HeaderInject,
        JWTAlgNone,
        NegativeQuantity,
        OAuthStateStrip,
        PrivilegeDowngrade,
        VerbTampering,
    )

    builders = {
        # G3 engine-validation mutations
        "noop": lambda: NoOpMutation(),
        "swap-auth": lambda: SwapAuthHeader(new_value=spec.params.get("new_value")),
        # G4 semantic library
        "jwt-alg-none": lambda: JWTAlgNone(),
        "oauth-state-strip": lambda: OAuthStateStrip(),
        "privilege-downgrade": lambda: PrivilegeDowngrade(),
        "negative-quantity": lambda: NegativeQuantity(),
        "header-inject-localhost": lambda: HeaderInject(),
        "verb-tamper": lambda: VerbTampering(),
        "csrf-token-strip": lambda: CSRFTokenStrip(),
    }
    fn = builders.get(spec.mutation)
    if fn is None:
        raise ValueError(
            f"Unknown mutation {spec.mutation!r}. "
            f"Known: {', '.join(sorted(builders.keys()))}."
        )
    return fn()


class FlowDiffRequest(BaseModel):
    """POST /v1/ghost/flows/{flow_id}/diff body.

    The captured flow plays as `alice_persona_name`. We replay it under
    `bob_persona_spec` (a persona dict in the same shape Phase 3 uses)
    and emit per-step diffs."""
    alice_persona_name: str = "alice"
    bob_persona_name: str = "bob"
    bob_persona_spec: Dict[str, Any] = {}
    bob_headers: Dict[str, str] = {}
    bob_cookies: Dict[str, str] = {}
    per_step_timeout: float = 10.0


@router.post("/flows/{flow_id}/diff")
async def diff_flow_endpoint(
    flow_id: str,
    req: FlowDiffRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Phase 4-G5: replay a captured flow under a different identity and
    surface per-step cross-principal diffs.

    Bob's identity is resolved by, in priority order:
      1. If `bob_persona_spec` has a `login_url`, call
         persona_auth.authenticate_persona() to get headers + cookies.
      2. Otherwise fall back to `bob_headers` + `bob_cookies` (already
         authenticated by the caller).

    The captured flow plays as Alice; Bob's replay uses
    override_headers so the captured Authorization is REPLACED, not
    augmented. Every step's response is compared across the two
    identities; findings carry the canonical IDOR signal taxonomy
    (identical-json = 0.90 confidence, etc.).
    """
    from core.ghost.flow import FlowMapper
    from core.ghost.flow_diff import diff_flow_across_principals

    fm = FlowMapper.instance()
    flow = fm.active_flows.get(flow_id) or fm.load_persisted(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found.")

    # Resolve Bob's identity. The persona_auth path is the canonical
    # approach (matches Phase 3); the explicit headers/cookies path is
    # for when the operator already has tokens (test scaffolding, CLI).
    bob_headers: Dict[str, str] = dict(req.bob_headers)
    bob_cookies: Dict[str, str] = dict(req.bob_cookies)
    if req.bob_persona_spec and req.bob_persona_spec.get("login_url"):
        from core.wraith.persona_auth import authenticate_persona
        try:
            h, c = await authenticate_persona(req.bob_persona_spec)
            bob_headers.update(h)
            bob_cookies.update(c)
        except Exception as e:
            logger.warning(
                f"[Ghost] bob persona auth failed: {type(e).__name__}: {e}; "
                f"falling back to explicit headers/cookies"
            )

    if not bob_headers and not bob_cookies:
        raise HTTPException(
            status_code=400,
            detail=(
                "Bob identity is empty — provide either bob_persona_spec "
                "with login_url, or bob_headers/bob_cookies directly."
            ),
        )

    diff = await diff_flow_across_principals(
        flow=flow,
        alice_persona_name=req.alice_persona_name,
        bob_persona_name=req.bob_persona_name,
        bob_headers=bob_headers,
        bob_cookies=bob_cookies,
        per_step_timeout=req.per_step_timeout,
    )
    return diff.to_dict()


@router.get("/flows/{flow_id}/propose")
async def propose_flow_mutations(
    flow_id: str,
    _: bool = Depends(verify_sensitive_token),
):
    """Phase 4-G4: inspect a captured flow and return mutation proposals.

    For every captured step, the proposer asks each mutation in the
    library 'does this hypothesis make sense here?' and emits a proposal
    when yes. Operators (or AI) review the list and pick which to
    actually run via POST /flows/{flow_id}/replay.

    Deterministic: same flow → same proposals. Cheap to call repeatedly.
    """
    from core.ghost.flow import FlowMapper
    from core.ghost.mutations import propose_mutations

    fm = FlowMapper.instance()
    flow = fm.active_flows.get(flow_id) or fm.load_persisted(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found.")

    proposals = propose_mutations(flow)
    return {
        "flow_id": flow_id,
        "flow_name": flow.name,
        "step_count": len(flow.steps),
        "proposal_count": len(proposals),
        "proposals": [p.to_dict() for p in proposals],
    }


@router.post("/flows/{flow_id}/replay")
async def replay_flow_endpoint(
    flow_id: str,
    req: ReplayRequest,
    _: bool = Depends(verify_sensitive_token),
):
    """Replay a captured flow, optionally with mutations injected at any
    step. Returns the new replay flow + per-step diffs against the
    original capture.

    The replay runs in an isolated httpx client (fresh cookie jar). Each
    step's response is captured and compared to the original; the
    response surfaces every divergence.
    """
    from core.ghost.flow import FlowMapper
    from core.ghost.replay import replay_flow

    fm = FlowMapper.instance()
    flow = fm.active_flows.get(flow_id) or fm.load_persisted(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail=f"Flow {flow_id!r} not found.")

    # Build mutations_by_step_index.
    mutations_by_step: Dict[int, List[Any]] = {}
    for spec in req.mutations:
        try:
            mut = _build_mutation(spec)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        mutations_by_step.setdefault(spec.step_index, []).append(mut)

    result = await replay_flow(
        flow,
        mutations_by_step_index=mutations_by_step,
        initial_cookies=req.initial_cookies,
        initial_headers=req.initial_headers,
        stop_on_divergence=req.stop_on_divergence,
        per_step_timeout=req.per_step_timeout,
    )
    return result.to_dict()
