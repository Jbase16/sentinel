from __future__ import annotations

import logging
from typing import Any, Dict, Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from core.cortex.models import (
    TopologyRequest,
    TopologyResponse,
    InsightRequest,
    InsightResponse,
)
from core.cortex.graph_analyzer import GraphAnalyzer
from core.cortex.insight_engine import InsightEngine

from core.epistemic.ledger import load_canonical_session_read_model
from core.reporting.poc_generator import PoCGenerator, PoCSafetyError
from core.cortex.canonical_graph import load_causal_graph_snapshot
from core.server.routers.auth import verify_token


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cortex", tags=["cortex"])


# ---------------------------------------------------------------------------
# Global singletons (process-wide by design)
# ---------------------------------------------------------------------------

_graph_analyzer = GraphAnalyzer()
_insight_engine = InsightEngine()


def get_graph_analyzer() -> GraphAnalyzer:
    return _graph_analyzer


def get_insight_engine() -> InsightEngine:
    return _insight_engine


# ---------------------------------------------------------------------------
# Analysis Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/analysis/topology",
    response_model=TopologyResponse,
    dependencies=[Depends(verify_token)],
)
async def analyze_topology(
    request: TopologyRequest,
    analyzer: GraphAnalyzer = Depends(get_graph_analyzer),
):
    """
    Performs topological analysis (centrality, paths, communities).
    """
    try:
        return await analyzer.analyze(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post(
    "/analysis/insights",
    response_model=InsightResponse,
    dependencies=[Depends(verify_token)],
)
async def generate_insights(
    request: InsightRequest,
    engine: InsightEngine = Depends(get_insight_engine),
) -> InsightResponse:
    """
    Generate LLM-driven insights for selected nodes.
    """
    return await engine.generate_insights(request)


@router.get("/graph", dependencies=[Depends(verify_token)])
async def get_current_graph():
    """
    Get the Causal/Pressure Graph for the active or most recent session.
    Returns 204 No Content if no session exists yet (graceful handling during scan startup).
    """
    from core.server.state import get_state
    from fastapi.responses import Response

    state = get_state()
    session_id = state.scan_state.get("session_id")

    if not session_id:
         # Fallback to most recent session in DB
         from core.data.db import Database
         db = Database.instance()
         rows = await db.fetch_all("SELECT id FROM sessions ORDER BY start_time DESC LIMIT 1", ())
         if rows:
             session_id = rows[0][0]

    if not session_id:
        # Return 204 No Content instead of error during scan initialization
        # This prevents "badStatus" errors when UI polls before session is ready
        return Response(status_code=204)

    try:
        snapshot = await load_causal_graph_snapshot(str(session_id))
        return snapshot.graph_dto
    except Exception as e:
        logger.warning(f"[Graph] Failed to build graph for session {session_id}: {e}")
        raise HTTPException(
            status_code=503,
            detail="canonical graph snapshot unavailable",
        ) from e


# ---------------------------------------------------------------------------
# Reporting (Phase 12 – minimal, correct)
# ---------------------------------------------------------------------------

def get_poc_generator() -> PoCGenerator:
    return PoCGenerator()


class ReportGenerateRequest(BaseModel):
    target: str = Field(..., description="Target name or root domain")
    scope: Optional[str] = Field(None)
    format: str = Field("markdown", description="markdown|json")
    include_attack_paths: bool = Field(True)
    max_paths: int = Field(5, ge=1, le=50)
    # Reports are always bound to one explicit session. Falling back to the
    # latest session makes a caller-selected target ambiguous and can expose
    # findings/evidence from a different scan.
    session_id: str = Field(..., min_length=1)
    finding_id: Optional[str] = Field(
        None,
        min_length=1,
        description=(
            "Exact canonical finding. May be omitted only when the session has "
            "exactly one valid SubmissionCandidate."
        ),
    )


class ReportGenerateResponse(BaseModel):
    report_id: str
    created_at: Optional[str]
    candidate_digest: str
    render_digest: str
    canonical_revision: str
    target: str
    scope: Optional[str]
    format: str
    content: str
    claims: Dict[str, Any]


class PoCResponse(BaseModel):
    finding_id: str
    title: str
    risk: str
    safe: bool
    commands: List[str]
    notes: List[str]
    created_at: str


def _require_session_target(
    *,
    session_data: Optional[dict],
    requested_target: Optional[str],
) -> str:
    """Return the authoritative target for an existing, matching session."""
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")

    session_target = str(session_data.get("target") or "").strip()
    if not session_target:
        raise HTTPException(
            status_code=409,
            detail="Session has no authoritative target",
        )

    if requested_target is not None and requested_target.strip() != session_target:
        raise HTTPException(
            status_code=403,
            detail="Target is not authorized for the requested session",
        )

    return session_target


@router.post(
    "/reporting/generate",
    response_model=ReportGenerateResponse,
    dependencies=[Depends(verify_token)],
)
async def generate_report(
    req: ReportGenerateRequest,
    graph_analyzer: GraphAnalyzer = Depends(get_graph_analyzer),
) -> ReportGenerateResponse:
    import json

    from core.data.db import Database
    from core.reporting.submission_candidate import (
        candidate_report_payload,
        render_submission_candidate,
        resolve_submission_candidate,
    )

    db = Database.instance()
    session_data = await db.get_session(req.session_id)
    _require_session_target(
        session_data=session_data,
        requested_target=req.target,
    )
    if req.scope:
        raise HTTPException(
            status_code=400,
            detail="Candidate reports do not accept caller-provided scope prose",
        )
    report_format = req.format.lower()
    if report_format not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="Unsupported report format")

    read_model = load_canonical_session_read_model(req.session_id)
    try:
        candidate = resolve_submission_candidate(
            read_model,
            finding_id=req.finding_id,
        )
        rendered = render_submission_candidate(candidate)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    payload = candidate_report_payload(candidate, rendered=rendered)
    content = (
        json.dumps(payload, sort_keys=True, indent=2)
        if report_format == "json"
        else rendered.markdown
    )

    return ReportGenerateResponse(
        report_id=candidate.candidate_digest,
        created_at=None,
        candidate_digest=candidate.candidate_digest,
        render_digest=rendered.render_digest,
        canonical_revision=candidate.canonical_revision,
        target=candidate.target_url,
        scope=None,
        format=report_format,
        content=content,
        claims=payload["claims"],
    )


@router.get(
    "/reporting/poc/{finding_id}",
    response_model=PoCResponse,
    dependencies=[Depends(verify_token)],
)
async def get_poc(
    finding_id: str,
    session_id: str = Query(..., min_length=1),
    target: Optional[str] = None,
    poc: PoCGenerator = Depends(get_poc_generator),
) -> PoCResponse:
    from core.data.db import Database

    db = Database.instance()
    session_data = await db.get_session(session_id)
    session_target = _require_session_target(
        session_data=session_data,
        requested_target=target,
    )

    read_model = load_canonical_session_read_model(session_id)
    finding = next(
        (
            item
            for item in read_model.finding_views()
            if str(item.get("id")) == str(finding_id)
        ),
        None,
    )

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        artifact = poc.generate_for_finding(
            finding=finding,
            target_hint=session_target,
        )
    except PoCSafetyError as e:
        raise HTTPException(
            status_code=400,
            detail=f"PoC blocked by safety policy: {e}",
        ) from e

    return PoCResponse(
        finding_id=artifact.finding_id,
        title=artifact.title,
        risk=artifact.risk,
        safe=artifact.safe,
        commands=artifact.commands,
        notes=artifact.notes,
        created_at=artifact.created_at,
    )
