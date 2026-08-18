from __future__ import annotations

import logging
from typing import Optional, List

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

from core.data.findings_store import get_finding_store
from core.epistemic.ledger import load_canonical_session_read_model
from core.reporting.report_composer import ReportComposer
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
        # Return empty graph instead of error to prevent UI crashes
        return {
            "session_id": session_id,
            "nodes": [],
            "edges": [],
            "count": {"nodes": 0, "edges": 0}
        }


# ---------------------------------------------------------------------------
# Reporting (Phase 12 – minimal, correct)
# ---------------------------------------------------------------------------

def get_report_composer(
    finding_store=Depends(get_finding_store),
    graph_analyzer: GraphAnalyzer = Depends(get_graph_analyzer),
) -> ReportComposer:
    from core.data.evidence_store import EvidenceStore
    return ReportComposer(
        finding_store=finding_store,
        evidence_ledger=EvidenceStore.instance(),
        graph_analyzer=graph_analyzer,
    )


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


class ReportGenerateResponse(BaseModel):
    report_id: str
    created_at: str
    target: str
    scope: Optional[str]
    format: str
    content: str


class PoCResponse(BaseModel):
    finding_id: str
    title: str
    risk: str
    safe: bool
    commands: List[str]
    notes: List[str]
    created_at: str


class _ListStore:
    """Minimal store adapter wrapping a pre-fetched list of entries.

    Lets us build a session-scoped ReportComposer from DB rows without the
    composer depending on session plumbing — it just calls ``get_all()``."""
    def __init__(self, items):
        self._items = list(items or [])

    def get_all(self):
        return list(self._items)


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
    from core.data.db import Database

    db = Database.instance()
    session_data = await db.get_session(req.session_id)
    target = _require_session_target(
        session_data=session_data,
        requested_target=req.target,
    )

    # Pull only the active canonical revision for this explicit session.  DB
    # finding/evidence tables are legacy projections, not reporting authority.
    read_model = load_canonical_session_read_model(req.session_id)
    composer = ReportComposer(
        finding_store=_ListStore(read_model.finding_views()),
        evidence_ledger=_ListStore(read_model.evidence_views()),
        graph_analyzer=graph_analyzer,
    )

    artifact = composer.generate(
        target=target,
        scope=req.scope,
        report_format=req.format,
        include_attack_paths=req.include_attack_paths,
        max_paths=req.max_paths,
    )

    return ReportGenerateResponse(
        report_id=artifact.report_id,
        created_at=artifact.created_at,
        target=artifact.target,
        scope=artifact.scope,
        format=artifact.format,
        content=artifact.content,
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
