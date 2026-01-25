from __future__ import annotations

from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends
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
from core.reporting.report_composer import ReportComposer
from core.reporting.poc_generator import PoCGenerator, PoCSafetyError
from core.cortex.causal_graph import get_graph_dto_for_session
from core.server.routers.auth import verify_token


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

@router.post("/analysis/topology", response_model=TopologyResponse)
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


@router.post("/analysis/insights", response_model=InsightResponse)
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
        return await get_graph_dto_for_session(session_id)
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
    return ReportComposer(
        finding_store=finding_store,
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


@router.post("/reporting/generate", response_model=ReportGenerateResponse)
def generate_report(
    req: ReportGenerateRequest,
    composer: ReportComposer = Depends(get_report_composer),
) -> ReportGenerateResponse:
    artifact = composer.generate(
        target=req.target,
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


@router.get("/reporting/poc/{finding_id}", response_model=PoCResponse)
def get_poc(
    finding_id: str,
    target: Optional[str] = None,
    poc: PoCGenerator = Depends(get_poc_generator),
    finding_store=Depends(get_finding_store),
) -> PoCResponse:
    finding = finding_store.get(finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        artifact = poc.generate_for_finding(
            finding=finding,
            target_hint=target,
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