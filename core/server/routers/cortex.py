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
    # Scope the report to a specific scan session. If omitted, the most
    # recent session is used. Without this, the report read the GLOBAL
    # cross-session finding store (every finding from every scan ever) —
    # producing findings/evidence that didn't belong to the scan the
    # operator was looking at (Calibration Run #21).
    session_id: Optional[str] = Field(None)


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


async def _resolve_session_id(db, requested: Optional[str]) -> Optional[str]:
    """Explicit session_id wins; otherwise fall back to the most-recent
    session so the report describes the scan the operator just ran."""
    if requested:
        return requested
    try:
        rows = await db.fetch_all(
            "SELECT id FROM sessions ORDER BY start_time DESC LIMIT 1"
        )
        if rows:
            return rows[0][0]
    except Exception as e:  # noqa: BLE001
        logger.warning("[reporting] could not resolve latest session: %s", e)
    return None


@router.post("/reporting/generate", response_model=ReportGenerateResponse)
async def generate_report(
    req: ReportGenerateRequest,
    graph_analyzer: GraphAnalyzer = Depends(get_graph_analyzer),
) -> ReportGenerateResponse:
    from core.data.db import Database

    db = Database.instance()
    session_id = await _resolve_session_id(db, req.session_id)

    if session_id:
        # Session-scoped: pull THIS scan's findings + evidence from the DB,
        # not the global cross-session singletons. This is what makes the
        # report agree with the Target Scan tab and the Bounty report.
        findings = await db.get_findings(session_id)
        evidence = await db.get_evidence(session_id)
        composer = ReportComposer(
            finding_store=_ListStore(findings),
            evidence_ledger=_ListStore(evidence),
            graph_analyzer=graph_analyzer,
        )
        # Prefer the session's real target if the caller didn't pin one.
        session_data = await db.get_session(session_id)
        target = req.target or (session_data or {}).get("target") or "target"
    else:
        # No sessions at all — fall back to the global stores (legacy path).
        from core.data.findings_store import get_finding_store
        from core.data.evidence_store import EvidenceStore
        composer = ReportComposer(
            finding_store=get_finding_store(),
            evidence_ledger=EvidenceStore.instance(),
            graph_analyzer=graph_analyzer,
        )
        target = req.target

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


@router.get("/reporting/poc/{finding_id}", response_model=PoCResponse)
async def get_poc(
    finding_id: str,
    target: Optional[str] = None,
    poc: PoCGenerator = Depends(get_poc_generator),
    finding_store=Depends(get_finding_store),
) -> PoCResponse:
    # 1. Try in-memory store (populated during active scans)
    finding = finding_store.get(finding_id)

    # 2. Fall back to DB — handles restarts and cross-session PoC generation
    if not finding:
        from core.data.db import Database
        db = Database.instance()
        all_findings = await db.get_findings()
        for f in all_findings:
            if str(f.get("id")) == str(finding_id):
                finding = f
                break

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