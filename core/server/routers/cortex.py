from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import Dict, Any
from core.cortex.models import TopologyRequest, TopologyResponse, InsightRequest, InsightResponse
from core.cortex.graph_analyzer import GraphAnalyzer
from core.cortex.insight_engine import InsightEngine

router = APIRouter(prefix="/cortex", tags=["cortex"])

# Singletons (Global state for cache/executors)
_graph_analyzer = GraphAnalyzer()
_insight_engine = InsightEngine()

@router.post("/analysis/topology", response_model=TopologyResponse)
async def analyze_topology(request: TopologyRequest):
    """
    Performs topological analysis (Centrality, Pathfinding, Community).
    Uses caching and process pool for performance.
    """
    try:
        # Check node count for safety limits if not set in caps?
        # GraphAnalyzer handles caps.
        
        response = await _graph_analyzer.analyze(request)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@v1_router.post("/analysis/insights", response_model=InsightResponse)
async def generate_insights(
    request: InsightRequest,
    engine: InsightEngine = Depends(get_insight_engine)
) -> InsightResponse:
    """
    Generate LLM-driven insights for specific nodes in the graph.
    """
    return await engine.generate_insights(request)


# ---- Reporting Endpoints (Phase 12) ----

def get_report_composer(
    finding_store: FindingStore = Depends(get_finding_store),
    evidence_ledger: EvidenceLedger = Depends(get_evidence_ledger),
    graph_analyzer: GraphAnalyzer = Depends(get_graph_analyzer),
) -> ReportComposer:
    return ReportComposer(
        finding_store=finding_store,
        evidence_ledger=evidence_ledger,
        graph_analyzer=graph_analyzer
    )

def get_poc_generator() -> PoCGenerator:
    return PoCGenerator()

class ReportGenerateRequest(BaseModel):
    target: str = Field(..., description="Target name or root domain for report labeling")
    scope: Optional[str] = Field(None, description="Optional scope string")
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

@v1_router.post("/reporting/generate", response_model=ReportGenerateResponse)
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

@v1_router.get("/reporting/poc/{finding_id}", response_model=PoCResponse)
def get_poc(
    finding_id: str,
    target: Optional[str] = None,
    poc: PoCGenerator = Depends(get_poc_generator),
    finding_store: FindingStore = Depends(get_finding_store),
) -> PoCResponse:
    # Minimal "store adapter": try a few common getters
    finding = None
    for method_name in ("get", "get_finding", "by_id", "fetch"):
        m = getattr(finding_store, method_name, None)
        if callable(m):
            finding = m(finding_id)
            if finding:
                break

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not isinstance(finding, dict):
        # Force conversion to dict if store returns objects
        if hasattr(finding, "dict"):
             finding = finding.dict()
        elif hasattr(finding, "to_dict"):
             finding = finding.to_dict()
        else:
             # Fallback attempt
             try:
                 finding = dict(finding)
             except (ValueError, TypeError):
                 raise HTTPException(status_code=500, detail="FindingStore must return dict-compatible object for PoC generation")

    try:
        artifact = poc.generate_for_finding(finding=finding, target_hint=target)
    except PoCSafetyError as e:
        raise HTTPException(status_code=400, detail=f"PoC blocked by safety policy: {e}") from e

    return PoCResponse(
        finding_id=artifact.finding_id,
        title=artifact.title,
        risk=artifact.risk,
        safe=artifact.safe,
        commands=artifact.commands,
        notes=artifact.notes,
        created_at=artifact.created_at,
    )
