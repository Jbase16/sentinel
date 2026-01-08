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

@router.post("/analysis/insights", response_model=InsightResponse)
async def generate_insights(request: InsightRequest):
    """
    Generates semantic insights using LLM.
    Client provides the graph context in the request for stateless operation.
    """
    try:
        if not request.graph_data:
             raise HTTPException(status_code=400, detail="graph_data is required for insight generation.")
             
        response = await _insight_engine.generate_insights(request, request.graph_data)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
