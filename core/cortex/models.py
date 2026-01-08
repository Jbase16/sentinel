from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any, Tuple

class AnalysisCaps(BaseModel):
    max_paths: int = Field(default=5, description="Maximum number of paths to return")
    timeout_seconds: float = Field(default=5.0, description="Hard timeout for analysis")
    approximation_threshold: int = Field(default=500, description="Node count threshold for switching to approximate centrality")

class TopologyRequest(BaseModel):
    graph_data: Dict[str, Any] = Field(description="Adjacency list or node/edge list representation")
    entry_nodes: List[str] = Field(default_factory=list, description="IDs of internet-exposed nodes")
    critical_assets: List[str] = Field(default_factory=list, description="IDs of high-value targets")
    caps: AnalysisCaps = Field(default_factory=AnalysisCaps)

class PathResult(BaseModel):
    path: List[str]
    score: Tuple[float, float, float] = Field(description="(length, risk_score, bottleneck_weight)")
    metadata: Dict[str, Any] = Field(default_factory=dict)

class TopologyResponse(BaseModel):
    graph_hash: str
    computed_at: float
    centrality: Dict[str, float]
    communities: Dict[str, int] # node_id -> community_id
    critical_paths: List[PathResult]
    limits_applied: Dict[str, bool] = Field(default_factory=dict)

class InsightRequest(BaseModel):
    graph_hash: str
    target_nodes: List[str]
    insight_type: str = Field(pattern="^(bridge|critical_path|cluster_summary|high_value_target)$")
    graph_data: Dict[str, Any] = Field(description="Adjacency list or node/edge list representation")

class InsightClaim(BaseModel):
    claim: str
    evidence: List[str] = Field(description="List of Node/Edge/Finding IDs")
    confidence: float

class InsightResponse(BaseModel):
    graph_hash: str
    insights: List[InsightClaim]
