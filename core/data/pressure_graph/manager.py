"""
Integration manager for pressure graph with Sentinel stores.

Bridges issues_store and killchain_store to pressure graph.
"""

from typing import Dict, Set, Optional

from core.utils.observer import Observable, Signal
from core.data.db import Database
from core.utils.async_helpers import create_safe_task
import asyncio
import logging


logger = logging.getLogger(__name__)

from .models import (
    PressureNode,
    PressureEdge,
    Remediation,
    EdgeType,
    PressureSource,
    RemediationState
)
from .propagator import PressurePropagator
from .counterfactual import CounterfactualEngine
from .min_fix_set import MinimalFixSetEngine
from .explanation import CausalExplainer
from core.cortex.events import get_event_bus, GraphEventType, GraphEvent
# ... imports continue ...


# Import Sentinel stores (will be available at runtime)
try:
    from core.data.issues_store import issues_store
    from core.data.killchain_store import killchain_store
except ImportError:
    # Fallback for testing
    issues_store = None
    killchain_store = None

class PressureGraphManager(Observable):
    """
    Main manager for pressure graph integration.
    
    Bridges Sentinel's existing stores to the pressure graph,
    exposing high-level decision-making APIs.
    """
    
    graph_updated = Signal()
    
    def __init__(self, session_id: str, issues_store=None, killchain_store=None, findings_store=None):
        """
        Initialize pressure graph manager.
        
        Args:
            session_id: Sentinel session ID
            issues_store: Optional specific issues store to watch
            killchain_store: Optional specific killchain store to watch
            findings_store: Optional specific findings store to watch
        """
        super().__init__()
        self.session_id = session_id
        self.db = Database.instance()
        
        self._issues_store = issues_store
        self._killchain_store = killchain_store
        self._findings_store = findings_store
        
        # Graph data
        self.nodes: Dict[str, PressureNode] = {}
        self.edges: Dict[str, PressureEdge] = {}
        
        # Sub-engines
        self.propagator: Optional[PressurePropagator] = None
        self.counterfactual: Optional[CounterfactualEngine] = None
        self.min_fix_set: Optional[MinimalFixSetEngine] = None
        self.explainer: Optional[CausalExplainer] = None
        
        # State
        self.crown_jewel_ids: Set[str] = set()
        self.baseline_pressures: Dict[str, float] = {}
        
        # Connect to store signals
        self._connect_stores()
        
        # Initialize engines on first data
        self._engines_initialized = False

        # Attempt to load persistent state if loop exists
        try:
            asyncio.get_running_loop()
            create_safe_task(self._load_state(), name="graph_load_state")
        except RuntimeError:
            pass
    
    async def _load_state(self):
        """Load graph state from DB."""
        if not self.session_id:
            return
            
        nodes_data, edges_data = await self.db.load_graph_snapshot(self.session_id)
        if not nodes_data and not edges_data:
            return
            
        # Reconstruct nodes
        for n in nodes_data:
            node = PressureNode(
                id=n["id"],
                type=n["type"],
                revision=n["data"].get("revision", 1),
                severity=n["data"].get("severity", 1.0),
                exposure=n["data"].get("exposure", 0.5),
                exploitability=n["data"].get("exploitability", 0.5),
                privilege_gain=n["data"].get("privilege_gain", 0.3),
                asset_value=n["data"].get("asset_value", 5.0),
                tool_reliability=n["data"].get("tool_reliability", 1.0),
                evidence_quality=n["data"].get("evidence_quality", 0.8),
                corroboration_count=n["data"].get("corroboration_count", 0),
                pressure_source=PressureSource(n["data"].get("pressure_source", "engine")),
                remediation_state=RemediationState(n["data"].get("remediation_state", "none")),
                mass=n["data"].get("mass", 1.0),
                charge=n["data"].get("charge", 0.0),
                temperature=n["data"].get("temperature", 0.0),
                structural=n["data"].get("structural", False)
            )
            self.nodes[node.id] = node
            
        # Reconstruct edges
        for e in edges_data:
            edge = PressureEdge(
                id=e["id"],
                source_id=e["source"],
                target_id=e["target"],
                type=EdgeType(e["type"]),
                transfer_factor=e.get("weight", 0.8),
                confidence=e["data"].get("confidence", 0.8),
                evidence_sources=e["data"].get("evidence_sources", []),
                created_at=e["data"].get("created_at", 0.0)
            )
            self.edges[edge.id] = edge
            
        if self.nodes or self.edges:
            self._initialize_engines()
            self.graph_updated.emit()
            logger.info(f"[GraphManager] Loaded {len(self.nodes)} nodes, {len(self.edges)} edges from DB.")

    async def save_snapshot(self):
        """Persist current graph state to DB."""
        if not self.session_id:
            return

        nodes_data = [
            {
                "id": n.id,
                "type": n.type,
                "label": f"{n.type}:{n.id}",
                "data": {
                    "severity": n.severity,
                    "exposure": n.exposure,
                    "exploitability": n.exploitability,
                    "privilege_gain": n.privilege_gain,
                    "asset_value": n.asset_value,
                    "tool_reliability": n.tool_reliability,
                    "evidence_quality": n.evidence_quality,
                    "corroboration_count": n.corroboration_count,
                    "pressure_source": n.pressure_source.value,
                    "remediation_state": n.remediation_state.value,
                    "revision": n.revision,
                    "mass": n.mass,
                    "charge": n.charge,
                    "temperature": n.temperature,
                    "structural": n.structural
                }
            }
            for n in self.nodes.values()
        ]
        
        edges_data = [
            {
                "id": e.id,
                "source": e.source_id,
                "target": e.target_id,
                "type": e.type.value,
                "weight": e.transfer_factor,
                "data": {
                    "confidence": e.confidence,
                    "evidence_sources": e.evidence_sources,
                    "created_at": e.created_at
                }
            }
            for e in self.edges.values()
        ]
        
        await self.db.save_graph_snapshot(self.session_id, nodes_data, edges_data)

    def to_dict(self) -> dict:
        """Return graph state as DTO-compatible dict."""
        return {
            "session_id": self.session_id,
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "label": f"{n.type}:{n.id}",
                    "data": {
                        "severity": n.severity,
                        "exposure": n.exposure,
                        "exploitability": n.exploitability,
                        "privilege_gain": n.privilege_gain,
                        "asset_value": n.asset_value,
                        "tool_reliability": n.tool_reliability,
                        "evidence_quality": n.evidence_quality,
                        "corroboration_count": n.corroboration_count,
                        "pressure_source": n.pressure_source.value,
                        "remediation_state": n.remediation_state.value,
                        "revision": n.revision,
                        "mass": n.mass,
                        "charge": n.charge,
                        "temperature": n.temperature,
                        "structural": n.structural
                    }
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.type.value,
                    "weight": e.transfer_factor,
                    "data": {
                        "confidence": e.confidence,
                        "evidence_sources": e.evidence_sources,
                        "created_at": e.created_at
                    }
                }
                for e in self.edges.values()
            ],
            "count": {
                "nodes": len(self.nodes),
                "edges": len(self.edges)
            }
        }


    
    def _connect_stores(self):
        """Connect to Sentinel store change signals."""
        # Issues Store
        store = self._issues_store if self._issues_store else issues_store
        if store and hasattr(store, 'issues_changed'):
            store.issues_changed.connect(self._on_issues_changed)
        
        # Killchain Store
        k_store = self._killchain_store if self._killchain_store else killchain_store
        if k_store and hasattr(k_store, 'edges_changed'):
            k_store.edges_changed.connect(self._on_killchain_changed)
    
        # Findings Store
        f_store = self._findings_store if self._findings_store else None
        # Note: we don't default to global findings_store to avoid noise from raw tools
        if f_store and hasattr(f_store, 'findings_changed'):
            f_store.findings_changed.connect(self._on_findings_changed)
            
        # Wire EventBus for Physics (Friction/Dynamics)
        try:
            get_event_bus().subscribe(self._on_event)
        except Exception:
            pass
            
    def _initialize_engines(self):
        """Initialize sub-engines when graph has data."""
        if self._engines_initialized:
            return
        
        if not self.nodes or not self.edges:
            return
        
        self.propagator = PressurePropagator(self.nodes, self.edges)
        self.counterfactual = CounterfactualEngine(
            self.nodes,
            self.edges,
            self.propagator
        )
        self.min_fix_set = MinimalFixSetEngine(
            self.nodes,
            self.edges,
            self.propagator
        )
        self.explainer = CausalExplainer(
            self.nodes,
            # We need to build the reverse adjacency list for explainer
            # Optimization: pass edges list, let explainer build index
            self._build_reverse_edges()
        )
        
        self._engines_initialized = True
        
    def _build_reverse_edges(self) -> Dict[str, list]:
        """Build target -> [incoming edges] map."""
        reverse = {}
        for edge in self.edges.values():
            reverse.setdefault(edge.target_id, []).append(edge)
        return reverse
    
    def _on_issues_changed(self):
        """
        Handle new issues from issues_store.
        Converts issues to pressure nodes.
        """
        if not issues_store:
            return
        
        # Get all issues
        try:
            issues = issues_store.get_all()
        except Exception:
            # Store might not be fully initialized
            return
        
        # Convert issues to pressure nodes
        for issue in issues:
            node = self._issue_to_pressure_node(issue)
            self.nodes[node.id] = node
        
        # Re-initialize engines if needed
        self._initialize_engines()
        
        # Recompute if crown jewels are set
        if self.crown_jewel_ids:
            self.recompute_pressure()
        
        self.graph_updated.emit()
    
    def _on_killchain_changed(self):
        """
        Handle new killchain edges from killchain_store.
        Converts killchain edges to pressure edges.
        """
        if not killchain_store:
            return
        
        # Get all edges
        try:
            edges = killchain_store.get_all()
        except Exception:
            # Store might not be fully initialized
            return
        
        # Convert edges to pressure edges
        for edge in edges:
            pressure_edge = self._killchain_to_pressure_edge(edge)
            self.edges[pressure_edge.id] = pressure_edge
        
        # Re-initialize engines if needed
        self._initialize_engines()
        
        # Recompute if crown jewels are set
        if self.crown_jewel_ids:
            self.recompute_pressure()
        
        self.graph_updated.emit()
    
        self.graph_updated.emit()
        
    def _on_findings_changed(self):
        """
        Handle new findings from findings_store.
        Converts findings to pressure nodes (treating them as potential issues).
        """
        store = self._findings_store
        if not store:
            return
            
        try:
            findings = store.get_all()
        except Exception:
            return
            
        for finding in findings:
            # Reusing issue conversion logic as structure is compatible
            node = self._issue_to_pressure_node(finding)
            self.nodes[node.id] = node
            
        self._initialize_engines()
        
        if self.crown_jewel_ids:
            self.recompute_pressure()
        else:
            # Always persist structure even if no pressure computed
            create_safe_task(self.save_snapshot(), name="graph_snapshot_findings")
            
        self.graph_updated.emit()
        
    def ingest_findings(self, findings: list[dict]):
        """
        Manually ingest a list of findings (e.g. from HTTP hydrator).
        """
        for finding in findings:
            node = self._issue_to_pressure_node(finding)
            self.nodes[node.id] = node
            
        self._initialize_engines()
        
        if self.crown_jewel_ids:
            self.recompute_pressure()
        else:
            create_safe_task(self.save_snapshot(), name="graph_snapshot_ingested")
            
        self.graph_updated.emit()
    
    def _on_event(self, event: GraphEvent):
        """
        Handle real-time events for physics effects.
        
        Currently handles:
        - TOOL_COMPLETED (Error) -> Friction Node
        - SCAN_FAILED -> Catastrophic Friction
        """
        payload = event.payload
        if payload.get("session_id") != self.session_id:
            return
            
        if event.type == GraphEventType.TOOL_COMPLETED:
            if payload.get("exit_code", 0) != 0:
                self._create_friction_node(
                    tool=payload.get("tool", "unknown"),
                    # Target usually in payload or we infer from context
                    target=payload.get("target") or "unknown_target"
                )
        
        elif event.type == GraphEventType.SCAN_FAILED:
            self._create_friction_node(
                tool="scanner_engine",
                target=payload.get("target", "system"),
                is_catastrophic=True
            )

    def _create_friction_node(self, tool: str, target: str, is_catastrophic: bool = False):
        """
        Materialize a failure as a physical object in the graph.
        
        Physics:
        - High Temperature (Vibration)
        - High Mass (Drag)
        - Connected via High Tension edge to Target
        """
        # Node ID unique to this failure instance
        import time
        node_id = f"friction_{tool}_{int(time.time()*1000)}"
        
        mass = 50.0 if is_catastrophic else 10.0
        temp = 1.0 # Max vibration
        
        node = PressureNode(
            id=node_id,
            type="friction",
            severity=5.0, # Semantic severity
            exposure=1.0, # Visible
            exploitability=0.0,
            privilege_gain=0.0,
            asset_value=0.0,
            tool_reliability=1.0,
            evidence_quality=1.0,
            corroboration_count=0,
            pressure_source=PressureSource.ENGINE, 
            remediation_state=RemediationState.NONE,
            revision=1,
            mass=mass,
            charge=0.0,
            temperature=temp,
            structural=False
        )
        self.nodes[node_id] = node
        
        # Link to target (Gravity Well)
        # We need to find the node ID for the target.
        # Simple heuristic: exact match or find asset node.
        # If target node not found, attached to "unknown" anchor?
        target_id = None
        for nid, n in self.nodes.items():
            if n.type == 'asset' or n.id == target:
                target_id = nid
                break
        
        if target_id:
            edge_id = f"tension_{node_id}_{target_id}"
            edge = PressureEdge(
                id=edge_id,
                source_id=target_id, # Anchor pulls on friction
                target_id=node_id,
                type=EdgeType.REQUIRES, # "Drag" relationship
                transfer_factor=1.0,
                confidence=1.0,
                evidence_sources=["physics_engine"],
                created_at=time.time()
            )
            self.edges[edge_id] = edge
            
        create_safe_task(self.save_snapshot(), name="graph_snapshot_friction")
        self.graph_updated.emit()
    
    def _issue_to_pressure_node(self, issue: dict) -> PressureNode:
        """
        Convert issue/finding to pressure node.
        
        Mapping:
        - severity → severity (0-10)
        - type → node type
        - proof/trust → confidence factors
        - target → determines exposure
        """
        # Map severity
        severity_map = {
            "CRITICAL": 10.0,
            "HIGH": 7.0,
            "MEDIUM": 5.0,
            "LOW": 3.0,
            "INFO": 1.0
        }
        
        severity_str = str(issue.get("severity", "INFO")).upper()
        severity = severity_map.get(severity_str, 1.0)
        
        # Determine node type
        issue_type = issue.get("type", "unknown")
        if issue_type in ["open_port", "exposed_service"]:
            node_type = "exposure"
        elif issue_type == "vulnerability":
            node_type = "vulnerability"
        elif issue_type in ["weak_auth", "credential_leak", "identity_issue"]:
            node_type = "identity_issue"
        elif issue_type in ["trust_relationship", "excessive_trust"]:
            node_type = "trust"
        else:
            node_type = "asset"
        
        # Exposure: how accessible?
        exposure = 0.5  # Default
        if issue_type == "open_port":
            exposure = 0.9  # Highly accessible
        elif "internal" in str(issue.get("target", "")).lower():
            exposure = 0.3  # Less accessible
        
        # Exploitability: from CVSS if available
        cvss_data = issue.get("cvss", {})
        if isinstance(cvss_data, dict):
            exploitability = cvss_data.get("exploitability", 5.0) / 10.0
        else:
            exploitability = 0.5
        
        # Privilege gain: what access does this provide?
        privilege_gain = 0.3  # Default
        proof = str(issue.get("proof", "")).lower()
        if "root" in proof or "admin" in proof:
            privilege_gain = 1.0
        elif "user" in proof or "account" in proof:
            privilege_gain = 0.5
        
        # Asset value: default to medium
        asset_value = 5.0

        # Calculate Mass/Charge/Temp based on semantics
        mass = 1.0
        charge = 0.0
        temperature = 0.0
        structural = False
        
        if severity >= 9.0: # Critical
            mass = 50.0
        elif severity >= 7.0: # High
            mass = 25.0
        elif severity >= 5.0: # Medium
            mass = 10.0
        else:
            mass = 5.0
            
        if issue_type == 'asset':
            mass = 100.0  # Gravity Well
            charge = 10.0 # Slight attraction
            
        if issue_type == 'vulnerability':
            charge = -5.0 # Slight repulsion (bad thing)
            
        if issue_type == 'trust':
            structural = True
            mass = 20.0
        
        # Evidence quality and tool reliability
        evidence_quality = 0.8  # Default
        tool_reliability = 1.0  # Default
        
        # Corroboration count (from issue metadata if available)
        corroboration_count = 0
        
        # Node ID
        node_id = issue.get("id", f"issue_{hash(str(issue))}")
        
        return PressureNode(
            id=node_id,
            type=node_type,
            severity=severity,
            exposure=exposure,
            exploitability=exploitability,
            privilege_gain=privilege_gain,
            asset_value=asset_value,
            tool_reliability=tool_reliability,
            evidence_quality=evidence_quality,
            corroboration_count=corroboration_count,
            pressure_source=PressureSource.ENGINE, 
            remediation_state=RemediationState.NONE,
            revision=1,
            mass=mass,
            charge=charge,
            temperature=temperature,
            structural=structural
        )
    
    def _killchain_to_pressure_edge(self, edge: dict) -> PressureEdge:
        """
        Convert killchain edge to pressure edge.
        """
        # Map edge type
        edge_type_map = {
            "CAUSES": EdgeType.ENABLES,
            "REACHES": EdgeType.REACHES,
            "REQUIRES": EdgeType.REQUIRES,
            "AMPLIFIES": EdgeType.AMPLIFIES
        }
        
        edge_type_str = str(edge.get("edge_type", "ENABLES")).upper()
        edge_type = edge_type_map.get(edge_type_str, EdgeType.ENABLES)
        
        # Transfer factor: how much pressure propagates?
        # Default to 0.8 for causal relationships
        transfer_factor = edge.get("transfer_factor", 0.8)
        
        # Confidence: from severity/evidence
        confidence = 0.8  # Default
        severity_str = str(edge.get("severity", "HIGH")).upper()
        if severity_str == "CRITICAL":
            confidence = 0.95
        elif severity_str == "HIGH":
            confidence = 0.9
        elif severity_str == "MEDIUM":
            confidence = 0.8
        
        # Edge ID
        edge_id = edge.get("id", f"edge_{hash(str(edge))}")
        
        return PressureEdge(
            id=edge_id,
            source_id=edge["source"],
            target_id=edge["target"],
            type=edge_type,
            transfer_factor=transfer_factor,
            confidence=confidence,
            evidence_sources=[edge.get("tool", "killchain")],
            created_at=edge.get("created_at", 0.0)
        )
    
    def set_crown_jewels(self, crown_jewel_ids: Set[str]):
        """
        Mark which nodes are crown jewels (critical assets).
        
        These are the sinks in the pressure graph.
        """
        self.crown_jewel_ids = crown_jewel_ids
        self.recompute_pressure()
    
    def recompute_pressure(self):
        """
        Recompute all pressures given current graph state.
        """
        if not self.propagator:
            return
        
        self.baseline_pressures = self.propagator.propagate(self.crown_jewel_ids)
        
        if self.counterfactual:
            self.counterfactual.set_baseline(
                self.crown_jewel_ids,
                self.baseline_pressures
            )
        
        # Persist graph state
        create_safe_task(self.save_snapshot(), name="graph_save_snapshot")
        
        self.graph_updated.emit()
    
    def generate_report(self) -> dict:
        """
        Generate comprehensive pressure report.
        
        This is the main output - what changes what gets fixed first.
        """
        # Ensure engines are initialized
        self._initialize_engines()
        
        if not self.propagator:
            return {
                "error": "No graph data available"
            }
        
        # Recompute if needed
        if not self.baseline_pressures:
            self.recompute_pressure()
        
        # Compute total pressure metrics
        total_system_pressure = sum(self.baseline_pressures.values())
        total_crown_jewel_pressure = sum(
            self.baseline_pressures.get(cj_id, 0.0)
            for cj_id in self.crown_jewel_ids
        )
        
        # Find top remediations
        top_remediations = []
        if self.counterfactual:
            top_remediations = self.counterfactual.find_top_remediations(
                self.crown_jewel_ids,
                top_n=10
            )
        
        # Compute minimal fix sets
        minimal_fix_sets = []
        if self.min_fix_set:
            minimal_fix_sets = self.min_fix_set.compute_minimal_fix_sets(
                self.crown_jewel_ids,
                max_sets=5
            )
        
        # Find critical paths
        critical_paths = self.find_critical_paths(top_n=5)
        
        # Find chokepoints
        chokepoints = self.find_chokepoints()
        
        return {
            "pressure_metrics": {
                "total_system_pressure": total_system_pressure,
                "total_crown_jewel_pressure": total_crown_jewel_pressure,
                "node_count": len(self.nodes),
                "edge_count": len(self.edges)
            },
            "top_remediations": top_remediations,
            "minimal_fix_sets": minimal_fix_sets,
            "critical_paths": critical_paths,
            "chokepoints": chokepoints,
            "baseline_pressures": self.baseline_pressures
        }
    
    def find_critical_paths(self, top_n: int = 5) -> list:
        """
        Find top N critical attack paths to crown jewels.
        
        Critical = high pressure on path, high confidence edges.
        """
        if not self.propagator:
            return []
        
        entry_points = self._find_entry_points()
        paths: list = []
        
        for entry_id in entry_points:
            path_nodes = self._find_path_to_crown_jewel(entry_id)
            if path_nodes:
                # Compute path pressure
                path_pressure = sum(
                    self.baseline_pressures.get(nid, 0.0)
                    for nid in path_nodes
                )
                
                # Compute path confidence (min edge confidence)
                path_confidence = 1.0
                for i in range(len(path_nodes) - 1):
                    edge = self._find_edge(path_nodes[i], path_nodes[i + 1])
                    if edge:
                        path_confidence = min(path_confidence, edge.confidence)
                
                paths.append({
                    "path": path_nodes,
                    "pressure": path_pressure,
                    "confidence": path_confidence,
                    "length": len(path_nodes)
                })
        
        # Sort by pressure (descending), then confidence (descending)
        paths.sort(
            key=lambda p: (p["pressure"], p["confidence"]),
            reverse=True
        )
        
        return paths[:top_n]
    
    def find_chokepoints(self) -> list:
        """
        Find chokepoints - nodes/edges whose removal maximally reduces crown-jewel pressure.
        
        These are high-value targets for remediation.
        """
        if not self.counterfactual or not self.propagator:
            return []
        
        chokepoints: list = []
        
        # Evaluate each node as a potential chokepoint
        for node_id, node in self.nodes.items():
            if node_id in self.crown_jewel_ids:
                continue
            
            # Simulate removing this node
            remediation = Remediation(
                id=f"remove_{node_id}",
                name=f"Remove {node.type} {node_id}",
                nodes_to_remove={node_id}
            )
            
            deltas = self.counterfactual.compute_deltas(remediation)
            
            delta_cj_pressure = sum(
                deltas.get(cj_id, 0.0)
                for cj_id in self.crown_jewel_ids
            )
            
            chokepoints.append({
                "node_id": node_id,
                "node_type": node.type,
                "delta_crown_jewel_pressure": delta_cj_pressure,
                "delta_system_pressure": sum(deltas.values())
            })
        
        # Sort by crown-jewel pressure reduction (descending)
        chokepoints.sort(
            key=lambda c: c["delta_crown_jewel_pressure"],
            reverse=True
        )
        
        return chokepoints[:10]
    
    def _find_path_to_crown_jewel(self, node_id: str) -> list:
        """
        DFS to find path from node to any crown jewel.
        """
        if node_id in self.crown_jewel_ids:
            return [node_id]
        
        visited = set()
        return self._find_path_dfs(node_id, visited)
    
    def _find_path_dfs(self, node_id: str, visited: set) -> list | None:
        """Recursive DFS helper."""
        if node_id in self.crown_jewel_ids:
            return [node_id]
        
        if node_id in visited:
            return None
        
        visited.add(node_id)
        
        # Sort outbound edges by transfer factor
        outbound = self.propagator.get_outbound_edges(node_id)
        outbound.sort(key=lambda e: e.transfer_factor, reverse=True)
        
        for edge in outbound:
            path = self._find_path_dfs(edge.target_id, visited)
            if path:
                return [node_id] + path
        
        visited.remove(node_id)
        return None
    
    def _find_edge(self, source_id: str, target_id: str) -> PressureEdge | None:
        """Find edge between two nodes."""
        for edge in self.edges.values():
            if edge.source_id == source_id and edge.target_id == target_id:
                return edge
        return None
    
    def _find_entry_points(self) -> list:
        """
        Find entry points (nodes with no inbound edges).
        """
        all_node_ids = set(self.nodes.keys())
        nodes_with_inbound = set()
        
        for edge in self.edges.values():
            nodes_with_inbound.add(edge.target_id)
        
        entry_points = list(all_node_ids - nodes_with_inbound)
        return entry_points

    def increase_pressure(self, node_id: str, amount: float, reason: str) -> None:
        """
        Directly increase pressure on a node (e.g., from Fuzzing Feedback).
        """
        if node_id not in self.nodes:
            logger.info(f"PressureGraph: Auto-creating missing node {node_id} from feedback.")
            # Heuristic: If it starts with service:, it's a Component.
            if node_id.startswith("service:"):
                 # Use PressureNode directly as ComponentNode doesn't exist yet/here
                 from core.data.pressure_graph.models import PressureNode, PressureSource, RemediationState
                 # Quick hack to get a valid node
                 self.nodes[node_id] = PressureNode(
                     id=node_id, 
                     type="service", # Generic type
                     severity=5.0,
                     exposure=0.5,
                     exploitability=0.5,
                     privilege_gain=0.1,
                     asset_value=5.0,
                     tool_reliability=1.0,
                     evidence_quality=1.0,
                     corroboration_count=0,
                     pressure_source=PressureSource.ENGINE, 
                     remediation_state=RemediationState.NONE,
                     revision=1
                 )
            else:
                 logger.warning(f"Feedback: Cannot increase pressure on unknown node {node_id} (and cannot auto-create).")
                 return
            
        node = self.nodes[node_id]
        
        # Amount from feedback is typically High (e.g. 9.0 * 10.0 = 90.0)
        # We normalize this into the node properties.
        
        # 1. Bump Exploitability (0-1)
        # A breach proves it is exploitable.
        old_exploitability = node.exploitability
        new_exploitability = min(1.0, old_exploitability + 0.2) # Increment by 20%
        
        # 2. Bump Severity (1-10)
        # Only if the observed severity is higher than what we thought
        # Note: Feedback 'amount' passed in is usually severity * policy_multiplier (e.g. 9.0 * 10 = 90)
        # So we infer observed severity from it.
        observed_severity = amount / 10.0 # Reverse default policy
        new_severity = max(node.severity, min(10.0, observed_severity))
        
        # Update Node
        # PressureNode is distinct (using dataclass replace or manual update)
        # Since it's a frozen dataclass maybe? No, checking definition... 
        # Wait, if PressureNode is frozen/immutable, we must replace it.
        # Assuming typical dataclass behavior or mutable.
        # Checking implementation: If it's frozen, we use 'replace'.
        from dataclasses import replace
        
        try:
            self.nodes[node_id] = replace(
                node, 
                exploitability=new_exploitability,
                severity=new_severity
            )
            logger.info(f"Feedback Applied: {node_id} Exploitability {old_exploitability}->{new_exploitability:.2f}, Severity {node.severity}->{new_severity:.2f}")
            
            # Persist and Notify
            self.recompute_pressure()
            
        except Exception as e:
            logger.error(f"Failed to update node {node_id}: {e}")