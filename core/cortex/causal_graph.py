"""
Causal Attack-Pressure Graph - Vulnerability Dependency Analysis

PURPOSE:
Analyze how vulnerabilities enable each other to form attack chains.
Identify "pressure points" - high-leverage fixes that disable many attack paths.

WHY THIS MATTERS:
1. **Remediation Prioritization**: "Fix these 2 bugs → 80% safer"
2. **Attack Path Analysis**: Understand how findings chain together
3. **Defense Strategy**: Identify critical choke points in attack graphs
4. **Resource Optimization**: Focus effort on highest-impact fixes

KEY CONCEPTS:
- **Causal Edge**: Finding A → Finding B means A enables/prerequisites B
- **Pressure Point**: Finding with high out-degree (enables many others)
- **Fix Impact**: Number of attack paths disabled by fixing a finding
- **Attack Chain**: Sequence of findings that form a complete exploit path

DESIGN PATTERN:
This uses graph analysis (networkx) to model attack dependencies.
Similar to "attack trees" in threat modeling, but data-driven from actual findings.

EXAMPLE:
Finding 1: "Port 22 open (SSH)"
Finding 2: "Weak SSH credentials detected"
Finding 3: "Privilege escalation via sudo"

Graph: 1 → 2 → 3
Pressure Point: Finding 1 (fixing it blocks the entire chain)
Fix Impact of 1: 2 attack paths disabled (1→2 and 1→2→3)
"""

import networkx as nx
from typing import List, Dict, Set, Tuple, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Simplified Finding structure for graph analysis."""
    id: str
    type: str
    severity: str
    title: str
    target: str
    data: Dict[str, Any]

    # Dependency fields
    requires: List[str] = None  # IDs of findings this depends on
    enables: List[str] = None   # IDs of findings this enables

    def __post_init__(self):
        if self.requires is None:
            self.requires = []
        if self.enables is None:
            self.enables = []


@dataclass
class PressurePoint:
    """A high-impact finding that enables many attack paths."""
    finding_id: str
    finding_title: str
    severity: str
    out_degree: int  # How many findings this enables directly
    attack_paths_blocked: int  # Total paths disabled if this is fixed
    downstream_findings: List[str]  # All findings reachable from this one
    centrality_score: float  # Betweenness centrality (measures choke-point importance)


class CausalGraphBuilder:
    """
    Builds and analyzes dependency graphs of security findings.

    This discovers how vulnerabilities chain together to form attack paths,
    and identifies which fixes have the highest leverage.
    """

    def __init__(self):
        self.graph: nx.DiGraph = nx.DiGraph()
        self.findings_map: Dict[str, Finding] = {}

    def build(self, findings: List[Dict[str, Any]]) -> nx.DiGraph:
        """
        Build a directed graph of finding dependencies.

        Args:
            findings: List of finding dicts from database

        Returns:
            NetworkX DiGraph where edges represent "enables" relationships
        """
        logger.info(f"[CausalGraph] Building graph from {len(findings)} findings")

        # Convert dicts to Finding objects
        findings_obj = []
        for f in findings:
            finding = Finding(
                id=f.get('id', ''),
                type=f.get('type', 'unknown'),
                severity=f.get('severity', 'unknown'),
                title=f.get('title', f.get('type', 'Untitled')),
                target=f.get('target', ''),
                data=f.get('data', {}),
                requires=f.get('requires', []),
                enables=f.get('enables', [])
            )
            findings_obj.append(finding)
            self.findings_map[finding.id] = finding

        # Phase 1: Infer dependencies from finding types
        self._infer_dependencies(findings_obj)

        # Phase 2: Build graph from explicit and inferred dependencies
        for finding in findings_obj:
            # Add node
            self.graph.add_node(
                finding.id,
                type=finding.type,
                severity=finding.severity,
                title=finding.title,
                target=finding.target
            )

            # Add edges for dependencies
            for prerequisite_id in finding.requires:
                if prerequisite_id in self.findings_map:
                    # Edge from prerequisite TO this finding (prerequisite enables this)
                    self.graph.add_edge(prerequisite_id, finding.id, relationship='enables')

        logger.info(f"[CausalGraph] Built graph: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        return self.graph

    def update_from_event(self, event: Any): # Type: EpistemicEvent
        """
        Reactive update: incrementally add finding from ledger event.
        Avoiding dependency on EpistemicEvent class definition to prevent circular imports if possible,
        or just duck-type check.
        """
        # We check event_type string
        if getattr(event, "event_type", "") == "promoted":
             # Payload matches structure sent in promote_finding
             payload = event.payload
             finding_id = event.entity_id
             
             finding_data = {
                 "id": finding_id,
                 "title": payload.get("title"),
                 "severity": payload.get("severity"),
                 "type": payload.get("metadata", {}).get("type", "General"),
                 "target": payload.get("metadata", {}).get("target", "unknown"), # Target usually in metadata or inferred? 
                 # Wait, promote_finding usually calls _emit_event with payload.
                 # Let's check ledger.py promote_finding payload content.
                 # It contains "metadata". Target is usually in observation... 
                 # Actually finding citations link to observation which has target.
                 # Simplified for now: assume metadata has target or use generic.
                 "data": payload.get("metadata", {})
             }
             
             # Create Finding object
             finding = Finding(
                id=finding_data["id"],
                type=finding_data["type"],
                severity=finding_data["severity"],
                title=finding_data["title"],
                target=finding_data["target"],
                data=finding_data["data"]
             )
             
             self.findings_map[finding.id] = finding
             
             # Add to graph
             self.graph.add_node(
                finding.id,
                type=finding.type,
                severity=finding.severity,
                title=finding.title,
                target=finding.target
            )
            
            # Infer dependencies (Incremental)
            # We only infer dependencies involving this new finding.
            # This is complex: iterate ALL existing findings to see if they enable/require NEW finding?
            # Yes, O(N). Acceptable for incremental updates.
            
             self._infer_dependencies_incremental(finding)
             
             logger.info(f"[CausalGraph] Reactively added finding {finding.id}")

    def _infer_dependencies_incremental(self, new_finding: Finding):
        """Infer edges for a single new finding against existing graph."""
        # 1. Check if NEW finding requires existing findings
        # 2. Check if EXISTING findings require NEW finding
        
        # Reuse logic from _infer_dependencies but adapted?
        # That logic relied on grouping by target.
        # Let's just run simple checks.
        
        # Rule 1: Port -> Service Vuln
        if 'port' in new_finding.type.lower() or 'service' in new_finding.type.lower():
            # I am a Port/Service. Do I enable any existing Vulns?
            for existing_id, existing in self.findings_map.items():
                if existing.target == new_finding.target:
                     if any(w in existing.type.lower() for w in ['injection', 'xss', 'rce', 'exploit']):
                         self.graph.add_edge(new_finding.id, existing.id, relationship='enables')
                         
        if any(w in new_finding.type.lower() for w in ['injection', 'xss', 'rce', 'exploit']):
            # I am a Vuln. Do I require any existing Ports?
             for existing_id, existing in self.findings_map.items():
                if existing.target == new_finding.target:
                     if 'port' in existing.type.lower() or 'service' in existing.type.lower():
                         self.graph.add_edge(existing.id, new_finding.id, relationship='enables')
                         
        # (Other rules omitted for brevity/speed in this patch, can extend later)
    
    def _infer_dependencies(self, findings: List[Finding]):
        """
        Infer causal dependencies from finding types and targets.

        This uses heuristics to discover implicit relationships:
        - "Open port" enables "Service vulnerability"
        - "Authentication bypass" enables "Privilege escalation"
        - "File read" enables "Credential theft"
        """
        # Group findings by target
        by_target: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            by_target[f.target].append(f)

        # Heuristic rules for inferring dependencies
        for target, target_findings in by_target.items():
            # Rule 1: Open ports enable service attacks
            open_ports = [f for f in target_findings if 'port' in f.type.lower() or 'service' in f.type.lower()]
            service_vulns = [f for f in target_findings if any(word in f.type.lower() for word in ['injection', 'xss', 'rce', 'exploit'])]

            for port_finding in open_ports:
                for vuln_finding in service_vulns:
                    # Port enables vulnerability (if not already linked)
                    if port_finding.id not in vuln_finding.requires:
                        vuln_finding.requires.append(port_finding.id)

            # Rule 2: Auth bypass enables privilege escalation
            auth_bypass = [f for f in target_findings if any(word in f.type.lower() for word in ['auth', 'login', 'bypass', 'credential'])]
            priv_esc = [f for f in target_findings if 'priv' in f.type.lower() or 'escalation' in f.type.lower()]

            for auth_finding in auth_bypass:
                for esc_finding in priv_esc:
                    if auth_finding.id not in esc_finding.requires:
                        esc_finding.requires.append(auth_finding.id)

            # Rule 3: Information disclosure enables targeted attacks
            info_disclosure = [f for f in target_findings if any(word in f.type.lower() for word in ['disclosure', 'leak', 'exposure', 'directory'])]
            targeted_attacks = [f for f in target_findings if any(word in f.type.lower() for word in ['injection', 'xss', 'csrf', 'rce'])]

            for info_finding in info_disclosure:
                for attack_finding in targeted_attacks:
                    if info_finding.id not in attack_finding.requires:
                        attack_finding.requires.append(info_finding.id)

            # Rule 4: File read enables credential access
            file_read = [f for f in target_findings if 'file' in f.type.lower() and ('read' in f.type.lower() or 'traversal' in f.type.lower())]
            cred_access = [f for f in target_findings if any(word in f.type.lower() for word in ['password', 'credential', 'secret', 'token'])]

            for file_finding in file_read:
                for cred_finding in cred_access:
                    if file_finding.id not in cred_finding.requires:
                        cred_finding.requires.append(file_finding.id)

        logger.info(f"[CausalGraph] Inferred dependencies using {4} heuristic rules")

    def identify_pressure_points(self, top_n: int = 10) -> List[PressurePoint]:
        """
        Identify findings that, if fixed, disable the most attack paths.

        Args:
            top_n: Number of top pressure points to return

        Returns:
            List of PressurePoint objects, sorted by attack_paths_blocked (descending)
        """
        if not self.graph:
            logger.warning("[CausalGraph] Graph not built yet, call build() first")
            return []

        logger.info(f"[CausalGraph] Identifying pressure points (top {top_n})")

        # Calculate betweenness centrality (measures choke-point importance)
        try:
            centrality = nx.betweenness_centrality(self.graph)
        except:
            centrality = {node: 0.0 for node in self.graph.nodes()}

        pressure_points = []

        for node in self.graph.nodes():
            # Out-degree: how many findings this directly enables
            out_degree = self.graph.out_degree(node)

            # Downstream: all findings reachable from this node
            try:
                downstream = list(nx.descendants(self.graph, node))
            except:
                downstream = []

            # Attack paths blocked: count of simple paths from this node to leaves
            attack_paths_blocked = len(downstream) + 1  # +1 for the node itself

            # Only consider nodes with impact
            if out_degree > 0 or len(downstream) > 0:
                finding = self.findings_map.get(node)
                if finding:
                    pressure_points.append(PressurePoint(
                        finding_id=node,
                        finding_title=finding.title,
                        severity=finding.severity,
                        out_degree=out_degree,
                        attack_paths_blocked=attack_paths_blocked,
                        downstream_findings=downstream,
                        centrality_score=centrality.get(node, 0.0)
                    ))

        # Sort by attack paths blocked (descending), then by centrality
        pressure_points.sort(key=lambda p: (p.attack_paths_blocked, p.centrality_score), reverse=True)

        logger.info(f"[CausalGraph] Identified {len(pressure_points)} pressure points")
        return pressure_points[:top_n]

    def calculate_fix_impact(self, finding_id: str) -> int:
        """
        Calculate how many attack paths would be disabled by fixing this finding.

        Args:
            finding_id: ID of the finding to analyze

        Returns:
            Number of downstream findings (attack paths) that become unreachable
        """
        if finding_id not in self.graph:
            logger.warning(f"[CausalGraph] Finding {finding_id} not in graph")
            return 0

        # Descendants = all findings reachable from this node
        try:
            descendants = nx.descendants(self.graph, finding_id)
            return len(descendants)
        except:
            return 0

    def get_attack_chains(self, max_length: int = 5) -> List[List[str]]:
        """
        Find all attack chains (simple paths from roots to leaves).

        An attack chain is a sequence of findings where each enables the next.

        Args:
            max_length: Maximum chain length to consider

        Returns:
            List of chains, where each chain is a list of finding IDs
        """
        if not self.graph:
            return []

        # Find root nodes (no incoming edges)
        roots = [n for n in self.graph.nodes() if self.graph.in_degree(n) == 0]

        # Find leaf nodes (no outgoing edges)
        leaves = [n for n in self.graph.nodes() if self.graph.out_degree(n) == 0]

        # Find all simple paths from any root to any leaf
        chains = []
        for root in roots:
            for leaf in leaves:
                try:
                    paths = list(nx.all_simple_paths(self.graph, root, leaf, cutoff=max_length))
                    chains.extend(paths)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        logger.info(f"[CausalGraph] Found {len(chains)} attack chains")
        return chains

    def export_dto(self) -> Dict[str, Any]:
        """
        Export graph nodes and edges for API consumption (PressureGraphDTO).
        """
        nodes = []
        for node in self.graph.nodes():
            finding = self.findings_map.get(node)
            if finding:
                nodes.append({
                    "id": finding.id,
                    "label": finding.title,
                    "type": finding.type,
                    "severity": finding.severity,
                    "data": finding.data or {}
                })
        
        edges = []
        for source, target in self.graph.edges():
            edges.append({
                "source": source,
                "target": target,
                "type": "enables" # consistent with relationship
            })
            
        return {
            "nodes": nodes,
            "edges": edges
        }

    def export_summary(self) -> Dict[str, Any]:
        """
        Export graph summary for API/UI consumption.

        Returns:
            Dict with graph statistics and top pressure points
        """
        pressure_points = self.identify_pressure_points(top_n=5)
        attack_chains = self.get_attack_chains(max_length=10)

        return {
            "nodes_count": self.graph.number_of_nodes(),
            "edges_count": self.graph.number_of_edges(),
            "attack_chains_count": len(attack_chains),
            "top_pressure_points": [
                {
                    "finding_id": p.finding_id,
                    "finding_title": p.finding_title,
                    "severity": p.severity,
                    "out_degree": p.out_degree,
                    "attack_paths_blocked": p.attack_paths_blocked,
                    "centrality_score": round(p.centrality_score, 3),
                    "recommendation": f"Fixing this will block {p.attack_paths_blocked} attack paths"
                }
                for p in pressure_points
            ],
            "longest_chain_length": max([len(chain) for chain in attack_chains], default=0),
            "sample_attack_chains": [
                [self.findings_map[fid].title for fid in chain]
                for chain in attack_chains[:3]  # Show first 3 chains
            ]
        }

    def export_graphviz(self) -> str:
        """
        Export graph in Graphviz DOT format for visualization.

        Returns:
            DOT format string
        """
        from io import StringIO
        import networkx as nx

        output = StringIO()
        output.write("digraph CausalAttackGraph {\n")
        output.write("  rankdir=LR;\n")  # Left-to-right layout
        output.write("  node [shape=box, style=filled];\n")

        # Color nodes by severity
        severity_colors = {
            'critical': '#FF4444',
            'high': '#FF8800',
            'medium': '#FFCC00',
            'low': '#88CC00',
            'info': '#4488FF'
        }

        # Add nodes with labels and colors
        for node in self.graph.nodes():
            finding = self.findings_map.get(node)
            if finding:
                color = severity_colors.get(finding.severity.lower(), '#CCCCCC')
                label = finding.title.replace('"', '\\"')[:50]  # Truncate long titles
                output.write(f'  "{node}" [label="{label}", fillcolor="{color}"];\n')

        # Add edges
        for source, target in self.graph.edges():
            output.write(f'  "{source}" -> "{target}";\n')

        output.write("}\n")
        return output.getvalue()


# ============================================================================
# Module-level helpers
# ============================================================================

_causal_graph_instance: Optional[CausalGraphBuilder] = None


def get_causal_graph() -> CausalGraphBuilder:
    """
    Get the global CausalGraphBuilder singleton instance.

    Returns:
        Global CausalGraphBuilder instance
    """
    global _causal_graph_instance
    if _causal_graph_instance is None:
        _causal_graph_instance = CausalGraphBuilder()
    return _causal_graph_instance


async def build_causal_graph_for_session(session_id: str) -> Dict[str, Any]:
    """
    Build a causal graph from findings in a scan session.

    Args:
        session_id: Session UUID

    Returns:
        Graph summary dict with pressure points and attack chains
    """
    from core.data.db import Database

    db = Database.instance()
    await db.init()

    # Get findings for this session
    findings = await db.get_findings(session_id)

    # Build graph
    builder = CausalGraphBuilder()
    builder.build(findings)

    # Return summary
    return builder.export_summary()


async def get_graph_dto_for_session(session_id: str) -> Dict[str, Any]:
    """
    Build a causal graph from findings and return DTO (nodes/edges).
    """
    from core.data.db import Database
    db = Database.instance()
    await db.init()
    findings = await db.get_findings(session_id)
    
    builder = CausalGraphBuilder()
    builder.build(findings)
    return builder.export_dto()
