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
import asyncio
import json
from typing import List, Dict, Set, Tuple, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import logging
import time
from enum import Enum
from urllib.parse import urlparse
import hashlib
import copy

logger = logging.getLogger(__name__)


class EnablementStrength(float, Enum):
    """Strength of enablement relationship between capabilities."""
    DIRECT = 2.0
    INDIRECT = 1.0
    WEAK = 0.5


# How much attacker effort is replaced by discovering each finding class.
EFFORT_ELIMINATED_BY_CAPABILITY: Dict[str, float] = {
    "credential_exposure": 9.0,
    "source_code": 8.0,
    "topology": 7.0,
    "confirmed_injection": 6.0,
    "stack_disclosure": 4.0,
    "port_disclosure": 3.0,
    "partial_info": 2.0,
}

# Renderer-friendly severity scale (0-10).
SEVERITY_SCORES: Dict[str, float] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}

# Short-lived DTO cache to avoid repeated full rebuilds during UI polling bursts.
_GRAPH_DTO_CACHE_TTL_SECONDS = 1.0
_graph_dto_cache: Dict[str, Dict[str, Any]] = {}
_graph_dto_locks: Dict[str, asyncio.Lock] = {}


def _get_effort_eliminated_table() -> Dict[str, float]:
    """
    Get effort elimination values from config, with hardcoded fallback.
    """
    try:
        from core.base.config import get_config

        table = get_config().capability_model.effort_eliminated_by_capability
        if isinstance(table, dict) and table:
            return {str(key): float(value) for key, value in table.items()}
    except Exception:
        pass
    return dict(EFFORT_ELIMINATED_BY_CAPABILITY)


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
    enablement_score: float = 0.0  # Information leverage score, separate from centrality.


class CausalGraphBuilder:
    """
    Builds and analyzes dependency graphs of security findings.

    This discovers how vulnerabilities chain together to form attack paths,
    and identifies which fixes have the highest leverage.
    """

    def __init__(self):
        self.graph: nx.DiGraph = nx.DiGraph()
        self.findings_map: Dict[str, Finding] = {}
        self._inferred_enablement_edges: List[Dict[str, Any]] = []
        self._chain_dependency_pairs: Set[Tuple[str, str]] = set()

    def build(self, findings: List[Dict[str, Any]]) -> nx.DiGraph:
        """
        Build a directed graph of finding dependencies.

        Args:
            findings: List of finding dicts from database

        Returns:
            NetworkX DiGraph where edges represent "enables" relationships
        """
        logger.info(f"[CausalGraph] Building graph from {len(findings)} findings")

        # Fresh build each invocation to avoid stale nodes/edges from prior sessions.
        self.graph.clear()
        self.findings_map.clear()
        self._inferred_enablement_edges = []
        self._chain_dependency_pairs = set()

        # Convert dicts to Finding objects
        findings_obj = []
        for f in findings:
            raw_data = f.get('data', {})
            if not isinstance(raw_data, dict):
                raw_data = {}

            # Keep backward compatibility with existing `data` usage, but retain
            # top-level fields needed for capability-aware graph inference.
            merged_data = dict(raw_data)
            for key in (
                "confirmation_level",
                "capability_types",
                "base_score",
                "score",
                "raw_score",
                "tags",
                "description",
                "value",
                "metadata",
            ):
                if key in f and key not in merged_data:
                    merged_data[key] = f.get(key)

            finding = Finding(
                id=f.get('id', ''),
                type=f.get('type', 'unknown'),
                severity=f.get('severity', 'unknown'),
                title=f.get('title', f.get('type', 'Untitled')),
                target=f.get('target', ''),
                data=merged_data,
                requires=f.get('requires', []),
                enables=f.get('enables', [])
            )
            findings_obj.append(finding)
            self.findings_map[finding.id] = finding

        # Phase 1: Infer dependencies from finding types
        enablement_edges = self._infer_dependencies(findings_obj)
        enablement_lookup: Dict[Tuple[str, str], Dict[str, Any]] = {
            (edge.get("source", ""), edge.get("target", "")): edge for edge in enablement_edges
        }

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
                    edge_key = (prerequisite_id, finding.id)
                    enablement_edge = enablement_lookup.get(edge_key)
                    relationship = "enables"
                    edge_attrs: Dict[str, Any] = {}

                    if enablement_edge is not None:
                        # Preserve existing chain semantics where already present.
                        if edge_key not in self._chain_dependency_pairs:
                            relationship = "enablement"
                        edge_attrs.update({
                            "strength": float(enablement_edge.get("strength", 0.0)),
                            "enablement_class": enablement_edge.get("enablement_class", "partial_info"),
                            "effort_replaced": float(enablement_edge.get("effort_replaced", 0.0)),
                            "enabled_at": float(enablement_edge.get("enabled_at", time.time())),
                            "enablement_edge": True,
                        })

                    self.graph.add_edge(
                        prerequisite_id,
                        finding.id,
                        relationship=relationship,
                        **edge_attrs,
                    )

        logger.info(f"[CausalGraph] Built graph: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        return self.graph

    def enrich_from_issues(self, issues: List[Dict[str, Any]]) -> int:
        """
        Overlay VulnRule-enriched metadata from issues onto raw findings,
        then re-run enablement edge inference.

        The pipeline stores raw findings (without confirmation_level,
        capability_types, or score) separately from VulnRule-enriched issues.
        CausalGraph only receives raw findings, so Rule 5 filters reject
        everything.  This method bridges the gap by matching issues back to
        findings and copying enrichment fields, then re-running
        _infer_information_enablement_edges().

        Matching strategy (3 tiers):
          1. SHA256 hash of each evidence dict in supporting_findings — same
             algorithm save_finding_txn() used to generate finding.id.
          2. (target, tool, type) tuple match between evidence dicts and findings.
          3. Target URL prefix match (issue.target is prefix of finding.target
             or vice versa), picking the highest-scored issue when ambiguous.

        Returns:
            Number of new enablement edges added.
        """
        import hashlib as _hl

        if not issues:
            logger.debug("[CausalGraph] enrich_from_issues: no issues provided")
            return 0

        logger.info(
            "[CausalGraph] enrich_from_issues: %d issues, %d findings in graph",
            len(issues), len(self.findings_map),
        )

        # --- Tier 1: SHA256 hash of supporting_finding dicts ---
        # save_finding_txn() computes finding.id = sha256(json.dumps(f, sort_keys=True))
        # and does NOT write the id back into the dict.  The evidence dicts in
        # supporting_findings are the same dicts (JSON round-tripped), so
        # recomputing the hash should yield the same finding ID.
        hash_to_issues: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for issue in issues:
            for sf in issue.get("supporting_findings", []):
                if isinstance(sf, dict):
                    try:
                        blob = json.dumps(sf, sort_keys=True)
                        h = _hl.sha256(blob.encode()).hexdigest()
                        hash_to_issues[h].append(issue)
                    except (TypeError, ValueError):
                        continue

        # --- Tier 2: (target, tool, type) tuple lookup ---
        evidence_key_to_issues: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
        for issue in issues:
            for sf in issue.get("supporting_findings", []):
                if isinstance(sf, dict):
                    key = (
                        str(sf.get("target", "")).strip().lower(),
                        str(sf.get("tool", "")).strip().lower(),
                        str(sf.get("type", "")).strip().lower(),
                    )
                    if key[0]:
                        evidence_key_to_issues[key].append(issue)

        def _parse_target(raw_target: str) -> Tuple[str, str, Tuple[str, ...]]:
            value = str(raw_target or "").strip().lower()
            if not value:
                return "", "", ()
            parsed = urlparse(value)
            # Support bare host/path values by treating them as path-only fallback.
            if parsed.scheme and parsed.netloc:
                path = (parsed.path or "").strip("/")
                segments = tuple(seg for seg in path.split("/") if seg)
                return parsed.scheme, parsed.netloc, segments
            path = value.strip("/")
            segments = tuple(seg for seg in path.split("/") if seg)
            return "", "", segments

        def _common_prefix_len(lhs: Tuple[str, ...], rhs: Tuple[str, ...]) -> int:
            size = min(len(lhs), len(rhs))
            n = 0
            while n < size and lhs[n] == rhs[n]:
                n += 1
            return n

        def _issue_rank(issue: Dict[str, Any]) -> Tuple[float, int, int, int, str]:
            try:
                score = float(issue.get("score", 0.0))
            except (TypeError, ValueError):
                score = 0.0

            raw_caps = issue.get("capability_types", [])
            if isinstance(raw_caps, str):
                raw_caps = [raw_caps]
            if not isinstance(raw_caps, list):
                raw_caps = []
            capabilities = {
                str(cap).strip().lower()
                for cap in raw_caps
                if str(cap).strip()
            }
            capability_specificity = sum(
                1 for cap in capabilities if cap in {"information", "access", "execution"}
            )

            confirmation = str(issue.get("confirmation_level", "probable")).strip().lower()
            confirmation_rank = {"hypothesized": 0, "probable": 1, "confirmed": 2}.get(
                confirmation, 1
            )

            support = issue.get("supporting_findings", [])
            support_count = len(support) if isinstance(support, list) else 0
            return (
                score,
                capability_specificity,
                confirmation_rank,
                -support_count,  # fewer supporting findings = more specific issue
                str(issue.get("id", "")),
            )

        def _select_best_issue(candidates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
            if not candidates:
                return None
            deduped: List[Dict[str, Any]] = []
            seen_obj_ids: Set[int] = set()
            for candidate in candidates:
                key = id(candidate)
                if key in seen_obj_ids:
                    continue
                seen_obj_ids.add(key)
                deduped.append(candidate)
            return max(deduped, key=_issue_rank) if deduped else None

        def _issue_semantic_sets(issue: Dict[str, Any]) -> Tuple[Set[str], Set[str], Set[str]]:
            tools: Set[str] = set()
            types: Set[str] = set()
            tags: Set[str] = set()
            for sf in issue.get("supporting_findings", []):
                if not isinstance(sf, dict):
                    continue
                tool = str(sf.get("tool", "")).strip().lower()
                finding_type = str(sf.get("type", "")).strip().lower()
                if tool:
                    tools.add(tool)
                if finding_type:
                    types.add(finding_type)
                raw_tags = sf.get("tags", [])
                if isinstance(raw_tags, str):
                    raw_tags = [raw_tags]
                if isinstance(raw_tags, list):
                    for tag in raw_tags:
                        tag_value = str(tag).strip().lower()
                        if tag_value:
                            tags.add(tag_value)
            issue_tags = issue.get("tags", [])
            if isinstance(issue_tags, str):
                issue_tags = [issue_tags]
            if isinstance(issue_tags, list):
                for tag in issue_tags:
                    tag_value = str(tag).strip().lower()
                    if tag_value:
                        tags.add(tag_value)
            return tools, types, tags

        def _passes_tier3_semantic_guard(finding: Finding, candidate_issue: Dict[str, Any]) -> bool:
            issue_tools, issue_types, issue_tags = issue_semantics.get(id(candidate_issue), (set(), set(), set()))
            f_tool = str(finding.data.get("tool", "")).strip().lower()
            f_type = str(finding.type).strip().lower()
            f_tags = self._finding_tags(finding)
            if f_tool and issue_tools and f_tool in issue_tools:
                return True
            if f_type and issue_types and f_type in issue_types:
                return True
            if f_tags and issue_tags and bool(f_tags.intersection(issue_tags)):
                return True
            return False

        def _issue_match_targets(issue: Dict[str, Any]) -> List[str]:
            targets: List[str] = []
            primary_target = str(issue.get("target", "")).strip()
            if primary_target:
                targets.append(primary_target)

            for sf in issue.get("supporting_findings", []):
                if not isinstance(sf, dict):
                    continue
                sf_target = str(sf.get("target", "")).strip()
                if sf_target:
                    targets.append(sf_target)
                sf_meta = sf.get("metadata", {})
                if isinstance(sf_meta, dict):
                    original_target = str(sf_meta.get("original_target", "")).strip()
                    if original_target:
                        targets.append(original_target)

            ordered: List[str] = []
            seen: Set[str] = set()
            for value in targets:
                if value in seen:
                    continue
                seen.add(value)
                ordered.append(value)
            return ordered

        def _finding_match_targets(finding: Finding) -> List[str]:
            targets: List[str] = []
            primary = str(finding.target or "").strip()
            if primary:
                targets.append(primary)
            metadata = finding.data.get("metadata", {})
            if isinstance(metadata, dict):
                original_target = str(metadata.get("original_target", "")).strip()
                if original_target:
                    targets.append(original_target)

            ordered: List[str] = []
            seen: Set[str] = set()
            for value in targets:
                if value in seen:
                    continue
                seen.add(value)
                ordered.append(value)
            return ordered

        # --- Tier 3: strict URL/path lookup (conservative to avoid over-enrichment) ---
        issues_by_origin: Dict[Tuple[str, str], List[Tuple[Dict[str, Any], Tuple[str, ...]]]] = defaultdict(list)
        issue_semantics: Dict[int, Tuple[Set[str], Set[str], Set[str]]] = {}
        for issue in issues:
            issue_semantics[id(issue)] = _issue_semantic_sets(issue)
            for raw_issue_target in _issue_match_targets(issue):
                scheme, netloc, path_segments = _parse_target(raw_issue_target)
                if not scheme or not netloc:
                    continue
                # Never tier3-match root-only targets; this caused near-complete graph enrichment.
                if not path_segments:
                    continue
                issues_by_origin[(scheme, netloc)].append((issue, path_segments))

        enriched_count = 0
        tier_stats = {"hash": 0, "key": 0, "prefix": 0}
        for finding in self.findings_map.values():
            # Tier 1: hash match
            matched_issue = _select_best_issue(hash_to_issues.get(finding.id, []))
            if matched_issue:
                tier_stats["hash"] += 1

            # Tier 2: (target, tool, type) match
            if matched_issue is None:
                tool = str(finding.data.get("tool", "")).strip().lower()
                finding_type = str(finding.type).strip().lower()
                tier2_candidates: List[Dict[str, Any]] = []
                for raw_target in _finding_match_targets(finding):
                    f_key = (str(raw_target).strip().lower(), tool, finding_type)
                    tier2_candidates.extend(evidence_key_to_issues.get(f_key, []))
                matched_issue = _select_best_issue(tier2_candidates)
                if matched_issue:
                    tier_stats["key"] += 1

            # Tier 3: strict same-origin path match with semantic guard.
            if matched_issue is None:
                best_issue: Optional[Dict[str, Any]] = None
                best_rank: Optional[Tuple[int, int, float, Tuple[float, int, int, int, str]]] = None
                ambiguous = False

                for raw_target in _finding_match_targets(finding):
                    f_scheme, f_netloc, f_segments = _parse_target(raw_target)
                    if not (f_scheme and f_netloc and f_segments):
                        continue

                    candidates = issues_by_origin.get((f_scheme, f_netloc), [])
                    for candidate_issue, issue_segments in candidates:
                        # Prefix in either direction, but both sides must have non-root paths.
                        if not (
                            f_segments[: len(issue_segments)] == issue_segments
                            or issue_segments[: len(f_segments)] == f_segments
                        ):
                            continue
                        if not _passes_tier3_semantic_guard(finding, candidate_issue):
                            continue

                        common = _common_prefix_len(f_segments, issue_segments)
                        try:
                            score = float(candidate_issue.get("score", 0))
                        except (TypeError, ValueError):
                            score = 0.0
                        rank = (common, len(issue_segments), score, _issue_rank(candidate_issue))

                        if best_rank is None or rank > best_rank:
                            best_issue = candidate_issue
                            best_rank = rank
                            ambiguous = False
                        elif rank == best_rank and best_issue is not candidate_issue:
                            ambiguous = True

                if best_issue is not None and not ambiguous:
                    matched_issue = best_issue
                    tier_stats["prefix"] += 1

            if matched_issue is None:
                continue

            # Overlay enrichment fields onto finding.data (non-destructive)
            for key in ("confirmation_level", "capability_types", "score",
                        "raw_score", "confirmation_multiplier"):
                if key in matched_issue and key not in finding.data:
                    finding.data[key] = matched_issue[key]

            enriched_count += 1

        logger.info(
            "[CausalGraph] enrich_from_issues matched %d/%d findings "
            "(tier1_hash=%d, tier2_key=%d, tier3_prefix=%d)",
            enriched_count, len(self.findings_map),
            tier_stats["hash"], tier_stats["key"], tier_stats["prefix"],
        )

        if enriched_count == 0:
            return 0

        # Re-run enablement edge inference with enriched metadata
        findings_list = list(self.findings_map.values())
        new_edges = self._infer_information_enablement_edges(findings_list)

        if not new_edges:
            logger.info(
                "[CausalGraph] Enriched %d findings but Rule 5 produced 0 enablement edges",
                enriched_count,
            )
            return 0

        # Apply the new enablement edges to the graph
        for edge in new_edges:
            source_id = edge["source"]
            target_id = edge["target"]
            if source_id in self.findings_map and target_id in self.findings_map:
                if not self.graph.has_edge(source_id, target_id):
                    self.graph.add_edge(
                        source_id,
                        target_id,
                        relationship="enablement",
                        strength=float(edge.get("strength", 0.0)),
                        enablement_class=edge.get("enablement_class", "partial_info"),
                        effort_replaced=float(edge.get("effort_replaced", 0.0)),
                        enabled_at=float(edge.get("enabled_at", time.time())),
                        enablement_edge=True,
                    )

        self._inferred_enablement_edges.extend(new_edges)

        logger.info(
            "[CausalGraph] Enriched %d findings from issues, inferred %d enablement edges",
            enriched_count,
            len(new_edges),
        )
        return len(new_edges)

    def build_decisions(self, decisions: List[Dict[str, Any]]) -> None:
        """
        Add decision nodes and edges to the graph.
        """
        import json
        for d in decisions:
            label = f"[{d.get('type','DECISION')}] {d.get('chosen','Unknown')}"
            node_data = {
                "reason": d.get("reason"),
                "confidence": d.get("context", {}).get("confidence", 1.0),
                "timestamp": d.get("timestamp"),
                # Physics for UI
                "mass": 2.0,
                "charge": 40.0,
                "color": "#9C27B0" # Purple for decisions
            }
            
            self.graph.add_node(
                d["id"],
                type="decision",
                title=label, # Use title for UI label consistency
                severity="info", # Decisions aren't vulns
                target=d.get("context", {}).get("target", "system"),
                data=node_data
            )

            # Link triggers (Evidence/Triggers -> Decision)
            # Triggers are finding IDs or event IDs.
            # Prefer first-class triggers field, fall back to evidence hack
            evidence = d.get("evidence", {})
            triggers = d.get("triggers") or evidence.get("triggers", [])
            for trigger_id in triggers:
                if trigger_id in self.graph:
                     self.graph.add_edge(trigger_id, d["id"], relationship="triggered")

            # Link parent (Decision -> Decision)
            parent_id = d.get("parent_id")
            if parent_id and parent_id in self.graph:
                self.graph.add_edge(parent_id, d["id"], relationship="caused")

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

        # Rule 5 (incremental): Information enablement edges for new finding.
        # Check if the new finding is a confirmed info/access finding that enables
        # existing findings, OR if existing info/access findings enable this one.
        all_findings_for_target = [
            f for f in self.findings_map.values()
            if f.target == new_finding.target
        ]
        if all_findings_for_target:
            edges = self._infer_information_enablement_edges(all_findings_for_target)
            for edge in edges:
                src, tgt = edge.get("source"), edge.get("target")
                if src and tgt and not self.graph.has_edge(src, tgt):
                    self.graph.add_edge(
                        src, tgt,
                        relationship="enablement",
                        strength=float(edge.get("strength", 0.0)),
                        enablement_class=edge.get("enablement_class", "partial_info"),
                        effort_replaced=float(edge.get("effort_replaced", 0.0)),
                        enabled_at=float(edge.get("enabled_at", time.time())),
                        enablement_edge=True,
                    )
    
    def _infer_dependencies(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Infer causal dependencies from finding types and targets.

        This uses heuristics to discover implicit relationships:
        - "Reconnaissance" enables "Service discovery"
        - "Service discovery" enables "Vulnerability identification"
        - "Connectivity" enables "Service access"
        - "Open port" enables "Service exploitation"
        """
        self._inferred_enablement_edges = []
        self._chain_dependency_pairs = set()

        # Group findings by target
        by_target: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            by_target[f.target].append(f)

        # Heuristic rules for inferring dependencies (updated to match actual scan output)
        for target, target_findings in by_target.items():
            # Rule 1: Reconnaissance (DNS/subdomain) enables service discovery
            recon_findings = [f for f in target_findings if any(word in f.type.lower() for word in
                ['dns', 'subdomain', 'enumeration', 'dns record'])]
            service_findings = [f for f in target_findings if any(word in f.type.lower() for word in
                ['port', 'open_port', 'service', 'unidentified_service'])]

            for recon_finding in recon_findings:
                for service_finding in service_findings:
                    if recon_finding.id not in service_finding.requires:
                        service_finding.requires.append(recon_finding.id)

            # Rule 2: Connectivity enables port scanning and service discovery
            connectivity_findings = [f for f in target_findings if 'connectivity' in f.type.lower()]
            port_findings = [f for f in target_findings if any(word in f.type.lower() for word in
                ['port', 'open_port', 'service'])]

            for conn_finding in connectivity_findings:
                for port_finding in port_findings:
                    if conn_finding.id not in port_finding.requires:
                        port_finding.requires.append(conn_finding.id)

            # Rule 3: Open ports/services enable vulnerability discovery
            service_findings_all = [f for f in target_findings if any(word in f.type.lower() for word in
                ['port', 'open_port', 'service', 'unidentified_service'])]
            vuln_findings = [f for f in target_findings if any(word in f.type.lower() for word in
                ['vuln', 'vulnerability', 'injection', 'xss', 'rce', 'exploit'])]

            for service_finding in service_findings_all:
                for vuln_finding in vuln_findings:
                    if service_finding.id not in vuln_finding.requires:
                        vuln_finding.requires.append(service_finding.id)

            # Rule 4: Generic vulnerability findings depend on any reconnaissance
            generic_vulns = [f for f in target_findings if f.type.lower() in ['vulnerability', 'vuln']]
            all_recon = [f for f in target_findings if any(word in f.type.lower() for word in
                ['dns', 'subdomain', 'port', 'service', 'connectivity', 'enumeration'])]

            for vuln_finding in generic_vulns:
                # Link to the most relevant recon finding (prefer service over DNS)
                if all_recon:
                    # Prefer service/port findings for vulnerabilities
                    service_recon = [f for f in all_recon if 'service' in f.type.lower() or 'port' in f.type.lower()]
                    best_recon = service_recon[0] if service_recon else all_recon[0]
                    if best_recon.id not in vuln_finding.requires:
                        vuln_finding.requires.append(best_recon.id)

        # Capture pre-Phase-2 chain edges so we do not overload existing semantics.
        self._chain_dependency_pairs = {
            (source_id, finding.id)
            for finding in findings
            for source_id in finding.requires
        }

        # Rule 5 (Phase 2): Information/access findings enable downstream capabilities.
        enablement_edges = self._infer_information_enablement_edges(findings)
        for edge in enablement_edges:
            source_id = edge.get("source")
            target_id = edge.get("target")
            if not source_id or not target_id:
                continue
            target_finding = self.findings_map.get(target_id)
            if target_finding and source_id not in target_finding.requires:
                target_finding.requires.append(source_id)

        self._inferred_enablement_edges = enablement_edges
        logger.info(
            "[CausalGraph] Inferred dependencies using 5 heuristic rules (%d enablement edges)",
            len(enablement_edges),
        )
        return enablement_edges

    @staticmethod
    def _finding_capability_types(finding: Finding) -> List[str]:
        raw = finding.data.get("capability_types", [])
        if isinstance(raw, str):
            values = [raw]
        elif isinstance(raw, list):
            values = raw
        else:
            values = []
        normalized = [str(v).strip().lower() for v in values if str(v).strip()]
        return normalized or ["execution"]

    @staticmethod
    def _finding_confirmation_level(finding: Finding) -> str:
        return str(finding.data.get("confirmation_level", "probable")).strip().lower()

    @staticmethod
    def _finding_base_score(finding: Finding) -> float:
        for key in ("base_score", "score", "raw_score"):
            value = finding.data.get(key)
            if value is None:
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return 0.0

    @staticmethod
    def _finding_tags(finding: Finding) -> Set[str]:
        tags = finding.data.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        if not isinstance(tags, list):
            return set()
        return {str(tag).strip().lower() for tag in tags if str(tag).strip()}

    @staticmethod
    def _finding_text_blob(finding: Finding) -> str:
        parts = [
            finding.type,
            finding.title,
            finding.data.get("description"),
            finding.data.get("message"),
            finding.data.get("proof"),
            finding.data.get("value"),
            finding.data.get("evidence_summary"),
        ]
        return " ".join(str(part) for part in parts if part).lower()

    def _infer_information_enablement_edges(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Create enablement edges from confirmed information/access findings
        to findings that become easier to exploit with that information.
        """
        edges: List[Dict[str, Any]] = []
        seen_pairs: Set[Tuple[str, str]] = set()
        max_edges_per_source = 4
        max_edges_per_target = 40

        by_target: Dict[str, List[Finding]] = defaultdict(list)
        for finding in findings:
            by_target[finding.target].append(finding)

        for target, target_findings in by_target.items():
            target_edges_created = 0
            info_findings = [
                finding
                for finding in target_findings
                if self._finding_confirmation_level(finding) == "confirmed"
                and self._finding_base_score(finding) >= 5.0
                and any(
                    capability in {"information", "access"}
                    for capability in self._finding_capability_types(finding)
                )
            ]

            info_findings.sort(
                key=lambda finding: (
                    self._finding_base_score(finding),
                    1 if "access" in self._finding_capability_types(finding) else 0,
                    str(finding.id),
                ),
                reverse=True,
            )

            seen_source_signatures: Set[Tuple[str, str]] = set()
            for info_finding in info_findings:
                if target_edges_created >= max_edges_per_target:
                    break
                source_id = info_finding.id
                if not source_id:
                    continue

                capability_types = self._finding_capability_types(info_finding)
                enablement_class = self._classify_enablement(info_finding)

                # Collapse near-identical source findings from overlapping tools.
                source_locator = self._finding_locator_hint(info_finding) or source_id
                source_signature = (enablement_class, source_locator)
                if source_signature in seen_source_signatures:
                    continue
                seen_source_signatures.add(source_signature)

                strength = self._enablement_strength(capability_types, enablement_class)
                effort_table = _get_effort_eliminated_table()
                effort = effort_table.get(enablement_class, 2.0)
                edges_created = 0
                seen_candidate_families: Set[str] = set()

                candidate_pool = sorted(
                    target_findings,
                    key=lambda candidate: (
                        self._finding_base_score(candidate),
                        str(candidate.id),
                    ),
                    reverse=True,
                )
                for candidate in candidate_pool:
                    if target_edges_created >= max_edges_per_target:
                        break
                    if edges_created >= max_edges_per_source:
                        break
                    target_id = candidate.id
                    if not target_id or target_id == source_id:
                        continue
                    if candidate.target != target:
                        continue  # Explicit cross-target guard.
                    if self._finding_confirmation_level(candidate) == "hypothesized":
                        continue
                    # Candidate must have explicit capability metadata from issue enrichment.
                    # Avoid assuming executability for raw findings.
                    candidate_raw_caps = candidate.data.get("capability_types")
                    if not candidate_raw_caps:
                        continue
                    candidate_caps = self._finding_capability_types(candidate)
                    if not any(cap in {"execution", "access"} for cap in candidate_caps):
                        continue

                    candidate_family = self._finding_attack_family(candidate)
                    if candidate_family in seen_candidate_families:
                        continue

                    if not self._would_benefit_from(candidate, enablement_class, capability_types):
                        continue

                    pair = (source_id, target_id)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    seen_candidate_families.add(candidate_family)

                    edges.append({
                        "source": source_id,
                        "target": target_id,
                        "type": "enablement",
                        "strength": float(strength),
                        "enablement_class": enablement_class,
                        "effort_replaced": float(effort),
                        "enabled_at": time.time(),
                    })
                    edges_created += 1
                    target_edges_created += 1

        return edges

    @staticmethod
    def _finding_locator_hint(finding: Finding) -> str:
        """
        Best-effort, stable locator used only for Rule-5 dedupe budgeting.
        """
        metadata = finding.data.get("metadata", {})
        if isinstance(metadata, dict):
            for key in ("path", "endpoint", "uri", "url", "location"):
                value = metadata.get(key)
                if value is None:
                    continue
                text = str(value).strip().lower()
                if not text:
                    continue
                if text.startswith(("http://", "https://")):
                    parsed = urlparse(text)
                    path = (parsed.path or "/").strip().lower()
                    if parsed.query:
                        path = f"{path}?{parsed.query}"
                    return path
                if text.startswith("/"):
                    return text
                if "/" in text:
                    return f"/{text.lstrip('/')}"

            port = metadata.get("port")
            if port is not None:
                host = str(metadata.get("host") or finding.target or "").strip().lower()
                return f"{host}:{port}"

        value = finding.data.get("value")
        if value is not None:
            text = str(value).strip().lower()
            if text:
                return text

        return ""

    def _finding_attack_family(self, finding: Finding) -> str:
        """
        Coarse candidate family used to avoid multiple near-identical Rule-5 edges.
        """
        finding_type = str(finding.type).strip().lower()
        tags = self._finding_tags(finding)
        text = f"{finding_type} {' '.join(sorted(tags))}"

        if any(token in text for token in ("auth", "login", "admin", "session")):
            return "auth_surface"
        if any(token in text for token in ("sqli", "sql", "injection", "xss", "rce", "lfi", "ssrf")):
            return "injection_surface"
        if any(token in text for token in ("service", "port", "network")):
            return "network_surface"
        if any(token in text for token in ("directory", "disclosure", "exposure", "backup", "source", "git")):
            return "exposure_surface"

        locator = self._finding_locator_hint(finding)
        if locator:
            return f"locator:{locator}"
        return finding_type or "generic"

    def _classify_enablement(self, finding: Finding) -> str:
        """
        Classify what form of attacker leverage this finding provides.
        """
        finding_type = str(finding.type).lower()
        tags = self._finding_tags(finding)
        text = self._finding_text_blob(finding)

        # Use shared credential indicators (single source of truth).
        from core.data.constants import CREDENTIAL_INDICATORS
        if "secret-leak" in tags or "credential" in finding_type:
            return "credential_exposure"
        if any(indicator in text for indicator in CREDENTIAL_INDICATORS):
            return "credential_exposure"
        if "backup-leak" in tags and any(indicator in text for indicator in CREDENTIAL_INDICATORS):
            return "credential_exposure"
        if "backup-leak" in tags:
            return "source_code"

        if "git" in finding_type or "source" in finding_type or ".git" in text:
            return "source_code"

        if "private-ip" in tags or "topology" in finding_type or "internal ip" in text:
            return "topology"

        if any(tag in tags for tag in ("sqli", "injection", "rce")):
            return "confirmed_injection"

        if "error-leakage" in tags or "stack" in finding_type or "traceback" in text:
            return "stack_disclosure"

        if "port" in finding_type or "service" in finding_type:
            return "port_disclosure"

        return "partial_info"

    @staticmethod
    def _enablement_strength(
        capability_types: List[str],
        enablement_class: str,
    ) -> EnablementStrength:
        """
        Determine edge strength for the inferred enablement.
        """
        if enablement_class in ("credential_exposure", "source_code"):
            return EnablementStrength.DIRECT
        if enablement_class in ("topology", "confirmed_injection"):
            return EnablementStrength.INDIRECT
        return EnablementStrength.WEAK

    @staticmethod
    def _would_benefit_from(
        target_finding: Finding,
        enablement_class: str,
        source_capability_types: List[str],
    ) -> bool:
        """
        Heuristic check: can this target finding benefit from source information?
        """
        target_type = str(target_finding.type).lower()
        raw_tags = target_finding.data.get("tags", [])
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        target_tags = {str(tag).strip().lower() for tag in raw_tags if str(tag).strip()}

        if enablement_class == "credential_exposure":
            return any(token in target_type for token in ("auth", "login", "admin", "session")) or any(
                tag in target_tags for tag in ("auth", "login", "admin")
            )

        if enablement_class == "topology":
            return "ssrf" in target_type or "cloud" in target_type or any(
                tag in target_tags for tag in ("ssrf", "cloud")
            )

        if enablement_class == "source_code":
            return any(token in target_type for token in ("injection", "sqli", "rce", "lfi", "ssrf", "auth", "login", "admin")) or any(
                tag in target_tags for tag in ("injection", "sqli", "rce", "lfi", "ssrf", "auth", "login", "admin")
            )

        if enablement_class == "confirmed_injection":
            return any(token in target_type for token in ("database", "sql", "auth", "admin")) or any(
                tag in target_tags for tag in ("database", "sql", "auth", "admin")
            )

        if enablement_class == "stack_disclosure":
            return any(token in target_type for token in ("rce", "injection", "xss", "lfi", "ssrf"))

        if enablement_class == "port_disclosure":
            return any(token in target_type for token in ("service", "admin", "auth")) or any(
                tag in target_tags for tag in ("service", "admin", "auth")
            )

        return False

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
            enablement_score = sum(
                float(data.get("strength", 0.0))
                for _, _, data in self.graph.out_edges(node, data=True)
                if data.get("relationship") == "enablement" or data.get("enablement_edge")
            )

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
                        centrality_score=centrality.get(node, 0.0),
                        enablement_score=enablement_score,
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

    def get_attack_chains(
        self,
        max_length: int = 5,
        include_metrics: bool = False,
    ) -> Any:
        """
        Find all attack chains (simple paths from roots to leaves).

        An attack chain is a sequence of findings where each enables the next.

        Args:
            max_length: Maximum chain length to consider

        Returns:
            If include_metrics=False (default): list of chains.
            If include_metrics=True: dict with chains + per-node metrics.
        """
        if not self.graph:
            return {"chains": [], "nodes": []} if include_metrics else []

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
        if not include_metrics:
            return chains

        try:
            centrality = nx.betweenness_centrality(self.graph)
        except Exception:
            centrality = {node: 0.0 for node in self.graph.nodes()}

        node_summaries: List[Dict[str, Any]] = []
        for node in self.graph.nodes():
            enablement_score = sum(
                float(data.get("strength", 0.0))
                for _, _, data in self.graph.out_edges(node, data=True)
                if data.get("relationship") == "enablement" or data.get("enablement_edge")
            )
            node_summaries.append({
                "node_id": node,
                "centrality_score": float(centrality.get(node, 0.0)),
                "enablement_score": enablement_score,
            })

        return {"chains": chains, "nodes": node_summaries}

    @staticmethod
    def _severity_score(finding: Finding) -> float:
        """
        Convert finding severity to the renderer's expected 0-10 scale.
        """
        raw = finding.data.get("base_score")
        if raw is None:
            raw = finding.data.get("score")
        if raw is None:
            raw = finding.data.get("raw_score")
        if raw is None:
            raw = finding.severity

        if isinstance(raw, (int, float)):
            value = float(raw)
            if 0.0 <= value <= 1.0:
                value *= 10.0
            return max(0.0, min(10.0, value))

        text = str(raw).strip().lower()
        if text in SEVERITY_SCORES:
            return SEVERITY_SCORES[text]
        try:
            value = float(text)
            if 0.0 <= value <= 1.0:
                value *= 10.0
            return max(0.0, min(10.0, value))
        except (TypeError, ValueError):
            return SEVERITY_SCORES.get(str(finding.severity).strip().lower(), 1.0)

    @staticmethod
    def _render_node_type(finding: Finding) -> str:
        """
        Collapse raw finding types into stable UI categories with richer color variance.
        """
        raw_type = str(finding.type or "").strip().lower()
        if raw_type in {"decision", "strategy_decision"}:
            return "decision"

        if any(token in raw_type for token in ("port", "service", "connectivity")):
            return "service" if "service" in raw_type else "port"

        if any(token in raw_type for token in ("credential", "auth", "session", "exposure", "leak")):
            return "exposure"

        if any(token in raw_type for token in ("dns", "subdomain", "topology", "asset")):
            return "asset"

        capabilities = CausalGraphBuilder._finding_capability_types(finding)
        if "access" in capabilities:
            return "exposure"
        if "execution" in capabilities:
            return "vulnerability"
        if "information" in capabilities:
            return "asset"

        return "vulnerability"

    @staticmethod
    def _derive_exposure(finding: Finding) -> float:
        """
        Estimate accessibility (0-1) from target context and finding type.
        """
        target = str(finding.target or "").lower()
        finding_type = str(finding.type or "").lower()
        text = CausalGraphBuilder._finding_text_blob(finding)

        if any(token in finding_type for token in ("open_port", "port", "service", "connectivity")):
            return 0.9
        if any(token in text for token in ("internet", "public", "externally exposed")):
            return 0.9
        if any(token in target for token in ("localhost", "127.0.0.1", "internal", ".local", "10.", "192.168.")):
            return 0.35
        return 0.6

    @staticmethod
    def _derive_exploitability(finding: Finding, severity_score: float) -> float:
        """
        Estimate exploitability (0-1) from confirmation level + capability + severity.
        """
        confirmation = CausalGraphBuilder._finding_confirmation_level(finding)
        confirmation_base = {
            "confirmed": 0.82,
            "probable": 0.62,
            "hypothesized": 0.38,
        }.get(confirmation, 0.5)

        capabilities = CausalGraphBuilder._finding_capability_types(finding)
        cap_bonus = 0.0
        if "access" in capabilities:
            cap_bonus += 0.10
        if "execution" in capabilities:
            cap_bonus += 0.08
        if "information" in capabilities:
            cap_bonus += 0.04

        severity_bonus = min(0.12, max(0.0, severity_score / 10.0) * 0.12)
        return max(0.0, min(1.0, confirmation_base + cap_bonus + severity_bonus))

    @staticmethod
    def _derive_privilege_gain(finding: Finding) -> float:
        """
        Estimate privilege gain (0-1) from capability metadata and finding semantics.
        """
        capabilities = CausalGraphBuilder._finding_capability_types(finding)
        finding_type = str(finding.type or "").lower()
        text = CausalGraphBuilder._finding_text_blob(finding)

        if "access" in capabilities or any(token in finding_type for token in ("credential", "session", "auth")):
            return 1.0
        if "execution" in capabilities or any(token in finding_type for token in ("rce", "injection", "xss", "ssrf")):
            return 0.8
        if "information" in capabilities:
            if any(token in text for token in ("admin", "password", "token", "secret")):
                return 0.6
            return 0.45
        return 0.2

    @staticmethod
    def _canonical_edge_type(raw_relationship: str, edge_attrs: Optional[Dict[str, Any]] = None) -> str:
        """
        Map backend edge semantics to renderer edge classes.
        """
        attrs = edge_attrs or {}
        relationship = str(raw_relationship or "").strip().lower()
        enablement_class = str(attrs.get("enablement_class", "")).strip().lower()

        if relationship in {"enablement", "enables"}:
            if enablement_class == "port_disclosure":
                return "HAS_PORT"
            if enablement_class == "source_code":
                return "USES_TECH"
            return "EXPOSES"

        if relationship in {"requires", "required_by", "depends_on", "dependency"}:
            return "VULNERABLE_TO"

        if relationship in {"triggered", "caused"}:
            return "USES_TECH"

        if "port" in relationship or enablement_class == "port_disclosure":
            return "HAS_PORT"
        if "tech" in relationship or "service" in relationship:
            return "USES_TECH"

        return "EXPOSES"

    def export_dto(self, session_id: str = "unknown") -> Dict[str, Any]:
        """
        Export graph nodes and edges for API consumption (PressureGraphDTO).
        """
        pressure_points = self.identify_pressure_points(top_n=max(10, self.graph.number_of_nodes()))
        pressure_by_id = {point.finding_id: point for point in pressure_points}

        chain_analysis = self.get_attack_chains(max_length=10, include_metrics=True)
        raw_chains: List[List[str]] = chain_analysis.get("chains", []) if isinstance(chain_analysis, dict) else []
        node_metrics: Dict[str, Dict[str, Any]] = {
            str(node.get("node_id")): node
            for node in (chain_analysis.get("nodes", []) if isinstance(chain_analysis, dict) else [])
        }

        entry_nodes = [str(node_id) for node_id in self.graph.nodes() if self.graph.in_degree(node_id) == 0]
        leaf_nodes = [str(node_id) for node_id in self.graph.nodes() if self.graph.out_degree(node_id) == 0]

        chain_membership: Dict[str, int] = defaultdict(int)
        for chain in raw_chains:
            for node_id in chain:
                chain_membership[str(node_id)] += 1

        nodes = []
        for node in self.graph.nodes():
            finding = self.findings_map.get(node)
            graph_attrs = self.graph.nodes[node]
            node_id = str(node)
            is_entry_node = node_id in entry_nodes
            is_leaf_node = node_id in leaf_nodes
            out_degree = int(self.graph.out_degree(node))
            in_degree = int(self.graph.in_degree(node))
            point = pressure_by_id.get(node_id)

            if finding:
                severity_score = self._severity_score(finding)
                exposure = self._derive_exposure(finding)
                exploitability = self._derive_exploitability(finding, severity_score)
                privilege_gain = self._derive_privilege_gain(finding)
                centrality_score = float(node_metrics.get(node_id, {}).get("centrality_score", 0.0))
                enablement_score = float(node_metrics.get(node_id, {}).get("enablement_score", 0.0))
                attack_paths_blocked = int(point.attack_paths_blocked if point else 0)
                downstream_count = int(len(point.downstream_findings) if point else 0)
                chain_count = int(chain_membership.get(node_id, 0))
                capabilities = self._finding_capability_types(finding)

                # Physics tuning: high-severity choke points become larger/brighter.
                mass = min(
                    120.0,
                    8.0 + (severity_score * 4.0) + (attack_paths_blocked * 1.5) + (centrality_score * 40.0),
                )
                charge = 15.0 + (10.0 if is_entry_node else 0.0) + (enablement_score * 3.0)

                node_data = {
                    "severity": round(severity_score, 2),
                    "raw_severity": str(finding.severity),
                    "exposure": round(exposure, 3),
                    "exploitability": round(exploitability, 3),
                    "privilege_gain": round(privilege_gain, 3),
                    "asset_value": round(min(10.0, 2.0 + attack_paths_blocked + enablement_score), 2),
                    "pressure_source": "causal_graph",
                    "revision": 2,
                    "description": str(finding.data.get("description", "")),
                    "finding_type": str(finding.type),
                    "target": str(finding.target),
                    "confirmation_level": self._finding_confirmation_level(finding),
                    "capability_types": capabilities,
                    "base_score": round(self._finding_base_score(finding), 3),
                    "centrality_score": round(centrality_score, 5),
                    "enablement_score": round(enablement_score, 5),
                    "out_degree": out_degree,
                    "in_degree": in_degree,
                    "downstream_count": downstream_count,
                    "attack_paths_blocked": attack_paths_blocked,
                    "attack_chain_membership": chain_count,
                    "is_entry_node": is_entry_node,
                    "is_leaf_node": is_leaf_node,
                    "fix_impact_estimate": attack_paths_blocked,
                    # Physics Properties (Defaults for UI)
                    "mass": round(mass, 3),
                    "charge": round(charge, 3),
                    "temperature": round(exploitability, 3),
                    "structural": False
                }
                nodes.append({
                    "id": finding.id,
                    "label": finding.title,
                    "type": self._render_node_type(finding),
                    "data": node_data
                })
            else:
                # Fallback for Decision Nodes or other non-finding nodes
                # Use attributes stored directly on graph node
                node_type = graph_attrs.get("type", "unknown")
                node_label = graph_attrs.get("title", str(node))
                node_data_raw = graph_attrs.get("data", {})

                # Check for physics attributes in data or root attrs
                mass = node_data_raw.get("mass", 1.0)
                charge = node_data_raw.get("charge", 30.0)

                # Construct data block
                node_data = {
                    "severity": 1.0,
                    "raw_severity": "info",
                    "exposure": 0.2,
                    "exploitability": round(float(node_data_raw.get("confidence", 0.5)), 3),
                    "privilege_gain": 0.0,
                    "asset_value": 1.0,
                    "pressure_source": "causal_graph",
                    "revision": 2,
                    "description": node_data_raw.get("reason", ""),
                    "out_degree": out_degree,
                    "in_degree": in_degree,
                    "downstream_count": 0,
                    "attack_paths_blocked": 0,
                    "attack_chain_membership": int(chain_membership.get(node_id, 0)),
                    "is_entry_node": is_entry_node,
                    "is_leaf_node": is_leaf_node,
                    "fix_impact_estimate": 0,
                    "mass": float(mass),
                    "charge": float(charge),
                    "temperature": float(node_data_raw.get("temperature", 0.0)),
                    "structural": False
                }
                # Merge rest of data
                node_data.update({k: v for k, v in node_data_raw.items() if k not in node_data})

                nodes.append({
                    "id": node,
                    "label": node_label,
                    "type": node_type,
                    "data": node_data
                })
        edges = []
        for u, v, data in self.graph.edges(data=True):
            relationship_raw = str(data.get("relationship", "enables"))
            canonical_type = self._canonical_edge_type(relationship_raw, data)

            weight_value = float(data.get("strength", data.get("weight", 1.0)))
            confidence = data.get("confidence")
            if confidence is None:
                confidence = min(1.0, max(0.1, weight_value / 2.0))

            edge_data = {
                "confidence": float(confidence),
                "created_at": data.get("enabled_at", time.time()),
                "relationship_raw": relationship_raw,
                "render_type": canonical_type,
            }
            if data.get("enablement_edge"):
                edge_data.update({
                    "enablement_class": data.get("enablement_class", "partial_info"),
                    "effort_replaced": float(data.get("effort_replaced", 0.0)),
                })

            edges.append({
                "id": f"{u}-{v}",
                "source": u,
                "target": v,
                "type": canonical_type,
                "weight": weight_value,
                "data": edge_data
            })

        id_to_title = {
            str(node_id): str(self.findings_map[node_id].title)
            for node_id in self.findings_map
            if node_id in self.graph.nodes
        }
        for node_id, attrs in self.graph.nodes(data=True):
            if str(node_id) not in id_to_title:
                id_to_title[str(node_id)] = str(attrs.get("title", node_id))

        attack_chains = []
        for idx, chain in enumerate(raw_chains[:100]):
            if not chain:
                continue
            chain_ids = [str(node_id) for node_id in chain]
            chain_score = 0.0
            for source, target in zip(chain_ids, chain_ids[1:]):
                edge_attrs = self.graph.get_edge_data(source, target) or {}
                chain_score += float(edge_attrs.get("strength", 1.0))
            attack_chains.append({
                "id": f"chain_{idx + 1}",
                "node_ids": chain_ids,
                "labels": [id_to_title.get(node_id, node_id) for node_id in chain_ids],
                "entry_node": chain_ids[0],
                "leaf_node": chain_ids[-1],
                "length": len(chain_ids),
                "score": round(chain_score, 3),
            })

        pressure_payload = [
            {
                "finding_id": point.finding_id,
                "finding_title": point.finding_title,
                "severity": point.severity,
                "out_degree": int(point.out_degree),
                "attack_paths_blocked": int(point.attack_paths_blocked),
                "downstream_findings": list(point.downstream_findings),
                "downstream_count": len(point.downstream_findings),
                "centrality_score": round(float(point.centrality_score), 5),
                "enablement_score": round(float(point.enablement_score), 5),
                "recommendation": f"Fixing this finding blocks approximately {point.attack_paths_blocked} attack paths",
            }
            for point in pressure_points
        ]

        critical_assets = [
            item["finding_id"]
            for item in sorted(
                pressure_payload,
                key=lambda item: (item["attack_paths_blocked"], item["centrality_score"]),
                reverse=True,
            )[:10]
        ]

        return {
            "session_id": session_id,
            "nodes": nodes,
            "edges": edges,
            "count": {
                "nodes": len(nodes),
                "edges": len(edges)
            },
            "entry_nodes": entry_nodes,
            "leaf_nodes": leaf_nodes,
            "critical_assets": critical_assets,
            "attack_chains": attack_chains,
            "pressure_points": pressure_payload,
            "graph_metrics": {
                "attack_chains_count": len(attack_chains),
                "pressure_points_count": len(pressure_payload),
                "entry_nodes_count": len(entry_nodes),
                "leaf_nodes_count": len(leaf_nodes),
            },
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
                    "enablement_score": round(p.enablement_score, 3),
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
            graph_attrs = self.graph.nodes[node]
            
            if finding:
                color = severity_colors.get(finding.severity.lower(), '#CCCCCC')
                label = finding.title.replace('"', '\\"')[:50]  # Truncate long titles
                output.write(f'  "{node}" [label="{label}", fillcolor="{color}"];\n')
            else:
                 # Fallback
                 color = graph_attrs.get("data", {}).get("color", "#CCCCCC")
                 label = graph_attrs.get("title", str(node)).replace('"', '\\"')[:50]
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

    # Get findings and issues for this session
    findings = await db.get_findings(session_id)
    issues = await db.get_issues(session_id)

    # Build graph
    builder = CausalGraphBuilder()
    builder.build(findings)
    builder.enrich_from_issues(issues)

    # Return summary
    return builder.export_summary()


async def get_graph_dto_for_session(
    session_id: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    issues: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build a causal graph from findings and return DTO (nodes/edges).
    Includes both causal graph edges AND persisted edges from the database.
    """
    from core.data.db import Database

    db = Database.instance()
    await db.init()
    if findings is None:
        findings = await db.get_findings(session_id)
    if issues is None:
        issues = await db.get_issues(session_id)
    logger.info(f"[CausalGraph] Building graph from {len(findings)} findings")

    def _stable_digest(items: List[Dict[str, Any]], keys: Tuple[str, ...]) -> str:
        hasher = hashlib.sha256()
        for item in sorted(items, key=lambda obj: str(obj.get("id", ""))):
            parts: List[str] = []
            for key in keys:
                value = item.get(key)
                if isinstance(value, (dict, list)):
                    try:
                        value_repr = json.dumps(value, sort_keys=True)
                    except Exception:
                        value_repr = str(value)
                else:
                    value_repr = str(value)
                parts.append(f"{key}={value_repr}")
            hasher.update("|".join(parts).encode())
            hasher.update(b";")
        return hasher.hexdigest()

    findings_digest = _stable_digest(
        findings,
        ("id", "type", "severity", "target", "created_at", "fingerprint"),
    )
    issues_digest = _stable_digest(
        issues,
        ("id", "title", "severity", "target", "score", "confirmation_level", "capability_types"),
    )

    decision_meta = await db.fetch_all(
        """
        SELECT COUNT(*), COALESCE(MAX(timestamp), '')
        FROM decisions
        WHERE json_extract(context, '$.scan_id') = ? OR json_extract(context, '$.session_id') = ?
        """,
        (session_id, session_id),
    )
    decision_count = int(decision_meta[0][0]) if decision_meta else 0
    decision_latest = str(decision_meta[0][1]) if decision_meta else ""

    snapshot_meta = await db.fetch_all(
        """
        SELECT
            (SELECT COUNT(*) FROM graph_nodes WHERE session_id = ?),
            (SELECT COUNT(*) FROM graph_edges WHERE session_id = ?)
        """,
        (session_id, session_id),
    )
    snapshot_nodes_count = int(snapshot_meta[0][0]) if snapshot_meta else 0
    snapshot_edges_count = int(snapshot_meta[0][1]) if snapshot_meta else 0

    cache_signature = "|".join(
        [
            findings_digest,
            issues_digest,
            str(decision_count),
            decision_latest,
            str(snapshot_nodes_count),
            str(snapshot_edges_count),
        ]
    )

    cache_entry = _graph_dto_cache.get(session_id)
    now = time.time()
    if cache_entry:
        age = now - float(cache_entry.get("built_at", 0.0))
        if age <= _GRAPH_DTO_CACHE_TTL_SECONDS and cache_entry.get("signature") == cache_signature:
            logger.debug("[CausalGraph] DTO cache hit for session %s (age=%.3fs)", session_id, age)
            return copy.deepcopy(cache_entry.get("dto", {}))

    lock = _graph_dto_locks.setdefault(session_id, asyncio.Lock())
    async with lock:
        cache_entry = _graph_dto_cache.get(session_id)
        if cache_entry:
            age = now - float(cache_entry.get("built_at", 0.0))
            if age <= _GRAPH_DTO_CACHE_TTL_SECONDS and cache_entry.get("signature") == cache_signature:
                logger.debug("[CausalGraph] DTO cache hit (locked) for session %s (age=%.3fs)", session_id, age)
                return copy.deepcopy(cache_entry.get("dto", {}))

        builder = CausalGraphBuilder()
        builder.build(findings)

        # Overlay VulnRule-enriched metadata from issues so Rule 5 can
        # see confirmation_level, capability_types, and score.
        enablement_count = builder.enrich_from_issues(issues)
        if enablement_count:
            logger.info(f"[CausalGraph] Issue enrichment produced {enablement_count} enablement edges")

        logger.info(
            f"[CausalGraph] Built causal graph: {builder.graph.number_of_nodes()} nodes, {builder.graph.number_of_edges()} edges"
        )

        async def _load_decision_layer(limit: int = 200) -> Dict[str, Any]:
            """
            Load decisions as a separate, optional overlay (not merged into core finding graph).
            """
            try:
                rows = await db.fetch_all(
                    """
                    SELECT id, type, chosen, reason, evidence, parent_id, timestamp, context
                    FROM decisions
                    WHERE json_extract(context, '$.scan_id') = ? OR json_extract(context, '$.session_id') = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (session_id, session_id, limit + 1),
                )
            except Exception as exc:
                logger.warning("[CausalGraph] Failed to load decision layer: %s", exc)
                return {"count": 0, "nodes": [], "edges": [], "truncated": False}

            truncated = len(rows) > limit
            if truncated:
                rows = rows[:limit]

            nodes: List[Dict[str, Any]] = []
            edges: List[Dict[str, Any]] = []
            node_ids: Set[str] = set()

            for row in rows:
                decision_id = str(row[0] or "")
                if not decision_id or decision_id in node_ids:
                    continue
                node_ids.add(decision_id)

                evidence = json.loads(row[4]) if row[4] else {}
                context = json.loads(row[7]) if row[7] else {}
                confidence = context.get("confidence", 1.0)
                try:
                    confidence = float(confidence)
                except (TypeError, ValueError):
                    confidence = 1.0
                ts_raw = row[6]
                try:
                    ts_value = float(ts_raw or 0.0)
                except (TypeError, ValueError):
                    # Keep deterministic fallback for non-numeric timestamps.
                    ts_value = 0.0

                nodes.append(
                    {
                        "id": decision_id,
                        "type": str(row[1] or "decision"),
                        "chosen": str(row[2] or ""),
                        "reason": str(row[3] or ""),
                        "timestamp": ts_value,
                        "parent_id": str(row[5] or "") or None,
                        "confidence": confidence,
                        "triggers": list((evidence or {}).get("triggers", []) or []),
                    }
                )

                parent_id = str(row[5] or "")
                if parent_id:
                    edges.append(
                        {
                            "id": f"{parent_id}->{decision_id}:caused",
                            "source": parent_id,
                            "target": decision_id,
                            "type": "CAUSED",
                        }
                    )

                for trigger in list((evidence or {}).get("triggers", []) or []):
                    trigger_id = str(trigger).strip()
                    if not trigger_id:
                        continue
                    edges.append(
                        {
                            "id": f"{trigger_id}->{decision_id}:triggered",
                            "source": trigger_id,
                            "target": decision_id,
                            "type": "TRIGGERED",
                        }
                    )

            return {
                "count": len(nodes),
                "nodes": nodes,
                "edges": edges,
                "truncated": truncated,
                "limit": limit,
            }

        decision_layer = await _load_decision_layer(limit=200)

        # Export DTO after all in-memory graph augmentations are complete.
        dto = builder.export_dto(session_id=session_id)

        # Load persisted graph snapshot from database (killchain/recon/correlator overlays).
        db_nodes, db_edges = await db.load_graph_snapshot(session_id)

        def _float_or(value: Any, default: float) -> float:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        def _int_or(value: Any, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        if db_nodes:
            existing_node_ids = {str(node.get("id")) for node in dto.get("nodes", [])}
            merged_nodes = list(dto.get("nodes", []))
            for db_node in db_nodes:
                node_id = str(db_node.get("id", ""))
                if not node_id or node_id in existing_node_ids:
                    continue
                node_type = str(db_node.get("type") or "").strip().lower()
                if node_type == "decision":
                    # Decisions are served through dto["decision_layer"], not merged into the finding graph.
                    continue

                payload = db_node.get("data") if isinstance(db_node.get("data"), dict) else {}
                severity_value = payload.get("severity", 1.0)
                try:
                    severity_score = float(severity_value)
                    if 0.0 <= severity_score <= 1.0:
                        severity_score *= 10.0
                except (TypeError, ValueError):
                    severity_score = 1.0

                merged_nodes.append({
                    "id": node_id,
                    "label": db_node.get("label") or node_id,
                    "type": str(db_node.get("type") or "asset"),
                    "data": {
                        "severity": max(0.0, min(10.0, severity_score)),
                        "raw_severity": str(payload.get("raw_severity", "info")),
                        "exposure": _float_or(payload.get("exposure", 0.5), 0.5),
                        "exploitability": _float_or(payload.get("exploitability", 0.5), 0.5),
                        "privilege_gain": _float_or(payload.get("privilege_gain", 0.1), 0.1),
                        "asset_value": _float_or(payload.get("asset_value", 5.0), 5.0),
                        "pressure_source": str(payload.get("pressure_source", "snapshot")),
                        "revision": _int_or(payload.get("revision", 2), 2),
                        "description": str(payload.get("description", "")),
                        "mass": _float_or(payload.get("mass", 8.0), 8.0),
                        "charge": _float_or(payload.get("charge", 15.0), 15.0),
                        "temperature": _float_or(payload.get("temperature", 0.0), 0.0),
                        "structural": bool(payload.get("structural", False)),
                        "is_entry_node": bool(payload.get("is_entry_node", False)),
                        "is_leaf_node": bool(payload.get("is_leaf_node", False)),
                    },
                })
                existing_node_ids.add(node_id)

            dto["nodes"] = merged_nodes
            dto["count"]["nodes"] = len(merged_nodes)

        if db_edges:
            logger.info(f"[CausalGraph] Adding {len(db_edges)} persisted edges from database")
            merged_edges = list(dto.get("edges", []))
            existing_keys = {
                (
                    str(edge.get("source", "")),
                    str(edge.get("target", "")),
                    str(edge.get("type", "")),
                    str((edge.get("data") or {}).get("relationship_raw", "")),
                )
                for edge in merged_edges
            }

            for db_edge in db_edges:
                source_id = str(db_edge.get("source", ""))
                target_id = str(db_edge.get("target", ""))
                raw_type = str(db_edge.get("type", "enables"))
                if not source_id or not target_id:
                    continue
                # Do not backflow decision-layer edges into the finding graph.
                if source_id not in existing_node_ids or target_id not in existing_node_ids:
                    continue

                db_data = db_edge.get("data") if isinstance(db_edge.get("data"), dict) else {}
                canonical_type = builder._canonical_edge_type(raw_type, db_data)
                edge_key = (source_id, target_id, canonical_type, raw_type)
                if edge_key in existing_keys:
                    continue

                confidence = db_data.get("confidence")
                if confidence is None:
                    try:
                        confidence = min(1.0, max(0.1, float(db_edge.get("weight", 1.0)) / 2.0))
                    except (TypeError, ValueError):
                        confidence = 0.5

                edge_data = dict(db_data)
                edge_data.setdefault("relationship_raw", raw_type)
                edge_data.setdefault("render_type", canonical_type)
                edge_data.setdefault("confidence", _float_or(confidence, 0.5))
                edge_data.setdefault("created_at", time.time())

                merged_edges.append({
                    "id": str(db_edge.get("id") or f"{source_id}-{target_id}"),
                    "source": source_id,
                    "target": target_id,
                    "type": canonical_type,
                    "weight": _float_or(db_edge.get("weight", 1.0), 1.0),
                    "data": edge_data,
                })
                existing_keys.add(edge_key)

            dto["edges"] = merged_edges
            dto["count"]["edges"] = len(merged_edges)
            logger.info(f"[CausalGraph] Final graph: {dto['count']['nodes']} nodes, {dto['count']['edges']} edges")
        else:
            logger.info(f"[CausalGraph] No persisted edges found in database for session {session_id}")

        dto["decision_layer"] = decision_layer
        _graph_dto_cache[session_id] = {
            "signature": cache_signature,
            "dto": copy.deepcopy(dto),
            "built_at": now,
        }
        if len(_graph_dto_cache) > 32:
            oldest_key = min(
                _graph_dto_cache.keys(),
                key=lambda key: float(_graph_dto_cache.get(key, {}).get("built_at", 0.0)),
            )
            _graph_dto_cache.pop(oldest_key, None)

        return dto
