# core/reasoning.py — derives attack paths and phase recommendations

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from core.data.findings import findings_store
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store


class ReasoningEngine:
    def analyze(self) -> Dict[str, object]:
        findings = findings_store.get_all()
        issues = issues_store.get_all()
        edges = killchain_store.get_all()

        attack_paths = self._build_attack_paths(edges)
        degraded_paths = [path for path in attack_paths if any("behavior" in node for node in path)]
        recommendations = self._recommend_phases(findings, issues)

        issues_summary = [
            {
                "title": issue.get("title"),
                "severity": issue.get("severity"),
                "target": issue.get("target"),
                "tags": issue.get("tags", []),
            }
            for issue in issues
        ]

        return {
            "attack_paths": attack_paths,
            "degraded_paths": degraded_paths,
            "recommended_phases": recommendations,
            "issues": issues_summary,
        }

    def _build_attack_paths(self, edges: List[dict]) -> List[List[str]]:
        graph = defaultdict(list)
        for edge in edges:
            src = edge.get("source") or "unknown"
            tgt = edge.get("target") or "issue"
            graph[src].append(tgt)

        paths: List[List[str]] = []

        def dfs(node: str, visited: List[str]):
            if node in visited:
                return
            visited.append(node)
            if node not in graph:
                paths.append(list(visited))
            else:
                for nxt in graph[node]:
                    dfs(nxt, visited)
            visited.pop()

        for src in list(graph.keys()):
            dfs(src, [])
        return paths

    def _recommend_phases(self, findings: List[dict], issues: List[dict]) -> List[str]:
        recommended: List[str] = []
        tags = {tag for f in findings for tag in f.get("tags", [])}
        issue_tags = {tag for issue in issues for tag in issue.get("tags", [])}

        if "timing-anomaly" in tags and "waf-bypass" not in issue_tags:
            recommended.append("Expand timing probes with payload variance to detect auth/rate-limit bypasses.")
        if "tls-probe" in tags:
            recommended.append("Perform in-depth TLS/cert audit and map reachable ciphers per asset.")
        if "secret-leak" in issue_tags:
            recommended.append("Trigger credential rotation workflow and search for additional leaked artifacts.")
        if "api" in tags:
            recommended.append("Schedule API diff analysis (param-fuzz and replay) for exposed endpoints.")

        return recommended


reasoning_engine = ReasoningEngine()
