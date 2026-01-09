from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from .types import ReportArtifact, iso_now


class ReportComposer:
    """
    Aggregates Sentinel intelligence into a structured JSON report and a Markdown rendering.
    """

    def __init__(
        self,
        finding_store: Any,
        evidence_ledger: Any,
        graph_analyzer: Any,
    ) -> None:
        self._finding_store = finding_store
        self._evidence_ledger = evidence_ledger
        self._graph_analyzer = graph_analyzer

    def generate(
        self,
        target: str,
        scope: Optional[str] = None,
        report_format: str = "markdown",
        include_attack_paths: bool = True,
        max_paths: int = 5,
    ) -> ReportArtifact:
        report_id = str(uuid.uuid4())
        created_at = iso_now()

        findings = self._safe_list_findings()
        evidence = self._safe_list_evidence()
        analysis = self._safe_graph_analysis(include_attack_paths, max_paths)

        structured = {
            "report_id": report_id,
            "created_at": created_at,
            "target": target,
            "scope": scope,
            "summary": self._build_summary(findings),
            "findings": findings,
            "evidence": evidence,
            "analysis": analysis,
        }

        if report_format.lower() == "json":
            content = json.dumps(structured, indent=2)
            fmt = "json"
        else:
            content = self._render_markdown(structured)
            fmt = "markdown"

        return ReportArtifact(
            report_id=report_id,
            created_at=created_at,
            target=target,
            scope=scope,
            format=fmt,
            content=content,
        )

    def _safe_list_findings(self) -> List[Dict[str, Any]]:
        for name in ("get_all", "list", "all_findings"):
            m = getattr(self._finding_store, name, None)
            if callable(m):
                return list(m())
        return []

    def _safe_list_evidence(self) -> List[Dict[str, Any]]:
        for name in ("get_all", "list", "all_entries"):
            m = getattr(self._evidence_ledger, name, None)
            if callable(m):
                return list(m())
        return []

    def _safe_graph_analysis(self, include_attack_paths: bool, max_paths: int) -> Dict[str, Any]:
        ga = self._graph_analyzer
        out: Dict[str, Any] = {}
        if include_attack_paths:
            m = getattr(ga, "critical_paths", None)
            if callable(m):
                out["attack_paths"] = m(max_paths=max_paths)
        return out

    def _build_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_risk: Dict[str, int] = {}
        for f in findings:
            risk = str(f.get("risk", "unknown")).lower()
            by_risk[risk] = by_risk.get(risk, 0) + 1
        return {"total_findings": len(findings), "by_risk": by_risk}

    def _render_markdown(self, structured: Dict[str, Any]) -> str:
        return json.dumps(structured, indent=2)
