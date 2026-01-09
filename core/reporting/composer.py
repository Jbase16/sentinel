from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from .types import ReportArtifact, iso_now


class ReportComposer:
    """
    Aggregates Sentinel intelligence into a structured JSON report and a Markdown rendering.

    This class deliberately avoids depending on specific internal store schemas:
    it expects "store-like" objects passed in with minimal callable surfaces.
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
        analysis = self._safe_graph_analysis(include_attack_paths=include_attack_paths, max_paths=max_paths)

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
            content = json.dumps(structured, indent=2, sort_keys=False)
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

    # --------- Store adapters (best-effort) ---------

    def _safe_list_findings(self) -> List[Dict[str, Any]]:
        store = self._finding_store
        # Try common method names without inventing deep schema
        for method_name in ("list_findings", "all_findings", "get_all", "list"):
            m = getattr(store, method_name, None)
            if callable(m):
                out = m()
                return self._coerce_list_of_dicts(out, label="findings")
        return []

    def _safe_list_evidence(self) -> List[Dict[str, Any]]:
        ledger = self._evidence_ledger
        for method_name in ("list_entries", "all_entries", "get_all", "list"):
            m = getattr(ledger, method_name, None)
            if callable(m):
                out = m()
                return self._coerce_list_of_dicts(out, label="evidence")
        return []

    def _safe_graph_analysis(self, include_attack_paths: bool, max_paths: int) -> Dict[str, Any]:
        ga = self._graph_analyzer
        analysis: Dict[str, Any] = {}

        # Try to pull “critical paths” and/or an “insights” object if it exists.
        # We do not assume exact method names; we only *use* them if present.
        if include_attack_paths:
            for method_name in ("critical_paths", "get_critical_paths", "compute_critical_paths"):
                m = getattr(ga, method_name, None)
                if callable(m):
                    paths = m(max_paths=max_paths) if "max_paths" in getattr(m, "__code__", {}).co_varnames else m()
                    analysis["attack_paths"] = self._coerce_list_of_dicts(paths, label="attack_paths")
                    break

        for method_name in ("insights", "get_insights", "analyze"):
            m = getattr(ga, method_name, None)
            if callable(m):
                try:
                    out = m()
                    analysis["insights"] = out if isinstance(out, dict) else {"value": out}
                except Exception as e:
                    analysis["insights_error"] = str(e)
                break

        return analysis

    def _coerce_list_of_dicts(self, out: Any, label: str) -> List[Dict[str, Any]]:
        if out is None:
            return []
        if isinstance(out, list):
            coerced: List[Dict[str, Any]] = []
            for item in out:
                if isinstance(item, dict):
                    coerced.append(item)
                else:
                    coerced.append({"value": item})
            return coerced
        if isinstance(out, dict):
            # Some APIs return {"items":[...]}
            if "items" in out and isinstance(out["items"], list):
                return self._coerce_list_of_dicts(out["items"], label=label)
            return [out]
        return [{"value": out}]

    # --------- Rendering ---------

    def _build_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(findings)
        by_risk: Dict[str, int] = {}
        for f in findings:
            risk = str(f.get("risk") or f.get("severity") or "unknown").lower()
            by_risk[risk] = by_risk.get(risk, 0) + 1
        return {"total_findings": total, "by_risk": dict(sorted(by_risk.items(), key=lambda kv: kv[0]))}

    def _render_markdown(self, structured: Dict[str, Any]) -> str:
        lines: List[str] = []
        lines.append(f"# Sentinel Report")
        lines.append("")
        lines.append(f"- **Report ID:** `{structured['report_id']}`")
        lines.append(f"- **Created:** `{structured['created_at']}`")
        lines.append(f"- **Target:** `{structured['target']}`")
        if structured.get("scope"):
            lines.append(f"- **Scope:** {structured['scope']}")
        lines.append("")

        summary = structured.get("summary", {})
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- Total findings: **{summary.get('total_findings', 0)}**")
        by_risk = summary.get("by_risk", {})
        if isinstance(by_risk, dict) and by_risk:
            for k, v in by_risk.items():
                lines.append(f"  - {k}: **{v}**")
        else:
            lines.append("- Risk breakdown: *(none)*")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        findings = structured.get("findings", [])
        if not findings:
            lines.append("_No findings available._")
        else:
            for f in findings:
                fid = f.get("id") or f.get("finding_id") or "unknown"
                title = f.get("title") or f.get("name") or f.get("type") or "Finding"
                risk = f.get("risk") or f.get("severity") or "unknown"
                host = f.get("host") or f.get("hostname") or ""
                port = f.get("port")
                loc = f"{host}:{port}" if host and port else (host or "")
                lines.append(f"### `{fid}` — {title}")
                lines.append(f"- **Risk:** `{risk}`")
                if loc:
                    lines.append(f"- **Location:** `{loc}`")
                if f.get("description"):
                    lines.append(f"- **Description:** {f['description']}")
                lines.append("")

        lines.append("## Evidence")
        lines.append("")
        evidence = structured.get("evidence", [])
        if not evidence:
            lines.append("_No evidence entries available._")
        else:
            for e in evidence:
                eid = e.get("id") or e.get("evidence_id") or "unknown"
                etype = e.get("type") or "evidence"
                ts = e.get("timestamp") or e.get("created_at") or ""
                lines.append(f"- `{eid}` **{etype}** {f'({ts})' if ts else ''}".rstrip())
                if e.get("summary"):
                    lines.append(f"  - {e['summary']}")

        lines.append("")
        lines.append("## Attack Path Analysis")
        lines.append("")
        analysis = structured.get("analysis", {}) or {}
        paths = analysis.get("attack_paths") or []
        if not paths:
            lines.append("_No attack paths available (or analyzer did not expose them)._")
        else:
            for i, p in enumerate(paths, start=1):
                lines.append(f"### Path {i}")
                if isinstance(p, dict):
                    if "nodes" in p:
                        nodes = p.get("nodes") or []
                        lines.append(f"- Nodes: `{ ' -> '.join(map(str, nodes)) }`" if nodes else "- Nodes: *(none)*")
                    if "risk" in p:
                        lines.append(f"- Path risk: `{p.get('risk')}`")
                    if "pressure" in p:
                        lines.append(f"- Pressure: `{p.get('pressure')}`")
                else:
                    lines.append(f"- {p}")
                lines.append("")

        return "\n".join(lines).strip() + "\n"
