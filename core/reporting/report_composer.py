from __future__ import annotations

import json
import textwrap
import uuid
from typing import Any, Dict, List, Optional

from .types import ReportArtifact, iso_now

# Severity ordering for sort and badge rendering
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SEVERITY_BADGE = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
    "info":     "🔵 INFO",
}


def _finding_heading(finding: Dict[str, Any]) -> str:
    """Compose a finding heading as ``type: distinguishing-detail`` so
    multiple findings of the same type (7 missing headers, 4 open ports)
    render distinct, useful headings instead of 7 identical 'Missing
    Security Header' lines."""
    ftype = finding.get("type") or "Finding"
    meta = finding.get("metadata") or {}
    detail = ""
    if meta.get("header"):
        detail = str(meta["header"])
    elif meta.get("port") is not None:
        detail = f"port {meta['port']}"
    elif meta.get("version"):
        detail = f"v{meta['version']}"
    else:
        msg = (finding.get("message") or "").strip()
        # Use a short, single-line message as the detail.
        if msg and len(msg) <= 60 and "\n" not in msg and msg.lower() != str(ftype).lower():
            detail = msg
    return f"{ftype}: {detail}" if detail else str(ftype)


def _as_entry_list(result: Any) -> List[Dict[str, Any]]:
    """Normalize a store's "list-everything" return into a list of dict entries.

    Stores expose this differently:
      - some return a list of entry dicts
      - EvidenceStore.get_all() returns a DICT keyed by entry id

    ``list(some_dict)`` returns the dict's KEYS (ids), not the entries —
    which is what crashed report generation (an int id reached
    ``ev.get("type")``). We take ``.values()`` for dicts, and defensively
    keep only dict-shaped entries so a stray scalar can never reach the
    renderer's ``.get()`` calls.
    """
    if isinstance(result, dict):
        items = list(result.values())
    else:
        try:
            items = list(result)
        except TypeError:
            return []
    return [item for item in items if isinstance(item, dict)]


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
                return _as_entry_list(m())
        return []

    def _safe_list_evidence(self) -> List[Dict[str, Any]]:
        for name in ("get_all", "list", "all_entries"):
            m = getattr(self._evidence_ledger, name, None)
            if callable(m):
                return _as_entry_list(m())
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
            # Findings carry `severity` ("MEDIUM"/"INFO"); older shapes used
            # `risk`. Read severity first, fall back to risk — reading only
            # `risk` made every finding "unknown" and produced an EMPTY
            # severity table even with 17 findings (Calibration Run #21).
            risk = str(f.get("severity") or f.get("risk") or "unknown").lower()
            by_risk[risk] = by_risk.get(risk, 0) + 1
        return {"total_findings": len(findings), "by_risk": by_risk}

    # ------------------------------------------------------------------
    # Markdown renderer — actual implementation
    # ------------------------------------------------------------------

    def _render_markdown(self, structured: Dict[str, Any]) -> str:
        """
        Render the structured report dict as a real Markdown bug bounty report.

        Sections:
          1. Header + metadata
          2. Executive Summary (severity breakdown table)
          3. Findings (one subsection per finding, sorted by severity)
          4. Evidence (request/response pairs if available)
          5. Attack Paths (if graph analysis produced any)
          6. Appendix: scan metadata
        """
        lines: List[str] = []

        target = structured.get("target", "Unknown Target")
        created_at = structured.get("created_at", "")
        report_id = structured.get("report_id", "")
        scope = structured.get("scope")
        summary = structured.get("summary", {})
        findings: List[Dict[str, Any]] = structured.get("findings", [])
        evidence: List[Dict[str, Any]] = structured.get("evidence", [])
        analysis: Dict[str, Any] = structured.get("analysis", {})

        # ── 1. Header ─────────────────────────────────────────────────────
        lines.append(f"# Security Assessment Report: {target}")
        lines.append("")
        lines.append(f"**Date:** {created_at[:10] if created_at else 'N/A'}  ")
        lines.append(f"**Report ID:** `{report_id}`  ")
        if scope:
            lines.append(f"**Scope:** {scope}  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── 2. Executive Summary ──────────────────────────────────────────
        lines.append("## Executive Summary")
        lines.append("")
        total = summary.get("total_findings", len(findings))
        by_risk: Dict[str, int] = summary.get("by_risk", {})

        if total == 0:
            lines.append(
                "> No findings were identified during this assessment. "
                "This may indicate the scan did not complete, the target was "
                "unreachable, or the target is well-hardened."
            )
        else:
            lines.append(
                f"This assessment of **{target}** identified **{total} finding(s)** "
                f"across the following severity categories:"
            )
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|------:|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_risk.get(sev, 0)
                if count:
                    badge = _SEVERITY_BADGE.get(sev, sev.upper())
                    lines.append(f"| {badge} | {count} |")
            lines.append("")

        lines.append("---")
        lines.append("")

        # ── 3. Findings ────────────────────────────────────────────────────
        lines.append("## Findings")
        lines.append("")

        if not findings:
            lines.append("_No findings to report._")
            lines.append("")
        else:
            # Sort by severity
            sorted_findings = sorted(
                findings,
                key=lambda f: _SEVERITY_ORDER.get(
                    str(f.get("risk") or f.get("severity") or "unknown").lower(), 5
                ),
            )

            for idx, f in enumerate(sorted_findings, start=1):
                sev_raw = str(f.get("risk") or f.get("severity") or "unknown").lower()
                badge = _SEVERITY_BADGE.get(sev_raw, sev_raw.upper())
                # Heading: prefer an explicit title, else compose type +
                # distinguishing detail so 7 "Missing Security Header" findings
                # don't render as 7 identical headings (Calibration Run #21).
                title = f.get("title") or f.get("name") or _finding_heading(f) or f"Finding #{idx}"
                finding_id = f.get("id") or f.get("finding_id") or ""
                target_url = f.get("target") or f.get("asset") or f.get("url") or target
                tool = f.get("tool") or f.get("source") or ""
                description = f.get("description") or f.get("summary") or ""
                remediation = f.get("remediation") or f.get("fix") or ""
                cvss_score = f.get("cvss_score") or f.get("cvss") or ""
                cvss_vector = f.get("cvss_vector") or ""
                duplicate_info = f.get("duplicate_info") or ""
                steps = f.get("steps_to_reproduce") or []
                poc = f.get("poc") or f.get("proof_of_concept") or ""
                references = f.get("references") or []

                lines.append(f"### {idx}. {title}")
                lines.append("")

                # Metadata table
                lines.append("| Field | Value |")
                lines.append("|-------|-------|")
                lines.append(f"| **Severity** | {badge} |")
                if finding_id:
                    lines.append(f"| **Finding ID** | `{finding_id}` |")
                lines.append(f"| **Target** | `{target_url}` |")
                if tool:
                    lines.append(f"| **Detected By** | {tool} |")
                if cvss_score:
                    lines.append(f"| **CVSS Score** | {cvss_score} |")
                if cvss_vector:
                    lines.append(f"| **CVSS Vector** | `{cvss_vector}` |")
                if duplicate_info:
                    lines.append(f"| **Dedup Status** | {duplicate_info} |")
                lines.append("")

                if description:
                    lines.append("**Description**")
                    lines.append("")
                    # Wrap long descriptions cleanly
                    for para in description.split("\n"):
                        lines.append(para)
                    lines.append("")

                if steps:
                    lines.append("**Steps to Reproduce**")
                    lines.append("")
                    if isinstance(steps, list):
                        for step_idx, step in enumerate(steps, start=1):
                            lines.append(f"{step_idx}. {step}")
                    else:
                        lines.append(str(steps))
                    lines.append("")

                if poc:
                    lines.append("**Proof of Concept**")
                    lines.append("")
                    lines.append("```")
                    lines.append(str(poc))
                    lines.append("```")
                    lines.append("")

                if remediation:
                    lines.append("**Remediation**")
                    lines.append("")
                    for para in remediation.split("\n"):
                        lines.append(para)
                    lines.append("")

                if references:
                    lines.append("**References**")
                    lines.append("")
                    if isinstance(references, list):
                        for ref in references:
                            if isinstance(ref, str) and ref.startswith("http"):
                                lines.append(f"- <{ref}>")
                            else:
                                lines.append(f"- {ref}")
                    else:
                        lines.append(f"- {references}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # ── 4. Evidence ────────────────────────────────────────────────────
        # Cap the rendered evidence list. A scan can capture hundreds/thousands
        # of artifacts (one per tool observation); dumping all of them buries
        # the report. Show the first N and summarize the remainder.
        _EVIDENCE_RENDER_CAP = 25
        if evidence:
            total_ev = len(evidence)
            shown = evidence[:_EVIDENCE_RENDER_CAP]
            lines.append("## Evidence")
            lines.append("")
            if total_ev > _EVIDENCE_RENDER_CAP:
                lines.append(
                    f"{total_ev} evidence artifact(s) were captured; showing the "
                    f"first {_EVIDENCE_RENDER_CAP}:"
                )
            else:
                lines.append(
                    f"The following {total_ev} evidence artifact(s) were captured during the assessment:"
                )
            lines.append("")
            for ev in shown:
                if not isinstance(ev, dict):
                    # Defensive: never call .get() on a non-dict entry
                    # (this is exactly what crashed report generation before).
                    continue
                # Evidence entries from EvidenceStore carry tool/summary/id;
                # fall back to the older type/description/url shape if present.
                ev_type = ev.get("type") or ev.get("tool") or "artifact"
                ev_desc = (
                    ev.get("description")
                    or ev.get("summary")
                    or ev.get("url")
                    or ""
                )
                ev_id = ev.get("id") or ""
                lines.append(f"- **{str(ev_type).upper()}**{': ' + str(ev_desc) if ev_desc else ''}"
                              f"{' (`' + str(ev_id) + '`)' if ev_id else ''}")
            if total_ev > _EVIDENCE_RENDER_CAP:
                lines.append(f"- _… and {total_ev - _EVIDENCE_RENDER_CAP} more artifact(s) "
                             f"(full set available in the scan record)._")
            lines.append("")
            lines.append("---")
            lines.append("")

        # ── 5. Attack Paths ────────────────────────────────────────────────
        attack_paths = analysis.get("attack_paths", [])
        if attack_paths:
            lines.append("## Attack Paths")
            lines.append("")
            lines.append(
                "The following attack paths were identified by graph analysis, "
                "ordered by estimated impact:"
            )
            lines.append("")
            for path_idx, path in enumerate(attack_paths, start=1):
                if isinstance(path, dict):
                    path_name = path.get("name") or path.get("title") or f"Path {path_idx}"
                    path_nodes = path.get("nodes") or path.get("steps") or []
                    path_score = path.get("score") or path.get("risk_score") or ""
                    lines.append(f"### Attack Path {path_idx}: {path_name}")
                    if path_score:
                        lines.append(f"**Risk Score:** {path_score}")
                        lines.append("")
                    if path_nodes:
                        for node in path_nodes:
                            lines.append(f"→ {node}")
                        lines.append("")
                else:
                    lines.append(f"{path_idx}. {path}")
                    lines.append("")
            lines.append("---")
            lines.append("")

        # ── 6. Appendix ────────────────────────────────────────────────────
        lines.append("## Appendix")
        lines.append("")
        lines.append("### Scan Metadata")
        lines.append("")
        lines.append(f"- **Target:** {target}")
        lines.append(f"- **Scan Completed:** {created_at}")
        lines.append(f"- **Report ID:** `{report_id}`")
        if scope:
            lines.append(f"- **Scope:** {scope}")
        lines.append(f"- **Total Findings:** {total}")
        lines.append("")
        lines.append(
            "_This report was generated by SentinelForge. "
            "All findings should be independently verified before submission. "
            "Severity ratings are based on CVSS 3.1 scoring._"
        )
        lines.append("")

        return "\n".join(lines)
