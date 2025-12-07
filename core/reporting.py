# core/reporting.py — report bundle generation utilities

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

from core.findings import findings_store
from core.issues_store import issues_store
from core.killchain_store import killchain_store
from core.risk import risk_engine
from core.reasoning import reasoning_engine


@dataclass
class ReportBundle:
    folder: str
    markdown_path: str
    json_path: str


from core.ai_engine import AIEngine

# ...

def create_report_bundle(base_dir: str = "reports") -> ReportBundle:
    """
    Export findings/issues/killchain data plus reasoning summary into markdown + JSON files.
    Returns the created bundle metadata.
    """
    os.makedirs(base_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    bundle_dir = os.path.join(base_dir, f"bundle-{timestamp}")
    os.makedirs(bundle_dir, exist_ok=True)

    findings = findings_store.get_all()
    issues = issues_store.get_all()
    risk_scores = risk_engine.get_scores()
    reasoning = reasoning_engine.analyze()
    edges = killchain_store.get_all()

    summary = {
        "generated_at": timestamp,
        "findings_count": len(findings),
        "issues_count": len(issues),
        "risk_scores": risk_scores,
        "reasoning": reasoning,
        "killchain_edges": edges,
    }

    # Generate AI Narrative Report if available
    ai_report = ""
    try:
        ai_engine = AIEngine.instance()
        if ai_engine.client:
            ai_report = ai_engine.generate_report_narrative(findings, issues)
    except Exception as e:
        ai_report = f"AI Report Generation Failed: {e}"

    markdown = _render_markdown(summary, findings, issues, ai_report)

    md_path = os.path.join(bundle_dir, "report.md")
    json_path = os.path.join(bundle_dir, "report.json")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown)

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    return ReportBundle(folder=bundle_dir, markdown_path=md_path, json_path=json_path)


def _render_markdown(summary: Dict, findings: List[dict], issues: List[dict], ai_report: str = "") -> str:
    lines = [
        "# AraUltra Report Bundle",
        "",
        f"- Generated: {summary['generated_at']} UTC",
        f"- Total Findings: {summary['findings_count']}",
        f"- Correlated Issues: {summary['issues_count']}",
        "",
    ]
    
    if ai_report:
        lines.append("## Executive Summary (AI Generated)")
        lines.append(ai_report)
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Top Assets by Risk")
    # ... (rest of the function)

    risk_scores = summary["risk_scores"]
    if risk_scores:
        for asset, score in sorted(risk_scores.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"- **{asset}** — score {score:.1f}")
    else:
        lines.append("- No risk data available yet.")

    lines.append("")
    lines.append("## Correlated Issues")
    if issues:
        for issue in issues:
            lines.extend([
                f"### {issue.get('title', issue.get('type', 'Issue'))}",
                f"- Target: {issue.get('target') or issue.get('asset') or 'unknown'}",
                f"- Severity: {issue.get('severity', 'INFO')}",
                f"- Tags: {', '.join(issue.get('tags', [])) or '—'}",
                f"- Description: {issue.get('description', issue.get('message', ''))}",
                ""
            ])
    else:
        lines.append("- No correlated issues yet.")

    lines.append("## Reasoning Snapshot")
    reasoning = summary["reasoning"]
    attack_paths = reasoning.get("attack_paths") or []
    if attack_paths:
        lines.append("### Attack Paths")
        for idx, path in enumerate(attack_paths, 1):
            lines.append(f"{idx}. " + " → ".join(path))
    else:
        lines.append("- No attack paths derived.")

    recommendations = reasoning.get("recommended_phases") or []
    lines.append("")
    lines.append("### Recommended Phases")
    if recommendations:
        for rec in recommendations:
            lines.append(f"- {rec}")
    else:
        lines.append("- No additional phases recommended.")

    lines.append("")
    lines.append("## Killchain Edges")
    edges = summary["killchain_edges"]
    if edges:
        for edge in edges[:50]:
            lines.append(
                f"- {edge.get('source')} → {edge.get('target')} | "
                f"{edge.get('severity')} | {edge.get('label') or edge.get('signal')}"
            )
        if len(edges) > 50:
            lines.append(f"- … {len(edges) - 50} more edges omitted")
    else:
        lines.append("- No killchain edges yet.")

    lines.append("")
    lines.append("## Raw Findings Snapshot (first 20)")
    for finding in findings[:20]:
        lines.append(
            f"- {finding.get('target')} | {finding.get('tool')} | "
            f"{finding.get('type')} | {finding.get('severity')}"
        )
    if len(findings) > 20:
        lines.append(f"- … {len(findings) - 20} more findings omitted")

    return "\n".join(lines) + "\n"
