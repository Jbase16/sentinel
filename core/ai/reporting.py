"""Module reporting: inline documentation for /Users/jason/Developer/sentinelforge/core/ai/reporting.py."""
#
# PURPOSE:
# Transforms raw security findings into professional penetration testing reports.
# Uses AI to write narrative explanations instead of just listing vulnerabilities.
#
# WHY AI-DRIVEN REPORTS:
# - Explains the "so what?" of findings (business impact)
# - Connects findings into attack chains (shows exploitation path)
# - Tailors language for different audiences (executives vs. technical teams)
# - Generates remediation roadmaps (prioritized fix recommendations)
#
# REPORT SECTIONS:
# 1. Executive Summary: High-level overview for leadership
# 2. Attack Narrative: Story of how findings could be chained
# 3. Technical Findings: Detailed vulnerability descriptions
# 4. Risk Assessment: Severity scoring and impact analysis
# 5. Remediation Roadmap: Prioritized fix recommendations
#
# HOW IT WORKS:
# - Gathers all findings, issues, and kill chain data
# - Feeds context to AI with specific prompts for each section
# - AI generates professional Markdown content
# - Falls back to template-based content if AI unavailable
#

from __future__ import annotations

import json
import os
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Any, Tuple

from core.data.findings_store import findings_store
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store
from core.data.risk import risk_engine
from core.cortex.reasoning import reasoning_engine
from core.ai.ai_engine import AIEngine
from core.scheduler.decisions import get_decision_ledger, DecisionType

logger = logging.getLogger(__name__)

@dataclass
class ReportBundle:
    """Class ReportBundle."""
    folder: str
    markdown_path: str
    json_path: str

class ReportComposer:
    """
    AI-driven 'Investigative Journalist' for security reporting.
    Generates semantic narratives rather than just listing bugs.
    """

    SECTIONS = [
        "executive_summary",
        "attack_narrative",
        "technical_findings",
        "risk_assessment",
        "remediation_roadmap"
    ]

    def __init__(self, session=None):
        """Function __init__."""
        self.ai = AIEngine.instance()
        self.session = session

    async def _build_attack_path_contract(
        self,
        context: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Build canonical attack-path contract for report generation.
        """
        from core.cortex.attack_path_contract import build_attack_path_contract

        session_id = str(
            context.get("session_id")
            or getattr(self.session, "id", "")
            or ""
        ).strip()
        if not session_id:
            return build_attack_path_contract(session_id="unknown", graph_dto={}), {}

        findings = context.get("findings", [])
        issues = context.get("issues", [])
        if not isinstance(findings, list):
            findings = []
        if not isinstance(issues, list):
            issues = []

        graph_dto: Dict[str, Any] = {}
        try:
            from core.cortex.causal_graph import get_graph_dto_for_session

            graph_dto = await get_graph_dto_for_session(
                session_id=session_id,
                findings=findings,
                issues=issues,
            )
        except Exception as exc:
            logger.debug("[ReportComposer] Failed to build graph DTO for attack narrative: %s", exc)

        contract = build_attack_path_contract(
            session_id=session_id,
            graph_dto=graph_dto,
        )
        return contract, graph_dto

    def _render_attack_narrative_from_contract(
        self,
        contract: Dict[str, Any],
        graph_dto: Dict[str, Any],
    ) -> str:
        """
        Deterministic attack narrative: only graph-validated chains are emitted.
        """
        session_id = str(contract.get("session_id") or "unknown")
        graph_hash = str(contract.get("graph_hash") or "unknown")
        chain_count = int(contract.get("chain_count", 0) or 0)
        chains = contract.get("chains", [])
        if not isinstance(chains, list):
            chains = []

        lines = ["## Attack Narrative", ""]
        lines.append(f"Session: `{session_id}`")
        lines.append(f"Graph Hash: `{graph_hash}`")
        lines.append(f"Graph-Validated Attack Chains: **{chain_count}**")
        lines.append("")

        if chain_count <= 0:
            lines.append(
                "No confirmed attack chain currently exists in the deterministic causal graph."
            )
            lines.append(
                "Potential exploitation stories are intentionally omitted until graph-validated."
            )
            return "\n".join(lines).strip()

        lines.append("Validated Chains:")
        for chain in chains[:10]:
            if not isinstance(chain, dict):
                continue
            chain_id = str(chain.get("id") or "chain")
            labels = chain.get("labels", [])
            if isinstance(labels, list) and labels:
                chain_text = " -> ".join(str(item) for item in labels if str(item))
            else:
                node_ids = chain.get("node_ids", [])
                chain_text = " -> ".join(str(item) for item in node_ids if str(item)) if isinstance(node_ids, list) else ""
            length = int(chain.get("length", 0) or 0)
            score = float(chain.get("score", 0.0) or 0.0)
            lines.append(f"- `{chain_id}` ({length} steps, score={score:.3f}): {chain_text}")

        pressure_points = graph_dto.get("pressure_points", []) if isinstance(graph_dto, dict) else []
        if isinstance(pressure_points, list) and pressure_points:
            lines.append("")
            lines.append("Top Pressure Points:")
            for pp in pressure_points[:5]:
                if not isinstance(pp, dict):
                    continue
                lines.append(
                    f"- {pp.get('finding_title', 'unknown')} "
                    f"(severity={pp.get('severity', 'unknown')}, "
                    f"blocks={pp.get('attack_paths_blocked', 0)} paths)"
                )

        return "\n".join(lines).strip()

    def _apply_attack_path_claim_guard(
        self,
        *,
        text: str,
        contract: Dict[str, Any],
        context_label: str,
    ) -> str:
        """
        Enforce graph-truth for report section text.
        """
        from core.cortex.attack_path_contract import sanitize_attack_path_claims

        result = sanitize_attack_path_claims(
            text,
            contract,
            require_chain_ids=True,
        )
        if bool(result.get("modified")):
            logger.warning(
                "[ReportComposer] Attack-path guard applied (%s): reason=%s removed=%s chain_count=%s",
                context_label,
                result.get("reason", "unknown"),
                result.get("removed_claims", 0),
                result.get("chain_count", 0),
            )
        return str(result.get("text") or "").strip()

    async def generate_section(self, section_name: str, context_override: Optional[Dict] = None) -> str:
        """
        Generates a specific section of the report using the LLM.
        """
        # Conditional branch.
        if section_name not in self.SECTIONS:
            return f"Error: Unknown section '{section_name}'"

        context = context_override or self._gather_context()
        attack_path_contract, graph_dto = await self._build_attack_path_contract(context)
        if isinstance(context, dict):
            context = dict(context)
            context["attack_path_contract"] = attack_path_contract
            context["graph_dto"] = graph_dto

        # Contract guardrail: attack narrative must be deterministic and graph-bound.
        if section_name == "attack_narrative":
            return self._render_attack_narrative_from_contract(attack_path_contract, graph_dto)

        prompts = {
            "executive_summary": self._prompt_exec_summary,
            "attack_narrative": self._prompt_attack_narrative,
            "technical_findings": self._prompt_technical,
            "risk_assessment": self._prompt_risk,
            "remediation_roadmap": self._prompt_remediation
        }

        prompt_fn = prompts.get(section_name)
        # Conditional branch.
        if not prompt_fn:
            return "Section not implemented."

        # Conditional branch.
        self.ai.ensure_client()
        if not self.ai.client:
            return self._fallback_content(section_name, context)

        user_prompt = prompt_fn(context)
        system_prompt = (
            "You are a Senior Security Consultant writing a penetration testing report. "
            "Your tone is professional, authoritative, and concise. "
            "Focus on business impact and attack chains, not just lists of bugs. "
            "Use Markdown formatting.\n\n"
            "CRITICAL CONSTRAINTS:\n"
            "- ONLY cite findings, numbers, and details from the provided scan data.\n"
            "- NEVER invent, estimate, or inflate vulnerability counts.\n"
            "- If data is limited, say so honestly — do not pad with generic content.\n"
            "- Do NOT mention internal tool names (Strategos, CAL, Cortex, Ledger, "
            "ScanOrchestrator, VulnRule) — these are implementation details.\n"
            "- Distinguish between CONFIRMED, PROBABLE, and HYPOTHESIZED findings."
        )

        try:
            result = await self.ai.client.generate_text(user_prompt, system_prompt)
            if not result:
                return "AI Generation failed (Empty response)."
            return self._apply_attack_path_claim_guard(
                text=result,
                contract=attack_path_contract,
                context_label=f"report_section:{section_name}",
            )
        except Exception as e:
            logger.error(f"[ReportComposer] AI generation failed for {section_name}: {e}")
            return self._fallback_content(section_name, context)

    async def generate_async(
        self,
        report_type: str = "full",
        format: str = "markdown",
        context_override: Optional[Dict] = None,
    ) -> str:
        """
        Generate a complete report asynchronously.

        Args:
            report_type: Type of report ('full', 'executive', 'technical')
            format: Output format ('markdown', 'json')

        Returns:
            Complete report content as string
        """
        logger.info(f"[ReportComposer] Generating {report_type} report in {format} format")

        # Determine which sections to include
        sections_to_generate = self.SECTIONS
        if report_type == "executive":
            sections_to_generate = ["executive_summary", "risk_assessment"]
        elif report_type == "technical":
            sections_to_generate = ["technical_findings", "attack_narrative", "remediation_roadmap"]

        # Generate all sections
        full_report = ""
        for section in sections_to_generate:
            logger.info(f"[ReportComposer] Generating section: {section}")
            section_content = await self.generate_section(section, context_override=context_override)
            full_report += f"\n\n{section_content}"

        # Format output
        if format == "json":
            return json.dumps({
                "type": report_type,
                "generated_at": datetime.utcnow().isoformat(),
                "sections": {
                    section: await self.generate_section(section, context_override=context_override)
                    for section in sections_to_generate
                }
            }, indent=2)

        return full_report.strip()

    def _gather_context(self) -> Dict:
        """Collect all available context for report generation.

        Reads from session stores when a session is attached, otherwise global
        stores (findings, issues, risk, killchain, reasoning).
        Each source is fetched defensively — a single store failure won't
        take down the whole report.
        """
        ctx: Dict = {
            "session_id": getattr(self.session, "id", None) if self.session else None,
            "findings": [],
            "issues": [],
            "risk": {},
            "killchain": [],
            "reasoning": {},
            "decisions": [],
        }
        try:
            if self.session:
                ctx["findings"] = self.session.findings.get_all()
            else:
                ctx["findings"] = findings_store.get_all()
        except Exception as exc:
            logger.warning("[ReportComposer] findings_store.get_all() failed: %s", exc)
        try:
            if self.session:
                ctx["issues"] = self.session.issues.get_all()
            else:
                ctx["issues"] = issues_store.get_all()
        except Exception as exc:
            logger.warning("[ReportComposer] issues_store.get_all() failed: %s", exc)
        try:
            ctx["risk"] = risk_engine.get_scores()
        except Exception as exc:
            logger.warning("[ReportComposer] risk_engine.get_scores() failed: %s", exc)
        try:
            if self.session:
                ctx["killchain"] = self.session.killchain.get_all()
            else:
                ctx["killchain"] = killchain_store.get_all()
        except Exception as exc:
            logger.warning("[ReportComposer] killchain_store.get_all() failed: %s", exc)
        try:
            ctx["reasoning"] = reasoning_engine.analyze()
        except Exception as exc:
            logger.warning("[ReportComposer] reasoning_engine.analyze() failed: %s", exc)
        try:
            ledger = get_decision_ledger()
            ctx["decisions"] = [
                d.to_event_payload()
                for d in ledger.get_all()
                if d.type in (DecisionType.INTENT_TRANSITION, DecisionType.PHASE_TRANSITION, DecisionType.ASSESSMENT)
            ]
        except Exception as exc:
            logger.warning("[ReportComposer] decision_ledger failed: %s", exc)
        return ctx

    # --- Helpers ---

    @staticmethod
    def _format_issues_block(issues: list, limit: int = 20) -> str:
        """Format enriched issues into a compact text block for prompts."""
        if not issues:
            return "(No enriched issues available.)\n"
        lines = []
        for issue in issues[:limit]:
            conf = issue.get("confirmation_level", "unknown").upper()
            caps = ", ".join(issue.get("capability_types", []))
            score = issue.get("score", "?")
            target = issue.get("target", "unknown")
            n_evidence = len(issue.get("supporting_findings", []))
            lines.append(
                f"- [{conf}] {issue.get('title', 'Untitled')} "
                f"(score: {score}, capabilities: [{caps}], "
                f"target: {target}, evidence_count: {n_evidence})"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _format_findings_block(findings: list, limit: int = 30) -> str:
        """Format raw findings into a compact text block for prompts."""
        if not findings:
            return "(No raw findings available.)\n"
        lines = []
        for f in findings[:limit]:
            lines.append(
                f"- [{f.get('severity', '?')}] {f.get('type', 'unknown')}: "
                f"{f.get('message') or f.get('value', '')} "
                f"(target: {f.get('target', 'unknown')}, tool: {f.get('tool', 'unknown')})"
            )
        return "\n".join(lines) + "\n"

    def _build_graph_summary(self, findings: list, issues: list, ctx: Optional[Dict[str, Any]] = None) -> str:
        """Build a causal graph summary string for report prompts."""
        contract = ctx.get("attack_path_contract") if isinstance(ctx, dict) else None
        graph_dto = ctx.get("graph_dto") if isinstance(ctx, dict) else None
        if isinstance(contract, dict):
            try:
                graph_counts = graph_dto.get("count", {}) if isinstance(graph_dto, dict) else {}
                nodes_count = int(graph_counts.get("nodes", 0) or 0)
                edges_count = int(graph_counts.get("edges", 0) or 0)

                chains = contract.get("chains", [])
                if not isinstance(chains, list):
                    chains = []
                chain_count = int(contract.get("chain_count", len(chains)) or 0)
                longest_chain = max(
                    (int(chain.get("length", 0) or 0) for chain in chains if isinstance(chain, dict)),
                    default=0,
                )

                parts = [
                    f"Nodes: {nodes_count}, Edges: {edges_count}",
                    f"Graph-validated attack chains: {chain_count}, Longest chain: {longest_chain} steps",
                ]
                pressure_points = graph_dto.get("pressure_points", []) if isinstance(graph_dto, dict) else []
                for pp in pressure_points[:5] if isinstance(pressure_points, list) else []:
                    if not isinstance(pp, dict):
                        continue
                    parts.append(
                        f"Pressure Point: {pp.get('finding_title', 'unknown')} "
                        f"(severity: {pp.get('severity', 'unknown')}, "
                        f"blocks {pp.get('attack_paths_blocked', 0)} attack paths, "
                        f"centrality: {pp.get('centrality_score', 0)})"
                    )
                for chain in chains[:3]:
                    if not isinstance(chain, dict):
                        continue
                    labels = chain.get("labels", [])
                    if isinstance(labels, list) and labels:
                        chain_text = " → ".join(str(item) for item in labels if str(item))
                    else:
                        node_ids = chain.get("node_ids", [])
                        chain_text = " → ".join(str(item) for item in node_ids if str(item)) if isinstance(node_ids, list) else ""
                    if chain_text:
                        parts.append(f"Chain {chain.get('id', 'chain')}: {chain_text}")
                return "\n".join(f"- {part}" for part in parts) + "\n"
            except Exception as exc:
                logger.debug("[ReportComposer] Canonical graph summary failed: %s", exc)

        try:
            from core.cortex.causal_graph import CausalGraphBuilder
            builder = CausalGraphBuilder()
            builder.build(findings)
            n_enablement = builder.enrich_from_issues(issues)
            summary = builder.export_summary()
            parts = [
                f"Nodes: {summary.get('nodes_count', 0)}, "
                f"Edges: {summary.get('edges_count', 0)} "
                f"({n_enablement} enablement edges)",
                f"Attack chains: {summary.get('attack_chains_count', 0)}, "
                f"Longest chain: {summary.get('longest_chain_length', 0)} steps",
            ]
            for pp in summary.get("top_pressure_points", [])[:5]:
                parts.append(
                    f"Pressure Point: {pp['finding_title']} "
                    f"(severity: {pp['severity']}, "
                    f"blocks {pp['attack_paths_blocked']} attack paths, "
                    f"centrality: {pp['centrality_score']})"
                )
            chains = summary.get("sample_attack_chains", [])
            for chain in chains[:3]:
                parts.append(f"Chain: {' → '.join(chain)}")
            return "\n".join(f"- {p}" for p in parts) + "\n"
        except Exception as exc:
            logger.debug("[ReportComposer] Graph summary failed: %s", exc)
            return "(Causal graph unavailable.)\n"

    # --- Prompts ---

    def _prompt_exec_summary(self, ctx: Dict) -> str:
        issues = ctx.get("issues", [])
        findings = ctx.get("findings", [])
        issues_block = self._format_issues_block(issues, limit=10)
        graph_block = self._build_graph_summary(findings, issues, ctx=ctx)

        return (
            "Write an Executive Summary for a penetration test report.\n\n"
            "STRICT RULES:\n"
            "- ONLY reference findings and issues listed below. Do NOT invent findings.\n"
            "- Use EXACT counts from the data. Do NOT hallucinate numbers.\n"
            "- Do NOT mention internal system names (Strategos, CAL, Cortex, Ledger).\n"
            "- Write for a CISO audience: business impact, not tool names.\n\n"
            f"SCAN DATA — {len(issues)} enriched issues, {len(findings)} raw findings:\n"
            f"{issues_block}\n"
            f"CAUSAL GRAPH:\n{graph_block}\n"
            "Summarize the overall security posture. Highlight the most critical risks "
            "and the key attack paths that connect them. Keep it under 300 words."
        )

    def _prompt_attack_narrative(self, ctx: Dict) -> str:
        issues = ctx.get("issues", [])
        findings = ctx.get("findings", [])
        issues_block = self._format_issues_block(issues)
        graph_block = self._build_graph_summary(findings, issues, ctx=ctx)

        return (
            "Write an Attack Narrative for a penetration test report.\n\n"
            "STRICT RULES:\n"
            "- ONLY describe attack paths that exist in the causal graph below.\n"
            "- Reference specific findings by name and target.\n"
            "- Do NOT invent exploitation steps that aren't supported by the evidence.\n"
            "- Distinguish CONFIRMED findings from PROBABLE and HYPOTHESIZED ones.\n\n"
            f"ENRICHED ISSUES:\n{issues_block}\n"
            f"CAUSAL GRAPH (attack chains and enablement relationships):\n{graph_block}\n"
            "Tell the story: how could an attacker chain these findings together? "
            "Start from initial reconnaissance and trace through to maximum impact. "
            "For each step, cite the specific finding and its confirmation level."
        )

    def _prompt_technical(self, ctx: Dict) -> str:
        findings = ctx.get("findings", [])
        issues = ctx.get("issues", [])
        findings_block = self._format_findings_block(findings)
        issues_block = self._format_issues_block(issues)

        return (
            "Draft the Technical Findings section of a penetration test report.\n\n"
            "STRICT RULES:\n"
            "- ONLY describe findings listed below. Do NOT invent vulnerabilities.\n"
            "- Use EXACT severity levels and targets from the data.\n"
            "- Group by vulnerability class or affected asset.\n"
            "- For each finding: describe what was found, where, severity, and evidence.\n\n"
            f"RAW FINDINGS ({len(findings)} total):\n{findings_block}\n"
            f"ENRICHED ISSUES ({len(issues)} total):\n{issues_block}\n"
            "For each issue, provide: description, affected target, severity, "
            "confirmation level, and supporting evidence summary."
        )

    def _prompt_risk(self, ctx: Dict) -> str:
        scores = ctx.get("risk", {})
        issues = ctx.get("issues", [])
        findings = ctx.get("findings", [])
        issues_block = self._format_issues_block(issues)
        graph_block = self._build_graph_summary(findings, issues, ctx=ctx)

        return (
            "Provide a Risk Assessment for a penetration test report.\n\n"
            "STRICT RULES:\n"
            "- Base risk ratings ONLY on the findings and scores provided below.\n"
            "- Do NOT invent risk scores or asset values.\n"
            "- Reference specific findings when explaining risk levels.\n\n"
            f"ASSET RISK SCORES: {json.dumps(scores, indent=2)}\n\n"
            f"ENRICHED ISSUES:\n{issues_block}\n"
            f"CAUSAL GRAPH:\n{graph_block}\n"
            "Explain which assets are at highest risk and why, based on the "
            "combination of confirmed vulnerabilities, attack chain exposure, "
            "and capability types (information, access, execution, evasion)."
        )

    def _prompt_remediation(self, ctx: Dict) -> str:
        issues = ctx.get("issues", [])
        findings = ctx.get("findings", [])
        issues_block = self._format_issues_block(issues)
        graph_block = self._build_graph_summary(findings, issues, ctx=ctx)

        return (
            "Draft a Remediation Roadmap for a penetration test report.\n\n"
            "STRICT RULES:\n"
            "- ONLY recommend fixes for findings listed below.\n"
            "- Prioritize by: (1) pressure points that block the most attack paths, "
            "(2) confirmed findings before probable/hypothesized, "
            "(3) higher score before lower score.\n"
            "- Be specific: name the finding, the fix, and the expected risk reduction.\n\n"
            f"ENRICHED ISSUES:\n{issues_block}\n"
            f"CAUSAL GRAPH (pressure points = highest-impact fixes):\n{graph_block}\n"
            "Structure as: Immediate (fix within 24h), Short-term (1-2 weeks), "
            "Long-term (architectural hardening). For each item, explain what it fixes "
            "and how many attack paths it blocks."
        )

    # --- Fallbacks ---

    def _fallback_content(self, section: str, ctx: Dict) -> str:
        """Function _fallback_content."""
        return f"## {section.replace('_', ' ').title()}\n\n*AI Unavailable. Raw data stats: {len(ctx.get('findings', []))} findings.*"


# Legacy wrapper for backward compatibility
async def create_report_bundle(base_dir: str = "reports") -> ReportBundle:
    """Function create_report_bundle."""
    composer = ReportComposer()
    full_report = ""
    # Loop over items.
    for section in composer.SECTIONS:
        section_content = await composer.generate_section(section)
        full_report += section_content + "\n\n"

    os.makedirs(base_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    bundle_dir = os.path.join(base_dir, f"bundle-{timestamp}")
    os.makedirs(bundle_dir, exist_ok=True)

    md_path = os.path.join(bundle_dir, "report.md")
    # Context-managed operation.
    with open(md_path, "w") as f:
        f.write(full_report)

    return ReportBundle(bundle_dir, md_path, "")
