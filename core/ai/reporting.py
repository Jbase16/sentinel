# core/reporting.py — report bundle generation utilities

from __future__ import annotations

import json
import os
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from core.data.findings_store import findings_store
from core.data.issues_store import issues_store
from core.data.killchain_store import killchain_store
from core.data.risk import risk_engine
from core.cortex.reasoning import reasoning_engine
from core.ai.ai_engine import AIEngine

logger = logging.getLogger(__name__)

@dataclass
class ReportBundle:
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

    def __init__(self):
        self.ai = AIEngine.instance()

    def generate_section(self, section_name: str, context_override: Optional[Dict] = None) -> str:
        """
        Generates a specific section of the report using the LLM.
        """
        if section_name not in self.SECTIONS:
            return f"Error: Unknown section '{section_name}'"

        context = context_override or self._gather_context()
        
        prompts = {
            "executive_summary": self._prompt_exec_summary,
            "attack_narrative": self._prompt_attack_narrative,
            "technical_findings": self._prompt_technical,
            "risk_assessment": self._prompt_risk,
            "remediation_roadmap": self._prompt_remediation
        }
        
        prompt_fn = prompts.get(section_name)
        if not prompt_fn:
            return "Section not implemented."

        if not self.ai.client:
            return self._fallback_content(section_name, context)

        user_prompt = prompt_fn(context)
        system_prompt = (
            "You are a Senior Security Consultant writing a high-stakes penetration testing report. "
            "Your tone is professional, authoritative, and concise. "
            "Focus on business impact and attack chains, not just list of bugs. "
            "Use Markdown formatting."
        )
        
        return self.ai.client.generate(user_prompt, system_prompt) or "AI Generation failed."

    def _gather_context(self) -> Dict:
        return {
            "findings": findings_store.get_all(),
            "issues": issues_store.get_all(),
            "risk": risk_engine.get_scores(),
            "killchain": killchain_store.get_all(),
            "reasoning": reasoning_engine.analyze()
        }

    # --- Prompts ---

    def _prompt_exec_summary(self, ctx: Dict) -> str:
        issues = ctx.get("issues", [])
        return (
            f"Write an Executive Summary for a security assessment.\n"
            f"Context: Found {len(issues)} confirmed issues. "
            f"Top risks: {', '.join([i.get('title', '') for i in issues[:3]])}.\n"
            "Summarize the overall security posture, highlight the most critical risks, and "
            "explain the potential business impact of these vulnerabilities being exploited."
        )

    def _prompt_attack_narrative(self, ctx: Dict) -> str:
        chains = ctx.get("reasoning", {}).get("attack_paths", [])
        if not chains:
            return "No complete attack chains were verified. Describe individual vectors found."
        
        chain_text = "\n".join([" -> ".join(path) for path in chains[:5]])
        return (
            f"Write an Attack Narrative describing how an attacker could compromise the target.\n"
            f"Observed Attack Chains:\n{chain_text}\n"
            "Tell the story of the attack. How does one finding lead to another? "
            "Connect the dots between recon, initial access, and impact."
        )

    def _prompt_technical(self, ctx: Dict) -> str:
        findings = ctx.get("findings", [])
        return (
            f"Draft the Technical Findings section.\n"
            f"Raw Data: {len(findings)} findings available.\n"
            "Group these findings logically (e.g., by vulnerability class or affected asset). "
            "For the top 5 most severe findings, provide technical depth: evidence, reproduction steps, and root cause."
        )

    def _prompt_risk(self, ctx: Dict) -> str:
        scores = ctx.get("risk", {})
        return (
            f"Provide a Risk Assessment based on these asset scores: {json.dumps(scores, indent=2)}\n"
            "Explain *why* certain assets are high risk. Factor in data sensitivity and exposure."
        )

    def _prompt_remediation(self, ctx: Dict) -> str:
        recs = ctx.get("reasoning", {}).get("recommended_phases", [])
        return (
            "Draft a Remediation Roadmap.\n"
            f"System recommendations: {json.dumps(recs)}\n"
            "Prioritize fixes based on impact. Suggest immediate 'stop the bleeding' fixes "
            "versus long-term architectural hardening."
        )

    # --- Fallbacks ---

    def _fallback_content(self, section: str, ctx: Dict) -> str:
        return f"## {section.replace('_', ' ').title()}\n\n*AI Unavailable. Raw data stats: {len(ctx.get('findings', []))} findings.*"


# Legacy wrapper for backward compatibility
def create_report_bundle(base_dir: str = "reports") -> ReportBundle:
    composer = ReportComposer()
    full_report = ""
    for section in composer.SECTIONS:
        full_report += composer.generate_section(section) + "\n\n"
    
    os.makedirs(base_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    bundle_dir = os.path.join(base_dir, f"bundle-{timestamp}")
    os.makedirs(bundle_dir, exist_ok=True)
    
    md_path = os.path.join(bundle_dir, "report.md")
    with open(md_path, "w") as f:
        f.write(full_report)
        
    return ReportBundle(bundle_dir, md_path, "")
