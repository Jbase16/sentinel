"""
Internal Tool Protocol for SentinelForge.

Defines the interface that all Python-based (in-process) tools must implement.
Unlike external tools that shell out to subprocesses, internal tools run as
async Python functions within the scanner engine process.

They return findings in the same dict schema as external tools, so the entire
downstream pipeline (dedup, vuln_rules, transaction commit, feedback loop)
works identically regardless of tool type.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class InternalToolContext:
    """
    Execution context passed to internal tools by the scanner engine.

    Carries everything an internal tool needs to make intelligent decisions
    without reaching into global singletons.
    """

    target: str
    scan_id: str
    session_id: str
    existing_findings: List[Dict[str, Any]]
    knowledge: Dict[str, Any]  # shared scan knowledge (waf_bypass_engine, session_bridge, etc.)
    mode: str = "research"     # "research" or "bounty"
    capability_gate: Optional[Any] = None  # Optional CapabilityGate snapshot for request-level policy checks

    def get_findings_by_tool(self, tool_name: str) -> List[Dict[str, Any]]:
        """Filter existing findings to those produced by a specific tool."""
        return [f for f in self.existing_findings if f.get("tool") == tool_name]

    def get_findings_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """Filter existing findings to those containing a specific tag."""
        return [
            f for f in self.existing_findings
            if tag in (f.get("tags") or [])
        ]

    def get_findings_by_severity(self, *severities: str) -> List[Dict[str, Any]]:
        """Filter existing findings to those at specific severity levels."""
        sev_set = {s.upper() for s in severities}
        return [
            f for f in self.existing_findings
            if (f.get("severity") or "").upper() in sev_set
        ]

    def get_injectable_findings(self) -> List[Dict[str, Any]]:
        """Return findings that have injectable parameters (URL params, form fields, etc.)."""
        results = []
        for f in self.existing_findings:
            meta = f.get("metadata") or {}
            has_params = bool(meta.get("params") or meta.get("query_params") or meta.get("parameters"))
            has_path = bool(meta.get("url") or meta.get("path"))
            if has_params or has_path:
                results.append(f)
        return results

    def get_unverified_findings(self) -> List[Dict[str, Any]]:
        """Return findings that haven't been verified by an internal tool yet."""
        return [
            f for f in self.existing_findings
            if not f.get("metadata", {}).get("verified")
            and (f.get("severity") or "").upper() in ("MEDIUM", "HIGH", "CRITICAL")
        ]


class InternalTool(ABC):
    """
    Base class for all internal Python tools in SentinelForge.

    Subclasses must implement:
      - name: str property (unique tool identifier, matches registry key)
      - execute(): async method that runs the tool logic and returns findings

    Findings must follow the standard finding dict schema:
    {
        "tool": str,           # self.name
        "type": str,           # e.g. "Verified SQLi", "IDOR", "Auth Bypass"
        "severity": str,       # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
        "message": str,        # Human-readable description
        "proof": str,          # Evidence (payload, response snippet, etc.)
        "target": str,         # Target URL/host
        "asset": str,          # Normalized asset identifier
        "tags": List[str],     # Classification tags
        "families": List[str], # Finding families for chain matching
        "confidence": float,   # 0.0-1.0
        "metadata": dict,      # Tool-specific metadata, MUST include "verified": True
    }
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier matching the registry key."""
        ...

    @abstractmethod
    async def execute(
        self,
        target: str,
        context: InternalToolContext,
        queue: asyncio.Queue[str],
    ) -> List[Dict[str, Any]]:
        """
        Run the tool and return findings.

        Args:
            target: The scan target (URL, host, IP).
            context: Execution context with existing findings, knowledge, etc.
            queue: Async queue for streaming log lines to the UI in real time.

        Returns:
            List of finding dicts in the standard schema.
        """
        ...

    async def log(self, queue: asyncio.Queue[str], message: str) -> None:
        """Convenience: push a log line to the UI stream."""
        await queue.put(f"[{self.name}] {message}")

    def make_finding(
        self,
        target: str,
        finding_type: str,
        severity: str,
        message: str,
        proof: str = "",
        confidence: float = 0.8,
        tags: Optional[List[str]] = None,
        families: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a finding dict in the standard schema.

        Ensures 'tool' and 'verified' are always set correctly.
        """
        meta = metadata or {}
        meta["verified"] = True
        meta["internal_tool"] = True

        return {
            "tool": self.name,
            "type": finding_type,
            "severity": severity.upper(),
            "message": message,
            "proof": proof,
            "target": target,
            "asset": target,
            "tags": tags or [],
            "families": families or [],
            "confidence": confidence,
            "metadata": meta,
        }
