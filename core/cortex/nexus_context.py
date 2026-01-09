# core/cortex/nexus_context.py
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from core.data.findings_store import findings_store
from core.cortex.events import get_event_bus, GraphEvent
from core.contracts.events import EventContract, EventType, ContractViolation

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NexusInsight:
    """A synthesized insight derived from raw data."""
    title: str
    description: str
    severity: str
    related_findings: List[str]  # Finding IDs


class NexusContext:
    """
    The Sense-Making Core of Sentinel.

    Responsibilities:
    1. Ingest findings from the Findings Store / Epistemic Ledger.
    2. Contextualize them against the Goal (Target).
    3. Synthesize 'Insights' (Attack Chains, Strategic Risks).
    4. Emit 'Hypothesis' events for auditable reasoning.
    5. Provide the narrative backbone for Reporting.
    """

    _instance: Optional["NexusContext"] = None

    @classmethod
    def instance(cls) -> "NexusContext":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self.bus = get_event_bus()
        self._emitted_hypotheses: Set[str] = set()
        self._active_hypotheses: Dict[str, Set[str]] = {}  # hyp_id -> set(finding_ids)
        self.bus.subscribe(self._handle_event)

    # ---------------------------------------------------------------------
    # Event Handling
    # ---------------------------------------------------------------------

    async def _handle_event(self, event: GraphEvent) -> None:
        """
        Listen for tool completions to drive falsification.
        Also listen for finding invalidation/suppression to prevent epistemic drift.
        """
        et = event.type

        if et == EventType.TOOL_COMPLETED:
            # Optional convention (non-breaking):
            # tool modules may include:
            #   hypothesis_id: str
            #   hypothesis_outcome: "supported" | "refuted" | "inconclusive"
            #   reason: str
            payload = event.payload or {}
            hypothesis_id = payload.get("hypothesis_id")
            outcome = payload.get("hypothesis_outcome")
            reason = payload.get("reason")

            if hypothesis_id and hypothesis_id in self._active_hypotheses and outcome:
                if outcome == "refuted":
                    self.refute_hypothesis(hypothesis_id, reason or "Validation attempt refuted hypothesis.")
                elif outcome in ("supported", "inconclusive"):
                    # We only have a contract for NEXUS_HYPOTHESIS_UPDATED with new_confidence + reason.
                    # If supported: bump confidence; if inconclusive: slight decay or keep stable.
                    old = self._guess_confidence_from_id(hypothesis_id)
                    if outcome == "supported":
                        new = min(1.0, max(old, 0.8) + 0.1)
                        why = reason or "Validation provided supporting evidence."
                    else:
                        new = max(0.0, old - 0.05)
                        why = reason or "Validation inconclusive; slight confidence decay."
                    self._emit_hypothesis_updated(hypothesis_id, old, new, why)

            return

        if et in (EventType.FINDING_INVALIDATED, EventType.FINDING_SUPPRESSED):
            payload = event.payload or {}
            finding_id = payload.get("finding_id") or payload.get("id")
            if not finding_id:
                return

            # Epistemic Hygiene: remove hypotheses that depend on this dead finding
            to_remove: List[str] = []
            for hyp_id, fids in self._active_hypotheses.items():
                if finding_id in fids:
                    to_remove.append(hyp_id)

            if to_remove:
                logger.info(
                    "[Nexus] Epistemic Hygiene: Removing %d hypotheses due to invalidation of finding %s",
                    len(to_remove),
                    finding_id,
                )
                for hyp_id in to_remove:
                    del self._active_hypotheses[hyp_id]
                    # Optional: emit NEXUS_HYPOTHESIS_REFUTED as “dependency death”
                    self._emit_hypothesis_refuted(
                        hypothesis_id=hyp_id,
                        reason=f"Hypothesis invalidated because constituent finding {finding_id} was removed.",
                        constituent_finding_ids=[finding_id],
                        refuting_evidence_id=None,
                    )

            return

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def refute_hypothesis(self, hypothesis_id: str, reason: str) -> None:
        """
        Public API to report a hypothesis failure.
        Triggers the Epistemic Recoil loop.
        """
        finding_ids = sorted(self._active_hypotheses.get(hypothesis_id, set()))
        if not finding_ids:
            logger.warning("[Nexus] Cannot refute unknown/expired hypothesis %s", hypothesis_id)
            return

        logger.info("[Nexus] Refuting Hypothesis %s: %s", hypothesis_id, reason)
        self._emit_hypothesis_refuted(
            hypothesis_id=hypothesis_id,
            reason=reason,
            constituent_finding_ids=finding_ids,
            refuting_evidence_id=None,
        )

        # Once refuted, yank it from actives (you can keep it if you want history)
        self._active_hypotheses.pop(hypothesis_id, None)

    def analyze_context(self) -> Dict[str, Any]:
        """
        Return the full synthesized context for consumers (Reporting, UI).
        """
        attack_paths = self.synthesize_attack_paths()
        recs = self.generate_recommendations()
        return {
            "attack_paths": attack_paths,
            "recommended_phases": recs,
            "insight_count": len(self._emitted_hypotheses),
        }

    # ---------------------------------------------------------------------
    # Synthesis
    # ---------------------------------------------------------------------

    def synthesize_attack_paths(self) -> List[List[str]]:
        """
        Analyze current findings to construct probable attack paths.
        Emits NEXUS_HYPOTHESIS_FORMED events for new discoveries.
        Returns a list of paths for immediate consumption.
        """
        findings = findings_store.get_all() or []
        paths: List[List[str]] = []

        open_ports = [f for f in findings if "port" in str(f.get("type", "")).lower()]
        web_vulns = [
            f for f in findings
            if ("xss" in str(f.get("type", "")).lower())
            or ("sql" in str(f.get("type", "")).lower())
        ]
        criticals = [f for f in findings if str(f.get("severity", "")).upper() in ("HIGH", "CRITICAL")]

        # Rule 1: Web Exposure -> Web Vuln
        RULE_ID = "rule_web_exposure_chain"
        RULE_VERSION = "1.0"

        for port in open_ports:
            port_val = str(port.get("value", "")).lower()
            if self._looks_like_web_port(port_val):
                for vuln in web_vulns:
                    vuln_type = str(vuln.get("type", "unknown")).strip()

                    path_desc = [
                        f"External Exposure ({port.get('value')})",
                        "Web Application Attack Surface",
                        f"Vulnerability Exploitation ({vuln_type})",
                    ]
                    paths.append(path_desc)

                    finding_ids = self._extract_finding_ids([port, vuln])
                    if not finding_ids:
                        continue

                    hyp_id = self._generate_hypothesis_id(finding_ids, RULE_ID, RULE_VERSION)
                    if hyp_id in self._emitted_hypotheses:
                        continue

                    self._emit_hypothesis_formed(
                        hypothesis_id=hyp_id,
                        constituent_finding_ids=finding_ids,
                        rule_id=RULE_ID,
                        rule_version=RULE_VERSION,
                        confidence=0.8,
                        explanation=f"Open web port combined with {vuln_type} suggests exploitable surface.",
                    )
                    self._emitted_hypotheses.add(hyp_id)
                    self._active_hypotheses[hyp_id] = set(finding_ids)

        # Rule 2: High/Critical isolated
        RULE_ID_CRIT = "rule_critical_isolated"
        RULE_VERSION_CRIT = "1.0"

        for crit in criticals:
            crit_type = str(crit.get("type", "unknown")).strip()
            crit_val = str(crit.get("value", "")).strip()

            paths.append([
                "Critical Exposure",
                f"{crit_type} ({crit_val})",
                "Potential System Compromise",
            ])

            finding_ids = self._extract_finding_ids([crit])
            if not finding_ids:
                continue

            hyp_id = self._generate_hypothesis_id(finding_ids, RULE_ID_CRIT, RULE_VERSION_CRIT)
            if hyp_id in self._emitted_hypotheses:
                continue

            sev = str(crit.get("severity", "CRITICAL")).upper()
            conf = 0.9 if sev == "CRITICAL" else 0.8

            self._emit_hypothesis_formed(
                hypothesis_id=hyp_id,
                constituent_finding_ids=finding_ids,
                rule_id=RULE_ID_CRIT,
                rule_version=RULE_VERSION_CRIT,
                confidence=conf,
                explanation=f"{sev} severity finding {crit_type} represents immediate compromise risk.",
            )
            self._emitted_hypotheses.add(hyp_id)
            self._active_hypotheses[hyp_id] = set(finding_ids)

        return paths

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate strategic recommendations based on the aggregate state.
        """
        findings = findings_store.get_all() or []
        if not findings:
            return [{"phase": "Discovery", "action": "Increase scan depth or scope."}]

        recs: List[Dict[str, Any]] = []
        has_critical = any(str(f.get("severity", "")).upper() == "CRITICAL" for f in findings)
        if has_critical:
            recs.append({
                "phase": "Immediate Action",
                "action": "Isolate affected assets and patch critical vulnerabilities immediately.",
            })
        return recs

    # ---------------------------------------------------------------------
    # Deterministic IDs + helpers
    # ---------------------------------------------------------------------

    def _generate_hypothesis_id(self, finding_ids: List[str], rule_id: str, rule_version: str) -> str:
        """
        Deterministic hash for a hypothesis:
        sha256(canonical_json({finding_ids_sorted, rule_id, rule_version}))
        """
        payload = {
            "finding_ids": sorted(finding_ids),
            "rule_id": rule_id,
            "rule_version": rule_version,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _looks_like_web_port(port_val: str) -> bool:
        # Supports formats: "80", "80/tcp", "tcp/80", "443", "443/tcp", etc.
        tokens = [t for t in port_val.replace("\\", "/").replace(":", "/").split("/") if t]
        return any(t in ("80", "443") for t in tokens) or (" 80" in port_val) or (" 443" in port_val)

    @staticmethod
    def _extract_finding_ids(findings: List[Dict[str, Any]]) -> List[str]:
        ids: List[str] = []
        for f in findings:
            fid = f.get("finding_id") or f.get("id")
            if isinstance(fid, str) and fid.strip():
                ids.append(fid.strip())
        # Contract expects list; schema says “sorted list” in description, so do it.
        return sorted(set(ids))

    @staticmethod
    def _guess_confidence_from_id(_: str) -> float:
        # Placeholder-free, but intentionally dumb: you don’t store confidence per hypothesis yet.
        # If you add state later, replace this with real values.
        return 0.75

    # ---------------------------------------------------------------------
    # Contract-validated emission
    # ---------------------------------------------------------------------

    def _emit_hypothesis_formed(
        self,
        hypothesis_id: str,
        constituent_finding_ids: List[str],
        rule_id: str,
        rule_version: str,
        confidence: float,
        explanation: Optional[str],
    ) -> None:
        payload: Dict[str, Any] = {
            "hypothesis_id": hypothesis_id,
            "constituent_finding_ids": sorted(constituent_finding_ids),
            "rule_id": rule_id,
            "rule_version": rule_version,
            "confidence": float(confidence),
        }
        if explanation:
            payload["explanation"] = explanation

        self._emit_contract_event(EventType.NEXUS_HYPOTHESIS_FORMED, payload)

    def _emit_hypothesis_updated(self, hypothesis_id: str, old: float, new: float, reason: str) -> None:
        payload: Dict[str, Any] = {
            "hypothesis_id": hypothesis_id,
            "previous_confidence": float(old),
            "new_confidence": float(new),
            "reason": reason,
        }
        self._emit_contract_event(EventType.NEXUS_HYPOTHESIS_UPDATED, payload)

    def _emit_hypothesis_refuted(
        self,
        hypothesis_id: str,
        reason: str,
        constituent_finding_ids: List[str],
        refuting_evidence_id: Optional[str],
    ) -> None:
        payload: Dict[str, Any] = {
            "hypothesis_id": hypothesis_id,
            "reason": reason,
            "constituent_finding_ids": sorted(constituent_finding_ids),
        }
        if refuting_evidence_id:
            payload["refuting_evidence_id"] = refuting_evidence_id

        self._emit_contract_event(EventType.NEXUS_HYPOTHESIS_REFUTED, payload)

    def _emit_contract_event(self, event_type: EventType, payload: Dict[str, Any]) -> None:
        try:
            EventContract.validate(event_type, payload)
        except ContractViolation as e:
            logger.error("[Nexus] Contract violation emitting %s: %s", event_type.value, e.violations)
            # In strict mode this would raise; but just in case strict is off elsewhere:
            raise
        self.bus.emit(GraphEvent(type=event_type, payload=payload))
