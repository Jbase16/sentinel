# core/cortex/nexus_context.py
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.data.findings_store import findings_store
from core.cortex.events import get_event_bus, GraphEvent
from core.contracts.events import EventContract, EventType, ContractViolation

logger = logging.getLogger(__name__)

from core.data.constants import INFORMATION_HYPOTHESIS_CONFIDENCE


@dataclass(frozen=True)
class NexusInsight:
    """A synthesized insight derived from raw data."""
    title: str
    description: str
    severity: str
    related_findings: List[str]  # Finding IDs


@dataclass
class NexusCorrelation:
    """
    Finding-to-finding correlation shape for information enablement synthesis.
    """
    source_finding_id: str
    source_finding_type: str
    target_finding_id: Optional[str]
    correlation_type: str  # "enablement", "chain", "singleton"
    confidence: float
    enabled_actions: List[str]
    enablement_edges: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


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
        self._tool_stats: Dict[str, int] = {"attempted": 0, "executed": 0, "failed": 0}
        self.bus.subscribe_async(self._handle_event)

    # ---------------------------------------------------------------------
    # Event Handling
    # ---------------------------------------------------------------------

    async def _handle_event(self, event: GraphEvent) -> None:
        """
        Listen for tool completions to drive falsification.
        Also listen for finding invalidation/suppression to prevent epistemic drift.
        """
        et = event.type

        if et == EventType.TOOL_STARTED:
            self._tool_stats["attempted"] += 1

        if et == EventType.TOOL_COMPLETED:
            self._tool_stats["executed"] += 1
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

    # ---------------------------------------------------------------------
    # Auditing (Phase 7)
    # ---------------------------------------------------------------------

    def audit_scan(self, scan_id: str, session_id: str, sequence_end: int) -> None:
        """
        Produce a deterministic System Self-Audit for a completed scan.
        Query subsystems statelessly and emit the artifact.
        """
        from core.auditing.builder import AuditBuilder
        from core.scheduler.decisions import get_decision_ledger
        from core.cortex.causal_graph import CausalGraphBuilder
        
        # 1. Gather Stats (Stateless Queries)
        # Decision Ledger is global/singleton for now
        decisions = get_decision_ledger().get_all() # TODO: filter by scan_id if ledger becomes multi-tenant
        
        # Graph Stats (approx from snapshot)
        # Ideally we'd have a snapshot of the graph at this exact moment. 
        # For now, we query the live graph builder which presumably holds state for this session.
        # But CausalGraphBuilder is not a singleton. We might need to access it via context or Strategy?
        # WAIT: CausalGraphBuilder is usually instantiated per use or in Strategos.
        # NexusContext doesn't hold the graph. 
        # BUT: verify_decisions.py showed us `CausalGraphBuilder.instance().graph`. 
        # Let's assume CausalGraphBuilder has a way to get stats.
        graph_stats = {"nodes": 0, "edges": 0}
        try:
             # Just a heuristic for now: We don't have a direct handle to the graph here.
             # In a real impl, we'd pass the graph or have it available.
             # For this refactor, we accept that 'graph' stats might be zero if not reachable, validation will fail.
             # Better: Use findings_store count as proxy for nodes?
             # Or: Strategos should probably invoke audit_scan and pass the graph. 
             # Refinement: NexusContext shouldn't own this? 
             # Plan said "Integrate into NexusContext or Strategos lifecycle".
             # Strategos owns the main loop. Let's keep it here but we might need to be passed the graph-stats.
             # Actually, let's look at DecisionLedger. It is a singleton.
             pass
        except Exception:
             pass

        # Tool Stats (We can query history from the bus or track locally if we were listening)
        # We process TOOL_COMPLETED events in _handle_event. We can add a counter there.
        # Impl detail: I'll add `_tool_stats` to NexusContext state.
        
        # Policy Stats (Stub for now, or query PolicyEngine if singleton)
        policy_stats = {"blocks": 0} 

        audit = AuditBuilder.build(
            scan_id=scan_id,
            session_id=session_id,
            sequence_end=sequence_end,
            decision_ledger=decisions,
            graph_stats=graph_stats, # Placeholder until we wire it
            tool_stats=self._tool_stats if hasattr(self, "_tool_stats") else {},
            policy_stats=policy_stats
        )
        
        logger.info("[Nexus] Emitting System Self-Audit for Scan %s", scan_id)
        self._emit_contract_event(EventType.SYSTEM_SELF_AUDIT_CREATED, audit.model_dump())

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

        # Rule 3: Confirmed information/access findings imply actionable enablement.
        RULE_ID_INFO = "rule_information_enablement"
        RULE_VERSION_INFO = "1.0"
        rule_3_findings = [
            finding
            for finding in findings
            if str(finding.get("confirmation_level", "probable")).strip().lower() == "confirmed"
            and any(
                capability in {"information", "access"}
                for capability in self._extract_capability_types(finding)
            )
            and self._extract_base_score(finding) >= 5.0
        ]

        for finding in rule_3_findings:
            finding_ids = self._extract_finding_ids([finding])
            if not finding_ids:
                continue

            hyp_id = self._generate_hypothesis_id(finding_ids, RULE_ID_INFO, RULE_VERSION_INFO)
            if hyp_id in self._emitted_hypotheses:
                continue

            confidence = self._confidence_for_information_finding(finding)
            explanation = self._enablement_explanation(finding)
            finding_type = str(finding.get("type", "information finding")).strip()

            paths.append([
                "Information Enablement",
                finding_type,
                "Targeted Exploitation Path",
            ])

            self._emit_hypothesis_formed(
                hypothesis_id=hyp_id,
                constituent_finding_ids=finding_ids,
                rule_id=RULE_ID_INFO,
                rule_version=RULE_VERSION_INFO,
                confidence=confidence,
                explanation=explanation,
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

    def get_tool_stats(self) -> Dict[str, int]:
        return self._tool_stats.copy()

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
    def _extract_capability_types(finding: Dict[str, Any]) -> List[str]:
        raw_capability_types = finding.get("capability_types", [])
        if isinstance(raw_capability_types, str):
            values = [raw_capability_types]
        elif isinstance(raw_capability_types, list):
            values = raw_capability_types
        else:
            values = []
        normalized = [str(item).strip().lower() for item in values if str(item).strip()]
        return normalized or ["execution"]

    @staticmethod
    def _extract_base_score(finding: Dict[str, Any]) -> float:
        for key in ("base_score", "score", "raw_score"):
            value = finding.get(key)
            if value is None:
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return 0.0

    def _confidence_for_information_finding(self, finding: Dict[str, Any]) -> float:
        """
        Map finding type/content into a conservative information-enablement confidence.
        """
        finding_type = str(finding.get("type", "")).lower()
        raw_tags = finding.get("tags", [])
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        tags = {str(tag).strip().lower() for tag in raw_tags if str(tag).strip()}
        content = " ".join(
            str(part)
            for part in (
                finding.get("value"),
                finding.get("description"),
                finding.get("title"),
                finding.get("evidence_summary"),
            )
            if part
        ).lower()

        credential_indicators = ("password", "api_key", "apikey", "secret", "token", "aws_access_key_id")
        if "secret-leak" in tags or "credential" in finding_type:
            return INFORMATION_HYPOTHESIS_CONFIDENCE["credential_exposure"]
        if "backup-leak" in tags and any(ind in content for ind in credential_indicators):
            return INFORMATION_HYPOTHESIS_CONFIDENCE["source_code_secrets"]
        if "private-ip" in tags or any(tag in tags for tag in ("topology", "internal")):
            return INFORMATION_HYPOTHESIS_CONFIDENCE["internal_topology"]
        if "backup-leak" in tags:
            return INFORMATION_HYPOTHESIS_CONFIDENCE["backup_config"]
        return INFORMATION_HYPOTHESIS_CONFIDENCE["backup_config"]

    def _enablement_explanation(self, finding: Dict[str, Any]) -> str:
        """
        Explain what attacker effort is reduced by this information finding.
        """
        finding_type = str(finding.get("type", "")).lower()
        raw_tags = finding.get("tags", [])
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        tags = {str(tag).strip().lower() for tag in raw_tags if str(tag).strip()}
        target = str(finding.get("target", "unknown"))

        if "secret-leak" in tags or "credential" in finding_type:
            return (
                f"Confirmed credential exposure on {target} enables direct authenticated access "
                "without brute-force effort."
            )
        if "backup-leak" in tags:
            return (
                f"Confirmed backup/source artifact exposure on {target} reveals application structure "
                "that enables targeted endpoint and secret exploitation."
            )
        if "private-ip" in tags:
            return (
                f"Confirmed internal topology exposure on {target} enables targeted SSRF and "
                "lateral movement toward private infrastructure."
            )
        if "git" in finding_type:
            return (
                f"Confirmed git metadata exposure on {target} enables repository intelligence "
                "and targeted exploit path selection."
            )
        return (
            f"Confirmed information exposure on {target} reduces attacker uncertainty and enables "
            "higher-probability follow-up exploitation."
        )

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
