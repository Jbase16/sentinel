"""
core/cortex/evidence_bundle.py

Normalize a confirmed finding into the evidence a hostile triager would weigh.

The detector's job is done by the time this runs — the finding is already
*verified*. The EvidenceBundle exists so the Finding Adversary (triage_adversary)
can judge PAYABILITY, not validity: does the proof cross a trust boundary, was it
obtained safely, is it a commodity pattern, was it against a production asset, are
the program rules even loaded. This module extracts those signals from the finding
metadata our engines emit; it makes no network calls and no judgments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Object nouns that carry obvious sensitivity (raise impact); vs synthetic/owned.
_SENSITIVE_NOUNS = ("card", "ssn", "passport", "invoice", "payment", "wallet",
                    "medical", "health", "message", "dm", "address", "credential",
                    "token", "secret", "order", "tax", "salary", "bank")
_LOCAL_HOST_RE = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\.local|\.test|\.internal|"
    r"192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)", re.IGNORECASE)
_GENERIC_ID_RE = re.compile(r"/(users?|accounts?|profiles?)/(\{?\w*id\}?|\*|\d+)", re.IGNORECASE)
_DESTRUCTIVE_WORDS = ("delete", "remove", "drop", "destroy", "wipe", "close account")


@dataclass
class EvidenceBundle:
    finding_id: str
    vuln_class: str
    subtype: Optional[str]
    target: str
    proof_mode: str
    restraint: Dict[str, Any]
    hops: List[Dict[str, Any]]
    confidence: Optional[str]
    raw_finding: Dict[str, Any]
    scope_loaded: bool = False
    program_rules_loaded: bool = False

    # ---- derived signals a triager reasons over -------------------------------

    @property
    def target_is_local(self) -> bool:
        return bool(_LOCAL_HOST_RE.search(self.target or ""))

    @property
    def has_restraint(self) -> bool:
        return bool(self.restraint)

    @property
    def owned_only(self) -> bool:
        return bool(self.restraint.get("owned_test_accounts_only"))

    @property
    def used_destructive(self) -> bool:
        if int(self.restraint.get("destructive_actions_sent", 0) or 0) > 0:
            return True
        # Lab chains prove BFLA by actually issuing the destructive op.
        if self.proof_mode == "lab":
            for h in self.hops:
                if any(w in str(h.get("label", "")).lower() for w in _DESTRUCTIVE_WORDS):
                    return True
        return False

    @property
    def cross_boundary(self) -> bool:
        """Does the proof demonstrate impact ACROSS an account/tenant/role boundary?"""
        if self.vuln_class == "bola":
            return True                       # a cross-account read, by definition
        if self.vuln_class == "exploit_chain":
            return True                       # every chain kind crosses a boundary
        return False                          # self_escalation / register mass-assign: own account

    @property
    def server_authz_delta(self) -> bool:
        """Did authoritative server-side state actually change / leak?"""
        if self.vuln_class in ("bola", "business_logic"):
            return True
        if self.vuln_class == "exploit_chain":
            return True
        if self.subtype == "self_escalation":
            return self.confidence == "HIGH"  # HIGH = persisted through a fresh login
        if self.vuln_class == "mass_assignment":
            return True                       # persisted a privileged field
        return False

    @property
    def business_impact(self) -> bool:
        if self.vuln_class == "business_logic":
            m = self.raw_finding.get("metadata") or {}
            return "money" in str(m).lower() or m.get("field") in ("price", "total", "amount", "balance")
        return False

    @property
    def object_sensitivity(self) -> str:
        """synthetic (we created it) | sensitive | unknown."""
        m = self.raw_finding.get("metadata") or {}
        if m.get("subtype") == "two_persona_owned" or (m.get("ownership_markers") or {}).get("planted"):
            return "synthetic"                # a throwaway object WE planted
        blob = f"{self.target} {m.get('object_type','')} {m.get('endpoint','')}".lower()
        if any(n in blob for n in _SENSITIVE_NOUNS):
            return "sensitive"
        return "unknown"

    @property
    def generic_pattern(self) -> bool:
        """Is this the kind of commodity pattern triage queues are flooded with?"""
        if self.vuln_class == "exploit_chain":
            return False                      # multi-step composition is not commodity
        if self.subtype in ("horizontal_enumeration", "two_persona_owned"):
            # scale enumeration and simple owned-object BOLA are common report shapes
            return True
        if self.vuln_class == "bola":
            return bool(_GENERIC_ID_RE.search(str((self.raw_finding.get("metadata") or {}).get("object_ref", ""))
                                              or self.target))
        return self.vuln_class in ("bola", "mass_assignment")

    @property
    def has_repro(self) -> bool:
        f = self.raw_finding
        m = f.get("metadata") or {}
        return bool(f.get("steps") or m.get("hops") or m.get("evidence")
                    or m.get("object_ref") or m.get("endpoint"))

    @classmethod
    def from_finding(cls, finding: Dict[str, Any], *, scope: Any = None,
                     program_rules: Any = None) -> "EvidenceBundle":
        m = finding.get("metadata") or {}
        return cls(
            finding_id=str(finding.get("id") or finding.get("finding_id") or ""),
            vuln_class=str(m.get("vuln_class") or ""),
            subtype=m.get("subtype"),
            target=str(finding.get("target") or finding.get("host") or ""),
            proof_mode=str(m.get("proof_mode") or "lab"),
            restraint=dict(m.get("restraint") or {}),
            hops=list(m.get("hops") or []),
            confidence=m.get("confidence") or m.get("epistemic"),
            raw_finding=finding,
            scope_loaded=scope is not None,
            program_rules_loaded=program_rules is not None,
        )
