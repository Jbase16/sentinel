"""
core/cortex/evidence_bundle.py

Normalize a confirmed finding into the evidence a hostile triager would weigh.

Design rule the whole thing turns on: DISTRUST THE DETECTOR'S LABEL. A finding
being tagged `bola` does not prove a cross-boundary impact — it proves the detector
thinks it found one. So every payability signal here is derived from CONCRETE
evidence the finding carries (differing personas, a planted/leaked owner marker, a
denied→allowed status delta, a fresh-login persistence, a stated invariant), never
from `vuln_class` alone. Let the finding prove the boundary; do not infer it from
the class. The detector detects; this extracts; the adversary prosecutes.

No network calls, no judgments — just signal extraction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Object nouns whose *class* is inherently sensitive (billing, PII, comms, creds).
_SENSITIVE_NOUNS = ("card", "ssn", "passport", "invoice", "payment", "wallet",
                    "medical", "health", "message", "dm", "address", "credential",
                    "token", "secret", "order", "tax", "salary", "bank", "billing")
# Business-logic isn't just money — it's "the app's rules are now fiction".
_BUSINESS_KW = ("price", "cost", "total", "amount", "balance", "discount", "refund",
                "quota", "limit", "approval", "role", "owner", "tenant", "shipping",
                "inventory", "quantity", "subscription", "plan", "entitlement",
                "license", "usage", "credit", "fee", "tier")
_DESTRUCTIVE_WORDS = ("delete", "remove", "drop", "destroy", "wipe", "close account",
                      "deactivate", "purge")
# Evidence phrasing that concretely indicates a crossed trust boundary.
_BOUNDARY_EVIDENCE = ("denied→allowed", "denied→allowed", "cross-account", "cross account",
                      "cross-tenant", "cross tenant", "other users", "another user",
                      "distinct owners", "foreign", "victim", "across the privilege boundary",
                      "previously-denied", "previously denied")
# Evidence phrasing that concretely indicates authoritative server-side change/leak.
_DELTA_EVIDENCE = ("persisted", "fresh login", "server state", "server-authoritative",
                   "reflected", "denied→allowed", "denied→allowed", "read back",
                   "leaked", "carried the owner", "carried victim")
_LOCAL_HOST_RE = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\.local|\.test|\.internal|"
    r"192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)", re.IGNORECASE)
_GENERIC_ID_RE = re.compile(r"/(users?|accounts?|profiles?)/(\{?\w*id\}?|\*|\d+)", re.IGNORECASE)
_SUCCESS = {200, 201, 202, 204}
_DENIED = {401, 403, 404}


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

    @property
    def _m(self) -> Dict[str, Any]:
        return self.raw_finding.get("metadata") or {}

    def _hop_text(self) -> str:
        return " ".join(f"{h.get('label','')} {h.get('evidence','')}" for h in self.hops).lower()

    # ---- environment ----------------------------------------------------------

    @property
    def target_is_local(self) -> bool:
        return bool(_LOCAL_HOST_RE.search(self.target or ""))

    @property
    def has_restraint(self) -> bool:
        return bool(self.restraint)

    @property
    def owned_only(self) -> bool:
        return bool(self.restraint.get("owned_test_accounts_only"))

    # ---- safety (adversarial: over-detect destructive, HOLD is cheap) ---------

    @property
    def used_destructive(self) -> bool:
        if int(self.restraint.get("destructive_actions_sent", 0) or 0) > 0:
            return True
        # Any hop that DID a destructive action — regardless of the claimed mode
        # (catches forged "bounty_safe + owned_only" findings whose hops delete).
        for h in self.hops:
            if str(h.get("method", "")).upper() == "DELETE":
                return True
        text = self._hop_text()
        return any(w in text for w in _DESTRUCTIVE_WORDS)

    # ---- impact: EVIDENCE-based, not class-based ------------------------------

    @property
    def cross_boundary(self) -> bool:
        """Did the proof demonstrably cross an account/tenant/role boundary?
        Proven by evidence — differing personas, an owner marker the actor could
        not have supplied, multiple distinct owners, a status delta, or explicit
        boundary flags — NOT by the finding calling itself 'bola'."""
        m = self._m
        if m.get("cross_account") is True or m.get("cross_tenant") is True:
            return True
        actor, owner = m.get("actor_persona") or m.get("accessor_persona"), m.get("target_owner_persona") or m.get("owner_persona")
        if actor and owner:
            return str(actor) != str(owner)
        if (m.get("ownership_markers") or {}).get("planted"):
            return True                                   # A read B's planted marker
        if m.get("leaked_markers"):
            return True                                   # attacker got victim's private data
        try:
            if int(m.get("distinct_owners", 0)) >= 2:
                return True                               # read >=2 other owners' objects
        except (TypeError, ValueError):
            pass
        delta = m.get("authorization_delta") or {}
        if isinstance(delta, dict) and delta.get("boundary") in {"account", "tenant", "role"}:
            return True
        return any(k in self._hop_text() for k in _BOUNDARY_EVIDENCE)

    @property
    def server_authz_delta(self) -> bool:
        """Did authoritative server-side state actually change / leak? Requires
        concrete evidence, not a class label."""
        m = self._m
        delta = m.get("authorization_delta") or {}
        if isinstance(delta, dict) and delta.get("before") and delta.get("after"):
            return True
        if (m.get("ownership_markers") or {}).get("planted") or m.get("leaked_markers"):
            return True
        try:
            if int(m.get("before_status", 0)) in _DENIED and int(m.get("after_status", 0)) in _SUCCESS:
                return True
        except (TypeError, ValueError):
            pass
        if self.subtype == "self_escalation":
            return self.confidence == "HIGH"              # HIGH = survived a fresh login
        ev = str(m.get("evidence", "")).lower()
        if any(w in ev for w in _DELTA_EVIDENCE):
            return True
        return any(w in self._hop_text() for w in _DELTA_EVIDENCE)

    @property
    def business_impact(self) -> bool:
        if self.vuln_class != "business_logic":
            return False
        blob = f"{self._m.get('field','')} {self._m.get('invariant','')}".lower()
        return any(k in blob for k in _BUSINESS_KW)

    @property
    def object_sensitivity(self) -> str:
        """synthetic_low | synthetic_sensitive_class | real_sensitive | unknown.
        A safe two-persona proof reads a SYNTHETIC object — that doesn't make the
        bug low-impact; impact comes from the object CLASS + the boundary. So a
        planted invoice is `synthetic_sensitive_class`, not merely `synthetic`."""
        m = self._m
        ocs = str(m.get("object_class_sensitivity") or "").strip().lower()
        synthetic = (m.get("subtype") == "two_persona_owned"
                     or bool((m.get("ownership_markers") or {}).get("planted")))
        blob = f"{self.target} {m.get('object_type','')} {m.get('endpoint','')} {m.get('object_ref','')}".lower()
        sensitive_noun = any(n in blob for n in _SENSITIVE_NOUNS)
        has_class = bool(ocs) and ocs not in ("low", "none", "public")
        if synthetic:
            return "synthetic_sensitive_class" if (has_class or sensitive_noun) else "synthetic_low"
        if m.get("real_data_accessed") is True and (has_class or sensitive_noun):
            return "real_sensitive"
        if has_class or sensitive_noun:
            return "real_sensitive"
        return "unknown"

    # ---- novelty / duplicate --------------------------------------------------

    @property
    def novelty_claims(self) -> List[str]:
        nc = self._m.get("novelty_claims")
        out = [str(x) for x in nc] if isinstance(nc, list) else []
        if self._m.get("cross_tenant") is True and "cross_tenant" not in out:
            out.append("cross_tenant")
        if self._m.get("authorization_matrix_delta"):
            out.append("matrix_cell_violation")
        return out

    @property
    def generic_pattern(self) -> bool:
        """A commodity shape triage queues are flooded with — UNLESS it carries a
        novelty differentiator, judged in the duplicate axis."""
        if self.vuln_class == "exploit_chain":
            return False                                  # composition judged separately
        if self.subtype in ("horizontal_enumeration", "two_persona_owned"):
            return True
        if self.vuln_class == "bola":
            return bool(_GENERIC_ID_RE.search(str(self._m.get("object_ref", "")) or self.target))
        return self.vuln_class == "mass_assignment"

    # ---- clarity / invariant --------------------------------------------------

    @property
    def has_repro(self) -> bool:
        f, m = self.raw_finding, self._m
        return bool(f.get("steps") or m.get("hops") or m.get("evidence")
                    or m.get("object_ref") or m.get("endpoint"))

    @property
    def intended_invariant(self) -> str:
        return str(self._m.get("intended_invariant") or "").strip()

    @property
    def observed_violation(self) -> str:
        return str(self._m.get("observed_violation") or "").strip()

    @classmethod
    def from_finding(cls, finding: Dict[str, Any]) -> "EvidenceBundle":
        m = finding.get("metadata") or {}
        return cls(
            finding_id=str(finding.get("id") or finding.get("finding_id") or ""),
            vuln_class=str(m.get("vuln_class") or ""),
            subtype=m.get("subtype"),
            target=str(finding.get("target") or finding.get("host") or ""),
            proof_mode=str(m.get("proof_mode") or "lab"),
            restraint=dict(m.get("restraint") or {}),
            hops=[h for h in (m.get("hops") or []) if isinstance(h, dict)],
            confidence=m.get("confidence") or m.get("epistemic"),
            raw_finding=finding,
        )
