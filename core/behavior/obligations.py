"""Passive derivation of durable security obligations from behavioral evidence.

The graph is an explicit-only reasoning artifact.  It converts proven controls,
authorization proposals, and latent affordances into content-addressed questions
and dependencies.  It performs no target I/O and cannot resolve its own questions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .affordances import LatentAffordanceResult
from .lifecycle import LifecycleMiningResult
from .normalize import stable_hash
from .proposals import (
    CROSS_OBJECT_READ,
    STATE_MUTATION,
    ProposalBatch,
)

SECURITY_OBLIGATION_MODE = "behavioral_security_obligation_v1"

OPEN = "open"
UPHELD = "upheld"
VIOLATED = "violated"
SUBSUMED = "subsumed"
BLOCKED = "blocked"
UNREACHABLE = "unreachable"
OBLIGATION_STATUSES = frozenset(
    {OPEN, UPHELD, VIOLATED, SUBSUMED, BLOCKED, UNREACHABLE}
)

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    if not isinstance(value, str) or _HASH_REF.fullmatch(value) is None:
        return False
    return prefix is None or value.startswith(f"{prefix}:")


def _canonical_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target_origin must be an absolute HTTP(S) origin") from exc
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise ValueError("target_origin must be an absolute HTTP(S) origin")
    actual_port = port or (443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + (
        f":{actual_port}" if actual_port != default_port else ""
    )


@dataclass(frozen=True)
class SecurityObligationLimits:
    max_obligations: int = 8_192
    max_dependencies: int = 16_384
    max_evidence_refs_per_obligation: int = 64

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def _obligation_identity_payload(
    *,
    target_ref: str,
    kind: str,
    property_kind: str,
    subject_ref: str,
    prerequisite_ids: Sequence[str],
    risk_class: str,
    requires_execution: bool,
) -> Dict[str, Any]:
    return {
        "target_ref": target_ref,
        "kind": kind,
        "property_kind": property_kind,
        "subject_ref": subject_ref,
        "prerequisite_ids": list(prerequisite_ids),
        "risk_class": risk_class,
        "requires_execution": requires_execution,
    }


@dataclass(frozen=True)
class SecurityObligation:
    obligation_id: str
    target_ref: str
    kind: str
    property_kind: str
    subject_ref: str
    status: str
    prerequisite_ids: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]
    evidence_digest: str
    source_kind: str
    risk_class: str
    requires_execution: bool
    mode: str = SECURITY_OBLIGATION_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        identity = _obligation_identity_payload(
            target_ref=self.target_ref,
            kind=self.kind,
            property_kind=self.property_kind,
            subject_ref=self.subject_ref,
            prerequisite_ids=self.prerequisite_ids,
            risk_class=self.risk_class,
            requires_execution=self.requires_execution,
        )
        expected_evidence = stable_hash(
            "security_obligation_evidence",
            {"source_kind": self.source_kind, "evidence_refs": self.evidence_refs},
        )
        if (
            self.obligation_id != stable_hash("security_obligation", identity)
            or self.evidence_digest != expected_evidence
            or self.mode != SECURITY_OBLIGATION_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.subject_ref, "security_subject")
            or self.status not in {OPEN, UPHELD}
            or not _SEMANTIC.fullmatch(self.kind)
            or not _SEMANTIC.fullmatch(self.property_kind)
            or not _SEMANTIC.fullmatch(self.source_kind)
            or self.risk_class not in {"control", "read", "state_mutation", "unknown"}
            or not isinstance(self.requires_execution, bool)
            or tuple(sorted(set(self.prerequisite_ids))) != self.prerequisite_ids
            or any(
                not _hash_ref(item, "security_obligation")
                for item in self.prerequisite_ids
            )
            or not self.evidence_refs
            or tuple(sorted(set(self.evidence_refs))) != self.evidence_refs
            or any(not _hash_ref(item) for item in self.evidence_refs)
            or not _hash_ref(
                self.evidence_digest,
                "security_obligation_evidence",
            )
        ):
            raise ValueError("security obligation contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "target_ref": self.target_ref,
            "kind": self.kind,
            "property_kind": self.property_kind,
            "subject_ref": self.subject_ref,
            "status": self.status,
            "prerequisite_ids": list(self.prerequisite_ids),
            "evidence_refs": list(self.evidence_refs),
            "evidence_digest": self.evidence_digest,
            "source_kind": self.source_kind,
            "risk_class": self.risk_class,
            "requires_execution": self.requires_execution,
            "mode": self.mode,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class SecurityObligationDiagnostics:
    lifecycle_controls: int
    ownership_boundaries: int
    authorization_counterexamples: int
    latent_confirmations: int
    capability_confinements: int
    duplicate_obligations: int
    dropped_obligations: int
    dropped_dependencies: int
    dropped_evidence_refs: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError(
                "security obligation diagnostics must be non-negative integers"
            )

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class SecurityObligationGraph:
    status: str
    target_ref: str
    input_digest: str
    graph_digest: str
    obligations: Tuple[SecurityObligation, ...]
    diagnostics: SecurityObligationDiagnostics
    mode: str = SECURITY_OBLIGATION_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        expected_status = "ready" if self.obligations else "empty"
        ids = [item.obligation_id for item in self.obligations]
        expected_graph_digest = stable_hash(
            "security_obligation_graph",
            {
                "target_ref": self.target_ref,
                "input_digest": self.input_digest,
                "obligations": [item.to_dict() for item in self.obligations],
                "diagnostics": self.diagnostics.to_dict(),
            },
        )
        known = set(ids)
        if (
            self.status != expected_status
            or self.mode != SECURITY_OBLIGATION_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.input_digest, "security_obligation_inputs")
            or self.graph_digest != expected_graph_digest
            or ids != sorted(set(ids))
            or any(item.target_ref != self.target_ref for item in self.obligations)
            or any(
                prerequisite not in known
                for item in self.obligations
                for prerequisite in item.prerequisite_ids
            )
            or _has_cycle(self.obligations)
        ):
            raise ValueError("security obligation graph contract is invalid")

    def by_id(self) -> Dict[str, SecurityObligation]:
        return {item.obligation_id: item for item in self.obligations}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "status": self.status,
            "target_ref": self.target_ref,
            "input_digest": self.input_digest,
            "graph_digest": self.graph_digest,
            "obligations": [item.to_dict() for item in self.obligations],
            "diagnostics": self.diagnostics.to_dict(),
        }


def _has_cycle(obligations: Sequence[SecurityObligation]) -> bool:
    dependencies = {item.obligation_id: item.prerequisite_ids for item in obligations}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(obligation_id: str) -> bool:
        if obligation_id in visiting:
            return True
        if obligation_id in visited:
            return False
        visiting.add(obligation_id)
        if any(visit(item) for item in dependencies.get(obligation_id, ())):
            return True
        visiting.remove(obligation_id)
        visited.add(obligation_id)
        return False

    return any(visit(item) for item in dependencies)


def _risk_from_proposal(value: str) -> str:
    if value == CROSS_OBJECT_READ:
        return "read"
    if value == STATE_MUTATION:
        return "state_mutation"
    return "unknown"


class SecurityObligationGraphBuilder:
    """Derive bounded questions without resolving or executing them."""

    def __init__(self, limits: Optional[SecurityObligationLimits] = None) -> None:
        self.limits = limits or SecurityObligationLimits()

    def build(
        self,
        *,
        target_origin: str,
        lifecycle: Optional[LifecycleMiningResult] = None,
        proposals: Optional[ProposalBatch] = None,
        affordances: Optional[LatentAffordanceResult] = None,
    ) -> SecurityObligationGraph:
        if lifecycle is not None and not isinstance(lifecycle, LifecycleMiningResult):
            raise TypeError("lifecycle must be a LifecycleMiningResult")
        if proposals is not None and not isinstance(proposals, ProposalBatch):
            raise TypeError("proposals must be a ProposalBatch")
        if affordances is not None and not isinstance(
            affordances,
            LatentAffordanceResult,
        ):
            raise TypeError("affordances must be a LatentAffordanceResult")

        canonical_origin = _canonical_origin(target_origin)
        target_ref = stable_hash("security_obligation_target", canonical_origin)
        if affordances is not None:
            expected_affordance_target = stable_hash(
                "latent_affordance_target",
                canonical_origin,
            )
            if affordances.target_ref != expected_affordance_target:
                raise ValueError("affordance target does not match obligation target")

        input_payload = {
            "target_ref": target_ref,
            "lifecycle": lifecycle.to_dict() if lifecycle is not None else None,
            "proposals": proposals.to_dict() if proposals is not None else None,
            "affordances": affordances.to_dict() if affordances is not None else None,
        }
        input_digest = stable_hash("security_obligation_inputs", input_payload)
        obligations: Dict[str, SecurityObligation] = {}
        counts = {
            "lifecycle_controls": 0,
            "ownership_boundaries": 0,
            "authorization_counterexamples": 0,
            "latent_confirmations": 0,
            "capability_confinements": 0,
        }
        duplicate_obligations = 0
        dropped_obligations = 0
        dropped_dependencies = 0
        dropped_evidence_refs = 0
        dependency_count = 0

        def add(
            *,
            kind: str,
            property_kind: str,
            subject_ref: str,
            status: str,
            prerequisite_ids: Iterable[str],
            evidence_refs: Iterable[str],
            source_kind: str,
            risk_class: str,
            requires_execution: bool,
            count_key: str,
        ) -> Optional[str]:
            nonlocal duplicate_obligations
            nonlocal dropped_obligations
            nonlocal dropped_dependencies
            nonlocal dropped_evidence_refs
            nonlocal dependency_count

            prerequisites = tuple(sorted(set(prerequisite_ids)))
            evidence = tuple(sorted(set(evidence_refs)))
            if len(evidence) > self.limits.max_evidence_refs_per_obligation:
                dropped_evidence_refs += (
                    len(evidence) - self.limits.max_evidence_refs_per_obligation
                )
                evidence = evidence[: self.limits.max_evidence_refs_per_obligation]
            identity = _obligation_identity_payload(
                target_ref=target_ref,
                kind=kind,
                property_kind=property_kind,
                subject_ref=subject_ref,
                prerequisite_ids=prerequisites,
                risk_class=risk_class,
                requires_execution=requires_execution,
            )
            obligation_id = stable_hash("security_obligation", identity)
            if obligation_id in obligations:
                duplicate_obligations += 1
                return obligation_id
            if len(obligations) >= self.limits.max_obligations:
                dropped_obligations += 1
                return None
            if dependency_count + len(prerequisites) > self.limits.max_dependencies:
                dropped_dependencies += len(prerequisites)
                return None
            obligation = SecurityObligation(
                obligation_id=obligation_id,
                target_ref=target_ref,
                kind=kind,
                property_kind=property_kind,
                subject_ref=subject_ref,
                status=status,
                prerequisite_ids=prerequisites,
                evidence_refs=evidence,
                evidence_digest=stable_hash(
                    "security_obligation_evidence",
                    {"source_kind": source_kind, "evidence_refs": evidence},
                ),
                source_kind=source_kind,
                risk_class=risk_class,
                requires_execution=requires_execution,
            )
            obligations[obligation_id] = obligation
            dependency_count += len(prerequisites)
            counts[count_key] += 1
            return obligation_id

        if lifecycle is not None:
            for candidate in lifecycle.candidates:
                for read_operation_id in candidate.read_operation_ids:
                    subject = stable_hash(
                        "security_subject",
                        {
                            "lifecycle_id": candidate.lifecycle_id,
                            "read_operation_id": read_operation_id,
                        },
                    )
                    control_id = add(
                        kind="owned_control",
                        property_kind="owned_control_reproducibility",
                        subject_ref=subject,
                        status=UPHELD,
                        prerequisite_ids=(),
                        evidence_refs=(candidate.lifecycle_id,),
                        source_kind="lifecycle",
                        risk_class="control",
                        requires_execution=False,
                        count_key="lifecycle_controls",
                    )
                    if control_id is not None:
                        add(
                            kind="ownership_boundary",
                            property_kind="object_authorization",
                            subject_ref=subject,
                            status=OPEN,
                            prerequisite_ids=(control_id,),
                            evidence_refs=(candidate.lifecycle_id,),
                            source_kind="lifecycle",
                            risk_class="read",
                            requires_execution=True,
                            count_key="ownership_boundaries",
                        )

        if proposals is not None:
            for proposal in proposals.proposals:
                add(
                    kind="authorization_counterexample",
                    property_kind=proposal.property_kind,
                    subject_ref=stable_hash(
                        "security_subject",
                        {
                            "proposal_id": proposal.proposal_id,
                            "action_id": proposal.action_id,
                        },
                    ),
                    status=OPEN,
                    prerequisite_ids=(),
                    evidence_refs=(proposal.proposal_id,),
                    source_kind="authorization_proposal",
                    risk_class=_risk_from_proposal(proposal.risk_class),
                    requires_execution=True,
                    count_key="authorization_counterexamples",
                )

        if affordances is not None:
            for candidate in affordances.candidates:
                subject = stable_hash(
                    "security_subject",
                    {
                        "affordance_id": candidate.affordance_id,
                        "route_ref": candidate.consumer_route_ref,
                    },
                )
                evidence_refs = (
                    candidate.affordance_id,
                    candidate.evidence_digest,
                    *candidate.artifact_refs,
                )
                confirmation_id = add(
                    kind="latent_operation_confirmation",
                    property_kind="operation_reachability",
                    subject_ref=subject,
                    status=OPEN,
                    prerequisite_ids=(),
                    evidence_refs=evidence_refs,
                    source_kind="latent_affordance",
                    risk_class=candidate.risk_class,
                    requires_execution=True,
                    count_key="latent_confirmations",
                )
                if confirmation_id is not None:
                    add(
                        kind="capability_confinement",
                        property_kind="capability_confinement",
                        subject_ref=subject,
                        status=OPEN,
                        prerequisite_ids=(confirmation_id,),
                        evidence_refs=evidence_refs,
                        source_kind="latent_affordance",
                        risk_class=candidate.risk_class,
                        requires_execution=True,
                        count_key="capability_confinements",
                    )

        ordered = tuple(obligations[key] for key in sorted(obligations))
        diagnostics = SecurityObligationDiagnostics(
            **counts,
            duplicate_obligations=duplicate_obligations,
            dropped_obligations=dropped_obligations,
            dropped_dependencies=dropped_dependencies,
            dropped_evidence_refs=dropped_evidence_refs,
        )
        graph_payload = {
            "target_ref": target_ref,
            "input_digest": input_digest,
            "obligations": [item.to_dict() for item in ordered],
            "diagnostics": diagnostics.to_dict(),
        }
        return SecurityObligationGraph(
            status="ready" if ordered else "empty",
            target_ref=target_ref,
            input_digest=input_digest,
            graph_digest=stable_hash("security_obligation_graph", graph_payload),
            obligations=ordered,
            diagnostics=diagnostics,
        )


__all__ = [
    "BLOCKED",
    "OBLIGATION_STATUSES",
    "OPEN",
    "SECURITY_OBLIGATION_MODE",
    "SUBSUMED",
    "UNREACHABLE",
    "UPHELD",
    "VIOLATED",
    "SecurityObligation",
    "SecurityObligationDiagnostics",
    "SecurityObligationGraph",
    "SecurityObligationGraphBuilder",
    "SecurityObligationLimits",
]
