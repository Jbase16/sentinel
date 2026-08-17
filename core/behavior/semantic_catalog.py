"""Unified, bounded semantic reconstruction from already-acquired target evidence.

The catalog joins observed HTTP/GraphQL exchanges, published client artifacts,
observed DOM controls, exact server-issued identifiers, proven lifecycles, and
receipt-bound browser transitions.  It performs no acquisition or execution and
retains no raw target values in its public contracts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .affordances import (
    ClientArtifact,
    LatentAffordanceResult,
    client_artifact_ref,
)
from .compiler import (
    Capability,
    CapabilityKind,
    OperationContract,
    OperationSafety,
    operation_contracts_from_records,
)
from .interaction_state import BrowserTransitionResult
from .interactions import InteractionIntentCatalog
from .lifecycle import LifecycleMiningResult
from .normalize import normalize_exchange, stable_hash


TARGET_SEMANTIC_CATALOG_MODE = "behavioral_target_semantic_catalog_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.]{0,191}$")
_METHODS = frozenset(
    {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "UNKNOWN"}
)
_TENANT_FIELDS = (
    "tenant_id",
    "organization_id",
    "organisation_id",
    "workspace_id",
)
_CONTROL_FIELD = re.compile(
    r"(?:^|[_-])(?:lifecycle|membership|permission|phase|privilege|role|stage|state|status)"
    r"(?:$|[_-])",
    re.IGNORECASE,
)


def _hash_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _semantic(value: str, *, fallback: str = "unresolved") -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value).strip())
    normalized = re.sub(r"[^a-z0-9]+", ".", separated.lower()).strip(".")
    if not normalized:
        normalized = fallback
    return normalized[:192].rstrip(".") or fallback


def _input_order_ref(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=repr,
        )
    except (TypeError, ValueError):
        encoded = repr(value)
    return stable_hash("semantic_input_order", encoded)


def _canonical_origin(value: str) -> str:
    try:
        parts = urlsplit(str(value or "").strip())
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError as exc:
        raise ValueError("semantic target origin is invalid") from exc
    if (
        scheme not in {"http", "https"}
        or not host
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("semantic target origin must be an absolute HTTP(S) origin")
    default = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    return f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}"


class EpistemicStatus(str, Enum):
    OBSERVED = "observed"
    SPECIFIED = "specified"
    PUBLISHED = "published"
    INFERRED = "inferred"
    UNCONFIRMED = "unconfirmed"


_EPISTEMIC_RANK = {
    EpistemicStatus.OBSERVED: 0,
    EpistemicStatus.SPECIFIED: 1,
    EpistemicStatus.PUBLISHED: 2,
    EpistemicStatus.INFERRED: 3,
    EpistemicStatus.UNCONFIRMED: 4,
}


class SemanticSourceKind(str, Enum):
    REST_EXCHANGE = "rest_exchange"
    GRAPHQL_EXCHANGE = "graphql_exchange"
    HTML_FORM = "html_form"
    DOM_CONTROL = "dom_control"
    JAVASCRIPT = "javascript"
    SOURCE_MAP = "source_map"
    OPENAPI = "openapi"
    CLIENT_VALIDATION = "client_validation"
    SERVER_IDENTIFIER = "server_identifier"
    LIFECYCLE = "lifecycle"
    BROWSER_TRANSITION = "browser_transition"
    OTHER_ARTIFACT = "other_artifact"


class SemanticProtocol(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    ARTIFACT_ROUTE = "artifact_route"
    HTML_FORM = "html_form"
    DOM_CONTROL = "dom_control"
    BROWSER_TRANSITION = "browser_transition"


class SemanticSlotKind(str, Enum):
    RESOURCE_ID = "resource_id"
    PARENT_ID = "parent_id"
    OWNER_ID = "owner_id"
    TENANT_ID = "tenant_id"
    ROLE = "role"
    LIFECYCLE_STATE = "lifecycle_state"
    VALUE = "value"


class SemanticRelationKind(str, Enum):
    OPERATION_REQUIRES = "operation_requires"
    OPERATION_PRODUCES = "operation_produces"
    PARENT = "parent"
    OWNERSHIP = "ownership"
    TENANT = "tenant"
    ROLE = "role"
    LIFECYCLE_READ = "lifecycle_read"
    LIFECYCLE_CLEANUP = "lifecycle_cleanup"


@dataclass(frozen=True)
class SemanticCatalogLimits:
    max_records_per_world: int = 4_096
    max_artifacts: int = 64
    max_body_chars: int = 2 * 1024 * 1024
    max_total_body_chars: int = 16 * 1024 * 1024
    max_sources: int = 32_768
    max_operations: int = 8_192
    max_slots: int = 65_536
    max_resources: int = 32_768
    max_relations: int = 65_536
    max_deficits: int = 2_048
    max_deficit_source_refs: int = 64

    def __post_init__(self) -> None:
        hard_limits = {
            "max_records_per_world": 4_096,
            "max_artifacts": 64,
            "max_body_chars": 2 * 1024 * 1024,
            "max_total_body_chars": 16 * 1024 * 1024,
            "max_sources": 32_768,
            "max_operations": 8_192,
            "max_slots": 65_536,
            "max_resources": 32_768,
            "max_relations": 65_536,
            "max_deficits": 2_048,
            "max_deficit_source_refs": 64,
        }
        for name, maximum in hard_limits.items():
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > maximum
            ):
                raise ValueError(f"{name} must be a bounded positive integer")
        if self.max_total_body_chars < self.max_body_chars:
            raise ValueError("max_total_body_chars must cover max_body_chars")


def _source_payload(
    *,
    kind: SemanticSourceKind,
    epistemic_status: EpistemicStatus,
    evidence_ref: str,
    world_ref: Optional[str],
    tenant_ref: Optional[str],
    locator_ref: Optional[str],
) -> Dict[str, Any]:
    return {
        "kind": kind.value,
        "epistemic_status": epistemic_status.value,
        "evidence_ref": evidence_ref,
        "world_ref": world_ref,
        "tenant_ref": tenant_ref,
        "locator_ref": locator_ref,
    }


@dataclass(frozen=True)
class SemanticSource:
    source_id: str
    kind: SemanticSourceKind
    epistemic_status: EpistemicStatus
    evidence_ref: str
    world_ref: Optional[str] = None
    tenant_ref: Optional[str] = None
    locator_ref: Optional[str] = None

    @classmethod
    def build(
        cls,
        *,
        kind: SemanticSourceKind,
        epistemic_status: EpistemicStatus,
        evidence_ref: str,
        world_ref: Optional[str] = None,
        tenant_ref: Optional[str] = None,
        locator_ref: Optional[str] = None,
    ) -> "SemanticSource":
        payload = _source_payload(
            kind=kind,
            epistemic_status=epistemic_status,
            evidence_ref=evidence_ref,
            world_ref=world_ref,
            tenant_ref=tenant_ref,
            locator_ref=locator_ref,
        )
        return cls(
            source_id=stable_hash("semantic_source", payload),
            kind=kind,
            epistemic_status=epistemic_status,
            evidence_ref=evidence_ref,
            world_ref=world_ref,
            tenant_ref=tenant_ref,
            locator_ref=locator_ref,
        )

    def __post_init__(self) -> None:
        payload = _source_payload(
            kind=self.kind,
            epistemic_status=self.epistemic_status,
            evidence_ref=self.evidence_ref,
            world_ref=self.world_ref,
            tenant_ref=self.tenant_ref,
            locator_ref=self.locator_ref,
        )
        if (
            self.source_id != stable_hash("semantic_source", payload)
            or not _hash_ref(self.evidence_ref)
            or (self.world_ref is not None and not _hash_ref(self.world_ref, "world"))
            or (
                self.tenant_ref is not None
                and not _hash_ref(self.tenant_ref, "semantic_tenant")
            )
            or (self.locator_ref is not None and not _hash_ref(self.locator_ref))
        ):
            raise ValueError("semantic source contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            **_source_payload(
                kind=self.kind,
                epistemic_status=self.epistemic_status,
                evidence_ref=self.evidence_ref,
                world_ref=self.world_ref,
                tenant_ref=self.tenant_ref,
                locator_ref=self.locator_ref,
            ),
        }


def _operation_identity_payload(
    *,
    action_id: str,
    label: str,
    protocol: SemanticProtocol,
    method: str,
    world_ref: Optional[str],
    tenant_ref: Optional[str],
) -> Dict[str, Any]:
    return {
        "action_id": action_id,
        "label": label,
        "protocol": protocol.value,
        "method": method,
        "world_ref": world_ref,
        "tenant_ref": tenant_ref,
    }


def _operation_evidence_payload(
    *,
    safety: OperationSafety,
    epistemic_status: EpistemicStatus,
    observed_success: bool,
    source_ids: Sequence[str],
    requires_slot_ids: Sequence[str],
    produces_slot_ids: Sequence[str],
) -> Dict[str, Any]:
    return {
        "safety": safety.value,
        "epistemic_status": epistemic_status.value,
        "observed_success": observed_success,
        "source_ids": list(source_ids),
        "requires_slot_ids": list(requires_slot_ids),
        "produces_slot_ids": list(produces_slot_ids),
    }


@dataclass(frozen=True)
class SemanticOperation:
    operation_ref: str
    evidence_digest: str
    action_id: str
    label: str
    protocol: SemanticProtocol
    method: str
    safety: OperationSafety
    epistemic_status: EpistemicStatus
    observed_success: bool
    world_ref: Optional[str]
    tenant_ref: Optional[str]
    source_ids: Tuple[str, ...]
    requires_slot_ids: Tuple[str, ...]
    produces_slot_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        identity = _operation_identity_payload(
            action_id=self.action_id,
            label=self.label,
            protocol=self.protocol,
            method=self.method,
            world_ref=self.world_ref,
            tenant_ref=self.tenant_ref,
        )
        evidence = _operation_evidence_payload(
            safety=self.safety,
            epistemic_status=self.epistemic_status,
            observed_success=self.observed_success,
            source_ids=self.source_ids,
            requires_slot_ids=self.requires_slot_ids,
            produces_slot_ids=self.produces_slot_ids,
        )
        if (
            self.operation_ref != stable_hash("semantic_operation", identity)
            or self.evidence_digest
            != stable_hash("semantic_operation_evidence", evidence)
            or not _hash_ref(self.action_id, "action")
            or _SEMANTIC.fullmatch(self.label) is None
            or self.method not in _METHODS
            or (self.world_ref is not None and not _hash_ref(self.world_ref, "world"))
            or (
                self.tenant_ref is not None
                and not _hash_ref(self.tenant_ref, "semantic_tenant")
            )
            or not self.source_ids
            or self.source_ids != tuple(sorted(set(self.source_ids)))
            or any(not _hash_ref(item, "semantic_source") for item in self.source_ids)
            or self.requires_slot_ids
            != tuple(sorted(set(self.requires_slot_ids)))
            or self.produces_slot_ids
            != tuple(sorted(set(self.produces_slot_ids)))
            or any(
                not _hash_ref(item, "semantic_slot")
                for item in (*self.requires_slot_ids, *self.produces_slot_ids)
            )
            or set(self.requires_slot_ids) & set(self.produces_slot_ids)
        ):
            raise ValueError("semantic operation contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_ref": self.operation_ref,
            "evidence_digest": self.evidence_digest,
            **_operation_identity_payload(
                action_id=self.action_id,
                label=self.label,
                protocol=self.protocol,
                method=self.method,
                world_ref=self.world_ref,
                tenant_ref=self.tenant_ref,
            ),
            **_operation_evidence_payload(
                safety=self.safety,
                epistemic_status=self.epistemic_status,
                observed_success=self.observed_success,
                source_ids=self.source_ids,
                requires_slot_ids=self.requires_slot_ids,
                produces_slot_ids=self.produces_slot_ids,
            ),
        }


def _slot_payload(
    *,
    operation_ref: str,
    capability: Capability,
    direction: str,
    slot_kind: SemanticSlotKind,
    server_issued: bool,
    source_ids: Sequence[str],
) -> Dict[str, Any]:
    return {
        "operation_ref": operation_ref,
        "capability": capability.to_dict(),
        "direction": direction,
        "slot_kind": slot_kind.value,
        "server_issued": server_issued,
        "source_ids": list(source_ids),
    }


@dataclass(frozen=True)
class SemanticSlot:
    slot_id: str
    operation_ref: str
    capability: Capability
    direction: str
    slot_kind: SemanticSlotKind
    server_issued: bool
    source_ids: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        operation_ref: str,
        capability: Capability,
        direction: str,
        slot_kind: SemanticSlotKind,
        server_issued: bool,
        source_ids: Sequence[str],
    ) -> "SemanticSlot":
        sources = tuple(sorted(set(source_ids)))
        payload = _slot_payload(
            operation_ref=operation_ref,
            capability=capability,
            direction=direction,
            slot_kind=slot_kind,
            server_issued=server_issued,
            source_ids=sources,
        )
        return cls(
            slot_id=stable_hash("semantic_slot", payload),
            operation_ref=operation_ref,
            capability=capability,
            direction=direction,
            slot_kind=slot_kind,
            server_issued=server_issued,
            source_ids=sources,
        )

    def __post_init__(self) -> None:
        payload = _slot_payload(
            operation_ref=self.operation_ref,
            capability=self.capability,
            direction=self.direction,
            slot_kind=self.slot_kind,
            server_issued=self.server_issued,
            source_ids=self.source_ids,
        )
        if (
            self.slot_id != stable_hash("semantic_slot", payload)
            or not _hash_ref(self.operation_ref, "semantic_operation")
            or self.direction not in {"requires", "produces"}
            or self.server_issued != (
                self.direction == "produces"
                and self.capability.kind is CapabilityKind.VALUE
            )
            or not self.source_ids
            or self.source_ids != tuple(sorted(set(self.source_ids)))
            or any(not _hash_ref(item, "semantic_source") for item in self.source_ids)
        ):
            raise ValueError("semantic slot contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            **_slot_payload(
                operation_ref=self.operation_ref,
                capability=self.capability,
                direction=self.direction,
                slot_kind=self.slot_kind,
                server_issued=self.server_issued,
                source_ids=self.source_ids,
            ),
        }


def _resource_payload(
    *,
    name: str,
    kind: SemanticSlotKind,
    world_ref: Optional[str],
    tenant_ref: Optional[str],
) -> Dict[str, Any]:
    return {
        "name": name,
        "kind": kind.value,
        "world_ref": world_ref,
        "tenant_ref": tenant_ref,
    }


@dataclass(frozen=True)
class SemanticResource:
    resource_ref: str
    evidence_digest: str
    name: str
    kind: SemanticSlotKind
    world_ref: Optional[str]
    tenant_ref: Optional[str]
    slot_ids: Tuple[str, ...]
    source_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        identity = _resource_payload(
            name=self.name,
            kind=self.kind,
            world_ref=self.world_ref,
            tenant_ref=self.tenant_ref,
        )
        evidence = {
            "slot_ids": list(self.slot_ids),
            "source_ids": list(self.source_ids),
        }
        if (
            self.resource_ref != stable_hash("semantic_resource", identity)
            or self.evidence_digest != stable_hash("semantic_resource_evidence", evidence)
            or _SEMANTIC.fullmatch(self.name) is None
            or self.kind is SemanticSlotKind.VALUE
            or (self.world_ref is not None and not _hash_ref(self.world_ref, "world"))
            or (
                self.tenant_ref is not None
                and not _hash_ref(self.tenant_ref, "semantic_tenant")
            )
            or not self.slot_ids
            or self.slot_ids != tuple(sorted(set(self.slot_ids)))
            or any(not _hash_ref(item, "semantic_slot") for item in self.slot_ids)
            or not self.source_ids
            or self.source_ids != tuple(sorted(set(self.source_ids)))
            or any(not _hash_ref(item, "semantic_source") for item in self.source_ids)
        ):
            raise ValueError("semantic resource contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_ref": self.resource_ref,
            "evidence_digest": self.evidence_digest,
            **_resource_payload(
                name=self.name,
                kind=self.kind,
                world_ref=self.world_ref,
                tenant_ref=self.tenant_ref,
            ),
            "slot_ids": list(self.slot_ids),
            "source_ids": list(self.source_ids),
        }


def _relation_payload(
    *,
    kind: SemanticRelationKind,
    from_ref: str,
    to_ref: str,
    epistemic_status: EpistemicStatus,
    source_ids: Sequence[str],
) -> Dict[str, Any]:
    return {
        "kind": kind.value,
        "from_ref": from_ref,
        "to_ref": to_ref,
        "epistemic_status": epistemic_status.value,
        "source_ids": list(source_ids),
    }


@dataclass(frozen=True)
class SemanticRelation:
    relation_ref: str
    kind: SemanticRelationKind
    from_ref: str
    to_ref: str
    epistemic_status: EpistemicStatus
    source_ids: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        kind: SemanticRelationKind,
        from_ref: str,
        to_ref: str,
        epistemic_status: EpistemicStatus,
        source_ids: Sequence[str],
    ) -> "SemanticRelation":
        sources = tuple(sorted(set(source_ids)))
        payload = _relation_payload(
            kind=kind,
            from_ref=from_ref,
            to_ref=to_ref,
            epistemic_status=epistemic_status,
            source_ids=sources,
        )
        return cls(
            relation_ref=stable_hash("semantic_relation", payload),
            kind=kind,
            from_ref=from_ref,
            to_ref=to_ref,
            epistemic_status=epistemic_status,
            source_ids=sources,
        )

    def __post_init__(self) -> None:
        payload = _relation_payload(
            kind=self.kind,
            from_ref=self.from_ref,
            to_ref=self.to_ref,
            epistemic_status=self.epistemic_status,
            source_ids=self.source_ids,
        )
        if (
            self.relation_ref != stable_hash("semantic_relation", payload)
            or not _hash_ref(self.from_ref)
            or not _hash_ref(self.to_ref)
            or self.from_ref == self.to_ref
            or not self.source_ids
            or self.source_ids != tuple(sorted(set(self.source_ids)))
            or any(not _hash_ref(item, "semantic_source") for item in self.source_ids)
        ):
            raise ValueError("semantic relation contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relation_ref": self.relation_ref,
            **_relation_payload(
                kind=self.kind,
                from_ref=self.from_ref,
                to_ref=self.to_ref,
                epistemic_status=self.epistemic_status,
                source_ids=self.source_ids,
            ),
        }


@dataclass(frozen=True)
class SemanticCoverageDeficit:
    deficit_id: str
    code: str
    count: int
    source_refs: Tuple[str, ...] = ()

    @classmethod
    def build(
        cls,
        *,
        code: str,
        count: int,
        source_refs: Sequence[str] = (),
    ) -> "SemanticCoverageDeficit":
        refs = tuple(sorted(set(source_refs)))
        payload = {"code": code, "count": count, "source_refs": list(refs)}
        return cls(
            deficit_id=stable_hash("semantic_coverage_deficit", payload),
            code=code,
            count=count,
            source_refs=refs,
        )

    def __post_init__(self) -> None:
        payload = {
            "code": self.code,
            "count": self.count,
            "source_refs": list(self.source_refs),
        }
        if (
            self.deficit_id != stable_hash("semantic_coverage_deficit", payload)
            or _SEMANTIC.fullmatch(self.code) is None
            or isinstance(self.count, bool)
            or not isinstance(self.count, int)
            or self.count <= 0
            or self.source_refs != tuple(sorted(set(self.source_refs)))
            or any(not _hash_ref(item) for item in self.source_refs)
        ):
            raise ValueError("semantic coverage deficit contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deficit_id": self.deficit_id,
            "code": self.code,
            "count": self.count,
            "source_refs": list(self.source_refs),
        }


@dataclass(frozen=True)
class SemanticCatalogDiagnostics:
    input_records: int
    accepted_records: int
    invalid_records: int
    sources: int
    operations: int
    slots: int
    resources: int
    relations: int
    deficits: int
    ambiguities: int
    conflicts: int
    dropped_records: int
    dropped_artifacts: int
    dropped_sources: int
    dropped_operations: int
    dropped_slots: int
    dropped_resources: int
    dropped_relations: int
    dropped_deficits: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("semantic catalog diagnostics are invalid")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _catalog_payload(
    *,
    status: str,
    target_ref: str,
    sources: Sequence[SemanticSource],
    operations: Sequence[SemanticOperation],
    slots: Sequence[SemanticSlot],
    resources: Sequence[SemanticResource],
    relations: Sequence[SemanticRelation],
    deficits: Sequence[SemanticCoverageDeficit],
    diagnostics: SemanticCatalogDiagnostics,
) -> Dict[str, Any]:
    return {
        "status": status,
        "target_ref": target_ref,
        "sources": [item.to_dict() for item in sources],
        "operations": [item.to_dict() for item in operations],
        "slots": [item.to_dict() for item in slots],
        "resources": [item.to_dict() for item in resources],
        "relations": [item.to_dict() for item in relations],
        "deficits": [item.to_dict() for item in deficits],
        "diagnostics": diagnostics.to_dict(),
    }


@dataclass(frozen=True)
class TargetSemanticCatalog:
    catalog_id: str
    status: str
    target_ref: str
    sources: Tuple[SemanticSource, ...]
    operations: Tuple[SemanticOperation, ...]
    slots: Tuple[SemanticSlot, ...]
    resources: Tuple[SemanticResource, ...]
    relations: Tuple[SemanticRelation, ...]
    deficits: Tuple[SemanticCoverageDeficit, ...]
    diagnostics: SemanticCatalogDiagnostics
    mode: str = TARGET_SEMANTIC_CATALOG_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        expected_status = (
            "no_semantics"
            if not self.operations
            else "partial"
            if self.deficits
            else "ready"
        )
        payload = _catalog_payload(
            status=self.status,
            target_ref=self.target_ref,
            sources=self.sources,
            operations=self.operations,
            slots=self.slots,
            resources=self.resources,
            relations=self.relations,
            deficits=self.deficits,
            diagnostics=self.diagnostics,
        )
        source_ids = {item.source_id for item in self.sources}
        operation_refs = {item.operation_ref for item in self.operations}
        slot_ids = {item.slot_id for item in self.slots}
        resource_refs = {item.resource_ref for item in self.resources}
        node_refs = operation_refs | resource_refs
        if (
            self.catalog_id != stable_hash("target_semantic_catalog", payload)
            or self.status != expected_status
            or self.mode != TARGET_SEMANTIC_CATALOG_MODE
            or self.executable
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or [item.source_id for item in self.sources] != sorted(source_ids)
            or [item.operation_ref for item in self.operations]
            != sorted(operation_refs)
            or [item.slot_id for item in self.slots] != sorted(slot_ids)
            or [item.resource_ref for item in self.resources]
            != sorted(resource_refs)
            or [item.relation_ref for item in self.relations]
            != sorted({item.relation_ref for item in self.relations})
            or [item.deficit_id for item in self.deficits]
            != sorted({item.deficit_id for item in self.deficits})
            or any(not set(item.source_ids) <= source_ids for item in self.operations)
            or any(
                not set((*item.requires_slot_ids, *item.produces_slot_ids)) <= slot_ids
                for item in self.operations
            )
            or any(
                item.operation_ref not in operation_refs
                or not set(item.source_ids) <= source_ids
                for item in self.slots
            )
            or any(
                not set(item.slot_ids) <= slot_ids
                or not set(item.source_ids) <= source_ids
                for item in self.resources
            )
            or any(
                item.from_ref not in node_refs
                or item.to_ref not in node_refs
                or not set(item.source_ids) <= source_ids
                for item in self.relations
            )
            or self.diagnostics.sources != len(self.sources)
            or self.diagnostics.operations != len(self.operations)
            or self.diagnostics.slots != len(self.slots)
            or self.diagnostics.resources != len(self.resources)
            or self.diagnostics.relations != len(self.relations)
            or self.diagnostics.deficits != len(self.deficits)
            or self.diagnostics.input_records
            != (
                self.diagnostics.accepted_records
                + self.diagnostics.invalid_records
                + self.diagnostics.dropped_records
            )
        ):
            raise ValueError("target semantic catalog contract is invalid")

    def planner_operations(self) -> Tuple[OperationContract, ...]:
        """Project semantic operations into the existing passive planner contract."""

        slots = {item.slot_id: item for item in self.slots}
        return tuple(
            OperationContract(
                operation_id=operation.action_id,
                label=operation.label,
                requires=tuple(
                    slots[item].capability for item in operation.requires_slot_ids
                ),
                produces=tuple(
                    slots[item].capability for item in operation.produces_slot_ids
                ),
                safety=operation.safety,
                observed_success=operation.observed_success,
                source_refs=tuple(
                    stable_hash("source_ref", item) for item in operation.source_ids
                ),
            )
            for operation in self.operations
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "catalog_id": self.catalog_id,
            **_catalog_payload(
                status=self.status,
                target_ref=self.target_ref,
                sources=self.sources,
                operations=self.operations,
                slots=self.slots,
                resources=self.resources,
                relations=self.relations,
                deficits=self.deficits,
                diagnostics=self.diagnostics,
            ),
        }


@dataclass
class _OperationDraft:
    action_id: str
    label: str
    protocol: SemanticProtocol
    method: str
    safety: OperationSafety
    world_ref: Optional[str]
    tenant_ref: Optional[str]
    sources: set[str] = field(default_factory=set)
    requires: set[Capability] = field(default_factory=set)
    produces: set[Capability] = field(default_factory=set)
    requires_source_ids: Dict[Capability, set[str]] = field(default_factory=dict)
    produces_source_ids: Dict[Capability, set[str]] = field(default_factory=dict)
    epistemic_statuses: set[EpistemicStatus] = field(default_factory=set)
    observed_success: bool = False

    def bind_default_sources(self) -> None:
        for capability in self.requires:
            self.requires_source_ids.setdefault(capability, set()).update(self.sources)
        for capability in self.produces:
            self.produces_source_ids.setdefault(capability, set()).update(self.sources)

    @property
    def key(self) -> Tuple[str, ...]:
        return (
            self.action_id,
            self.label,
            self.protocol.value,
            self.method,
            self.world_ref or "",
            self.tenant_ref or "",
        )

    @property
    def operation_ref(self) -> str:
        return stable_hash(
            "semantic_operation",
            _operation_identity_payload(
                action_id=self.action_id,
                label=self.label,
                protocol=self.protocol,
                method=self.method,
                world_ref=self.world_ref,
                tenant_ref=self.tenant_ref,
            ),
        )


class _DeficitAccumulator:
    def __init__(self) -> None:
        self.counts: Dict[str, int] = {}
        self.refs: Dict[str, set[str]] = {}

    def add(
        self,
        code: str,
        count: int = 1,
        refs: Iterable[str] = (),
    ) -> None:
        if count <= 0:
            return
        self.counts[code] = self.counts.get(code, 0) + count
        self.refs.setdefault(code, set()).update(item for item in refs if _hash_ref(item))


def _tenant_ref(record: Mapping[str, Any]) -> Optional[str]:
    for key in _TENANT_FIELDS:
        value = record.get(key)
        if value not in (None, ""):
            return stable_hash(
                "semantic_tenant",
                {"field": key, "value": str(value)},
            )
    return None


def _control_capabilities(value: Any) -> Tuple[Tuple[Capability, ...], bool]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return (), False
    output: set[Capability] = set()
    truncated = False
    seen_fields = 0

    def visit(item: Any, path: Tuple[str, ...], depth: int) -> None:
        nonlocal seen_fields, truncated
        if depth > 7:
            truncated = True
            return
        if isinstance(item, Mapping):
            for raw_key in sorted(item, key=str):
                seen_fields += 1
                if seen_fields > 256:
                    truncated = True
                    return
                key = _semantic(str(raw_key), fallback="field").replace(".", "_")
                child_path = (*path, key)
                if _CONTROL_FIELD.search(key):
                    kind = (
                        CapabilityKind.STATE
                        if set(key.split("_"))
                        & {"lifecycle", "phase", "stage", "state", "status"}
                        else CapabilityKind.VALUE
                    )
                    output.add(Capability(kind, "_".join(child_path[-2:])))
                visit(item[raw_key], child_path, depth + 1)
        elif isinstance(item, list):
            for child in item[:8]:
                visit(child, path, depth + 1)
            if len(item) > 8:
                truncated = True

    visit(value, (), 0)
    return tuple(sorted(output, key=lambda item: item.key)), truncated


def _record_label(contract: OperationContract) -> Tuple[str, bool, SemanticProtocol]:
    if "/" not in contract.label and " " not in contract.label:
        return (
            f"graphql.{_semantic(contract.label)}",
            False,
            SemanticProtocol.GRAPHQL,
        )
    redacted = "{value}" in contract.label
    return (
        f"rest.{_semantic(contract.label)}",
        redacted,
        SemanticProtocol.REST,
    )


def _graphql_hint(record: Mapping[str, Any]) -> bool:
    try:
        path = urlsplit(str(record.get("url") or "")).path.lower().rstrip("/")
    except ValueError:
        path = ""
    if path.endswith("/graphql"):
        return True
    body = record.get("request_body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (TypeError, ValueError):
            return False
    return isinstance(body, Mapping) and bool(
        {"operationName", "query", "extensions"} & set(body)
    )


def _artifact_label(method: str, path_template: str) -> Tuple[str, bool]:
    synthetic_method = method if method in _METHODS else "UNKNOWN"
    synthetic = {
        "method": synthetic_method,
        "url": f"https://semantic.invalid{path_template}",
        "response_status": 0,
    }
    contracts = operation_contracts_from_records((synthetic,))
    if not contracts:
        return "artifact_route.unresolved", True
    label = contracts[0].label
    return f"artifact_route.{_semantic(label)}", "{value}" in label


def _slot_kind(capability: Capability) -> SemanticSlotKind:
    name = capability.name.lower()
    tokens = set(re.split(r"[_.:-]+", name))
    if capability.kind is CapabilityKind.STATE or tokens & {
        "phase",
        "stage",
        "state",
        "status",
    }:
        return SemanticSlotKind.LIFECYCLE_STATE
    if tokens & {"role", "permission", "privilege"}:
        return SemanticSlotKind.ROLE
    if name.startswith("parent_") or "parent" in tokens:
        return SemanticSlotKind.PARENT_ID
    if tokens & {"tenant", "organization", "organisation", "workspace"}:
        return SemanticSlotKind.TENANT_ID
    if name.startswith(("owner_", "user_", "member_")):
        return SemanticSlotKind.OWNER_ID
    if name.endswith(("_id", "_ids", "_uuid")) or name in {"id", "ids", "uuid"}:
        return SemanticSlotKind.RESOURCE_ID
    return SemanticSlotKind.VALUE


def _resource_name(slot: SemanticSlot) -> str:
    if slot.slot_kind is SemanticSlotKind.LIFECYCLE_STATE:
        return "lifecycle_state"
    name = slot.capability.name.lower().replace(":", ".")
    name = re.sub(r"(?:_ids?|_uuid)$", "", name)
    if slot.slot_kind is SemanticSlotKind.ROLE:
        name = "role"
    return _semantic(name, fallback=slot.slot_kind.value)


def _intent_safety(risk_class: str) -> OperationSafety:
    if risk_class == "read_interaction":
        return OperationSafety.READ_ONLY
    if risk_class == "destructive":
        return OperationSafety.DESTRUCTIVE
    if risk_class == "externally_consequential":
        return OperationSafety.EXTERNAL_EFFECT
    return OperationSafety.UNKNOWN


class TargetSemanticCatalogBuilder:
    """Compile heterogeneous acquired evidence into one redacted semantic graph."""

    def __init__(
        self,
        limits: SemanticCatalogLimits = SemanticCatalogLimits(),
    ) -> None:
        if not isinstance(limits, SemanticCatalogLimits):
            raise TypeError("limits must be SemanticCatalogLimits")
        self.limits = limits

    def build(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        target_ref: str,
        target_origin: str,
        world_id: str = "captured",
        peer_records: Sequence[Mapping[str, Any]] = (),
        peer_world_id: str = "peer",
        artifacts: Sequence[ClientArtifact] = (),
        affordances: Optional[LatentAffordanceResult] = None,
        interactions: Optional[InteractionIntentCatalog] = None,
        lifecycle: Optional[LifecycleMiningResult] = None,
        browser_transitions: Sequence[BrowserTransitionResult] = (),
    ) -> TargetSemanticCatalog:
        origin = _canonical_origin(target_origin)
        if target_ref != stable_hash("security_obligation_target", origin):
            raise ValueError("semantic target_ref does not match target_origin")
        if isinstance(records, (str, bytes)) or isinstance(
            peer_records, (str, bytes)
        ):
            raise TypeError("semantic records must be sequences")
        if any(not isinstance(item, Mapping) for item in (*records, *peer_records)):
            raise TypeError("semantic records must contain mappings")
        if not isinstance(world_id, str) or not world_id:
            raise ValueError("semantic world_id must be non-empty")
        if peer_records and (
            not isinstance(peer_world_id, str)
            or not peer_world_id
            or peer_world_id == world_id
        ):
            raise ValueError("semantic peer world must be distinct")
        if isinstance(artifacts, (str, bytes)) or any(
            not isinstance(item, ClientArtifact) for item in artifacts
        ):
            raise TypeError("semantic artifacts must contain ClientArtifact values")
        if any(
            not isinstance(item, BrowserTransitionResult)
            for item in browser_transitions
        ):
            raise TypeError("browser_transitions must contain BrowserTransitionResult values")
        if affordances is not None and not isinstance(
            affordances,
            LatentAffordanceResult,
        ):
            raise TypeError("affordances must be a LatentAffordanceResult")
        if interactions is not None and not isinstance(
            interactions,
            InteractionIntentCatalog,
        ):
            raise TypeError("interactions must be an InteractionIntentCatalog")
        if lifecycle is not None and not isinstance(lifecycle, LifecycleMiningResult):
            raise TypeError("lifecycle must be a LifecycleMiningResult")
        if affordances is not None and affordances.target_ref != stable_hash(
            "latent_affordance_target",
            origin,
        ):
            raise ValueError("semantic affordance target does not match target_origin")
        if interactions is not None and interactions.target_ref != stable_hash(
            "interaction_target",
            origin,
        ):
            raise ValueError("semantic interaction target does not match target_origin")

        deficits = _DeficitAccumulator()
        source_values: Dict[str, SemanticSource] = {}
        drafts: Dict[Tuple[str, ...], _OperationDraft] = {}
        input_records = len(records) + len(peer_records)
        accepted_records = 0
        invalid_records = 0
        dropped_records = 0
        total_body_chars = 0
        observation_actions: Dict[str, set[str]] = {}
        lifecycle_sources: Dict[str, str] = {}

        def add_source(source: SemanticSource) -> str:
            source_values[source.source_id] = source
            return source.source_id

        def add_draft(value: _OperationDraft) -> None:
            value.bind_default_sources()
            existing = drafts.get(value.key)
            if existing is None:
                drafts[value.key] = value
                return
            if existing.safety is not value.safety:
                deficits.add(
                    "conflicting_operation_safety",
                    refs=(*existing.sources, *value.sources),
                )
            existing.sources.update(value.sources)
            existing.requires.update(value.requires)
            existing.produces.update(value.produces)
            for capability, source_ids in value.requires_source_ids.items():
                existing.requires_source_ids.setdefault(capability, set()).update(
                    source_ids
                )
            for capability, source_ids in value.produces_source_ids.items():
                existing.produces_source_ids.setdefault(capability, set()).update(
                    source_ids
                )
            existing.epistemic_statuses.update(value.epistemic_statuses)
            existing.observed_success = existing.observed_success or value.observed_success

        worlds = ((world_id, records), (peer_world_id, peer_records))
        for default_world, world_records in worlds:
            ordered = sorted(world_records, key=_input_order_ref)
            retained = ordered[: self.limits.max_records_per_world]
            dropped = len(ordered) - len(retained)
            dropped_records += dropped
            deficits.add("record_limit_truncated", dropped)
            for record in retained:
                body_chars = sum(
                    len(value)
                    for value in (
                        record.get("request_body"),
                        record.get("response_body"),
                    )
                    if isinstance(value, str)
                )
                if (
                    body_chars > self.limits.max_body_chars
                    or total_body_chars + body_chars > self.limits.max_total_body_chars
                ):
                    invalid_records += 1
                    deficits.add("record_body_limit_exceeded")
                    continue
                total_body_chars += body_chars
                try:
                    exchange = normalize_exchange(
                        record,
                        source_id=str(record.get("id") or _input_order_ref(record)),
                        world_id=str(record.get("persona_id") or default_world),
                    )
                    contracts = operation_contracts_from_records(
                        (record,),
                        world_id=str(record.get("persona_id") or default_world),
                    )
                except (TypeError, ValueError):
                    invalid_records += 1
                    deficits.add("invalid_observation_record")
                    continue
                if len(contracts) != 1:
                    invalid_records += 1
                    deficits.add("operation_contract_unavailable")
                    continue
                accepted_records += 1
                contract = contracts[0]
                request_controls, request_controls_truncated = _control_capabilities(
                    record.get("request_body")
                )
                response_controls, response_controls_truncated = _control_capabilities(
                    record.get("response_body")
                )
                label, redacted, protocol = _record_label(contract)
                graphql_unresolved = (
                    protocol is SemanticProtocol.REST and _graphql_hint(record)
                )
                if graphql_unresolved:
                    label = "graphql.operation.unresolved"
                    redacted = False
                    protocol = SemanticProtocol.GRAPHQL
                tenant_ref = _tenant_ref(record)
                source_kind = (
                    SemanticSourceKind.GRAPHQL_EXCHANGE
                    if protocol is SemanticProtocol.GRAPHQL
                    else SemanticSourceKind.REST_EXCHANGE
                )
                exchange_source_id = add_source(
                    SemanticSource.build(
                        kind=source_kind,
                        epistemic_status=EpistemicStatus.OBSERVED,
                        evidence_ref=exchange.source_id,
                        world_ref=exchange.world_id,
                        tenant_ref=tenant_ref,
                    )
                )
                source_ids = {exchange_source_id}
                if any(item.kind is CapabilityKind.VALUE for item in contract.produces):
                    source_ids.add(
                        add_source(
                            SemanticSource.build(
                                kind=SemanticSourceKind.SERVER_IDENTIFIER,
                                epistemic_status=EpistemicStatus.OBSERVED,
                                evidence_ref=exchange.source_id,
                                world_ref=exchange.world_id,
                                tenant_ref=tenant_ref,
                                locator_ref=stable_hash(
                                    "semantic_identifier_shape",
                                    [item.to_dict() for item in contract.produces],
                                ),
                            )
                        )
                    )
                if redacted:
                    deficits.add("redacted_path_semantics", refs=source_ids)
                if graphql_unresolved:
                    deficits.add(
                        "graphql_operation_semantics_unresolved",
                        refs=source_ids,
                    )
                if request_controls_truncated or response_controls_truncated:
                    deficits.add(
                        "control_metadata_truncated",
                        refs=source_ids,
                    )
                observation_actions.setdefault(exchange.source_id, set()).add(
                    contract.operation_id
                )
                required_capabilities = {*contract.requires, *request_controls}
                produced_capabilities = (
                    {*contract.produces, *response_controls}
                    if contract.observed_success
                    else set()
                )
                add_draft(
                    _OperationDraft(
                        action_id=contract.operation_id,
                        label=label,
                        protocol=protocol,
                        method=exchange.method if exchange.method in _METHODS else "UNKNOWN",
                        safety=contract.safety,
                        world_ref=exchange.world_id,
                        tenant_ref=tenant_ref,
                        sources=source_ids,
                        requires=required_capabilities,
                        produces=produced_capabilities,
                        requires_source_ids={
                            capability: {exchange_source_id}
                            for capability in required_capabilities
                        },
                        produces_source_ids={
                            capability: set(source_ids)
                            for capability in produced_capabilities
                        },
                        epistemic_statuses={EpistemicStatus.OBSERVED},
                        observed_success=contract.observed_success,
                    )
                )

        for actions in observation_actions.values():
            if len(actions) > 1:
                deficits.add("conflicting_observation_source", len(actions) - 1)
        action_labels: Dict[Tuple[str, str, str], set[str]] = {}
        for draft in drafts.values():
            key = (draft.action_id, draft.world_ref or "", draft.tenant_ref or "")
            action_labels.setdefault(key, set()).add(draft.label)
        for labels in action_labels.values():
            if len(labels) > 1:
                deficits.add("ambiguous_action_semantics", len(labels) - 1)

        artifact_ref_to_source: Dict[str, str] = {}
        artifact_versions: Dict[str, set[str]] = {}
        ordered_artifacts = sorted(artifacts, key=client_artifact_ref)
        retained_artifacts = ordered_artifacts[: self.limits.max_artifacts]
        dropped_artifacts = len(ordered_artifacts) - len(retained_artifacts)
        deficits.add("artifact_limit_truncated", dropped_artifacts)
        artifact_kinds = {
            "javascript": (
                SemanticSourceKind.JAVASCRIPT,
                EpistemicStatus.PUBLISHED,
            ),
            "source_map": (
                SemanticSourceKind.SOURCE_MAP,
                EpistemicStatus.PUBLISHED,
            ),
            "openapi": (SemanticSourceKind.OPENAPI, EpistemicStatus.SPECIFIED),
            "other": (
                SemanticSourceKind.OTHER_ARTIFACT,
                EpistemicStatus.UNCONFIRMED,
            ),
        }
        for artifact in retained_artifacts:
            evidence_ref = client_artifact_ref(artifact)
            locator_ref = stable_hash("semantic_artifact_locator", artifact.source)
            kind, status = artifact_kinds[artifact.kind]
            source_id = add_source(
                SemanticSource.build(
                    kind=kind,
                    epistemic_status=status,
                    evidence_ref=evidence_ref,
                    locator_ref=locator_ref,
                )
            )
            artifact_ref_to_source[evidence_ref] = source_id
            artifact_versions.setdefault(locator_ref, set()).add(evidence_ref)
        for versions in artifact_versions.values():
            if len(versions) > 1:
                deficits.add("conflicting_artifact_versions", len(versions) - 1, versions)

        if affordances is not None:
            affordance_diagnostics = affordances.diagnostics
            deficits.add(
                "ambiguous_published_routes",
                affordance_diagnostics.ambiguous_routes,
            )
            deficits.add(
                "unmatched_published_routes",
                affordance_diagnostics.unmatched_routes,
            )
            deficits.add(
                "published_route_truncation",
                affordance_diagnostics.dropped_candidates
                + affordance_diagnostics.dropped_artifacts,
            )
            for candidate in affordances.candidates:
                source_ids = {
                    artifact_ref_to_source[item]
                    for item in candidate.artifact_refs
                    if item in artifact_ref_to_source
                }
                if not source_ids:
                    deficits.add(
                        "published_route_source_unavailable",
                        refs=candidate.artifact_refs,
                    )
                    continue
                producer_source = add_source(
                    SemanticSource.build(
                        kind=SemanticSourceKind.SERVER_IDENTIFIER,
                        epistemic_status=EpistemicStatus.OBSERVED,
                        evidence_ref=candidate.producer_source_ref,
                        world_ref=candidate.world_ref,
                        locator_ref=stable_hash(
                            "semantic_identifier_locator",
                            candidate.producer_locator.to_dict(),
                        ),
                    )
                )
                source_ids.add(producer_source)
                label, redacted = _artifact_label(
                    candidate.consumer_method,
                    candidate.consumer_path_template,
                )
                if redacted:
                    deficits.add("redacted_published_route_semantics", refs=source_ids)
                statuses = {
                    source_values[item].epistemic_status
                    for item in source_ids
                    if item in source_values
                }
                add_draft(
                    _OperationDraft(
                        action_id=stable_hash(
                            "action",
                            {"published_route_ref": candidate.consumer_route_ref},
                        ),
                        label=label,
                        protocol=SemanticProtocol.ARTIFACT_ROUTE,
                        method=(
                            candidate.consumer_method
                            if candidate.consumer_method in _METHODS
                            else "UNKNOWN"
                        ),
                        safety=(
                            OperationSafety.READ_ONLY
                            if candidate.risk_class == "read"
                            else OperationSafety.UNKNOWN
                        ),
                        world_ref=candidate.world_ref,
                        tenant_ref=None,
                        sources=source_ids,
                        requires={candidate.capability},
                        epistemic_statuses=statuses or {EpistemicStatus.UNCONFIRMED},
                    )
                )

        if interactions is not None:
            deficits.add(
                "interaction_control_truncation",
                interactions.diagnostics.dropped_controls,
            )
            deficits.add(
                "ambiguous_interaction_controls",
                interactions.diagnostics.invalid_controls
                + interactions.diagnostics.truncated_locators,
            )
            for intent in interactions.intents:
                is_form = intent.intent_kind in {"submit_form", "filter"}
                source_kind = (
                    SemanticSourceKind.HTML_FORM
                    if is_form
                    else SemanticSourceKind.DOM_CONTROL
                )
                source_ids = {
                    add_source(
                        SemanticSource.build(
                            kind=source_kind,
                            epistemic_status=EpistemicStatus.OBSERVED,
                            evidence_ref=intent.intent_id,
                            world_ref=intent.world_ref,
                            locator_ref=intent.locator_ref,
                        )
                    )
                }
                requires: set[Capability] = set()
                if intent.input_type:
                    source_ids.add(
                        add_source(
                            SemanticSource.build(
                                kind=SemanticSourceKind.CLIENT_VALIDATION,
                                epistemic_status=EpistemicStatus.PUBLISHED,
                                evidence_ref=intent.intent_id,
                                world_ref=intent.world_ref,
                                locator_ref=intent.locator_ref,
                            )
                        )
                    )
                    requires.add(
                        Capability(
                            CapabilityKind.VALUE,
                            f"form.{_semantic(intent.input_type)}",
                        )
                    )
                if is_form:
                    deficits.add(
                        "form_operation_semantics_incomplete",
                        refs=source_ids,
                    )
                add_draft(
                    _OperationDraft(
                        action_id=stable_hash("action", {"intent_id": intent.intent_id}),
                        label=(
                            f"form.{_semantic(intent.expected_side_effect)}."
                            f"{_semantic(intent.intent_kind)}"
                        ),
                        protocol=(
                            SemanticProtocol.HTML_FORM
                            if is_form
                            else SemanticProtocol.DOM_CONTROL
                        ),
                        method="UNKNOWN",
                        safety=_intent_safety(intent.risk_class),
                        world_ref=intent.world_ref,
                        tenant_ref=None,
                        sources=source_ids,
                        requires=requires,
                        epistemic_statuses={EpistemicStatus.OBSERVED},
                    )
                )

        for result in sorted(browser_transitions, key=lambda item: item.result_id):
            transition = result.transition
            source_id = add_source(
                SemanticSource.build(
                    kind=SemanticSourceKind.BROWSER_TRANSITION,
                    epistemic_status=EpistemicStatus.OBSERVED,
                    evidence_ref=transition.transition_id,
                    world_ref=result.after_state.world_ref,
                    locator_ref=result.after_state.page_ref,
                )
            )
            for action_id in transition.new_operation_refs:
                deficits.add("browser_operation_semantics_unresolved", refs=(source_id,))
                add_draft(
                    _OperationDraft(
                        action_id=action_id,
                        label="browser.discovered.operation",
                        protocol=SemanticProtocol.BROWSER_TRANSITION,
                        method="UNKNOWN",
                        safety=OperationSafety.UNKNOWN,
                        world_ref=result.after_state.world_ref,
                        tenant_ref=None,
                        sources={source_id},
                        epistemic_statuses={EpistemicStatus.UNCONFIRMED},
                    )
                )

        if lifecycle is not None:
            deficits.add(
                "incomplete_lifecycle_evidence",
                lifecycle.diagnostics.incomplete_groups
                + lifecycle.diagnostics.ambiguous_cleanup_groups
                + lifecycle.diagnostics.role_conflict_groups,
            )
            for candidate in lifecycle.candidates:
                lifecycle_sources[candidate.lifecycle_id] = add_source(
                    SemanticSource.build(
                        kind=SemanticSourceKind.LIFECYCLE,
                        epistemic_status=EpistemicStatus.INFERRED,
                        evidence_ref=candidate.lifecycle_id,
                        world_ref=candidate.world_ref,
                    )
                )

        ordered_sources = tuple(
            source_values[key] for key in sorted(source_values)
        )
        retained_sources = ordered_sources[: self.limits.max_sources]
        retained_source_ids = {item.source_id for item in retained_sources}
        dropped_sources = len(ordered_sources) - len(retained_sources)
        deficits.add("semantic_source_limit_truncated", dropped_sources)

        candidate_drafts = []
        evidence_source_drops = 0
        for draft in sorted(drafts.values(), key=lambda item: item.key):
            draft.sources.intersection_update(retained_source_ids)
            for capabilities, source_map in (
                (draft.requires, draft.requires_source_ids),
                (draft.produces, draft.produces_source_ids),
            ):
                for capability in tuple(capabilities):
                    refs = source_map.setdefault(capability, set(draft.sources))
                    refs.intersection_update(retained_source_ids)
                    if not refs:
                        capabilities.discard(capability)
                        source_map.pop(capability, None)
            if not draft.sources:
                evidence_source_drops += 1
                continue
            candidate_drafts.append(draft)
        deficits.add("operation_evidence_source_truncated", evidence_source_drops)
        retained_drafts = candidate_drafts[: self.limits.max_operations]
        dropped_operations = (
            len(candidate_drafts) - len(retained_drafts) + evidence_source_drops
        )
        deficits.add(
            "semantic_operation_limit_truncated",
            len(candidate_drafts) - len(retained_drafts),
        )

        slot_values: list[SemanticSlot] = []
        for draft in retained_drafts:
            for direction, capabilities, source_map in (
                ("requires", draft.requires, draft.requires_source_ids),
                ("produces", draft.produces, draft.produces_source_ids),
            ):
                for capability in sorted(capabilities, key=lambda item: item.key):
                    slot_values.append(
                        SemanticSlot.build(
                            operation_ref=draft.operation_ref,
                            capability=capability,
                            direction=direction,
                            slot_kind=_slot_kind(capability),
                            server_issued=(
                                direction == "produces"
                                and capability.kind is CapabilityKind.VALUE
                            ),
                            source_ids=tuple(source_map[capability]),
                        )
                    )
        slot_values.sort(key=lambda item: item.slot_id)
        retained_slots = tuple(slot_values[: self.limits.max_slots])
        dropped_slots = len(slot_values) - len(retained_slots)
        deficits.add("semantic_slot_limit_truncated", dropped_slots)
        slots_by_operation: Dict[str, Dict[str, list[str]]] = {}
        for slot in retained_slots:
            slots_by_operation.setdefault(
                slot.operation_ref,
                {"requires": [], "produces": []},
            )[slot.direction].append(slot.slot_id)

        operations = []
        for draft in retained_drafts:
            slot_group = slots_by_operation.get(
                draft.operation_ref,
                {"requires": [], "produces": []},
            )
            status = min(
                draft.epistemic_statuses or {EpistemicStatus.UNCONFIRMED},
                key=lambda item: _EPISTEMIC_RANK[item],
            )
            sources = tuple(sorted(draft.sources))
            required = tuple(sorted(slot_group["requires"]))
            produced = tuple(sorted(slot_group["produces"]))
            evidence = _operation_evidence_payload(
                safety=draft.safety,
                epistemic_status=status,
                observed_success=draft.observed_success,
                source_ids=sources,
                requires_slot_ids=required,
                produces_slot_ids=produced,
            )
            operations.append(
                SemanticOperation(
                    operation_ref=draft.operation_ref,
                    evidence_digest=stable_hash("semantic_operation_evidence", evidence),
                    action_id=draft.action_id,
                    label=draft.label,
                    protocol=draft.protocol,
                    method=draft.method,
                    safety=draft.safety,
                    epistemic_status=status,
                    observed_success=draft.observed_success,
                    world_ref=draft.world_ref,
                    tenant_ref=draft.tenant_ref,
                    source_ids=sources,
                    requires_slot_ids=required,
                    produces_slot_ids=produced,
                )
            )
        operations.sort(key=lambda item: item.operation_ref)
        operations_by_ref = {item.operation_ref: item for item in operations}

        resource_groups: Dict[
            Tuple[str, SemanticSlotKind, Optional[str], Optional[str]],
            Dict[str, set[str]],
        ] = {}
        for slot in retained_slots:
            if slot.slot_kind is SemanticSlotKind.VALUE:
                continue
            operation = operations_by_ref[slot.operation_ref]
            key = (
                _resource_name(slot),
                slot.slot_kind,
                operation.world_ref,
                operation.tenant_ref,
            )
            group = resource_groups.setdefault(key, {"slots": set(), "sources": set()})
            group["slots"].add(slot.slot_id)
            group["sources"].update(slot.source_ids)
        resource_values = []
        resource_by_slot: Dict[str, str] = {}
        for key in sorted(
            resource_groups,
            key=lambda item: (item[0], item[1].value, item[2] or "", item[3] or ""),
        ):
            name, kind, resource_world, resource_tenant = key
            group = resource_groups[key]
            identity = _resource_payload(
                name=name,
                kind=kind,
                world_ref=resource_world,
                tenant_ref=resource_tenant,
            )
            slots = tuple(sorted(group["slots"]))
            sources = tuple(sorted(group["sources"]))
            evidence = {"slot_ids": list(slots), "source_ids": list(sources)}
            resource = SemanticResource(
                resource_ref=stable_hash("semantic_resource", identity),
                evidence_digest=stable_hash("semantic_resource_evidence", evidence),
                name=name,
                kind=kind,
                world_ref=resource_world,
                tenant_ref=resource_tenant,
                slot_ids=slots,
                source_ids=sources,
            )
            resource_values.append(resource)
            for slot_id in slots:
                resource_by_slot[slot_id] = resource.resource_ref
        resource_values.sort(key=lambda item: item.resource_ref)
        retained_resources = tuple(resource_values[: self.limits.max_resources])
        retained_resource_refs = {item.resource_ref for item in retained_resources}
        dropped_resources = len(resource_values) - len(retained_resources)
        deficits.add("semantic_resource_limit_truncated", dropped_resources)
        resource_by_slot = {
            slot_id: resource_ref
            for slot_id, resource_ref in resource_by_slot.items()
            if resource_ref in retained_resource_refs
        }

        relation_values: Dict[str, SemanticRelation] = {}

        def add_relation(relation: SemanticRelation) -> None:
            relation_values[relation.relation_ref] = relation

        slots_by_id = {item.slot_id: item for item in retained_slots}
        for operation in operations:
            operation_resource_slots = [
                slots_by_id[item]
                for item in (*operation.requires_slot_ids, *operation.produces_slot_ids)
                if item in resource_by_slot
            ]
            primary_refs = {
                resource_by_slot[item.slot_id]
                for item in operation_resource_slots
                if item.slot_kind is SemanticSlotKind.RESOURCE_ID
            }
            for slot in operation_resource_slots:
                resource_ref = resource_by_slot[slot.slot_id]
                relation_kind = (
                    SemanticRelationKind.OPERATION_REQUIRES
                    if slot.direction == "requires"
                    else SemanticRelationKind.OPERATION_PRODUCES
                )
                add_relation(
                    SemanticRelation.build(
                        kind=relation_kind,
                        from_ref=operation.operation_ref,
                        to_ref=resource_ref,
                        epistemic_status=operation.epistemic_status,
                        source_ids=slot.source_ids,
                    )
                )
                contextual_kind = {
                    SemanticSlotKind.PARENT_ID: SemanticRelationKind.PARENT,
                    SemanticSlotKind.OWNER_ID: SemanticRelationKind.OWNERSHIP,
                    SemanticSlotKind.TENANT_ID: SemanticRelationKind.TENANT,
                    SemanticSlotKind.ROLE: SemanticRelationKind.ROLE,
                }.get(slot.slot_kind)
                if contextual_kind is None:
                    continue
                for primary_ref in primary_refs:
                    if primary_ref == resource_ref:
                        continue
                    add_relation(
                        SemanticRelation.build(
                            kind=contextual_kind,
                            from_ref=primary_ref,
                            to_ref=resource_ref,
                            epistemic_status=operation.epistemic_status,
                            source_ids=slot.source_ids,
                        )
                    )

        operation_lookup: Dict[Tuple[str, Optional[str]], list[str]] = {}
        for operation in operations:
            operation_lookup.setdefault(
                (operation.action_id, operation.world_ref),
                [],
            ).append(operation.operation_ref)
        if lifecycle is not None:
            for candidate in lifecycle.candidates:
                source_id = lifecycle_sources.get(candidate.lifecycle_id)
                if source_id not in retained_source_ids:
                    deficits.add("lifecycle_source_truncated")
                    continue
                create_refs = operation_lookup.get(
                    (candidate.create_operation_id, candidate.world_ref),
                    (),
                )
                cleanup_refs = operation_lookup.get(
                    (candidate.cleanup_operation_id, candidate.world_ref),
                    (),
                )
                read_refs = tuple(
                    ref
                    for action_id in candidate.read_operation_ids
                    for ref in operation_lookup.get((action_id, candidate.world_ref), ())
                )
                if not create_refs or not cleanup_refs or not read_refs:
                    deficits.add("lifecycle_operation_semantics_unavailable", refs=(source_id,))
                    continue
                for create_ref in create_refs:
                    for read_ref in read_refs:
                        add_relation(
                            SemanticRelation.build(
                                kind=SemanticRelationKind.LIFECYCLE_READ,
                                from_ref=create_ref,
                                to_ref=read_ref,
                                epistemic_status=EpistemicStatus.INFERRED,
                                source_ids=(source_id,),
                            )
                        )
                    for cleanup_ref in cleanup_refs:
                        add_relation(
                            SemanticRelation.build(
                                kind=SemanticRelationKind.LIFECYCLE_CLEANUP,
                                from_ref=create_ref,
                                to_ref=cleanup_ref,
                                epistemic_status=EpistemicStatus.INFERRED,
                                source_ids=(source_id,),
                            )
                        )

        ordered_relations = tuple(
            relation_values[key] for key in sorted(relation_values)
        )
        retained_relations = ordered_relations[: self.limits.max_relations]
        dropped_relations = len(ordered_relations) - len(retained_relations)
        deficits.add("semantic_relation_limit_truncated", dropped_relations)

        deficit_values = []
        for code in sorted(deficits.counts):
            refs = tuple(sorted(deficits.refs.get(code, ())))[
                : self.limits.max_deficit_source_refs
            ]
            deficit_values.append(
                SemanticCoverageDeficit.build(
                    code=code,
                    count=deficits.counts[code],
                    source_refs=refs,
                )
            )
        deficit_values.sort(key=lambda item: item.deficit_id)
        retained_deficits = tuple(deficit_values[: self.limits.max_deficits])
        dropped_deficits = len(deficit_values) - len(retained_deficits)
        ambiguity_count = sum(
            item.count for item in retained_deficits if "ambiguous" in item.code
        )
        conflict_count = sum(
            item.count for item in retained_deficits if "conflict" in item.code
        )
        diagnostics = SemanticCatalogDiagnostics(
            input_records=input_records,
            accepted_records=accepted_records,
            invalid_records=invalid_records,
            sources=len(retained_sources),
            operations=len(operations),
            slots=len(retained_slots),
            resources=len(retained_resources),
            relations=len(retained_relations),
            deficits=len(retained_deficits),
            ambiguities=ambiguity_count,
            conflicts=conflict_count,
            dropped_records=dropped_records,
            dropped_artifacts=dropped_artifacts,
            dropped_sources=dropped_sources,
            dropped_operations=dropped_operations,
            dropped_slots=dropped_slots,
            dropped_resources=dropped_resources,
            dropped_relations=dropped_relations,
            dropped_deficits=dropped_deficits,
        )
        status = (
            "no_semantics"
            if not operations
            else "partial"
            if retained_deficits
            else "ready"
        )
        payload = _catalog_payload(
            status=status,
            target_ref=target_ref,
            sources=retained_sources,
            operations=tuple(operations),
            slots=retained_slots,
            resources=retained_resources,
            relations=retained_relations,
            deficits=retained_deficits,
            diagnostics=diagnostics,
        )
        return TargetSemanticCatalog(
            catalog_id=stable_hash("target_semantic_catalog", payload),
            status=status,
            target_ref=target_ref,
            sources=retained_sources,
            operations=tuple(operations),
            slots=retained_slots,
            resources=retained_resources,
            relations=retained_relations,
            deficits=retained_deficits,
            diagnostics=diagnostics,
        )


__all__ = [
    "EpistemicStatus",
    "SemanticCatalogDiagnostics",
    "SemanticCatalogLimits",
    "SemanticCoverageDeficit",
    "SemanticOperation",
    "SemanticProtocol",
    "SemanticRelation",
    "SemanticRelationKind",
    "SemanticResource",
    "SemanticSlot",
    "SemanticSlotKind",
    "SemanticSource",
    "SemanticSourceKind",
    "TARGET_SEMANTIC_CATALOG_MODE",
    "TargetSemanticCatalog",
    "TargetSemanticCatalogBuilder",
]
