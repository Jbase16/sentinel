"""Redacted, non-executable authorization experiment proposals.

Proposal mode turns two passive captures into reviewable three-leg experiments:
peer baseline, source baseline, and source principal with a peer-owned identifier.
It does not contain a transport, does not retain identifier values, and cannot
promote a finding.  A later activation gate must rehydrate a proposal from its
source capture and submit the concrete action to ``PolicyExecutor``.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from .normalize import normalize_exchange, stable_hash

PROPOSAL_MODE = "proposal_only"
OBJECT_AUTHORIZATION = "object_authorization"
CROSS_OBJECT_READ = "CROSS_OBJECT_READ"
STATE_MUTATION = "STATE_MUTATION"
UNKNOWN_AUTHORIZATION = "UNKNOWN_AUTHORIZATION"

_ID_SHAPE = re.compile(
    r"^(?:[A-Za-z0-9_-]{16,128}|\d{4,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
_ID_KEY = re.compile(
    r"(?:^|[_-])(?:id|ids|uuid|guid|encid|token)$|id$|owner|tenant|account|"
    r"organization|organisation|business|entity|resource|member|user|project|team",
    re.IGNORECASE,
)
_READ_LABEL = re.compile(r"^(?:get|list|fetch|read|view|find|search|query|download|export)", re.I)
_PATH_STATIC = frozenset({"api", "v1", "v2", "v3", "new", "create", "search", "me"})


@dataclass(frozen=True)
class ProposalLimits:
    max_occurrences_per_world: int = 8_192
    max_correspondences: int = 64
    max_proposals: int = 512
    max_mutations_per_proposal: int = 16

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ResourceCorrespondence:
    semantic_key: str
    source_value_hash: str
    peer_value_hash: str
    source_observations: int
    peer_observations: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "semantic_key": self.semantic_key,
            "source_value_hash": self.source_value_hash,
            "peer_value_hash": self.peer_value_hash,
            "source_observations": self.source_observations,
            "peer_observations": self.peer_observations,
        }


@dataclass(frozen=True)
class MutationLocator:
    location_kind: str
    pointer: str
    semantic_key: str
    source_value_hash: str
    replacement_value_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location_kind": self.location_kind,
            "pointer": self.pointer,
            "semantic_key": self.semantic_key,
            "source_value_hash": self.source_value_hash,
            "replacement_value_hash": self.replacement_value_hash,
        }


@dataclass(frozen=True)
class ProposalLeg:
    name: str
    actor_world_ref: str
    identifier_source: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "actor_world_ref": self.actor_world_ref,
            "identifier_source": self.identifier_source,
        }


@dataclass(frozen=True)
class AuthorizationExperimentProposal:
    proposal_id: str
    action_id: str
    operation_label: str
    source_ref: str
    source_record_index: int
    risk_class: str
    mutations: Tuple[MutationLocator, ...]
    legs: Tuple[ProposalLeg, ...]
    property_kind: str = OBJECT_AUTHORIZATION
    mode: str = PROPOSAL_MODE
    executable: bool = False
    requires_owned_worlds: bool = True
    requires_policy_reclassification: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "property_kind": self.property_kind,
            "mode": self.mode,
            "executable": self.executable,
            "action_id": self.action_id,
            "operation_label": self.operation_label,
            "source_ref": self.source_ref,
            "source_record_index": self.source_record_index,
            "risk_class": self.risk_class,
            "requires_owned_worlds": self.requires_owned_worlds,
            "requires_policy_reclassification": self.requires_policy_reclassification,
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "legs": [leg.to_dict() for leg in self.legs],
            "evidence_requirements": [
                "peer_baseline",
                "source_baseline",
                "counterfactual_response",
                "peer_private_marker_or_owned_state_delta",
                "policy_and_scope_provenance",
            ],
        }


@dataclass(frozen=True)
class ProposalBatch:
    proposals: Tuple[AuthorizationExperimentProposal, ...]
    correspondences: Tuple[ResourceCorrespondence, ...]
    diagnostics: Dict[str, Any]
    mode: str = PROPOSAL_MODE
    executable: bool = False

    def operation_labels(self) -> Tuple[str, ...]:
        return tuple(sorted({proposal.operation_label for proposal in self.proposals}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "correspondences": [item.to_dict() for item in self.correspondences],
            "proposals": [proposal.to_dict() for proposal in self.proposals],
            "diagnostics": dict(self.diagnostics),
        }


@dataclass(frozen=True)
class _Occurrence:
    semantic_key: str
    raw_value: str
    record_index: int
    operation_index: Optional[int]
    operation_label: str
    location_kind: str
    pointer: str
    pairable: bool = True


@dataclass(frozen=True)
class _RawCorrespondence:
    semantic_key: str
    source_value: str
    peer_value: str
    source_count: int
    peer_count: int

    def redacted(self) -> ResourceCorrespondence:
        return ResourceCorrespondence(
            semantic_key=self.semantic_key,
            source_value_hash=stable_hash("observed_value", self.source_value),
            peer_value_hash=stable_hash("observed_value", self.peer_value),
            source_observations=self.source_count,
            peer_observations=self.peer_count,
        )


def _json_pointer(parts: Iterable[Any]) -> str:
    def escape(value: Any) -> str:
        return str(value).replace("~", "~0").replace("/", "~1")

    return "/" + "/".join(escape(part) for part in parts)


def _candidate_text(key: str, value: Any) -> Optional[str]:
    if not _ID_KEY.search(key) or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 256 or any(character.isspace() for character in text):
        return None
    return text


def _is_path_candidate(segment: str, parent: str) -> bool:
    if not segment or segment.lower() in _PATH_STATIC:
        return False
    if segment.isdigit() or _ID_SHAPE.fullmatch(segment):
        return True
    return parent.lower().endswith("s") and len(segment) <= 128


def _walk_identifiers(
    value: Any,
    *,
    namespace: str,
    base_path: Tuple[Any, ...],
    record_index: int,
    operation_index: Optional[int],
    operation_label: str,
) -> Iterable[_Occurrence]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = (*base_path, key)
            candidate = _candidate_text(str(key), child)
            if candidate is not None:
                yield _Occurrence(
                    semantic_key=f"{namespace}:{str(key).lower()}",
                    raw_value=candidate,
                    record_index=record_index,
                    operation_index=operation_index,
                    operation_label=operation_label,
                    location_kind="json_body",
                    pointer=_json_pointer(path),
                )
            yield from _walk_identifiers(
                child,
                namespace=namespace,
                base_path=path,
                record_index=record_index,
                operation_index=operation_index,
                operation_label=operation_label,
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_identifiers(
                child,
                namespace=namespace,
                base_path=(*base_path, index),
                record_index=record_index,
                operation_index=operation_index,
                operation_label=operation_label,
            )


def _request_method(record: Mapping[str, Any], *, graphql: bool = False) -> str:
    explicit = record.get("method")
    if explicit:
        return str(explicit).upper()
    if graphql or record.get("request_body") not in (None, "", "[Binary/FormData]"):
        return "POST"
    return "GET"


def _path_template(url: str) -> str:
    path = unquote(urlsplit(url).path or "/")
    segments = path.split("/")
    normalized = []
    for index, segment in enumerate(segments):
        parent = segments[index - 1] if index > 0 else ""
        normalized.append("{id}" if _is_path_candidate(segment, parent) else segment)
    return "/".join(normalized) or "/"


def _extract_occurrences(
    records: Sequence[Mapping[str, Any]], limits: ProposalLimits
) -> Tuple[List[_Occurrence], int]:
    occurrences: List[_Occurrence] = []
    dropped = 0

    def add(items: Iterable[_Occurrence]) -> None:
        nonlocal dropped
        for item in items:
            if len(occurrences) >= limits.max_occurrences_per_world:
                dropped += 1
            else:
                occurrences.append(item)

    for record_index, record in enumerate(records):
        url = str(record.get("url") or "/")
        parts = urlsplit(url)
        method = _request_method(record)
        rest_label = f"{method} {_path_template(url)}"

        path_segments = unquote(parts.path or "/").split("/")
        for index, segment in enumerate(path_segments):
            parent = path_segments[index - 1].lower() if index > 0 and path_segments[index - 1] else str(index)
            if not _is_path_candidate(segment, parent):
                continue
            add([_Occurrence(
                semantic_key=f"path:{parent}",
                raw_value=segment,
                record_index=record_index,
                operation_index=None,
                operation_label=rest_label,
                location_kind="url_path",
                pointer=f"/url/path/{index}",
            )])

        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            candidate = _candidate_text(key, value)
            if candidate is not None:
                add([_Occurrence(
                    semantic_key=f"query:{key.lower()}",
                    raw_value=candidate,
                    record_index=record_index,
                    operation_index=None,
                    operation_label=rest_label,
                    location_kind="url_query",
                    pointer=_json_pointer(("url", "query", key)),
                )])

        headers = record.get("request_headers") or record.get("headers") or {}
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if isinstance(value, str) and _ID_SHAPE.fullmatch(value):
                    add([_Occurrence(
                        semantic_key=f"header:{str(key).lower()}",
                        raw_value=str(value),
                        record_index=record_index,
                        operation_index=None,
                        operation_label=rest_label,
                        location_kind="request_header",
                        pointer=_json_pointer(("headers", str(key).lower())),
                        pairable=False,
                    )])

        raw_body = record.get("request_body")
        if not isinstance(raw_body, str) or raw_body in ("", "[Binary/FormData]"):
            continue
        try:
            payload = json.loads(raw_body)
        except (TypeError, ValueError):
            continue

        payload_items = payload if isinstance(payload, list) else [payload]
        graphql_found = False
        for operation_index, item in enumerate(payload_items):
            if not isinstance(item, Mapping) or not (item.get("operationName") or item.get("variables")):
                continue
            graphql_found = True
            label = str(item.get("operationName") or "graphql_operation")
            root = (operation_index,) if isinstance(payload, list) else ()
            add(_walk_identifiers(
                item.get("variables") or {},
                namespace="graphql",
                base_path=(*root, "variables"),
                record_index=record_index,
                operation_index=operation_index,
                operation_label=label,
            ))

        if not graphql_found:
            add(_walk_identifiers(
                payload,
                namespace="body",
                base_path=(),
                record_index=record_index,
                operation_index=None,
                operation_label=rest_label,
            ))

    return occurrences, dropped


def _infer_correspondences(
    source: Sequence[_Occurrence], peer: Sequence[_Occurrence], limits: ProposalLimits
) -> Tuple[List[_RawCorrespondence], int]:
    source_values: Dict[str, Counter[str]] = defaultdict(Counter)
    peer_values: Dict[str, Counter[str]] = defaultdict(Counter)
    for item in source:
        if item.pairable:
            source_values[item.semantic_key][item.raw_value] += 1
    for item in peer:
        if item.pairable:
            peer_values[item.semantic_key][item.raw_value] += 1

    ranked: List[Tuple[int, str, str, str, int, int]] = []
    for semantic_key in source_values.keys() & peer_values.keys():
        source_value, source_count = source_values[semantic_key].most_common(1)[0]
        peer_value, peer_count = peer_values[semantic_key].most_common(1)[0]
        if source_value == peer_value:
            continue
        ranked.append((
            min(source_count, peer_count), semantic_key,
            source_value, peer_value, source_count, peer_count,
        ))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    dropped = max(0, len(ranked) - limits.max_correspondences)
    return [
        _RawCorrespondence(key, source_value, peer_value, source_count, peer_count)
        for _, key, source_value, peer_value, source_count, peer_count
        in ranked[:limits.max_correspondences]
    ], dropped


def _risk_class(record: Mapping[str, Any], operation_label: str, *, graphql: bool) -> str:
    method = _request_method(record, graphql=graphql)
    raw_body = record.get("request_body")
    if isinstance(raw_body, str) and re.search(r"\bmutation\b", raw_body, re.I):
        return STATE_MUTATION
    if method in {"PUT", "PATCH", "DELETE"}:
        return STATE_MUTATION
    if method in {"GET", "HEAD", "OPTIONS"} or _READ_LABEL.search(operation_label):
        return CROSS_OBJECT_READ
    return UNKNOWN_AUTHORIZATION


def compile_authorization_proposals(
    source_records: Sequence[Mapping[str, Any]],
    peer_records: Sequence[Mapping[str, Any]],
    *,
    source_world: str = "source",
    peer_world: str = "peer",
    limits: Optional[ProposalLimits] = None,
) -> ProposalBatch:
    """Compile redacted authorization proposals from two passive captures.

    ``source`` is the actor whose observed operation will eventually be replayed;
    ``peer`` supplies the corresponding foreign-owned identifier.  Values exist
    only in local stack frames during compilation and never enter the returned
    proposal batch.
    """
    active_limits = limits or ProposalLimits()
    source_occurrences, source_occurrence_drops = _extract_occurrences(
        source_records, active_limits
    )
    peer_occurrences, peer_occurrence_drops = _extract_occurrences(
        peer_records, active_limits
    )
    correspondences, correspondence_drops = _infer_correspondences(
        source_occurrences, peer_occurrences, active_limits
    )

    source_world_ref = stable_hash("world", source_world)
    peer_world_ref = stable_hash("world", peer_world)
    proposals: List[AuthorizationExperimentProposal] = []
    proposal_drops = 0
    mutation_drops = 0
    seen: set[str] = set()

    for pair in correspondences:
        candidates = [
            item for item in source_occurrences
            if item.semantic_key == pair.semantic_key and item.raw_value == pair.source_value
        ]
        groups: Dict[Tuple[int, Optional[int], str], List[_Occurrence]] = defaultdict(list)
        for item in candidates:
            groups[(item.record_index, item.operation_index, item.operation_label)].append(item)

        # Record-level URL/header occurrences carrying the same identifier must be
        # mutated with an operation-specific body occurrence. They are added below.
        record_level = [
            item for item in source_occurrences
            if item.raw_value == pair.source_value and item.operation_index is None
        ]

        for (record_index, operation_index, operation_label), group in sorted(groups.items()):
            if operation_index is not None:
                group.extend(item for item in record_level if item.record_index == record_index)
            unique_locations = {
                (item.location_kind, item.pointer, item.semantic_key): item for item in group
            }
            mutation_items = [unique_locations[key] for key in sorted(unique_locations)]
            if not mutation_items:
                continue
            mutation_drops += max(
                0, len(mutation_items) - active_limits.max_mutations_per_proposal
            )
            mutation_items = mutation_items[:active_limits.max_mutations_per_proposal]

            record = source_records[record_index]
            graphql = operation_index is not None
            method = _request_method(record, graphql=graphql)
            normalized_record = dict(record)
            normalized_record["method"] = method
            normalized = normalize_exchange(
                normalized_record,
                source_id=f"source:{record_index}",
                world_id=source_world,
            )
            source_value_hash = stable_hash("observed_value", pair.source_value)
            peer_value_hash = stable_hash("observed_value", pair.peer_value)
            mutation_locators = tuple(
                MutationLocator(
                    location_kind=item.location_kind,
                    pointer=item.pointer,
                    semantic_key=item.semantic_key,
                    source_value_hash=source_value_hash,
                    replacement_value_hash=peer_value_hash,
                )
                for item in mutation_items
            )
            descriptor = {
                "action_id": normalized.action_id,
                "operation_label": operation_label,
                "source_ref": normalized.source_id,
                "mutations": [item.to_dict() for item in mutation_locators],
                "source_world_ref": source_world_ref,
                "peer_world_ref": peer_world_ref,
            }
            proposal_id = stable_hash("authorization_proposal", descriptor)
            if proposal_id in seen:
                continue
            seen.add(proposal_id)
            if len(proposals) >= active_limits.max_proposals:
                proposal_drops += 1
                continue
            proposals.append(AuthorizationExperimentProposal(
                proposal_id=proposal_id,
                action_id=normalized.action_id,
                operation_label=operation_label,
                source_ref=normalized.source_id,
                source_record_index=record_index,
                risk_class=_risk_class(record, operation_label, graphql=graphql),
                mutations=mutation_locators,
                legs=(
                    ProposalLeg("peer_baseline", peer_world_ref, "peer_observed_value"),
                    ProposalLeg("source_baseline", source_world_ref, "source_observed_value"),
                    ProposalLeg("counterfactual", source_world_ref, "peer_observed_value"),
                ),
            ))

    proposals.sort(key=lambda item: (item.operation_label, item.proposal_id))
    return ProposalBatch(
        proposals=tuple(proposals),
        correspondences=tuple(item.redacted() for item in correspondences),
        diagnostics={
            "source_records": len(source_records),
            "peer_records": len(peer_records),
            "source_identifier_occurrences": len(source_occurrences),
            "peer_identifier_occurrences": len(peer_occurrences),
            "correspondence_count": len(correspondences),
            "proposal_count": len(proposals),
            "dropped": {
                "source_occurrences": source_occurrence_drops,
                "peer_occurrences": peer_occurrence_drops,
                "correspondences": correspondence_drops,
                "proposals": proposal_drops,
                "mutations": mutation_drops,
            },
        },
    )
