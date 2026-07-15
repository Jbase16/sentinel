"""Passive mining of target-published, capability-linked latent operations.

The miner joins successful captured response capabilities to parameterized routes
published in already-acquired client artifacts.  It emits only evidence-backed,
previously unobserved operation affordances.  It has no transport, never retains
raw capability values in its public result, and cannot authorize execution.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from .compiler import Capability, value_capability_for_field_path
from .lineage import LineageLimits, LocatorKind, ValueLineageLedger, ValueLocator
from .normalize import normalize_exchange, stable_hash

LATENT_AFFORDANCE_MODE = "behavioral_latent_affordance_v1"

_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_PLACEHOLDER = re.compile(
    r"^(?:\$\{(?P<template>[A-Za-z_$][A-Za-z0-9_$]*)\}|"
    r":(?P<colon>[A-Za-z_][A-Za-z0-9_]*)|"
    r"\{(?P<brace>[A-Za-z_][A-Za-z0-9_]*)\})$"
)
_HASH = re.compile(r"^[0-9a-f]{64}$")
_GENERIC_PARAMETER = frozenset({"id", "ids", "key", "token", "url", "uuid"})


def _is_hash_ref(value: Any, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    return bool(_HASH.fullmatch(value[len(prefix) + 1 :]))


@dataclass(frozen=True)
class ClientArtifact:
    """Caller-supplied artifact text that has already been acquired in scope."""

    source: str
    text: str = field(repr=False, compare=False)
    kind: str = "javascript"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source, str)
            or not self.source
            or len(self.source) > 4_096
            or any(ord(character) < 0x20 for character in self.source)
            or not isinstance(self.text, str)
            or self.kind not in {"javascript", "source_map", "openapi", "other"}
        ):
            raise ValueError("client artifact contract is invalid")


@dataclass(frozen=True)
class LatentAffordanceLimits:
    max_records: int = 4_096
    max_artifacts: int = 32
    max_artifact_bytes: int = 2 * 1024 * 1024
    max_total_artifact_bytes: int = 16 * 1024 * 1024
    max_string_literals_per_artifact: int = 100_000
    max_routes: int = 4_096
    max_candidates: int = 1_024
    max_json_depth: int = 16
    max_value_chars: int = 4_096

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class LatentAffordanceCandidate:
    affordance_id: str
    target_ref: str
    producer_operation_id: str
    producer_source_ref: str
    producer_locator: ValueLocator
    world_ref: str
    capability: Capability
    value_hash: str
    evidence_digest: str
    consumer_route_ref: str
    consumer_method: str
    consumer_path_template: str
    consumer_parameter_location: str
    consumer_parameter_pointer: str
    artifact_refs: Tuple[str, ...]
    evidence_kinds: Tuple[str, ...]
    risk_class: str
    sensitive: bool
    mode: str = LATENT_AFFORDANCE_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        identity = _candidate_identity_payload(
            target_ref=self.target_ref,
            producer_operation_id=self.producer_operation_id,
            world_ref=self.world_ref,
            capability=self.capability,
            consumer_route_ref=self.consumer_route_ref,
            consumer_method=self.consumer_method,
            consumer_path_template=self.consumer_path_template,
            consumer_parameter_location=self.consumer_parameter_location,
            consumer_parameter_pointer=self.consumer_parameter_pointer,
            risk_class=self.risk_class,
            sensitive=self.sensitive,
        )
        evidence = _candidate_evidence_payload(
            producer_source_ref=self.producer_source_ref,
            producer_locator=self.producer_locator,
            value_hash=self.value_hash,
            artifact_refs=self.artifact_refs,
            evidence_kinds=self.evidence_kinds,
        )
        if (
            self.affordance_id != stable_hash("latent_affordance", identity)
            or self.evidence_digest
            != stable_hash("latent_affordance_evidence", evidence)
            or self.mode != LATENT_AFFORDANCE_MODE
            or self.executable
            or not _is_hash_ref(self.target_ref, "latent_affordance_target")
            or not _is_hash_ref(self.producer_source_ref, "source_ref")
            or not _is_hash_ref(self.world_ref, "world")
            or not _is_hash_ref(self.value_hash, "latent_value")
            or not _is_hash_ref(
                self.evidence_digest,
                "latent_affordance_evidence",
            )
            or not _is_hash_ref(self.consumer_route_ref, "latent_route")
            or not self.producer_operation_id
            or self.consumer_method not in (*_HTTP_METHODS, "UNKNOWN")
            or not self.consumer_path_template.startswith("/")
            or self.consumer_parameter_location not in {"path", "query"}
            or not self.consumer_parameter_pointer.startswith("/")
            or not self.artifact_refs
            or tuple(sorted(set(self.artifact_refs))) != self.artifact_refs
            or any(
                not _is_hash_ref(item, "client_artifact") for item in self.artifact_refs
            )
            or not self.evidence_kinds
            or tuple(sorted(set(self.evidence_kinds))) != self.evidence_kinds
            or self.risk_class not in {"read", "state_mutation", "unknown"}
        ):
            raise ValueError("latent affordance candidate contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "affordance_id": self.affordance_id,
            "target_ref": self.target_ref,
            "producer_operation_id": self.producer_operation_id,
            "producer_source_ref": self.producer_source_ref,
            "producer_locator": self.producer_locator.to_dict(),
            "world_ref": self.world_ref,
            "capability": self.capability.to_dict(),
            "value_hash": self.value_hash,
            "evidence_digest": self.evidence_digest,
            "consumer_route_ref": self.consumer_route_ref,
            "consumer_method": self.consumer_method,
            "consumer_path_template": self.consumer_path_template,
            "consumer_parameter_location": self.consumer_parameter_location,
            "consumer_parameter_pointer": self.consumer_parameter_pointer,
            "artifact_refs": list(self.artifact_refs),
            "evidence_kinds": list(self.evidence_kinds),
            "risk_class": self.risk_class,
            "sensitive": self.sensitive,
            "requires_active_confirmation": True,
        }


@dataclass(frozen=True)
class LatentAffordanceDiagnostics:
    records: int
    successful_response_records: int
    produced_capabilities: int
    ambiguous_producer_groups: int
    artifacts: int
    artifact_bytes: int
    dropped_artifacts: int
    dropped_artifact_bytes: int
    routes_extracted: int
    observed_routes_rejected: int
    unmatched_routes: int
    ambiguous_routes: int
    duplicate_candidates: int
    dropped_candidates: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError(
                "latent affordance diagnostics must be non-negative integers"
            )

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class LatentAffordanceResult:
    status: str
    target_ref: str
    capture_digest: str
    artifact_digest: str
    candidates: Tuple[LatentAffordanceCandidate, ...]
    diagnostics: LatentAffordanceDiagnostics
    mode: str = LATENT_AFFORDANCE_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        expected_status = "ready" if self.candidates else "no_latent_affordances"
        candidate_ids = [item.affordance_id for item in self.candidates]
        if (
            self.status != expected_status
            or self.mode != LATENT_AFFORDANCE_MODE
            or self.executable
            or not _is_hash_ref(self.target_ref, "latent_affordance_target")
            or not _is_hash_ref(self.capture_digest, "capture_set")
            or not _is_hash_ref(self.artifact_digest, "artifact_set")
            or candidate_ids != sorted(set(candidate_ids))
            or any(item.target_ref != self.target_ref for item in self.candidates)
        ):
            raise ValueError("latent affordance result contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "status": self.status,
            "target_ref": self.target_ref,
            "capture_digest": self.capture_digest,
            "artifact_digest": self.artifact_digest,
            "candidates": [item.to_dict() for item in self.candidates],
            "diagnostics": self.diagnostics.to_dict(),
        }


@dataclass(frozen=True)
class _ProducedValue:
    operation_id: str
    source_ref: str
    locator: ValueLocator
    world_ref: str
    capability: Capability
    value_hash: str


@dataclass(frozen=True)
class _RouteEvidence:
    method: str
    path_template: str
    parameter_name: str
    parameter_location: str
    parameter_pointer: str
    parent_name: str
    artifact_ref: str
    evidence_kind: str

    @property
    def key(self) -> Tuple[str, ...]:
        return (
            self.method,
            self.path_template,
            self.parameter_name,
            self.parameter_location,
            self.parameter_pointer,
        )


def _candidate_identity_payload(**values: Any) -> Dict[str, Any]:
    payload = dict(values)
    payload["capability"] = values["capability"].to_dict()
    return payload


def _candidate_evidence_payload(**values: Any) -> Dict[str, Any]:
    payload = dict(values)
    payload["producer_locator"] = values["producer_locator"].to_dict()
    payload["artifact_refs"] = list(values["artifact_refs"])
    payload["evidence_kinds"] = list(values["evidence_kinds"])
    return payload


def _origin_key(value: str) -> Optional[Tuple[str, str, int]]:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not host:
        return None
    return scheme, host, port or (443 if scheme == "https" else 80)


def _canonical_origin(value: Tuple[str, str, int]) -> str:
    scheme, host, port = value
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + (f":{port}" if port != default else "")


def _body_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if not value.lstrip().startswith(("{", "[")):
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return None


def _bounded_scalar(value: Any, *, limit: int) -> Optional[str]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value.strip()
    else:
        return None
    if (
        not text
        or len(text) > limit
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in text)
    ):
        return None
    return text


def _pointer(parts: Iterable[Any]) -> str:
    return "/" + "/".join(
        str(item).replace("~", "~0").replace("/", "~1") for item in parts
    )


def _walk_produced(
    value: Any,
    *,
    operation_id: str,
    source_ref: str,
    world_ref: str,
    capture_digest: str,
    limits: LatentAffordanceLimits,
    semantic_path: Tuple[str, ...] = (),
    pointer_path: Tuple[Any, ...] = (),
    depth: int = 0,
) -> Iterable[_ProducedValue]:
    if depth > limits.max_json_depth:
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            next_semantic = (*semantic_path, str(key))
            next_pointer = (*pointer_path, key)
            capability = value_capability_for_field_path(next_semantic)
            raw = _bounded_scalar(child, limit=limits.max_value_chars)
            if capability is not None and raw is not None:
                yield _ProducedValue(
                    operation_id=operation_id,
                    source_ref=source_ref,
                    locator=ValueLocator(
                        LocatorKind.RESPONSE_JSON, _pointer(next_pointer)
                    ),
                    world_ref=world_ref,
                    capability=capability,
                    value_hash=stable_hash(
                        "latent_value",
                        {"capture_digest": capture_digest, "value": raw},
                    ),
                )
            yield from _walk_produced(
                child,
                operation_id=operation_id,
                source_ref=source_ref,
                world_ref=world_ref,
                capture_digest=capture_digest,
                limits=limits,
                semantic_path=next_semantic,
                pointer_path=next_pointer,
                depth=depth + 1,
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_produced(
                child,
                operation_id=operation_id,
                source_ref=source_ref,
                world_ref=world_ref,
                capture_digest=capture_digest,
                limits=limits,
                semantic_path=semantic_path,
                pointer_path=(*pointer_path, index),
                depth=depth + 1,
            )


def _decode_string(body: str, quote: str) -> Optional[str]:
    output: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}
    while index < len(body):
        character = body[index]
        if character != "\\":
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(body):
            return None
        escaped = body[index]
        if escaped in escapes:
            output.append(escapes[escaped])
        elif escaped in {"\\", "'", '"', "`", "/"}:
            output.append(escaped)
        elif escaped == "u" and index + 4 < len(body):
            digits = body[index + 1 : index + 5]
            if not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                return None
            output.append(chr(int(digits, 16)))
            index += 4
        elif escaped == "x" and index + 2 < len(body):
            digits = body[index + 1 : index + 3]
            if not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                return None
            output.append(chr(int(digits, 16)))
            index += 2
        elif escaped in {"\n", "\r"}:
            pass
        else:
            output.append(escaped)
        index += 1
    return "".join(output)


def _string_literals(value: str, *, limit: int) -> Iterable[Tuple[str, int, int]]:
    emitted = 0
    index = 0
    while index < len(value) and emitted < limit:
        quote = value[index]
        if quote not in {"'", '"', "`"}:
            index += 1
            continue
        start_quote = index
        start = index + 1
        index = start
        escaped = False
        while index < len(value):
            character = value[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                decoded = _decode_string(value[start:index], quote)
                if decoded is not None:
                    emitted += 1
                    yield decoded, start_quote, index + 1
                index += 1
                break
            index += 1


def _method_near_literal(text: str, start: int, end: int) -> str:
    before = text[max(0, start - 96) : start]
    after = text[end : min(len(text), end + 192)]
    direct = re.search(
        r"(?:axios\s*\.)?(get|head|options|post|put|patch|delete)\s*\(\s*$",
        before,
        re.IGNORECASE,
    )
    if direct is not None:
        return direct.group(1).upper()
    if re.search(r"fetch\s*\(\s*$", before, re.IGNORECASE):
        configured = re.search(
            r"\bmethod\s*:\s*['\"](GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)['\"]",
            after,
            re.IGNORECASE,
        )
        return configured.group(1).upper() if configured is not None else "GET"
    surrounding = before[-64:] + after[:128]
    configured = re.search(
        r"\bmethod\s*:\s*['\"](GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)['\"]",
        surrounding,
        re.IGNORECASE,
    )
    return configured.group(1).upper() if configured is not None else "UNKNOWN"


def _placeholder_name(value: str) -> Optional[str]:
    match = _PLACEHOLDER.fullmatch(value)
    if match is None:
        return None
    return next(item for item in match.groups() if item is not None)


def _route_evidence(
    value: str,
    *,
    method: str,
    target_origin: Tuple[str, str, int],
    artifact_ref: str,
    evidence_kind: str,
) -> Optional[_RouteEvidence]:
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > 4_096
        or any(ord(character) < 0x20 or character == "\\" for character in candidate)
        or candidate.startswith("//")
    ):
        return None
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        if (
            _origin_key(candidate) != target_origin
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port == 0
        ):
            return None
    elif not candidate.startswith("/"):
        return None
    if parsed.fragment:
        return None

    parameters: list[Tuple[str, str, str, str]] = []
    normalized_segments: list[str] = []
    raw_segments = (parsed.path or "/").split("/")
    for index, segment in enumerate(raw_segments):
        if segment in {".", ".."}:
            return None
        name = _placeholder_name(segment)
        if name is None:
            if "${" in segment or "{" in segment or "}" in segment:
                return None
            normalized_segments.append(segment)
            continue
        parent = raw_segments[index - 1] if index > 0 else ""
        normalized_segments.append(f"{{{name}}}")
        parameters.append((name, "path", f"/segments/{index}", parent))

    query_parts: list[Tuple[str, str]] = []
    for key, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
        name = _placeholder_name(raw_value)
        if name is None:
            if "${" in raw_value or "{" in raw_value or "}" in raw_value:
                return None
            query_parts.append((key, stable_hash("literal", raw_value)))
            continue
        query_parts.append((key, f"{{{name}}}"))
        parameters.append((name, "query", f"/query/{key}", key))

    if len(parameters) != 1:
        return None
    parameter_name, location, pointer, parent = parameters[0]
    path = "/".join(normalized_segments) or "/"
    query = "&".join(f"{key}={item}" for key, item in sorted(query_parts))
    template = path + (f"?{query}" if query else "")
    return _RouteEvidence(
        method=method if method in _HTTP_METHODS else "UNKNOWN",
        path_template=template,
        parameter_name=parameter_name,
        parameter_location=location,
        parameter_pointer=pointer,
        parent_name=parent,
        artifact_ref=artifact_ref,
        evidence_kind=evidence_kind,
    )


def _openapi_routes(
    value: Any,
    *,
    target_origin: Tuple[str, str, int],
    artifact_ref: str,
) -> Iterable[_RouteEvidence]:
    if not isinstance(value, Mapping) or not isinstance(value.get("paths"), Mapping):
        return
    for path, definition in value["paths"].items():
        if not isinstance(path, str) or not isinstance(definition, Mapping):
            continue
        for method in sorted(_HTTP_METHODS):
            if method.lower() not in definition:
                continue
            route = _route_evidence(
                path,
                method=method,
                target_origin=target_origin,
                artifact_ref=artifact_ref,
                evidence_kind="openapi_path",
            )
            if route is not None:
                yield route


def _artifact_texts(artifact: ClientArtifact) -> Tuple[str, ...]:
    if artifact.kind != "source_map":
        return (artifact.text,)
    try:
        parsed = json.loads(artifact.text)
    except (TypeError, ValueError):
        return ()
    if not isinstance(parsed, Mapping) or not isinstance(
        parsed.get("sourcesContent"), list
    ):
        return ()
    return tuple(item for item in parsed["sourcesContent"] if isinstance(item, str))


def _capability_matches_route(capability: Capability, route: _RouteEvidence) -> bool:
    parameter = value_capability_for_field_path((route.parameter_name,))
    if parameter is not None and parameter == capability:
        return True
    normalized_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", route.parameter_name)
    normalized_name = re.sub(r"[^a-zA-Z0-9]+", "_", normalized_name).strip("_").lower()
    if normalized_name not in _GENERIC_PARAMETER:
        return False
    suffix = f"_{normalized_name}"
    if not capability.name.endswith(suffix):
        return False
    stem = capability.name[: -len(suffix)]
    parent = re.sub(r"[^a-zA-Z0-9]+", "_", route.parent_name).strip("_").lower()
    parent_tokens = set(parent.rstrip("s").split("_"))
    return bool(stem) and set(stem.split("_")) <= parent_tokens


def _route_shape(value: str) -> str:
    return re.sub(r"\{[^{}]+\}", "{}", value).lower()


def _risk_class(method: str) -> str:
    if method in _READ_METHODS:
        return "read"
    if method in _HTTP_METHODS:
        return "state_mutation"
    return "unknown"


class LatentAffordanceMiner:
    """Join captured response capabilities to unobserved artifact operations."""

    def __init__(self, limits: Optional[LatentAffordanceLimits] = None) -> None:
        self.limits = limits or LatentAffordanceLimits()

    def mine(
        self,
        records: Sequence[Mapping[str, Any]],
        artifacts: Sequence[ClientArtifact],
        *,
        target_origin: str,
        world_id: str = "captured",
    ) -> LatentAffordanceResult:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("affordance records must be a sequence of mappings")
        if len(records) > self.limits.max_records:
            raise ValueError("affordance records exceed max_records")
        if isinstance(artifacts, (str, bytes)) or any(
            not isinstance(item, ClientArtifact) for item in artifacts
        ):
            raise TypeError("artifacts must be a sequence of ClientArtifact values")
        origin = _origin_key(target_origin)
        parsed_origin = urlsplit(target_origin)
        if (
            origin is None
            or parsed_origin.username is not None
            or parsed_origin.password is not None
            or parsed_origin.path not in {"", "/"}
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise ValueError("target_origin must be an absolute HTTP(S) origin")

        lineage_limits = LineageLimits(max_value_chars=self.limits.max_value_chars)
        ledger = ValueLineageLedger(
            records,
            world_id=world_id,
            lineage_limits=lineage_limits,
        )
        observations = {item.record_index: item for item in ledger.observations}
        produced: list[_ProducedValue] = []
        observed_routes: set[Tuple[str, str]] = set()
        successful_records = 0
        for index, record in enumerate(records):
            try:
                exchange = normalize_exchange(
                    record,
                    source_id=str(record.get("id") or index),
                    world_id=str(record.get("persona_id") or world_id),
                )
            except (TypeError, ValueError):
                continue
            observed_template = exchange.path_template
            if exchange.query_keys:
                observed_template += "?" + "&".join(
                    f"{key}={{value}}" for key in exchange.query_keys
                )
            observed_routes.add((exchange.method, _route_shape(observed_template)))
            observation = observations.get(index)
            body = _body_json(record.get("response_body"))
            if (
                observation is None
                or not 200 <= exchange.response_status < 300
                or not isinstance(body, (Mapping, list))
            ):
                continue
            successful_records += 1
            produced.extend(
                _walk_produced(
                    body,
                    operation_id=observation.operation_id,
                    source_ref=observation.source_ref,
                    world_ref=observation.world_ref,
                    capture_digest=ledger.capture_digest,
                    limits=self.limits,
                )
            )

        producer_groups: Dict[Tuple[str, str], list[_ProducedValue]] = {}
        for item in produced:
            producer_groups.setdefault(
                (item.world_ref, item.capability.key), []
            ).append(item)
        unambiguous_producers = {
            key: values[0]
            for key, values in producer_groups.items()
            if len(values) == 1
        }
        ambiguous_producer_groups = sum(
            1 for values in producer_groups.values() if len(values) != 1
        )

        accepted_artifacts: list[Tuple[ClientArtifact, str]] = []
        artifact_hashes: list[str] = []
        artifact_bytes = 0
        dropped_artifacts = 0
        dropped_artifact_bytes = 0
        for artifact in artifacts:
            encoded_bytes = len(artifact.text.encode("utf-8", errors="replace"))
            if len(accepted_artifacts) >= self.limits.max_artifacts:
                dropped_artifacts += 1
                continue
            if (
                encoded_bytes > self.limits.max_artifact_bytes
                or artifact_bytes + encoded_bytes > self.limits.max_total_artifact_bytes
            ):
                dropped_artifact_bytes += encoded_bytes
                continue
            artifact_ref = stable_hash(
                "client_artifact",
                {
                    "source": artifact.source,
                    "text": artifact.text,
                    "kind": artifact.kind,
                },
            )
            accepted_artifacts.append((artifact, artifact_ref))
            artifact_hashes.append(artifact_ref)
            artifact_bytes += encoded_bytes

        routes: list[_RouteEvidence] = []
        for artifact, artifact_ref in accepted_artifacts:
            if artifact.kind in {"openapi", "other"}:
                try:
                    parsed = json.loads(artifact.text)
                except (TypeError, ValueError):
                    parsed = None
                for route in _openapi_routes(
                    parsed,
                    target_origin=origin,
                    artifact_ref=artifact_ref,
                ):
                    if len(routes) >= self.limits.max_routes:
                        break
                    routes.append(route)
            artifact_texts = (
                () if artifact.kind == "openapi" else _artifact_texts(artifact)
            )
            literals_seen = 0
            for text in artifact_texts:
                remaining_literals = (
                    self.limits.max_string_literals_per_artifact - literals_seen
                )
                if remaining_literals <= 0:
                    break
                for literal, start, end in _string_literals(
                    text,
                    limit=remaining_literals,
                ):
                    literals_seen += 1
                    latent_route = _route_evidence(
                        literal,
                        method=_method_near_literal(text, start, end),
                        target_origin=origin,
                        artifact_ref=artifact_ref,
                        evidence_kind=(
                            "source_map_string"
                            if artifact.kind == "source_map"
                            else "client_string"
                        ),
                    )
                    if latent_route is not None:
                        routes.append(latent_route)
                    if len(routes) >= self.limits.max_routes:
                        break
                if len(routes) >= self.limits.max_routes:
                    break
            if len(routes) >= self.limits.max_routes:
                break

        grouped_routes: Dict[Tuple[str, ...], list[_RouteEvidence]] = {}
        for route in routes:
            grouped_routes.setdefault(route.key, []).append(route)

        target_ref = stable_hash("latent_affordance_target", _canonical_origin(origin))
        candidates_by_id: Dict[str, LatentAffordanceCandidate] = {}
        observed_rejected = 0
        unmatched_routes = 0
        ambiguous_routes = 0
        duplicate_candidates = 0
        dropped_candidates = 0
        for key in sorted(grouped_routes):
            evidence = grouped_routes[key]
            route = evidence[0]
            shape = _route_shape(route.path_template)
            if (
                (route.method, shape) in observed_routes
                or route.method == "UNKNOWN"
                and any(item_shape == shape for _method, item_shape in observed_routes)
            ):
                observed_rejected += 1
                continue
            matches = [
                producer
                for producer in unambiguous_producers.values()
                if _capability_matches_route(producer.capability, route)
            ]
            if not matches:
                unmatched_routes += 1
                continue
            if len(matches) > 1 and len({item.world_ref for item in matches}) == 1:
                ambiguous_routes += 1
                continue
            artifact_refs = tuple(sorted({item.artifact_ref for item in evidence}))
            evidence_kinds = tuple(sorted({item.evidence_kind for item in evidence}))
            route_ref = stable_hash(
                "latent_route",
                {
                    "target_ref": target_ref,
                    "method": route.method,
                    "path_template": route.path_template,
                    "parameter_location": route.parameter_location,
                    "parameter_pointer": route.parameter_pointer,
                },
            )
            for producer in sorted(
                matches,
                key=lambda item: (item.world_ref, item.operation_id, item.source_ref),
            ):
                candidate_values = {
                    "target_ref": target_ref,
                    "producer_operation_id": producer.operation_id,
                    "producer_source_ref": producer.source_ref,
                    "producer_locator": producer.locator,
                    "world_ref": producer.world_ref,
                    "capability": producer.capability,
                    "value_hash": producer.value_hash,
                    "evidence_digest": stable_hash(
                        "latent_affordance_evidence",
                        _candidate_evidence_payload(
                            producer_source_ref=producer.source_ref,
                            producer_locator=producer.locator,
                            value_hash=producer.value_hash,
                            artifact_refs=artifact_refs,
                            evidence_kinds=evidence_kinds,
                        ),
                    ),
                    "consumer_route_ref": route_ref,
                    "consumer_method": route.method,
                    "consumer_path_template": route.path_template,
                    "consumer_parameter_location": route.parameter_location,
                    "consumer_parameter_pointer": route.parameter_pointer,
                    "artifact_refs": artifact_refs,
                    "evidence_kinds": evidence_kinds,
                    "risk_class": _risk_class(route.method),
                    "sensitive": producer.capability.name.endswith(("_token", "_key")),
                }
                identity = _candidate_identity_payload(
                    target_ref=target_ref,
                    producer_operation_id=producer.operation_id,
                    world_ref=producer.world_ref,
                    capability=producer.capability,
                    consumer_route_ref=route_ref,
                    consumer_method=route.method,
                    consumer_path_template=route.path_template,
                    consumer_parameter_location=route.parameter_location,
                    consumer_parameter_pointer=route.parameter_pointer,
                    risk_class=_risk_class(route.method),
                    sensitive=producer.capability.name.endswith(("_token", "_key")),
                )
                affordance_id = stable_hash("latent_affordance", identity)
                if affordance_id in candidates_by_id:
                    duplicate_candidates += 1
                    continue
                if len(candidates_by_id) >= self.limits.max_candidates:
                    dropped_candidates += 1
                    continue
                candidates_by_id[affordance_id] = LatentAffordanceCandidate(
                    affordance_id=affordance_id,
                    **candidate_values,
                )

        candidates = tuple(candidates_by_id[key] for key in sorted(candidates_by_id))
        diagnostics = LatentAffordanceDiagnostics(
            records=len(records),
            successful_response_records=successful_records,
            produced_capabilities=len(produced),
            ambiguous_producer_groups=ambiguous_producer_groups,
            artifacts=len(accepted_artifacts),
            artifact_bytes=artifact_bytes,
            dropped_artifacts=dropped_artifacts,
            dropped_artifact_bytes=dropped_artifact_bytes,
            routes_extracted=len(grouped_routes),
            observed_routes_rejected=observed_rejected,
            unmatched_routes=unmatched_routes,
            ambiguous_routes=ambiguous_routes,
            duplicate_candidates=duplicate_candidates,
            dropped_candidates=dropped_candidates,
        )
        return LatentAffordanceResult(
            status="ready" if candidates else "no_latent_affordances",
            target_ref=target_ref,
            capture_digest=ledger.capture_digest,
            artifact_digest=stable_hash("artifact_set", sorted(artifact_hashes)),
            candidates=candidates,
            diagnostics=diagnostics,
        )


__all__ = [
    "LATENT_AFFORDANCE_MODE",
    "ClientArtifact",
    "LatentAffordanceCandidate",
    "LatentAffordanceDiagnostics",
    "LatentAffordanceLimits",
    "LatentAffordanceMiner",
    "LatentAffordanceResult",
]
