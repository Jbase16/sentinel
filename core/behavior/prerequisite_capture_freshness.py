"""Redacted prior-artifact versus current-capture binding for graph execution."""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .normalize import normalize_exchange, stable_hash

GRAPH_BOUND_CAPTURE_FRESHNESS_MODE = (
    "behavioral_graph_bound_capture_freshness_v1"
)

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")


class GraphBoundCaptureFreshnessDenied(RuntimeError):
    """A prior graph artifact no longer matches the current paired capture."""


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise GraphBoundCaptureFreshnessDenied(
            "graph_bound_capture_target_origin_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _records(values: Sequence[Mapping[str, Any]], *, label: str) -> Tuple[Dict[str, Any], ...]:
    if not values or any(not isinstance(item, Mapping) for item in values):
        raise GraphBoundCaptureFreshnessDenied(
            f"graph_bound_{label}_capture_is_invalid"
        )
    return tuple(dict(item) for item in values)


def graph_bound_capture_artifact_ref(
    values: Sequence[Mapping[str, Any]],
    *,
    target_origin: str,
    world_id: str,
) -> str:
    """Hash one private capture without returning any captured value."""

    origin = _canonical_origin(target_origin)
    records = _records(values, label="current")
    if not isinstance(world_id, str) or not world_id:
        raise GraphBoundCaptureFreshnessDenied(
            "graph_bound_capture_world_is_invalid"
        )
    return stable_hash(
        "graph_bound_capture_artifact",
        {
            "target_ref": stable_hash("behavioral_capture_target", origin),
            "world_ref": stable_hash("world", world_id),
            "records": list(records),
        },
    )


def _snapshot(
    values: Sequence[Mapping[str, Any]],
    *,
    target_origin: str,
    world_id: str,
    label: str,
) -> Tuple[str, int]:
    origin = _canonical_origin(target_origin)
    records = _records(values, label=label)
    descriptors = []
    for record in records:
        try:
            exchange = normalize_exchange(record, world_id=world_id)
        except (TypeError, ValueError) as exc:
            raise GraphBoundCaptureFreshnessDenied(
                f"graph_bound_{label}_capture_is_invalid"
            ) from exc
        if exchange.origin != origin:
            raise GraphBoundCaptureFreshnessDenied(
                f"graph_bound_{label}_capture_origin_mismatch"
            )
        descriptors.append(
            {
                "action_id": exchange.action_id,
                "state_id": exchange.state_id,
                "request_truncated": exchange.request_truncated,
                "response_truncated": exchange.response_truncated,
            }
        )
    return stable_hash("graph_bound_capture_snapshot", descriptors), len(records)


def _payload(binding: "GraphBoundCaptureFreshnessBinding") -> Dict[str, Any]:
    return {
        "target_ref": binding.target_ref,
        "source_world_ref": binding.source_world_ref,
        "peer_world_ref": binding.peer_world_ref,
        "prior_source_artifact_ref": binding.prior_source_artifact_ref,
        "prior_peer_artifact_ref": binding.prior_peer_artifact_ref,
        "current_source_capture_ref": binding.current_source_capture_ref,
        "current_peer_capture_ref": binding.current_peer_capture_ref,
        "prior_source_snapshot_ref": binding.prior_source_snapshot_ref,
        "prior_peer_snapshot_ref": binding.prior_peer_snapshot_ref,
        "current_source_snapshot_ref": binding.current_source_snapshot_ref,
        "current_peer_snapshot_ref": binding.current_peer_snapshot_ref,
        "prior_selection_ref": binding.prior_selection_ref,
        "current_selection_ref": binding.current_selection_ref,
        "source_record_count": binding.source_record_count,
        "peer_record_count": binding.peer_record_count,
        "current_capture_revalidated": True,
        "selection_revalidated": binding.selection_revalidated,
        "target_requests_sent": 0,
        "backend_dispatch_authority": False,
        "promotion_authority": False,
        "finding_authority": False,
        "retry_authority": False,
    }


@dataclass(frozen=True)
class GraphBoundCaptureFreshnessBinding:
    binding_id: str
    target_ref: str
    source_world_ref: str
    peer_world_ref: str
    prior_source_artifact_ref: str
    prior_peer_artifact_ref: str
    current_source_capture_ref: str
    current_peer_capture_ref: str
    prior_source_snapshot_ref: str
    prior_peer_snapshot_ref: str
    current_source_snapshot_ref: str
    current_peer_snapshot_ref: str
    prior_selection_ref: Optional[str]
    current_selection_ref: Optional[str]
    source_record_count: int
    peer_record_count: int
    current_capture_revalidated: bool = True
    selection_revalidated: bool = False
    target_requests_sent: int = 0
    backend_dispatch_authority: bool = False
    promotion_authority: bool = False
    finding_authority: bool = False
    retry_authority: bool = False
    mode: str = GRAPH_BOUND_CAPTURE_FRESHNESS_MODE

    @classmethod
    def build(
        cls,
        *,
        prior_source_records: Sequence[Mapping[str, Any]],
        prior_peer_records: Sequence[Mapping[str, Any]],
        current_source_records: Sequence[Mapping[str, Any]],
        current_peer_records: Sequence[Mapping[str, Any]],
        target_origin: str,
        source_world_id: str,
        peer_world_id: str,
    ) -> "GraphBoundCaptureFreshnessBinding":
        if (
            not isinstance(source_world_id, str)
            or not source_world_id
            or not isinstance(peer_world_id, str)
            or not peer_world_id
            or source_world_id == peer_world_id
        ):
            raise GraphBoundCaptureFreshnessDenied(
                "graph_bound_capture_world_pair_is_invalid"
            )
        origin = _canonical_origin(target_origin)
        prior_source_snapshot, prior_source_count = _snapshot(
            prior_source_records,
            target_origin=origin,
            world_id=source_world_id,
            label="prior_source",
        )
        prior_peer_snapshot, prior_peer_count = _snapshot(
            prior_peer_records,
            target_origin=origin,
            world_id=peer_world_id,
            label="prior_peer",
        )
        current_source_snapshot, current_source_count = _snapshot(
            current_source_records,
            target_origin=origin,
            world_id=source_world_id,
            label="current_source",
        )
        current_peer_snapshot, current_peer_count = _snapshot(
            current_peer_records,
            target_origin=origin,
            world_id=peer_world_id,
            label="current_peer",
        )
        if (
            prior_source_snapshot != current_source_snapshot
            or prior_peer_snapshot != current_peer_snapshot
            or prior_source_count != current_source_count
            or prior_peer_count != current_peer_count
        ):
            raise GraphBoundCaptureFreshnessDenied(
                "graph_bound_prior_capture_is_stale"
            )
        values = {
            "binding_id": "",
            "target_ref": stable_hash("behavioral_capture_target", origin),
            "source_world_ref": stable_hash("world", source_world_id),
            "peer_world_ref": stable_hash("world", peer_world_id),
            "prior_source_artifact_ref": graph_bound_capture_artifact_ref(
                prior_source_records,
                target_origin=origin,
                world_id=source_world_id,
            ),
            "prior_peer_artifact_ref": graph_bound_capture_artifact_ref(
                prior_peer_records,
                target_origin=origin,
                world_id=peer_world_id,
            ),
            "current_source_capture_ref": graph_bound_capture_artifact_ref(
                current_source_records,
                target_origin=origin,
                world_id=source_world_id,
            ),
            "current_peer_capture_ref": graph_bound_capture_artifact_ref(
                current_peer_records,
                target_origin=origin,
                world_id=peer_world_id,
            ),
            "prior_source_snapshot_ref": prior_source_snapshot,
            "prior_peer_snapshot_ref": prior_peer_snapshot,
            "current_source_snapshot_ref": current_source_snapshot,
            "current_peer_snapshot_ref": current_peer_snapshot,
            "prior_selection_ref": None,
            "current_selection_ref": None,
            "source_record_count": current_source_count,
            "peer_record_count": current_peer_count,
        }
        payload = {
            key: value
            for key, value in values.items()
            if key != "binding_id"
        }
        payload.update(
            {
                "current_capture_revalidated": True,
                "selection_revalidated": False,
                "target_requests_sent": 0,
                "backend_dispatch_authority": False,
                "promotion_authority": False,
                "finding_authority": False,
                "retry_authority": False,
            }
        )
        return cls(
            **{
                **values,
                "binding_id": stable_hash(
                    "graph_bound_capture_freshness",
                    payload,
                ),
            }
        )

    def __post_init__(self) -> None:
        refs = (
            (self.target_ref, "behavioral_capture_target"),
            (self.source_world_ref, "world"),
            (self.peer_world_ref, "world"),
            (self.prior_source_artifact_ref, "graph_bound_capture_artifact"),
            (self.prior_peer_artifact_ref, "graph_bound_capture_artifact"),
            (self.current_source_capture_ref, "graph_bound_capture_artifact"),
            (self.current_peer_capture_ref, "graph_bound_capture_artifact"),
            (self.prior_source_snapshot_ref, "graph_bound_capture_snapshot"),
            (self.prior_peer_snapshot_ref, "graph_bound_capture_snapshot"),
            (self.current_source_snapshot_ref, "graph_bound_capture_snapshot"),
            (self.current_peer_snapshot_ref, "graph_bound_capture_snapshot"),
        )
        if (
            self.mode != GRAPH_BOUND_CAPTURE_FRESHNESS_MODE
            or self.binding_id
            != stable_hash("graph_bound_capture_freshness", _payload(self))
            or any(
                not isinstance(value, str)
                or _HASH_REF.fullmatch(value) is None
                or not value.startswith(f"{prefix}:")
                for value, prefix in refs
            )
            or self.source_world_ref == self.peer_world_ref
            or self.prior_source_snapshot_ref
            != self.current_source_snapshot_ref
            or self.prior_peer_snapshot_ref != self.current_peer_snapshot_ref
            or (
                self.selection_revalidated
                and (
                    not isinstance(self.prior_selection_ref, str)
                    or _HASH_REF.fullmatch(self.prior_selection_ref) is None
                    or not self.prior_selection_ref.startswith(
                        "graph_bound_capture_selection:"
                    )
                    or self.prior_selection_ref
                    != self.current_selection_ref
                )
            )
            or (
                not self.selection_revalidated
                and (
                    self.prior_selection_ref is not None
                    or self.current_selection_ref is not None
                )
            )
            or isinstance(self.source_record_count, bool)
            or self.source_record_count < 1
            or isinstance(self.peer_record_count, bool)
            or self.peer_record_count < 1
            or not self.current_capture_revalidated
            or self.target_requests_sent != 0
            or self.backend_dispatch_authority
            or self.promotion_authority
            or self.finding_authority
            or self.retry_authority
        ):
            raise ValueError("graph-bound capture freshness binding is invalid")

    def bind_selection(
        self,
        *,
        prior_selection: Mapping[str, Any],
        current_selection: Mapping[str, Any],
    ) -> "GraphBoundCaptureFreshnessBinding":
        if not isinstance(prior_selection, Mapping) or not isinstance(
            current_selection,
            Mapping,
        ):
            raise TypeError("graph-bound capture selections must be mappings")
        prior_ref = stable_hash(
            "graph_bound_capture_selection",
            dict(prior_selection),
        )
        current_ref = stable_hash(
            "graph_bound_capture_selection",
            dict(current_selection),
        )
        if prior_ref != current_ref:
            raise GraphBoundCaptureFreshnessDenied(
                "graph_bound_prior_capture_selection_is_stale"
            )
        values = {item.name: getattr(self, item.name) for item in fields(self)}
        values.update(
            {
                "binding_id": "",
                "prior_selection_ref": prior_ref,
                "current_selection_ref": current_ref,
                "selection_revalidated": True,
            }
        )
        payload = self.to_dict()
        for key in ("schema_version", "mode", "binding_id"):
            payload.pop(key)
        payload.update(
            {
                "prior_selection_ref": prior_ref,
                "current_selection_ref": current_ref,
                "selection_revalidated": True,
            }
        )
        values["binding_id"] = stable_hash(
            "graph_bound_capture_freshness",
            payload,
        )
        return type(self)(**values)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "binding_id": self.binding_id,
            **_payload(self),
        }
