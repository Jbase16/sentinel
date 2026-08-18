"""Read-only PressureGraph projection of one canonical causal snapshot."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from core.behavior.normalize import stable_hash
from core.behavior.receipts import re_full_sha256
from core.cortex.canonical_graph import CausalGraphSnapshot

from .models import EdgeType, PressureEdge, PressureNode, PressureSource


_EDGE_TYPES = {
    "enables": EdgeType.ENABLES,
    "reaches": EdgeType.REACHES,
    "requires": EdgeType.REQUIRES,
    "amplifies": EdgeType.AMPLIFIES,
    "exposes": EdgeType.EXPOSES,
    "vulnerable_to": EdgeType.VULNERABLE_TO,
    "uses_tech": EdgeType.USES_TECH,
    "has_port": EdgeType.HAS_PORT,
}


def _number(
    value: Any,
    *,
    field_name: str,
    minimum: float = 0.0,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool):
        raise ValueError(f"PressureGraph {field_name} is invalid")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"PressureGraph {field_name} is invalid") from exc
    if (
        not math.isfinite(parsed)
        or parsed < minimum
        or (maximum is not None and parsed > maximum)
    ):
        raise ValueError(f"PressureGraph {field_name} is invalid")
    return parsed


def _node_from_canonical(value: Mapping[str, Any]) -> PressureNode:
    node_id = value.get("id")
    node_type = value.get("type")
    data = value.get("data")
    if (
        not isinstance(node_id, str)
        or not node_id
        or not isinstance(node_type, str)
        or not node_type
        or not isinstance(data, Mapping)
    ):
        raise ValueError("PressureGraph canonical node is invalid")
    confirmation = str(data.get("confirmation_level") or "probable").lower()
    revision = data.get("revision", 1)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("PressureGraph node revision is invalid")
    return PressureNode(
        id=node_id,
        type=node_type,
        severity=_number(
            data.get("severity", 1.0),
            field_name="node severity",
            maximum=10.0,
        ),
        exposure=_number(
            data.get("exposure", 0.0),
            field_name="node exposure",
            maximum=1.0,
        ),
        exploitability=_number(
            data.get("exploitability", 0.0),
            field_name="node exploitability",
            maximum=1.0,
        ),
        privilege_gain=_number(
            data.get("privilege_gain", 0.0),
            field_name="node privilege gain",
            maximum=1.0,
        ),
        asset_value=_number(
            data.get("asset_value", 1.0),
            field_name="node asset value",
            maximum=10.0,
        ),
        tool_reliability=1.0,
        evidence_quality=1.0 if confirmation == "confirmed" else 0.7,
        corroboration_count=0,
        description=str(data.get("description") or ""),
        pressure_source=PressureSource.CANONICAL,
        revision=revision,
        mass=_number(data.get("mass", 1.0), field_name="node mass"),
        charge=_number(
            data.get("charge", 0.0),
            field_name="node charge",
            minimum=-1000.0,
        ),
        temperature=_number(
            data.get("temperature", 0.0),
            field_name="node temperature",
        ),
        structural=bool(data.get("structural", False)),
    )


def _edge_from_canonical(
    value: Mapping[str, Any],
    *,
    node_ids: frozenset[str],
) -> PressureEdge:
    edge_id = value.get("id")
    source = value.get("source")
    target = value.get("target")
    edge_type_raw = value.get("type")
    data = value.get("data")
    if not all(isinstance(item, str) and item for item in (edge_id, source, target)):
        raise ValueError("PressureGraph canonical edge identity is invalid")
    if source not in node_ids or target not in node_ids:
        raise ValueError("PressureGraph canonical edge is orphaned")
    if edge_id != f"{source}-{target}":
        raise ValueError("PressureGraph canonical edge id is mismatched")
    if not isinstance(edge_type_raw, str) or not isinstance(data, Mapping):
        raise ValueError("PressureGraph canonical edge is invalid")
    edge_type = _EDGE_TYPES.get(edge_type_raw.lower())
    if edge_type is None:
        raise ValueError("PressureGraph canonical edge type is unsupported")
    confidence = _number(
        data.get("confidence", 0.0),
        field_name="edge confidence",
        maximum=1.0,
    )
    return PressureEdge(
        id=edge_id,
        source_id=source,
        target_id=target,
        type=edge_type,
        transfer_factor=_number(
            value.get("weight", 0.0),
            field_name="edge weight",
        ),
        confidence=confidence,
        evidence_sources=(source, target),
        created_at=_number(
            data.get("created_at", 0.0),
            field_name="edge created_at",
        ),
    )


def _node_material(node: PressureNode) -> Dict[str, Any]:
    return {
        "id": node.id,
        "type": node.type,
        "severity": node.severity,
        "exposure": node.exposure,
        "exploitability": node.exploitability,
        "privilege_gain": node.privilege_gain,
        "asset_value": node.asset_value,
        "evidence_quality": node.evidence_quality,
        "description": node.description,
        "revision": node.revision,
        "mass": node.mass,
        "charge": node.charge,
        "temperature": node.temperature,
        "structural": node.structural,
        "base_pressure": node.base_pressure,
    }


def _edge_material(edge: PressureEdge) -> Dict[str, Any]:
    return {
        "id": edge.id,
        "source": edge.source_id,
        "target": edge.target_id,
        "type": edge.type.value,
        "weight": edge.transfer_factor,
        "confidence": edge.confidence,
        "evidence_sources": list(edge.evidence_sources),
        "created_at": edge.created_at,
    }


@dataclass(frozen=True, init=False)
class PressureGraphProjection:
    session_id: str
    evidence_revision: str
    graph_hash: str
    projection_hash: str
    nodes: Tuple[PressureNode, ...]
    edges: Tuple[PressureEdge, ...]
    _source_json: str

    def __init__(self, snapshot: CausalGraphSnapshot) -> None:
        if not isinstance(snapshot, CausalGraphSnapshot):
            raise TypeError("snapshot must be a CausalGraphSnapshot")
        source = snapshot.graph_dto
        if (
            source.get("session_id") != snapshot.session_id
            or source.get("evidence_revision") != snapshot.evidence_revision
            or source.get("graph_hash") != snapshot.graph_hash
            or not re_full_sha256(snapshot.graph_hash)
        ):
            raise ValueError("PressureGraph source snapshot identity is invalid")
        raw_nodes = source.get("nodes")
        raw_edges = source.get("edges")
        if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
            raise ValueError("PressureGraph source snapshot shape is invalid")
        nodes = tuple(_node_from_canonical(item) for item in raw_nodes)
        node_ids = frozenset(item.id for item in nodes)
        if len(node_ids) != len(nodes):
            raise ValueError("PressureGraph canonical node ids are duplicated")
        edges = tuple(
            _edge_from_canonical(item, node_ids=node_ids) for item in raw_edges
        )
        edge_ids = {item.id for item in edges}
        if len(edge_ids) != len(edges):
            raise ValueError("PressureGraph canonical edge ids are duplicated")
        count = source.get("count")
        if not isinstance(count, Mapping) or (
            count.get("nodes") != len(nodes) or count.get("edges") != len(edges)
        ):
            raise ValueError("PressureGraph canonical counts are inconsistent")
        material = {
            "schema_version": 1,
            "session_id": snapshot.session_id,
            "evidence_revision": snapshot.evidence_revision,
            "source_graph_hash": snapshot.graph_hash,
            "nodes": [_node_material(item) for item in nodes],
            "edges": [_edge_material(item) for item in edges],
        }
        object.__setattr__(self, "session_id", snapshot.session_id)
        object.__setattr__(self, "evidence_revision", snapshot.evidence_revision)
        object.__setattr__(self, "graph_hash", snapshot.graph_hash)
        object.__setattr__(
            self,
            "projection_hash",
            stable_hash("pressure_graph_projection", material),
        )
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(
            self,
            "_source_json",
            json.dumps(source, sort_keys=True, separators=(",", ":")),
        )

    def to_dict(self) -> Dict[str, Any]:
        value = json.loads(self._source_json)
        node_index = {item.id: item for item in self.nodes}
        for node in value["nodes"]:
            projected = node_index[node["id"]]
            node.setdefault("data", {})["pressure_projection"] = {
                "base_pressure": projected.base_pressure,
                "evidence_quality": projected.evidence_quality,
                "pressure_source": projected.pressure_source.value,
            }
        edge_index = {item.id: item for item in self.edges}
        for edge in value["edges"]:
            projected = edge_index[edge["id"]]
            edge.setdefault("data", {})["pressure_projection"] = {
                "effective_transfer": projected.effective_transfer,
                "evidence_sources": list(projected.evidence_sources),
            }
        value["source_graph_hash"] = self.graph_hash
        value["projection_hash"] = self.projection_hash
        value["projection_owner"] = "canonical_causal_graph"
        return value


def project_pressure_graph(snapshot: CausalGraphSnapshot) -> PressureGraphProjection:
    return PressureGraphProjection(snapshot)


__all__ = ["PressureGraphProjection", "project_pressure_graph"]
