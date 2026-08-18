from __future__ import annotations

from copy import deepcopy

import pytest

from core.cortex.attack_path_contract import build_attack_path_contract
from core.cortex.canonical_graph import CausalGraphSnapshot
from core.data.pressure_graph.manager import PressureGraphManager
from core.data.pressure_graph.projection import project_pressure_graph
from core.utils.observer import Signal


def _node(node_id: str, *, severity: float) -> dict:
    return {
        "id": node_id,
        "label": node_id,
        "type": "finding",
        "data": {
            "severity": severity,
            "exposure": 0.8,
            "exploitability": 0.7,
            "privilege_gain": 0.4,
            "asset_value": 6.0,
            "confirmation_level": "confirmed",
            "description": f"evidence for {node_id}",
            "revision": 2,
            "mass": 10.0,
            "charge": 5.0,
            "temperature": 0.2,
            "structural": False,
        },
    }


def _snapshot(
    *,
    revision_suffix: str,
    edge_id: str = "find-a-find-b",
    edge_target: str = "find-b",
    invalidated: bool = False,
) -> CausalGraphSnapshot:
    session_id = "pressure-session-16"
    evidence_revision = "canonical_session_read_model:" + revision_suffix * 64
    if invalidated:
        nodes = []
        edges = []
        entry_nodes = []
        critical_assets = []
    else:
        nodes = [_node("find-a", severity=7.0), _node("find-b", severity=9.0)]
        edges = [
            {
                "id": edge_id,
                "source": "find-a",
                "target": edge_target,
                "type": "EXPOSES",
                "weight": 0.9,
                "data": {
                    "confidence": 0.8,
                    "created_at": 0.0,
                    "relationship_raw": "enables",
                    "render_type": "EXPOSES",
                },
            }
        ]
        entry_nodes = ["find-a"]
        critical_assets = ["find-b"]
    graph = {
        "session_id": session_id,
        "evidence_revision": evidence_revision,
        "nodes": nodes,
        "edges": edges,
        "count": {"nodes": len(nodes), "edges": len(edges)},
        "entry_nodes": entry_nodes,
        "leaf_nodes": ["find-b"] if nodes else [],
        "critical_assets": critical_assets,
        "attack_chains": [],
        "pressure_points": [],
        "graph_metrics": {},
    }
    contract = build_attack_path_contract(
        session_id=session_id,
        graph_dto=graph,
        evidence_revision=evidence_revision,
    )
    graph["graph_hash"] = contract["graph_hash"]
    return CausalGraphSnapshot(
        session_id=session_id,
        evidence_revision=evidence_revision,
        graph_dto=graph,
        attack_path_contract=contract,
    )


class _SignalStore:
    def __init__(self, signal_name: str) -> None:
        setattr(self, signal_name, Signal())

    def get_all(self):
        raise AssertionError("peer graph store must not be read")


def test_pressure_graph_is_a_sealed_canonical_projection() -> None:
    snapshot = _snapshot(revision_suffix="a")
    first = project_pressure_graph(snapshot)
    second = project_pressure_graph(snapshot)

    assert first.graph_hash == snapshot.graph_hash
    assert first.projection_hash == second.projection_hash
    assert [item.id for item in first.nodes] == ["find-a", "find-b"]
    assert [item.id for item in first.edges] == ["find-a-find-b"]
    assert first.edges[0].evidence_sources == ("find-a", "find-b")
    dto = first.to_dict()
    assert dto["projection_owner"] == "canonical_causal_graph"
    assert dto["source_graph_hash"] == snapshot.graph_hash
    assert dto["entry_nodes"] == ["find-a"]
    assert dto["critical_assets"] == ["find-b"]

    issues = _SignalStore("issues_changed")
    killchain = _SignalStore("edges_changed")
    findings = _SignalStore("findings_changed")
    manager = PressureGraphManager(
        session_id=snapshot.session_id,
        issues_store=issues,
        killchain_store=killchain,
        findings_store=findings,
        canonical_snapshot=snapshot,
    )
    assert issues.issues_changed._observers == []
    assert killchain.edges_changed._observers == []
    assert findings.findings_changed._observers == []
    assert manager.to_dict()["graph_hash"] == snapshot.graph_hash
    manager._on_issues_changed()
    assert set(manager.nodes) == {"find-a", "find-b"}
    with pytest.raises(RuntimeError, match="read-only"):
        manager.ingest_findings([{"id": "invented"}])
    with pytest.raises(RuntimeError, match="critical assets are canonical"):
        manager.set_crown_jewels({"invented"})


@pytest.mark.parametrize(
    ("snapshot", "message"),
    [
        (_snapshot(revision_suffix="b", edge_id="wrong-edge"), "mismatched"),
        (
            _snapshot(
                revision_suffix="c",
                edge_id="find-a-find-missing",
                edge_target="find-missing",
            ),
            "orphaned",
        ),
    ],
)
def test_pressure_projection_rejects_noncanonical_edge_identity(
    snapshot: CausalGraphSnapshot,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        project_pressure_graph(snapshot)


def test_invalidation_changes_the_projected_graph_hash() -> None:
    before = _snapshot(revision_suffix="d")
    after = _snapshot(revision_suffix="e", invalidated=True)
    before_projection = project_pressure_graph(before)
    after_projection = project_pressure_graph(after)

    assert before.evidence_revision != after.evidence_revision
    assert before.graph_hash != after.graph_hash
    assert before_projection.graph_hash != after_projection.graph_hash
    assert before_projection.projection_hash != after_projection.projection_hash
    detached = deepcopy(before_projection.to_dict())
    detached["edges"].clear()
    assert len(before_projection.to_dict()["edges"]) == 1
