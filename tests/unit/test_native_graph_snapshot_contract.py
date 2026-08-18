"""Source contracts for the native canonical-graph handoff.

The macOS target is compiled at the WO checkpoint. These focused checks keep
the authority-sensitive mapping easy to review alongside Python tests.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP_STATE = ROOT / "ui" / "Sources" / "Models" / "HelixAppState.swift"
GRAPH_MODELS = ROOT / "ui" / "Sources" / "Models" / "PressureGraphModels.swift"
GRAPH_VIEW = ROOT / "ui" / "Sources" / "Graph" / "NeuralGraphView.swift"
NETWORK_VIEW = ROOT / "ui" / "Sources" / "Views" / "Graph" / "NetworkGraphView.swift"


def _method(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    return source[start_index : source.index(end, start_index)]


def test_native_analysis_uses_only_the_server_snapshot_and_hash() -> None:
    source = APP_STATE.read_text(encoding="utf-8")
    analysis = _method(source, "func fetchAnalysis()", "func fetchInsights(")
    insights = _method(source, "func fetchInsights(", "struct PendingAction")

    assert "canonicalGraphData(from: snapshot)" in analysis
    assert "snapshot.entryNodes ?? []" in analysis
    assert "snapshot.criticalAssets ?? []" in analysis
    assert "snapshot.graphHash" in insights

    for client_inference in (
        "inboundCounts",
        "entryTypeHints",
        "highestPressure",
        "criticalNodes.isEmpty",
        "analysis.graph_hash",
    ):
        assert client_inference not in analysis + insights


def test_native_dto_requires_snapshot_identity_and_edge_evidence() -> None:
    models = GRAPH_MODELS.read_text(encoding="utf-8")
    network = NETWORK_VIEW.read_text(encoding="utf-8")

    assert 'case evidenceRevision = "evidence_revision"' in models
    assert 'case graphHash = "graph_hash"' in models
    assert 'case evidenceSources = "evidence_sources"' in models
    assert "snapshot.graphHash.prefix(12)" in network
    assert "snapshot.evidenceRevision" in network


def test_edge_evidence_drilldown_uses_server_authored_references() -> None:
    source = GRAPH_VIEW.read_text(encoding="utf-8")
    drilldown = _method(
        source,
        "private var selectedEdgeEvidenceView",
        "private var headerView",
    )

    assert 'Text("EDGE EVIDENCE")' in drilldown
    assert "edge.data?.evidenceSources" in drilldown
    assert "edge.source == selectedNodeId ? edge.target : edge.source" in drilldown


def test_live_renderer_has_no_unsealed_event_mutation_path() -> None:
    app_state = APP_STATE.read_text(encoding="utf-8")
    graph_view = GRAPH_VIEW.read_text(encoding="utf-8")

    assert "eventClient.graphEventPublisher" not in app_state
    assert "renderer.handleGraphEvent" not in graph_view
    assert "eventClient: appState.eventClient" not in graph_view
