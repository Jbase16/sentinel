import asyncio
import inspect

from core.cortex.causal_graph import CausalGraphBuilder
from core.cortex.insight_engine import InsightEngine
from core.cortex.models import InsightRequest


class _StubAI:
    async def safe_generate(self, **_kwargs) -> str:
        return (
            '{"insights": [{"claim": "edge-backed", '
            '"evidence": ["finding-a-finding-b"], "confidence": 0.9}]}'
        )


def test_insight_engine_uses_request_graph_context_and_accepts_edge_ids() -> None:
    assert list(inspect.signature(InsightEngine.generate_insights).parameters) == [
        "self",
        "request",
    ]

    engine = InsightEngine.__new__(InsightEngine)
    engine.ai = _StubAI()
    request = InsightRequest(
        graph_hash="a" * 64,
        target_nodes=["finding-a"],
        insight_type="cluster_summary",
        graph_data={
            "nodes": [{"id": "finding-a", "type": "finding"}],
            "edges": [
                {
                    "id": "finding-a-finding-b",
                    "source": "finding-a",
                    "target": "finding-b",
                }
            ],
        },
    )

    response = asyncio.run(engine.generate_insights(request))

    assert response.graph_hash == request.graph_hash
    assert len(response.insights) == 1
    assert response.insights[0].evidence == ["finding-a-finding-b"]


def test_canonical_graph_edges_expose_only_finding_evidence_ids() -> None:
    builder = CausalGraphBuilder()
    builder.build(
        [
            {
                "id": "finding-a",
                "type": "exposure",
                "severity": "medium",
                "title": "Exposure",
                "target": "https://owned.example.test",
            },
            {
                "id": "finding-b",
                "type": "vulnerability",
                "severity": "high",
                "title": "Vulnerability",
                "target": "https://owned.example.test",
                "requires": ["finding-a"],
            },
        ]
    )

    graph = builder.export_dto(session_id="session-native-contract")
    edge = next(
        edge
        for edge in graph["edges"]
        if edge["source"] == "finding-a" and edge["target"] == "finding-b"
    )

    assert edge["id"] == "finding-a-finding-b"
    assert edge["data"]["evidence_sources"] == ["finding-a", "finding-b"]
