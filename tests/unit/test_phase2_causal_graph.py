import pytest

from core.cortex.causal_graph import CausalGraphBuilder


def test_enablement_edge_created_for_confirmed_information_findings():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-info",
            "type": "git_exposure",
            "title": "Exposed .git metadata",
            "severity": "CRITICAL",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "base_score": 9.5,
            "tags": ["backup-leak"],
        },
        {
            "id": "f-vuln",
            "type": "sqli",
            "title": "SQL injection on login endpoint",
            "severity": "HIGH",
            "target": "example.com",
            "confirmation_level": "probable",
            "capability_types": ["execution"],
            "base_score": 7.0,
            "tags": ["sqli"],
        },
    ]

    graph = builder.build(findings)
    assert graph.has_edge("f-info", "f-vuln")

    edge_data = graph.get_edge_data("f-info", "f-vuln")
    assert edge_data["relationship"] == "enablement"
    assert edge_data["enablement_edge"] is True
    assert edge_data["strength"] == pytest.approx(2.0)
    assert edge_data["enablement_class"] == "source_code"


def test_enablement_edges_are_scoped_to_single_target():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-cred",
            "type": "credential_dump",
            "title": "Credential exposure",
            "severity": "CRITICAL",
            "target": "target-a.example",
            "confirmation_level": "confirmed",
            "capability_types": ["access"],
            "base_score": 9.5,
            "tags": ["secret-leak"],
        },
        {
            "id": "f-login",
            "type": "admin_panel",
            "title": "Admin login page",
            "severity": "MEDIUM",
            "target": "target-b.example",
            "confirmation_level": "confirmed",
            "capability_types": ["execution"],
            "base_score": 6.0,
            "tags": ["auth"],
        },
    ]

    graph = builder.build(findings)
    assert not graph.has_edge("f-cred", "f-login")


def test_enablement_score_remains_separate_from_centrality():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-source",
            "type": "git_exposure",
            "title": "Exposed git metadata",
            "severity": "HIGH",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "base_score": 9.0,
            "tags": ["backup-leak"],
        },
        {
            "id": "f-exec",
            "type": "rce",
            "title": "Remote code execution",
            "severity": "CRITICAL",
            "target": "example.com",
            "confirmation_level": "probable",
            "capability_types": ["execution"],
            "base_score": 8.0,
            "tags": ["rce"],
        },
    ]

    builder.build(findings)
    analysis = builder.get_attack_chains(include_metrics=True)
    node_summary = {node["node_id"]: node for node in analysis["nodes"]}

    assert node_summary["f-source"]["enablement_score"] == pytest.approx(2.0)
    assert "centrality_score" in node_summary["f-source"]
