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


def test_enrich_from_issues_creates_enablement_edges_for_raw_findings():
    """
    Reproduces the production bug: raw findings from the FINDINGS table
    lack confirmation_level, capability_types, and score.  Rule 5 silently
    rejects them all, producing 0 enablement edges.

    After enrich_from_issues() overlays metadata from the ISSUES table,
    Rule 5 should fire and create edges.

    Uses realistic data: finding IDs are SHA256 hashes of the finding dict
    (as save_finding_txn() computes them), and supporting_findings contain
    the original finding dicts (without id) as matchers produce them.
    """
    import hashlib

    builder = CausalGraphBuilder()

    # These are the "original" finding dicts as produced by _normalize_findings()
    # and passed to both save_finding_txn() and apply_rules().
    # save_finding_txn() computes id = sha256(json.dumps(d, sort_keys=True))
    # but does NOT add id back to the dict.
    git_raw = {
        "type": "version_disclosure",
        "severity": "HIGH",
        "target": "localhost",
        "tool": "feroxbuster",
        "message": "/.git/config  (Status: 200) [Size: 244]",
        "tags": ["backup-leak"],
        "families": [],
        "metadata": {},
    }
    ssrf_raw = {
        "type": "vulnerability",
        "severity": "HIGH",
        "target": "localhost",
        "tool": "wafw00f",
        "message": "Possible SSRF indicator",
        "tags": [],
        "families": [],
        "metadata": {},
    }
    admin_raw = {
        "type": "directory_disclosure",
        "severity": "MEDIUM",
        "target": "localhost",
        "tool": "gobuster",
        "message": "/admin (Status: 301)",
        "tags": ["auth"],
        "families": [],
        "metadata": {},
    }

    # Compute SHA256 IDs exactly like save_finding_txn() does
    import json
    git_id = hashlib.sha256(json.dumps(git_raw, sort_keys=True).encode()).hexdigest()
    ssrf_id = hashlib.sha256(json.dumps(ssrf_raw, sort_keys=True).encode()).hexdigest()
    admin_id = hashlib.sha256(json.dumps(admin_raw, sort_keys=True).encode()).hexdigest()

    # get_findings() returns the parsed JSON blob + adds id and created_at
    raw_findings = [
        {**git_raw, "id": git_id, "created_at": 0.0},
        {**ssrf_raw, "id": ssrf_id, "created_at": 0.0},
        {**admin_raw, "id": admin_id, "created_at": 0.0},
    ]

    # Build from raw findings — Rule 5 should find nothing
    graph = builder.build(raw_findings)
    enablement_edges_before = [
        (u, v)
        for u, v, d in graph.edges(data=True)
        if d.get("enablement_edge") is True
    ]
    assert len(enablement_edges_before) == 0, (
        "Raw findings should NOT produce enablement edges"
    )

    # Enriched issues as stored in ISSUES table by VulnRule.apply().
    # supporting_findings contains the original dicts WITHOUT id
    # (because save_finding_txn computes id separately and doesn't
    # write it back to the dict).
    issues = [
        {
            "id": "issue-git",
            "rule_id": "BACKUP_ARTIFACT_EXPOSED",
            "title": "Backup Artifact Exposed",
            "severity": "HIGH",
            "target": "localhost",
            "score": 9.5,
            "raw_score": 9.5,
            "confirmation_level": "confirmed",
            "confirmation_multiplier": 1.0,
            "capability_types": ["information", "access"],
            "tags": ["backup-leak"],
            "supporting_findings": [git_raw],
        },
        {
            "id": "issue-ssrf",
            "rule_id": "SSRF_INDICATOR",
            "title": "SSRF Indicator",
            "severity": "HIGH",
            "target": "localhost",
            "score": 5.6,
            "raw_score": 8.0,
            "confirmation_level": "hypothesized",
            "confirmation_multiplier": 0.4,
            "capability_types": ["execution"],
            "tags": [],
            "supporting_findings": [ssrf_raw],
        },
        {
            "id": "issue-admin",
            "rule_id": "DIRECTORY_ENUMERATION",
            "title": "Directory Enumeration",
            "severity": "MEDIUM",
            "target": "localhost",
            "score": 4.2,
            "raw_score": 6.0,
            "confirmation_level": "confirmed",
            "confirmation_multiplier": 1.0,
            "capability_types": ["execution"],
            "tags": ["auth"],
            "supporting_findings": [admin_raw],
        },
    ]

    # Enrich from issues — Tier 1 hash matching should work, Rule 5 should fire
    new_edge_count = builder.enrich_from_issues(issues)
    assert new_edge_count > 0, "Enrichment should produce enablement edges"

    # Verify .git/config now has enrichment data
    git_finding = builder.findings_map[git_id]
    assert git_finding.data.get("confirmation_level") == "confirmed"
    assert "information" in git_finding.data.get("capability_types", [])
    assert git_finding.data.get("score") == 9.5

    # Verify enablement edge from .git/config to admin panel
    enablement_edges_after = [
        (u, v, d)
        for u, v, d in graph.edges(data=True)
        if d.get("enablement_edge") is True
    ]
    assert len(enablement_edges_after) > 0, "Should have enablement edges after enrichment"

    # The .git exposure should enable the admin panel (source_code → auth target)
    edge_sources = {u for u, v, d in enablement_edges_after}
    assert git_id in edge_sources, ".git/config should be source of enablement edge"


def test_enrich_from_issues_does_not_overwrite_existing_metadata():
    """Enrichment should not clobber fields already present on findings."""
    builder = CausalGraphBuilder()

    # Finding that already has enrichment fields in its data
    # (e.g., from a previous enrichment pass or from the scanner itself)
    finding_raw = {
        "type": "git_exposure",
        "severity": "HIGH",
        "target": "example.com",
        "tool": "feroxbuster",
        "message": "/.git/config exposed",
        "tags": [],
        "families": [],
        "metadata": {},
    }

    import hashlib, json
    fid = hashlib.sha256(json.dumps(finding_raw, sort_keys=True).encode()).hexdigest()

    findings = [
        {
            **finding_raw,
            "id": fid,
            "created_at": 0.0,
            "confirmation_level": "probable",  # Already set
            "capability_types": ["information"],  # Already set
            "base_score": 7.0,  # Already set
        },
    ]
    builder.build(findings)

    issues = [
        {
            "id": "issue-1",
            "title": "Backup Artifact Exposed",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "score": 9.5,
            "supporting_findings": [finding_raw],
        },
    ]

    builder.enrich_from_issues(issues)
    f = builder.findings_map[fid]
    # Original values should be preserved (not overwritten)
    assert f.data["confirmation_level"] == "probable"
    assert f.data["capability_types"] == ["information"]


def test_enrich_from_issues_empty_issues_is_noop():
    """Calling with empty issues should return 0 and change nothing."""
    builder = CausalGraphBuilder()
    builder.build([
        {"id": "f1", "type": "vuln", "title": "Test", "severity": "HIGH", "target": "t"}
    ])
    assert builder.enrich_from_issues([]) == 0
    assert builder.enrich_from_issues(None) == 0
