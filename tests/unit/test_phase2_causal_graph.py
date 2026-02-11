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


def test_enrich_from_issues_tier3_does_not_match_root_prefix_targets():
    """
    Tier 3 must not enrich by broad root URL prefix alone.
    This prevents near-complete graphs when all findings share a base URL.
    """
    import hashlib
    import json

    builder = CausalGraphBuilder()

    finding_raw = {
        "type": "directory_disclosure",
        "severity": "MEDIUM",
        "target": "http://localhost:3003/admin",
        "tool": "feroxbuster",
        "message": "/admin (Status: 301)",
        "tags": ["auth"],
        "families": ["exposure"],
        "metadata": {"path": "/admin"},
    }
    finding_id = hashlib.sha256(json.dumps(finding_raw, sort_keys=True).encode()).hexdigest()
    builder.build([{**finding_raw, "id": finding_id, "created_at": 0.0}])

    # Issue target is root-only and should not tier3-match this finding.
    unrelated_supporting = {
        "type": "open_port",
        "severity": "LOW",
        "target": "http://localhost:3003",
        "tool": "nmap",
        "message": "80/tcp open",
        "tags": [],
        "families": ["recon-phase2"],
        "metadata": {"port": 80},
    }
    issues = [
        {
            "id": "issue-root",
            "title": "Generic Root Issue",
            "severity": "HIGH",
            "target": "http://localhost:3003",
            "score": 9.0,
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "supporting_findings": [unrelated_supporting],
        }
    ]

    new_edge_count = builder.enrich_from_issues(issues)
    assert new_edge_count == 0
    assert builder.findings_map[finding_id].data.get("confirmation_level") is None


def test_export_dto_includes_attack_chains_and_pressure_points():
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

    builder.build(findings)
    dto = builder.export_dto(session_id="test-session")

    assert "attack_chains" in dto
    assert "pressure_points" in dto
    assert "entry_nodes" in dto
    assert isinstance(dto["attack_chains"], list)
    assert isinstance(dto["pressure_points"], list)

    assert dto["edges"], "Expected at least one edge in exported DTO"
    edge = dto["edges"][0]
    assert edge["type"] in {"EXPOSES", "VULNERABLE_TO", "HAS_PORT", "USES_TECH"}
    assert "relationship_raw" in edge.get("data", {})


def test_export_dto_uses_dynamic_risk_fields_not_flat_defaults():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-cred",
            "type": "credential_dump",
            "title": "Credential exposure",
            "severity": "CRITICAL",
            "target": "public.example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["access"],
            "base_score": 9.0,
            "tags": ["secret-leak"],
        },
        {
            "id": "f-hypo",
            "type": "ssrf",
            "title": "Potential SSRF",
            "severity": "MEDIUM",
            "target": "internal.localhost",
            "confirmation_level": "hypothesized",
            "capability_types": ["execution"],
            "base_score": 5.0,
            "tags": ["ssrf"],
        },
    ]

    builder.build(findings)
    dto = builder.export_dto(session_id="risk-session")
    node_map = {node["id"]: node for node in dto["nodes"]}

    cred_data = node_map["f-cred"]["data"]
    hypo_data = node_map["f-hypo"]["data"]

    # Severity should be on a 0-10 scale (not old 0-1 compressed values).
    assert cred_data["severity"] > 8.0
    assert hypo_data["severity"] >= 4.0

    # Fields should be derived, not fixed constants.
    assert cred_data["exploitability"] != hypo_data["exploitability"]
    assert cred_data["exposure"] != hypo_data["exposure"]
    assert cred_data["privilege_gain"] > hypo_data["privilege_gain"]


def test_enablement_edges_require_explicit_candidate_capability_metadata():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-cred",
            "type": "credential_dump",
            "title": "Credential exposure",
            "severity": "CRITICAL",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["access", "information"],
            "base_score": 9.0,
            "tags": ["secret-leak"],
        },
        {
            # Looks auth-related but lacks capability_types enrichment metadata.
            "id": "f-login",
            "type": "admin_login",
            "title": "Admin login page",
            "severity": "MEDIUM",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "tags": ["auth"],
        },
    ]

    graph = builder.build(findings)
    assert not graph.has_edge("f-cred", "f-login")


def test_enablement_edges_are_rate_limited_per_source():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-cred",
            "type": "credential_dump",
            "title": "Credential exposure",
            "severity": "CRITICAL",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["access", "information"],
            "base_score": 9.5,
            "tags": ["secret-leak"],
        }
    ]

    for idx in range(12):
        findings.append(
            {
                "id": f"f-auth-{idx}",
                "type": "admin_login",
                "title": f"Auth target {idx}",
                "severity": "HIGH",
                "target": "example.com",
                "confirmation_level": "probable",
                "capability_types": ["execution"],
                "base_score": 7.0,
                "tags": ["auth"],
            }
        )

    graph = builder.build(findings)
    outgoing = list(graph.out_edges("f-cred"))
    assert len(outgoing) <= 4


def test_rule5_dedupes_overlapping_sources_and_candidate_families():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-info-primary",
            "type": "git_exposure",
            "title": "Exposed .git metadata",
            "severity": "CRITICAL",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "base_score": 9.5,
            "tags": ["backup-leak"],
            "metadata": {"path": "/.git/config"},
        },
        {
            # Same locator/class from another tool should not create a second
            # fan-out source in Rule-5.
            "id": "f-info-secondary",
            "type": "git_disclosure",
            "title": "Git config exposed via alternate probe",
            "severity": "HIGH",
            "target": "example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "base_score": 9.0,
            "tags": ["backup-leak"],
            "metadata": {"path": "/.git/config"},
        },
        {
            "id": "f-auth-1",
            "type": "admin_login",
            "title": "Admin login page",
            "severity": "HIGH",
            "target": "example.com",
            "confirmation_level": "probable",
            "capability_types": ["execution"],
            "base_score": 7.0,
            "tags": ["auth"],
            "metadata": {"path": "/admin"},
        },
        {
            "id": "f-auth-2",
            "type": "session_login",
            "title": "Session login endpoint",
            "severity": "HIGH",
            "target": "example.com",
            "confirmation_level": "probable",
            "capability_types": ["execution"],
            "base_score": 6.8,
            "tags": ["auth"],
            "metadata": {"path": "/login"},
        },
        {
            "id": "f-sqli",
            "type": "sqli",
            "title": "SQL injection candidate",
            "severity": "HIGH",
            "target": "example.com",
            "confirmation_level": "probable",
            "capability_types": ["execution"],
            "base_score": 7.5,
            "tags": ["sqli"],
            "metadata": {"path": "/api/users"},
        },
    ]

    graph = builder.build(findings)
    enablement_edges = [
        (u, v, d)
        for u, v, d in graph.edges(data=True)
        if d.get("enablement_edge") is True
    ]

    edge_sources = {u for u, _, _ in enablement_edges}
    assert "f-info-primary" in edge_sources
    assert "f-info-secondary" not in edge_sources

    primary_targets = [v for u, v, _ in enablement_edges if u == "f-info-primary"]
    auth_targets = [
        v
        for v in primary_targets
        if "auth" in str(builder.findings_map[v].type).lower()
        or "login" in str(builder.findings_map[v].type).lower()
    ]
    assert len(auth_targets) <= 1


def test_enrich_from_issues_tier1_prefers_best_scored_issue_for_same_finding():
    import hashlib
    import json

    builder = CausalGraphBuilder()

    source_raw = {
        "type": "version_disclosure",
        "severity": "HIGH",
        "target": "localhost",
        "tool": "feroxbuster",
        "message": "/.git/config exposed",
        "tags": ["backup-leak"],
        "families": [],
        "metadata": {"original_target": "http://localhost:3003/.git/config"},
    }
    sink_raw = {
        "type": "directory_disclosure",
        "severity": "MEDIUM",
        "target": "localhost",
        "tool": "gobuster",
        "message": "/admin discovered",
        "tags": ["auth"],
        "families": [],
        "metadata": {"original_target": "http://localhost:3003/admin"},
    }

    source_id = hashlib.sha256(json.dumps(source_raw, sort_keys=True).encode()).hexdigest()
    sink_id = hashlib.sha256(json.dumps(sink_raw, sort_keys=True).encode()).hexdigest()

    builder.build(
        [
            {**source_raw, "id": source_id, "created_at": 0.0},
            {**sink_raw, "id": sink_id, "created_at": 0.0},
        ]
    )

    issues = [
        {
            "id": "issue-low",
            "title": "Low-confidence chain",
            "target": "localhost",
            "score": 4.4,
            "confirmation_level": "probable",
            "capability_types": ["execution"],
            "supporting_findings": [source_raw],
        },
        {
            "id": "issue-high",
            "title": "High-confidence artifact exposure",
            "target": "localhost",
            "score": 9.5,
            "confirmation_level": "confirmed",
            "capability_types": ["information", "access"],
            "supporting_findings": [source_raw],
        },
        {
            "id": "issue-sink",
            "title": "Admin surface",
            "target": "localhost",
            "score": 6.0,
            "confirmation_level": "confirmed",
            "capability_types": ["execution"],
            "supporting_findings": [sink_raw],
        },
    ]

    builder.enrich_from_issues(issues)

    source_finding = builder.findings_map[source_id]
    assert source_finding.data.get("score") == 9.5
    assert source_finding.data.get("confirmation_level") == "confirmed"
    assert source_finding.data.get("capability_types") == ["information", "access"]


def test_enrich_from_issues_tier3_uses_original_target_when_target_is_hostname_only():
    builder = CausalGraphBuilder()
    findings = [
        {
            "id": "f-host-only",
            "type": "directory_disclosure",
            "title": "Admin endpoint exposed",
            "severity": "MEDIUM",
            "target": "localhost",
            "tool": "feroxbuster",
            "tags": ["auth"],
            "metadata": {"original_target": "http://localhost:3003/admin"},
        }
    ]
    builder.build(findings)

    issues = [
        {
            "id": "issue-tier3",
            "title": "Auth surface issue",
            "target": "localhost",
            "score": 7.1,
            "confirmation_level": "confirmed",
            "capability_types": ["execution"],
            "tags": ["auth"],
            "supporting_findings": [
                {
                    "type": "other",
                    "severity": "LOW",
                    "target": "localhost",
                    "tool": "othertool",
                    "message": "auxiliary evidence",
                    "tags": ["auth"],
                    "metadata": {
                        "original_target": "http://localhost:3003/admin/panel"
                    },
                }
            ],
        }
    ]

    new_edges = builder.enrich_from_issues(issues)
    assert new_edges == 0  # no second finding to connect, but enrichment should still occur

    enriched = builder.findings_map["f-host-only"]
    assert enriched.data.get("confirmation_level") == "confirmed"
    assert enriched.data.get("capability_types") == ["execution"]
    assert enriched.data.get("score") == 7.1
