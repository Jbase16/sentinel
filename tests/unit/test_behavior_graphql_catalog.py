"""Persisted GraphQL catalog tests; all artifacts are local strings."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import core.behavior.graphql_catalog as catalog_module
from core.behavior.graphql_catalog import GraphQLCatalogLimits, PersistedOperationCatalog
from core.behavior.proposals import STATE_MUTATION, compile_authorization_proposals
from core.behavior.scheduler import BehavioralPrimaryScheduler, PrimaryPlannerConfig
from core.foundry.vault import ResearchPersona


def _persisted(operation, resource_id, document_hash=None):
    item = {"operationName": operation, "variables": {"accountId": resource_id}}
    if document_hash:
        item["extensions"] = {
            "persistedQuery": {"version": 1, "sha256Hash": document_hash}
        }
    return {
        "method": "POST",
        "url": "https://api.example.test/graphql",
        "request_body": json.dumps(item),
    }


def _persona(persona_id):
    return ResearchPersona(persona_id, persona_id, f"{persona_id}@research.example")


def test_exact_persisted_hash_recovers_query_document_from_js_string():
    document = "query GetAccount($accountId: ID!) { account(id: $accountId) { id email } }"
    digest = hashlib.sha256(document.encode()).hexdigest()
    catalog = PersistedOperationCatalog()
    artifact = f'const operation = {json.dumps(document)};'

    assert catalog.ingest_artifact("https://api.example.test/app.js", artifact) == 1
    result = catalog.resolve_records([_persisted("GetAccount", 42, digest)])

    body = json.loads(result.records[0]["request_body"])
    assert body["query"] == document
    assert result.resolved_operations == 1
    assert result.unresolved_operations == 0


def test_hash_mismatch_never_falls_back_to_matching_operation_name():
    document = "query GetAccount($accountId: ID!) { account(id: $accountId) { id } }"
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/app.js", json.dumps(document))

    result = catalog.resolve_records([_persisted("GetAccount", 42, "0" * 64)])

    assert "query" not in json.loads(result.records[0]["request_body"])
    assert result.unresolved_operations == 1


def test_malformed_persisted_binding_never_falls_back_to_operation_name():
    document = "query GetAccount($accountId: ID!) { account(id: $accountId) { id } }"
    record = _persisted("GetAccount", 42)
    body = json.loads(record["request_body"])
    body["extensions"] = {
        "persistedQuery": {"version": 1, "sha256Hash": "not-a-sha256"}
    }
    record["request_body"] = json.dumps(body)
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/app.js", json.dumps(document))

    result = catalog.resolve_records([record])

    assert "query" not in json.loads(result.records[0]["request_body"])
    assert result.unresolved_operations == 1


def test_exact_hash_preserves_fragment_definitions_in_document():
    document = (
        "query GetAccount($accountId: ID!) { account(id: $accountId) { ...AccountFields } } "
        "fragment AccountFields on Account { id email }"
    )
    digest = hashlib.sha256(document.encode()).hexdigest()
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/app.js", json.dumps(document))

    result = catalog.resolve_records([_persisted("GetAccount", 42, digest)])

    assert json.loads(result.records[0]["request_body"])["query"] == document


def test_exact_hash_without_operation_name_resolves_only_one_operation_document():
    document = "query GetAccount($accountId: ID!) { account(id: $accountId) { id } }"
    digest = hashlib.sha256(document.encode()).hexdigest()
    record = {
        "method": "POST",
        "url": "https://api.example.test/graphql",
        "request_body": json.dumps({
            "variables": {"accountId": 42},
            "documentId": digest,
        }),
    }
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/app.js", json.dumps(document))

    result = catalog.resolve_records([record])

    assert json.loads(result.records[0]["request_body"])["query"] == document
    assert result.resolved_operations == 1


def test_name_only_resolution_fails_closed_when_documents_are_ambiguous():
    first = "query GetAccount { account { id } }"
    second = "query GetAccount { account { id email } }"
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/a.js", json.dumps(first))
    catalog.ingest_artifact("https://api.example.test/b.js", json.dumps(second))

    result = catalog.resolve_records([_persisted("GetAccount", 42)])

    assert result.resolved_operations == 0
    assert result.ambiguous_operations == 1


def test_resolved_mutation_is_classified_as_state_mutation_not_read():
    document = "mutation UpdateAccount($accountId: ID!) { update(id: $accountId) { id } }"
    source = [_persisted("UpdateAccount", 42)]
    peer = [_persisted("UpdateAccount", 84)]
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/app.js", json.dumps(document))
    resolved_source = catalog.resolve_records(source).records
    resolved_peer = catalog.resolve_records(peer).records

    batch = compile_authorization_proposals(resolved_source, resolved_peer)

    assert len(batch.proposals) == 1
    assert batch.proposals[0].risk_class == STATE_MUTATION


def test_resolved_query_becomes_eligible_for_primary_planner():
    document = "query GetAccount($accountId: ID!) { account(id: $accountId) { id } }"
    source = [_persisted("GetAccount", 42)]
    peer = [_persisted("GetAccount", 84)]
    catalog = PersistedOperationCatalog()
    catalog.ingest_artifact("https://api.example.test/app.js", json.dumps(document))
    source_resolved = catalog.resolve_records(source).records
    peer_resolved = catalog.resolve_records(peer).records
    scheduler = BehavioralPrimaryScheduler(PrimaryPlannerConfig(enabled=False))

    plan = scheduler.plan(
        source_resolved,
        peer_resolved,
        source_persona=_persona("source"),
        peer_persona=_persona("peer"),
    )

    assert plan.selected is not None
    assert plan.selected.proposal.operation_label == "GetAccount"


def test_artifact_and_document_bounds_are_enforced():
    limits = GraphQLCatalogLimits(
        max_artifacts=1,
        max_artifact_bytes=128,
        max_total_artifact_bytes=128,
        max_documents=1,
        max_document_chars=100,
        max_string_literals_per_artifact=4,
    )
    catalog = PersistedOperationCatalog(limits)
    catalog.ingest_artifact("a.js", json.dumps("query A { a }"))
    catalog.ingest_artifact("b.js", json.dumps("query B { b }"))

    assert catalog.diagnostics()["artifacts"] == 1
    assert catalog.diagnostics()["dropped"]["artifacts"] == 1


def test_catalog_has_no_network_or_async_execution_surface():
    tree = ast.parse(Path(catalog_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))
