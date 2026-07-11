"""Proposal-mode authorization planning and legacy compatibility tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import core.behavior.proposals as proposal_module
from core.behavior.compat import compare_with_legacy_bola
from core.behavior.proposals import (
    CROSS_OBJECT_READ,
    PROPOSAL_MODE,
    STATE_MUTATION,
    ProposalLimits,
    compile_authorization_proposals,
)

SOURCE_ID = "RlLB9Tjpk7YfkTaBB0SpzA"
PEER_ID = "9QsBs4y23m6HH4aB38ffkA"


def _gql_record(operation: str, resource_id: str, *, query: str | None = None):
    item = {
        "operationName": operation,
        "variables": {"BizEncId": resource_id},
    }
    if query:
        item["query"] = query
    return {
        "action": "network_capture",
        "type": "xhr",
        "url": "/gql/batch",
        "request_headers": {
            "content-type": "application/json",
            "x-biz-context": resource_id,
            "authorization": "Bearer private-session-token",
        },
        "request_body": json.dumps([item]),
        "response_body": json.dumps({"data": {"privateMarker": resource_id}}),
    }


def _capture(resource_id: str):
    return [
        _gql_record("GetUpcomingAppointments", resource_id),
        _gql_record("GetNotifications", resource_id),
        _gql_record("GetBizLeftNav", resource_id),
    ]


def test_compile_three_leg_authorization_proposals_without_raw_values():
    batch = compile_authorization_proposals(
        _capture(SOURCE_ID), _capture(PEER_ID),
        source_world="researcher-a", peer_world="researcher-b",
    )

    assert batch.mode == PROPOSAL_MODE
    assert batch.executable is False
    assert set(batch.operation_labels()) == {
        "GetUpcomingAppointments", "GetNotifications", "GetBizLeftNav",
    }
    assert all(proposal.risk_class == CROSS_OBJECT_READ for proposal in batch.proposals)
    assert all(len(proposal.legs) == 3 for proposal in batch.proposals)
    assert all(proposal.executable is False for proposal in batch.proposals)

    encoded = json.dumps(batch.to_dict(), sort_keys=True)
    for secret in (
        SOURCE_ID, PEER_ID, "private-session-token", "researcher-a", "researcher-b",
    ):
        assert secret not in encoded
    assert "finding" not in encoded.lower()


def test_proposal_compilation_is_deterministic():
    first = compile_authorization_proposals(
        _capture(SOURCE_ID), _capture(PEER_ID),
        source_world="researcher-a", peer_world="researcher-b",
    )
    second = compile_authorization_proposals(
        _capture(SOURCE_ID), _capture(PEER_ID),
        source_world="researcher-a", peer_world="researcher-b",
    )
    assert first.to_dict() == second.to_dict()


def test_proposal_module_has_no_network_or_async_execution_surface():
    tree = ast.parse(Path(proposal_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree))


def test_proposal_contains_exact_body_and_header_mutation_locators():
    batch = compile_authorization_proposals(_capture(SOURCE_ID), _capture(PEER_ID))
    proposal = next(item for item in batch.proposals if item.operation_label == "GetNotifications")
    locations = {(item.location_kind, item.pointer) for item in proposal.mutations}

    assert ("json_body", "/0/variables/BizEncId") in locations
    assert ("request_header", "/headers/x-biz-context") in locations
    assert all(locator.source_value_hash.startswith("observed_value:") for locator in proposal.mutations)
    assert all(locator.replacement_value_hash.startswith("observed_value:") for locator in proposal.mutations)


def test_static_candidate_set_matches_existing_bola_engine():
    source = _capture(SOURCE_ID)
    peer = _capture(PEER_ID)
    batch = compile_authorization_proposals(source, peer)

    report = compare_with_legacy_bola(batch, source, peer)
    assert report.executable is False
    assert report.legacy_pair_detected is True
    assert report.candidate_equivalent is True
    assert report.missing_from_proposals == ()
    assert report.additional_proposal_labels == ()


def test_comparison_never_invokes_bola_hunt(monkeypatch):
    source = _capture(SOURCE_ID)
    peer = _capture(PEER_ID)
    batch = compile_authorization_proposals(source, peer)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("hunt must not run in proposal mode")

    monkeypatch.setattr("core.wraith.bola_replay.hunt", forbidden)
    report = compare_with_legacy_bola(batch, source, peer)
    assert report.candidate_equivalent is True


def test_graphql_mutation_is_never_classified_as_a_read():
    source = [_gql_record(
        "UpdateBusiness",
        SOURCE_ID,
        query="mutation UpdateBusiness($BizEncId: ID!) { updateBusiness(id: $BizEncId) { id } }",
    )]
    peer = [_gql_record(
        "UpdateBusiness",
        PEER_ID,
        query="mutation UpdateBusiness($BizEncId: ID!) { updateBusiness(id: $BizEncId) { id } }",
    )]

    batch = compile_authorization_proposals(source, peer)
    assert len(batch.proposals) == 1
    assert batch.proposals[0].risk_class == STATE_MUTATION
    assert batch.proposals[0].requires_policy_reclassification is True


def test_shared_identifier_produces_no_authorization_proposal():
    batch = compile_authorization_proposals(_capture(SOURCE_ID), _capture(SOURCE_ID))
    assert batch.proposals == ()
    assert batch.correspondences == ()
    assert batch.diagnostics["proposal_count"] == 0


def test_proposal_count_is_bounded_and_diagnostics_are_honest():
    batch = compile_authorization_proposals(
        _capture(SOURCE_ID), _capture(PEER_ID),
        limits=ProposalLimits(max_proposals=1),
    )
    assert len(batch.proposals) == 1
    assert batch.diagnostics["dropped"]["proposals"] == 2


def test_rest_path_correspondence_is_supported_without_application_semantics():
    source = [{
        "method": "GET",
        "url": f"https://api.example.test/v1/documents/{SOURCE_ID}",
        "response_status": 200,
        "response_body": '{"kind":"document"}',
    }]
    peer = [{
        "method": "GET",
        "url": f"https://api.example.test/v1/documents/{PEER_ID}",
        "response_status": 200,
        "response_body": '{"kind":"document"}',
    }]

    batch = compile_authorization_proposals(source, peer)
    assert len(batch.proposals) == 1
    proposal = batch.proposals[0]
    assert proposal.operation_label == "GET /v1/documents/{id}"
    assert proposal.risk_class == CROSS_OBJECT_READ
    assert proposal.mutations[0].location_kind == "url_path"
    assert SOURCE_ID not in json.dumps(batch.to_dict())


def test_short_numeric_rest_ids_are_not_missed():
    source = [{"method": "GET", "url": "https://api.example.test/v1/users/42"}]
    peer = [{"method": "GET", "url": "https://api.example.test/v1/users/84"}]
    batch = compile_authorization_proposals(source, peer)
    assert len(batch.proposals) == 1
    assert batch.proposals[0].operation_label == "GET /v1/users/{id}"


def test_integer_json_identifiers_produce_exact_json_pointer():
    source = [{
        "method": "POST", "url": "https://api.example.test/v1/lookup",
        "request_body": json.dumps({"accountId": 42}),
    }]
    peer = [{
        "method": "POST", "url": "https://api.example.test/v1/lookup",
        "request_body": json.dumps({"accountId": 84}),
    }]
    batch = compile_authorization_proposals(source, peer)
    assert len(batch.proposals) == 1
    assert batch.proposals[0].mutations[0].pointer == "/accountId"
