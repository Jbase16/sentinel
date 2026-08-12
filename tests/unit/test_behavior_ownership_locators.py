"""Passive generalized ownership locator evidence tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

import core.behavior as behavior_package
from core.behavior.ownership_locators import (
    GENERALIZED_OWNERSHIP_MODE,
    GeneralizedOwnershipLocatorCompiler,
    OwnershipLocatorKind,
    OwnershipProtocol,
)


ORIGIN = "https://api.example.test"
OBJECT_ID = "document_4f8a0d3e9c1b7a62"


def _create(*, persona_id: str = "alice", url: str = f"{ORIGIN}/api/documents"):
    return {
        "id": "create-document",
        "persona_id": persona_id,
        "method": "POST",
        "url": url,
        "request_body": json.dumps({"title": "controlled ownership marker"}),
        "response_status": 201,
        "response_body": json.dumps({"documentId": OBJECT_ID}),
    }


def _uses(*, persona_id: str = "alice"):
    return (
        {
            "id": "path-use",
            "persona_id": persona_id,
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{OBJECT_ID}",
            "response_status": 200,
            "response_body": json.dumps({"ok": True}),
        },
        {
            "id": "query-use",
            "persona_id": persona_id,
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/export?documentId={OBJECT_ID}",
            "response_status": 200,
            "response_body": json.dumps({"ok": True}),
        },
        {
            "id": "json-use",
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/api/documents/lookup",
            "request_body": json.dumps({"documentId": OBJECT_ID}),
            "response_status": 200,
            "response_body": json.dumps({"ok": True}),
        },
        {
            "id": "form-use",
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/api/documents/lookup-form",
            "request_headers": {
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
            },
            "request_body": f"documentId={OBJECT_ID}",
            "response_status": 200,
            "response_body": json.dumps({"ok": True}),
        },
        {
            "id": "graphql-use",
            "persona_id": persona_id,
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "request_body": json.dumps(
                {
                    "operationName": "DocumentLookup",
                    "variables": {"documentId": OBJECT_ID},
                }
            ),
            "response_status": 200,
            "response_body": json.dumps({"data": {"document": {"ok": True}}}),
        },
    )


def _records():
    return (_create(), *_uses())


def test_compiler_proves_all_generalized_locator_families_without_authority():
    result = GeneralizedOwnershipLocatorCompiler().compile(_records())

    assert result.status == "ready"
    assert result.mode == GENERALIZED_OWNERSHIP_MODE
    assert result.executable is False
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.executable is False
    assert evidence.capability_key == "value:document_id"
    assert evidence.create_response_locator.pointer == "/documentId"
    assert {item.locator_kind for item in evidence.uses} == {
        OwnershipLocatorKind.PATH,
        OwnershipLocatorKind.QUERY,
        OwnershipLocatorKind.JSON,
        OwnershipLocatorKind.FORM,
        OwnershipLocatorKind.GRAPHQL_VARIABLE,
    }
    assert {
        item.protocol
        for item in evidence.uses
        if item.locator_kind is OwnershipLocatorKind.GRAPHQL_VARIABLE
    } == {OwnershipProtocol.GRAPHQL}
    assert result.diagnostics.accepted_bindings == 5
    assert result.diagnostics.path_bindings == 1
    assert result.diagnostics.query_bindings == 1
    assert result.diagnostics.json_bindings == 1
    assert result.diagnostics.form_bindings == 1
    assert result.diagnostics.graphql_variable_bindings == 1
    for use in evidence.uses:
        assert result.evidence_for_binding(use.lineage_binding_id) == evidence


def test_public_evidence_is_redacted_and_deterministic():
    first = GeneralizedOwnershipLocatorCompiler().compile(_records())
    second = GeneralizedOwnershipLocatorCompiler().compile(_records())
    serialized = json.dumps(first.to_dict(), sort_keys=True)

    assert first.to_dict() == second.to_dict()
    for raw_value in (
        ORIGIN,
        OBJECT_ID,
        "controlled ownership marker",
        "alice",
    ):
        assert raw_value not in serialized
    assert "/variables/documentId" in serialized


def test_graphql_requires_protocol_evidence_not_a_variables_field_name_alone():
    records = (
        _create(),
        {
            "id": "ordinary-json-use",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/api/documents/lookup",
            "request_body": json.dumps({"variables": {"documentId": OBJECT_ID}}),
            "response_status": 200,
            "response_body": json.dumps({"ok": True}),
        },
    )

    result = GeneralizedOwnershipLocatorCompiler().compile(records)

    assert result.evidence[0].uses[0].locator_kind is OwnershipLocatorKind.JSON
    assert result.evidence[0].uses[0].protocol is OwnershipProtocol.HTTP


def test_graphql_batch_variable_is_classified_explicitly():
    records = (
        _create(),
        {
            "id": "graphql-batch-use",
            "persona_id": "alice",
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "request_body": json.dumps(
                [
                    {
                        "operationName": "DocumentLookup",
                        "variables": {"documentId": OBJECT_ID},
                    }
                ]
            ),
            "response_status": 200,
            "response_body": json.dumps([{"data": {"document": {"ok": True}}}]),
        },
    )

    result = GeneralizedOwnershipLocatorCompiler().compile(records)

    use = result.evidence[0].uses[0]
    assert use.locator_kind is OwnershipLocatorKind.GRAPHQL_VARIABLE
    assert use.locator_pointer == "/0/variables/documentId"


def test_cross_world_value_never_becomes_ownership_evidence():
    result = GeneralizedOwnershipLocatorCompiler().compile(
        (_create(persona_id="alice"), *_uses(persona_id="bob"))
    )

    assert result.status == "no_proven_ownership"
    assert result.evidence == ()
    assert result.diagnostics.exact_bindings == 0


@pytest.mark.parametrize(
    "create_record",
    [
        _create(url=f"{ORIGIN}/api/payments"),
        {
            **_create(),
            "request_body": json.dumps({"title": "controlled", "role": "admin"}),
        },
        {**_create(), "method": "PUT"},
    ],
)
def test_unsafe_or_non_create_producer_fails_closed(create_record):
    result = GeneralizedOwnershipLocatorCompiler().compile((create_record, _uses()[0]))

    assert result.status == "no_proven_ownership"
    assert result.diagnostics.unsafe_create_bindings == 1


def test_failed_owner_use_is_not_accepted_as_object_semantics():
    failed_use = {**_uses()[0], "response_status": 403}

    result = GeneralizedOwnershipLocatorCompiler().compile((_create(), failed_use))

    assert result.status == "no_proven_ownership"
    assert result.diagnostics.unsuccessful_use_bindings == 1


def test_sensitive_capability_is_never_promoted_to_object_ownership():
    token = "secret_download_token_123456"
    records = (
        {
            **_create(),
            "response_body": json.dumps({"downloadToken": token}),
        },
        {
            **_uses()[1],
            "url": f"{ORIGIN}/api/download?downloadToken={token}",
        },
    )

    result = GeneralizedOwnershipLocatorCompiler().compile(records)

    assert result.status == "no_proven_ownership"
    assert result.diagnostics.sensitive_bindings == 1
    assert token not in json.dumps(result.to_dict(), sort_keys=True)


def test_duplicate_producers_are_ambiguous_and_not_selected_arbitrarily():
    records = (
        _create(),
        {**_create(), "id": "create-document-again"},
        _uses()[0],
    )

    result = GeneralizedOwnershipLocatorCompiler().compile(records)

    assert result.status == "no_proven_ownership"
    assert result.evidence == ()
    assert result.diagnostics.ambiguous_consumers == 1


def test_caller_ownership_assertions_cannot_replace_creation_evidence():
    asserted_use = {
        **_uses()[0],
        "target_is_researcher_owned": True,
        "target_owner_persona_id": "alice",
    }

    result = GeneralizedOwnershipLocatorCompiler().compile((asserted_use,))

    assert result.status == "no_proven_ownership"
    assert result.evidence == ()


def test_content_addressed_contracts_reject_tampering():
    result = GeneralizedOwnershipLocatorCompiler().compile(_records())
    evidence = result.evidence[0]
    use = evidence.uses[0]

    with pytest.raises(ValueError, match="ownership use evidence"):
        replace(use, method="DELETE")
    with pytest.raises(ValueError, match="generalized ownership evidence"):
        replace(evidence, uses=tuple(reversed(evidence.uses)))


def test_compiler_rejects_non_record_sequences_and_stays_explicit_only():
    with pytest.raises(TypeError, match="sequence of mappings"):
        GeneralizedOwnershipLocatorCompiler().compile("not records")

    assert not hasattr(behavior_package, "GeneralizedOwnershipLocatorCompiler")
