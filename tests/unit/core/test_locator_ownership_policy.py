"""R5A3a locator-aware ownership safety guard tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from core.cortex.execution_policy import (
    CandidateAction,
    ExecutionPolicy,
    PolicyExecutor,
)
from core.safety.action_classifier import CROSS_OBJECT_READ, SAFE_READ
from core.safety.ownership_locator import (
    LOCATOR_OWNERSHIP_MODE,
    LocatorOwnershipDenied,
    OwnedRequestLocatorKind,
)
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget


ORIGIN = "https://api.example.test"
ACTOR = "bob-owned-persona"
OWNER = "alice-owned-persona"
OBJECT_ID = "document_2222222222222222"
SOURCE_PROOF_REF = f"ownership_experiment_proof:{'a' * 64}"
SOURCE_ROLE_REF = f"ownership_experiment_role:{'b' * 64}"


def _request(kind: OwnedRequestLocatorKind, *, object_id=OBJECT_ID):
    if kind is OwnedRequestLocatorKind.PATH:
        return {
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/{object_id}",
            "body": None,
            "pointer": "/segments/2",
        }
    if kind is OwnedRequestLocatorKind.QUERY:
        return {
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/export?documentId={object_id}",
            "body": None,
            "pointer": "/documentId/0",
        }
    if kind is OwnedRequestLocatorKind.JSON:
        return {
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/lookup",
            "body": {"document": {"id": object_id}, "view": "summary"},
            "pointer": "/document/id",
        }
    if kind is OwnedRequestLocatorKind.FORM:
        return {
            "method": "GET",
            "url": f"{ORIGIN}/api/documents/lookup-form",
            "body": f"view=summary&documentId={object_id}",
            "pointer": "/documentId/0",
        }
    if kind is OwnedRequestLocatorKind.GRAPHQL_VARIABLE:
        return {
            "method": "POST",
            "url": f"{ORIGIN}/graphql",
            "body": {
                "operationName": "GetDocument",
                "query": (
                    "query GetDocument($documentId: ID!) "
                    "{ document(id: $documentId) { title } }"
                ),
                "variables": {"documentId": object_id},
            },
            "pointer": "/variables/documentId",
        }
    raise AssertionError(f"unsupported locator kind: {kind}")


def _registry(*, owner=OWNER):
    registry = OwnershipRegistry()
    registry.register_created_value(
        f"{ORIGIN}/api/documents",
        OBJECT_ID,
        actor_persona=owner,
    )
    return registry


def _proof(registry, request, kind, *, actor=ACTOR, owner=OWNER):
    return registry.issue_locator_proof(
        source_proof_ref=SOURCE_PROOF_REF,
        source_role_binding_ref=SOURCE_ROLE_REF,
        actor_persona_id=actor,
        target_owner_persona_id=owner,
        method=request["method"],
        url=request["url"],
        body=request["body"],
        locator_kind=kind,
        locator_pointer=request["pointer"],
    )


def _action(request, *, actor=ACTOR, owner=OWNER, owned=True, hint=CROSS_OBJECT_READ):
    return CandidateAction(
        method=request["method"],
        url=request["url"],
        body=request["body"],
        hint=hint,
        actor_persona_id=actor,
        target_owner_persona_id=owner,
        target_is_researcher_owned=owned,
        expected_side_effect="none",
        proof_goal="controlled object authorization",
    )


def _policy(registry=None, *, scope=True):
    return ExecutionPolicy(
        "bounty_safe",
        scope_filter=(lambda url: str(url).startswith(f"{ORIGIN}/")) if scope else None,
        budget=ProofBudget(
            max_total_requests=10,
            max_requests_per_endpoint=4,
            max_cross_object_reads=2,
            max_privilege_mutations=0,
            max_creates=0,
            allow_delete=False,
            allow_real_user_data_access=False,
        ),
        ownership_registry=registry,
    )


@pytest.mark.parametrize("kind", tuple(OwnedRequestLocatorKind))
def test_registry_issues_and_policy_verifies_every_locator_without_authority(kind):
    registry = _registry()
    request = _request(kind)
    proof = _proof(registry, request, kind)
    policy = _policy(registry)
    before = policy.budget.snapshot()

    verification = policy.verify_locator_ownership(_action(request), proof)

    assert verification.verified is True
    assert verification.reason == "locator_ownership_verified"
    assert verification.proof_ref == proof.proof_ref
    assert verification.mode == LOCATOR_OWNERSHIP_MODE
    assert verification.target_requests_sent == 0
    assert verification.budget_consumed is False
    assert verification.execution_authority is False
    assert policy.budget.snapshot() == before
    assert proof.target_requests_sent == 0
    assert proof.budget_consumed is False
    assert proof.backend_dispatch_authority is False
    assert proof.executable is False


@pytest.mark.parametrize("kind", tuple(OwnedRequestLocatorKind))
def test_public_proof_is_opaque_and_never_exports_the_registry_seal(kind):
    registry = _registry()
    request = _request(kind)
    proof = _proof(registry, request, kind)
    serialized = json.dumps(proof.to_dict(), sort_keys=True)

    for raw_value in (
        ORIGIN,
        ACTOR,
        OWNER,
        OBJECT_ID,
        "GetDocument",
        "view=summary",
    ):
        assert raw_value not in serialized
    assert proof.locator_pointer in serialized
    assert proof._seal not in serialized
    assert "_seal" not in serialized


def test_query_duplicate_occurrence_is_exact_and_order_bound():
    registry = _registry()
    request = {
        "method": "GET",
        "url": (
            f"{ORIGIN}/api/documents/export?documentId=decoy&documentId={OBJECT_ID}"
        ),
        "body": None,
        "pointer": "/documentId/1",
    }
    proof = _proof(registry, request, OwnedRequestLocatorKind.QUERY)
    assert registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    ).verified

    reordered = f"{ORIGIN}/api/documents/export?documentId={OBJECT_ID}&documentId=decoy"
    verification = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=reordered,
        body=request["body"],
    )
    assert verification.verified is False


def test_graphql_requires_protocol_evidence_beyond_a_variables_field():
    registry = _registry()
    ordinary_json = {
        "method": "POST",
        "url": f"{ORIGIN}/api/documents/lookup",
        "body": {"variables": {"documentId": OBJECT_ID}},
        "pointer": "/variables/documentId",
    }

    with pytest.raises(
        LocatorOwnershipDenied,
        match="graphql_protocol_is_unproven",
    ):
        _proof(registry, ordinary_json, OwnedRequestLocatorKind.GRAPHQL_VARIABLE)

    proof = _proof(registry, ordinary_json, OwnedRequestLocatorKind.JSON)
    assert proof.locator_kind is OwnedRequestLocatorKind.JSON


def test_graphql_batch_variable_is_supported_at_the_exact_index():
    registry = _registry()
    request = {
        "method": "POST",
        "url": f"{ORIGIN}/graphql",
        "body": [
            {
                "operationName": "OtherQuery",
                "variables": {"documentId": "decoy"},
            },
            {
                "operationName": "GetDocument",
                "variables": {"documentId": OBJECT_ID},
            },
        ],
        "pointer": "/1/variables/documentId",
    }

    proof = _proof(registry, request, OwnedRequestLocatorKind.GRAPHQL_VARIABLE)

    assert proof.locator_pointer == "/1/variables/documentId"
    assert registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    ).verified


@pytest.mark.parametrize("kind", tuple(OwnedRequestLocatorKind))
def test_proof_cannot_be_reused_after_object_request_or_locator_drift(kind):
    registry = _registry()
    request = _request(kind)
    proof = _proof(registry, request, kind)

    changed = _request(kind, object_id="document_3333333333333333")
    verification = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=changed["method"],
        url=changed["url"],
        body=changed["body"],
    )

    assert verification.verified is False
    assert verification.execution_authority is False


def test_exact_proof_can_be_rechecked_but_is_never_consumed_or_executable():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.JSON)
    proof = _proof(registry, request, OwnedRequestLocatorKind.JSON)

    first = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )
    second = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )

    assert first.to_dict() == second.to_dict()
    assert first.verified is True
    assert first.execution_authority is False


def test_request_fingerprint_binds_method_url_and_unrelated_body_material():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.JSON)
    proof = _proof(registry, request, OwnedRequestLocatorKind.JSON)

    variations = (
        {**request, "method": "HEAD"},
        {**request, "url": f"{request['url']}?format=full"},
        {
            **request,
            "body": {"document": {"id": OBJECT_ID}, "view": "full"},
        },
    )
    for changed in variations:
        result = registry.verify_locator_proof(
            proof,
            actor_persona_id=ACTOR,
            target_owner_persona_id=OWNER,
            method=changed["method"],
            url=changed["url"],
            body=changed["body"],
        )
        assert result.verified is False


def test_mapping_key_order_is_canonical_not_false_drift():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.JSON)
    proof = _proof(registry, request, OwnedRequestLocatorKind.JSON)
    reordered_body = {
        "view": "summary",
        "document": {"id": OBJECT_ID},
    }

    verification = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=reordered_body,
    )

    assert verification.verified is True


def test_actor_owner_and_registry_identity_are_all_bound():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.QUERY)
    proof = _proof(registry, request, OwnedRequestLocatorKind.QUERY)

    wrong_actor = registry.verify_locator_proof(
        proof,
        actor_persona_id="different-actor",
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )
    wrong_owner = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id="different-owner",
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )
    other_registry = _registry().verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )

    assert wrong_actor.verified is False
    assert wrong_owner.verified is False
    assert other_registry.reason == "locator_ownership_registry_mismatch"


def test_ambiguous_same_id_across_owned_collections_fails_closed():
    registry = _registry()
    registry.register_created_value(
        f"{ORIGIN}/api/archives",
        OBJECT_ID,
        actor_persona=OWNER,
    )
    request = _request(OwnedRequestLocatorKind.QUERY)

    with pytest.raises(
        LocatorOwnershipDenied,
        match="missing_or_ambiguous",
    ):
        _proof(registry, request, OwnedRequestLocatorKind.QUERY)


def test_proof_becomes_invalid_if_registry_later_becomes_ambiguous():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.FORM)
    proof = _proof(registry, request, OwnedRequestLocatorKind.FORM)
    registry.register_created_value(
        f"{ORIGIN}/api/archives",
        OBJECT_ID,
        actor_persona=OWNER,
    )

    verification = registry.verify_locator_proof(
        proof,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )

    assert verification.verified is False
    assert verification.reason == "locator_owned_object_is_missing_or_ambiguous"


def test_invalid_source_refs_and_same_persona_pair_cannot_be_sealed():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.PATH)
    with pytest.raises(
        LocatorOwnershipDenied,
        match="source_contract_is_invalid",
    ):
        registry.issue_locator_proof(
            source_proof_ref="caller-assertion",
            source_role_binding_ref=SOURCE_ROLE_REF,
            actor_persona_id=ACTOR,
            target_owner_persona_id=OWNER,
            method=request["method"],
            url=request["url"],
            body=request["body"],
            locator_kind=OwnedRequestLocatorKind.PATH,
            locator_pointer=request["pointer"],
        )
    with pytest.raises(
        LocatorOwnershipDenied,
        match="distinct_actor_and_owner",
    ):
        _proof(registry, request, OwnedRequestLocatorKind.PATH, actor=OWNER)


def test_private_seal_tampering_is_detected_even_when_public_shape_is_unchanged():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.QUERY)
    proof = _proof(registry, request, OwnedRequestLocatorKind.QUERY)
    forged = replace(proof, _seal="0" * 64)

    verification = registry.verify_locator_proof(
        forged,
        actor_persona_id=ACTOR,
        target_owner_persona_id=OWNER,
        method=request["method"],
        url=request["url"],
        body=request["body"],
    )

    assert verification.verified is False
    assert verification.reason == "locator_ownership_request_or_proof_mismatch"


@pytest.mark.parametrize(
    ("action_change", "reason"),
    (
        ({"hint": SAFE_READ}, "locator_ownership_requires_cross_object_read"),
        ({"owned": False}, "locator_ownership_intent_is_missing"),
        ({"actor": OWNER}, "locator_ownership_actor_or_owner_mismatch"),
    ),
)
def test_policy_guard_rejects_wrong_action_semantics(action_change, reason):
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.JSON)
    proof = _proof(registry, request, OwnedRequestLocatorKind.JSON)
    action = _action(request, **action_change)

    verification = _policy(registry).verify_locator_ownership(action, proof)

    assert verification.verified is False
    assert verification.reason == reason


def test_policy_guard_requires_scope_and_registry_without_mutating_budget():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.QUERY)
    proof = _proof(registry, request, OwnedRequestLocatorKind.QUERY)
    action = _action(request)
    out_of_scope = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: False,
        ownership_registry=registry,
    )
    missing_scope = ExecutionPolicy(
        "bounty_safe",
        ownership_registry=registry,
    )
    no_registry = _policy(None)
    before = no_registry.budget.snapshot()

    assert (
        out_of_scope.verify_locator_ownership(action, proof).reason
        == "locator_ownership_action_is_out_of_scope"
    )
    assert (
        missing_scope.verify_locator_ownership(action, proof).reason
        == "locator_ownership_scope_filter_is_unavailable"
    )
    assert (
        no_registry.verify_locator_ownership(action, proof).reason
        == "locator_ownership_registry_is_unavailable"
    )
    assert no_registry.budget.snapshot() == before


def test_policy_guard_requires_bounty_safe_owned_data_only_mode():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.QUERY)
    proof = _proof(registry, request, OwnedRequestLocatorKind.QUERY)
    action = _action(request)
    lab_policy = ExecutionPolicy(
        "lab",
        scope_filter=lambda url: True,
        ownership_registry=registry,
    )
    permissive_budget = ProofBudget(
        max_total_requests=10,
        max_requests_per_endpoint=4,
        max_cross_object_reads=2,
        max_privilege_mutations=0,
        max_creates=0,
        allow_delete=False,
        allow_real_user_data_access=True,
    )
    permissive_policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: True,
        budget=permissive_budget,
        ownership_registry=registry,
    )

    assert (
        lab_policy.verify_locator_ownership(action, proof).reason
        == "locator_ownership_requires_bounty_safe_policy"
    )
    assert (
        permissive_policy.verify_locator_ownership(action, proof).reason
        == "locator_ownership_requires_owned_data_only_policy"
    )


@pytest.mark.asyncio
async def test_verified_generalized_proof_does_not_expand_policy_or_transport_authority():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.QUERY)
    proof = _proof(registry, request, OwnedRequestLocatorKind.QUERY)
    policy = _policy(registry)
    action = _action(request)
    calls = []

    async def raw_send(*args, **kwargs):
        calls.append((args, kwargs))
        return 200, {"unexpected": True}

    assert policy.verify_locator_ownership(action, proof).verified is True
    decision = policy.evaluate_action(action)
    assert decision.allowed is False
    assert decision.reason == "cross_object_read_target_not_proven_researcher_created"

    status, response = await PolicyExecutor(raw_send, policy).send_action(action)
    assert status == 0
    assert response == {
        "_policy_denied": "cross_object_read_target_not_proven_researcher_created"
    }
    assert calls == []
    assert "locator_ownership_proof" not in CandidateAction.__dataclass_fields__


def test_legacy_url_ownership_gate_remains_compatible():
    registry = _registry()
    request = _request(OwnedRequestLocatorKind.PATH)
    decision = _policy(registry).evaluate_action(_action(request))

    assert decision.allowed is True
    assert decision.reason == "ok"
