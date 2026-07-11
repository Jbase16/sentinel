"""Gate C controlled-execution tests. All transports are in-memory fakes."""

from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

from core.behavior.active import (
    CONTROLLED_WORKFLOW,
    ControlledAuthorizationExecutor,
    ControlledExecutionDenied,
)
import core.behavior.active as active_module
from core.behavior.proposals import compile_authorization_proposals
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import ResearchPersona
from core.safety.proof_budget import ProofBudget
from core.safety.provenance import ProvenanceSink

SOURCE_ID = "RlLB9Tjpk7YfkTaBB0SpzA"
PEER_ID = "9QsBs4y23m6HH4aB38ffkA"
ORIGIN = "https://api.example.test"


def _persona(persona_id: str) -> ResearchPersona:
    return ResearchPersona(
        persona_id=persona_id,
        label=persona_id,
        email=f"{persona_id}@research.example",
    )


def _record(operation: str, resource_id: str, *, query: str | None = None):
    csrf_token = "csrf-source-session" if resource_id == SOURCE_ID else "csrf-peer-session"
    item = {"operationName": operation, "variables": {"BizEncId": resource_id}}
    if query:
        item["query"] = query
    return {
        "method": "POST",
        "url": f"{ORIGIN}/gql/batch",
        "request_headers": {
            "content-type": "application/json",
            "x-csrf-token": csrf_token,
        },
        "request_body": json.dumps([item]),
    }


def _envelope(*, workflow: str = CONTROLLED_WORKFLOW) -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="gate-c-test",
        researcher_identity="researcher",
        target_handle="example",
        authorized_origins=[ORIGIN],
        authorization_basis="public bug bounty authorization",
        disclosure_attestation=True,
        allowed_workflows=[workflow],
        created_at=time.time() - 10,
        expires_at=time.time() + 3600,
    )
    envelope.sign()
    return envelope


class _Target:
    def __init__(self, *, baseline_status: int = 200) -> None:
        self.calls = []
        self.baseline_status = baseline_status

    async def send(self, persona: str, method: str, url: str, body=None, **kwargs):
        self.calls.append((persona, method, url, body, kwargs))
        if self.baseline_status != 200 and len(self.calls) == 1:
            return self.baseline_status, {"error": "stale session"}
        text = body or ""
        if persona == "peer":
            return 200, {"ownerName": "PeerPrivateMarker", "id": PEER_ID}
        if SOURCE_ID in text and PEER_ID not in text:
            return 200, {"ownerName": "SourcePrivateMarker", "id": SOURCE_ID}
        return 200, {"ownerName": "PeerPrivateMarker", "id": PEER_ID}


def _executor_pair(target: _Target, *, budget: ProofBudget | None = None):
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
        budget=budget,
    )
    sink = ProvenanceSink()

    def executor(persona: str):
        async def raw(method, url, body=None, **kwargs):
            return await target.send(persona, method, url, body, **kwargs)

        return PolicyExecutor(raw, policy, provenance=sink)

    return {"source": executor("source"), "peer": executor("peer")}, sink


def _fixture(operation: str = "GetPrivateObject", *, query: str | None = None):
    if query is None:
        query = (
            "query GetPrivateObject($BizEncId: ID!) "
            "{ privateObject(id: $BizEncId) { id } }"
        )
    source = [_record(operation, SOURCE_ID, query=query)]
    peer = [_record(operation, PEER_ID, query=query)]
    source_persona = _persona("source")
    peer_persona = _persona("peer")
    batch = compile_authorization_proposals(
        source,
        peer,
        source_world=source_persona.persona_id,
        peer_world=peer_persona.persona_id,
    )
    return source, peer, source_persona, peer_persona, batch


def test_gate_c_has_no_direct_network_client_or_raw_send_bypass():
    tree = ast.parse(Path(active_module.__file__).read_text())
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots & {"httpx", "requests", "socket", "urllib3", "websockets"}
    assert not any(
        isinstance(node, ast.Attribute) and node.attr == "raw_send"
        for node in ast.walk(tree)
    )


@pytest.mark.asyncio
async def test_controlled_execution_uses_policy_for_three_legs_and_legacy_verdict():
    source, peer, source_persona, peer_persona, batch = _fixture()
    target = _Target()
    executors, sink = _executor_pair(target)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )

    result = await gate.execute(batch.proposals[0], source, peer)

    assert result.status == "completed"
    assert result.legacy_verdict.verdict == "BOLA_CONFIRMED"
    assert result.finding is result.legacy_verdict.finding
    assert result.requests_attempted == result.requests_sent == 3
    assert len(target.calls) == 3
    assert target.calls[0][4]["headers"]["x-csrf-token"] == "csrf-peer-session"
    assert target.calls[1][4]["headers"]["x-csrf-token"] == "csrf-source-session"
    assert target.calls[2][4]["headers"]["x-csrf-token"] == "csrf-source-session"
    assert executors["source"].policy.budget.snapshot()["cross_object_reads"] == 1
    assert len(sink.action_blocks) == 3
    assert sink.verify()


@pytest.mark.asyncio
async def test_controlled_execution_supports_generic_rest_resource_urls():
    source = [{"method": "GET", "url": f"{ORIGIN}/v1/documents/{SOURCE_ID}"}]
    peer = [{"method": "GET", "url": f"{ORIGIN}/v1/documents/{PEER_ID}"}]
    source_persona = _persona("source")
    peer_persona = _persona("peer")
    batch = compile_authorization_proposals(
        source,
        peer,
        source_world=source_persona.persona_id,
        peer_world=peer_persona.persona_id,
    )
    calls = []

    async def respond(persona, method, url, body=None, **kwargs):
        calls.append((persona, method, url, body, kwargs))
        if persona == "peer" or PEER_ID in url:
            return 200, {"ownerName": "PeerPrivateMarker", "id": PEER_ID}
        return 200, {"ownerName": "SourcePrivateMarker", "id": SOURCE_ID}

    policy = ExecutionPolicy("bounty_safe", scope_filter=lambda url: url.startswith(ORIGIN))
    sink = ProvenanceSink()

    def make_executor(persona):
        async def raw(method, url, body=None, **kwargs):
            return await respond(persona, method, url, body, **kwargs)

        return PolicyExecutor(raw, policy, provenance=sink)

    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors={"source": make_executor("source"), "peer": make_executor("peer")},
    )

    result = await gate.execute(batch.proposals[0], source, peer)

    assert result.legacy_verdict.verdict == "BOLA_CONFIRMED"
    assert len(calls) == 3
    assert calls[2][2].endswith(PEER_ID)


@pytest.mark.asyncio
async def test_unsigned_or_unpermitted_envelope_denies_before_transport():
    source, peer, source_persona, peer_persona, batch = _fixture()
    target = _Target()
    executors, _ = _executor_pair(target)
    envelope = _envelope(workflow="different_workflow")
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=envelope,
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )

    with pytest.raises(ControlledExecutionDenied, match="authorization_envelope_denied"):
        await gate.execute(batch.proposals[0], source, peer)
    assert target.calls == []


@pytest.mark.asyncio
async def test_write_class_proposal_denies_before_transport():
    source, peer, source_persona, peer_persona, batch = _fixture(
        "UpdatePrivateObject",
        query="mutation UpdatePrivateObject($BizEncId: ID!) { update(id: $BizEncId) { id } }",
    )
    target = _Target()
    executors, _ = _executor_pair(target)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )

    with pytest.raises(ControlledExecutionDenied, match="only_cross_object_read"):
        await gate.execute(batch.proposals[0], source, peer)
    assert target.calls == []


@pytest.mark.asyncio
async def test_persisted_graphql_operation_without_query_is_not_assumed_safe():
    source = [_record("GetPrivateObject", SOURCE_ID)]
    peer = [_record("GetPrivateObject", PEER_ID)]
    source_persona = _persona("source")
    peer_persona = _persona("peer")
    batch = compile_authorization_proposals(
        source,
        peer,
        source_world=source_persona.persona_id,
        peer_world=peer_persona.persona_id,
    )
    target = _Target()
    executors, _ = _executor_pair(target)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )

    with pytest.raises(ControlledExecutionDenied, match="requires_captured_query_document"):
        await gate.execute(batch.proposals[0], source, peer)
    assert target.calls == []


@pytest.mark.asyncio
async def test_stale_capture_rejects_proposal_before_transport():
    source, peer, source_persona, peer_persona, batch = _fixture()
    target = _Target()
    executors, _ = _executor_pair(target)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )
    changed_source = [_record("GetDifferentObject", SOURCE_ID)]

    with pytest.raises(ControlledExecutionDenied, match="does_not_match_current_captures"):
        await gate.execute(batch.proposals[0], changed_source, peer)
    assert target.calls == []


@pytest.mark.asyncio
async def test_failed_peer_baseline_aborts_before_counterfactual():
    source, peer, source_persona, peer_persona, batch = _fixture()
    target = _Target(baseline_status=401)
    executors, sink = _executor_pair(target)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )

    result = await gate.execute(batch.proposals[0], source, peer)

    assert result.status == "aborted"
    assert result.legacy_verdict.verdict == "ERROR"
    assert result.legacy_verdict.detail == "baseline_session_is_not_usable"
    assert len(target.calls) == 1
    assert len(sink.action_blocks) == 1


@pytest.mark.asyncio
async def test_policy_denial_of_counterfactual_never_reaches_raw_transport():
    source, peer, source_persona, peer_persona, batch = _fixture()
    target = _Target()
    budget = ProofBudget(
        max_total_requests=3,
        max_requests_per_endpoint=3,
        max_cross_object_reads=0,
        allow_delete=False,
        allow_real_user_data_access=False,
    )
    executors, sink = _executor_pair(target, budget=budget)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )

    result = await gate.execute(batch.proposals[0], source, peer)

    assert result.legacy_verdict.verdict == "DENIED"
    assert result.requests_attempted == 3
    assert result.requests_sent == 2
    assert len(target.calls) == 2
    assert result.policy_denials == 1
    assert len(sink.action_blocks) == 3


@pytest.mark.asyncio
async def test_controlled_executor_is_single_use():
    source, peer, source_persona, peer_persona, batch = _fixture()
    target = _Target()
    executors, _ = _executor_pair(target)
    gate = ControlledAuthorizationExecutor(
        target_origin=ORIGIN,
        authorization=_envelope(),
        source_persona=source_persona,
        peer_persona=peer_persona,
        executors=executors,
    )
    await gate.execute(batch.proposals[0], source, peer)

    with pytest.raises(ControlledExecutionDenied, match="already_consumed"):
        await gate.execute(batch.proposals[0], source, peer)
    assert len(target.calls) == 3
