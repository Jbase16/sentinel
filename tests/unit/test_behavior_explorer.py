"""Closed-loop paired read exploration tests with in-memory transports."""

from __future__ import annotations

import json

import pytest

from core.behavior.explorer import BehavioralReadExplorer, ReadExplorationLimits
from core.behavior.proposals import compile_authorization_proposals
from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.safety.provenance import ProvenanceSink

ORIGIN = "https://api.example.test"
SOURCE_PERSONA = "source"
PEER_PERSONA = "peer"
SOURCE_ID = "RlLB9Tjpk7YfkTaBB0SpzA"
PEER_ID = "9QsBs4y23m6HH4aB38ffkA"


def _root(persona_id: str, body: str):
    return {
        "persona_id": persona_id,
        "method": "GET",
        "url": f"{ORIGIN}/start",
        "response_status": 200,
        "response_body": body,
    }


def _executors(responses):
    calls = []
    policy = ExecutionPolicy(
        "bounty_safe",
        scope_filter=lambda url: url.startswith(ORIGIN),
    )
    provenance = ProvenanceSink()

    def make(persona_id):
        async def raw_send(method, url, body=None, **kwargs):
            calls.append((persona_id, method, url, body, kwargs))
            return responses[persona_id][url]

        return PolicyExecutor(raw_send, policy, provenance=provenance)

    return {
        SOURCE_PERSONA: make(SOURCE_PERSONA),
        PEER_PERSONA: make(PEER_PERSONA),
    }, calls, provenance


@pytest.mark.asyncio
async def test_explorer_discovers_owned_links_and_stops_on_first_proposal():
    source_url = f"{ORIGIN}/api/documents/{SOURCE_ID}"
    peer_url = f"{ORIGIN}/api/documents/{PEER_ID}"
    common_urls = [f"{ORIGIN}/common/section-{index}" for index in range(8)]
    common_links = "".join(f'<a href="{url}">common</a>' for url in common_urls)
    source = [
        _root(
            SOURCE_PERSONA,
            common_links + f'<a href="{source_url}">Owned document</a>',
        )
    ]
    peer = [
        _root(
            PEER_PERSONA,
            json.dumps({"common": common_urls, "owned_url": peer_url}),
        )
    ]
    executors, calls, provenance = _executors({
        SOURCE_PERSONA: {source_url: (200, '{"owner":"source"}')},
        PEER_PERSONA: {peer_url: (200, '{"owner":"peer"}')},
    })
    explorer = BehavioralReadExplorer(
        target_origin=ORIGIN,
        source_persona_id=SOURCE_PERSONA,
        peer_persona_id=PEER_PERSONA,
        executors=executors,
    )

    def has_proposal(source_records, peer_records):
        return bool(
            compile_authorization_proposals(
                source_records,
                peer_records,
                source_world=SOURCE_PERSONA,
                peer_world=PEER_PERSONA,
            ).proposals
        )

    result = await explorer.explore(source, peer, stop_when=has_proposal)

    assert [(call[0], call[2]) for call in calls] == [
        (SOURCE_PERSONA, source_url),
        (PEER_PERSONA, peer_url),
    ]
    assert result.diagnostics == {
        "pairs_attempted": 1,
        "pairs_completed": 1,
        "requests_attempted": 2,
        "requests_sent": 2,
        "successful_responses": 2,
        "policy_denials": 0,
        "failed_requests": 0,
        "candidates_discovered": 18,
        "selected_after_pair": 1,
        "frontier_exhausted": False,
    }
    assert len(result.source_records) == len(result.peer_records) == 2
    assert provenance.verify()


@pytest.mark.asyncio
async def test_explorer_rejects_stateful_static_and_out_of_scope_references():
    source_url = f"{ORIGIN}/api/documents/{SOURCE_ID}"
    peer_url = f"{ORIGIN}/api/documents/{PEER_ID}"
    unsafe = (
        '<a href="/logout">logout</a>'
        '<a href="https://api.example.test\\@outside.example/private">authority confusion</a>'
        '<a href="/api/%2564elete/account">double encoded delete</a>'
        '<a href="/assets/app.js">asset</a>'
        '<a href="https://outside.example/private">outside</a>'
    )
    source = [_root(SOURCE_PERSONA, unsafe + f'<a href="{source_url}">safe</a>')]
    peer = [_root(PEER_PERSONA, unsafe + f'<a href="{peer_url}">safe</a>')]
    executors, calls, _ = _executors({
        SOURCE_PERSONA: {source_url: (200, "source")},
        PEER_PERSONA: {peer_url: (200, "peer")},
    })
    explorer = BehavioralReadExplorer(
        target_origin=ORIGIN,
        source_persona_id=SOURCE_PERSONA,
        peer_persona_id=PEER_PERSONA,
        executors=executors,
        limits=ReadExplorationLimits(max_pairs=1),
    )

    result = await explorer.explore(source, peer, stop_when=lambda *_args: False)

    assert [call[2] for call in calls] == [source_url, peer_url]
    assert result.diagnostics["pairs_attempted"] == 1
    assert result.diagnostics["policy_denials"] == 0


@pytest.mark.asyncio
async def test_explorer_requires_a_structurally_shared_world_frontier():
    source = [_root(SOURCE_PERSONA, '<a href="/api/documents/12345">document</a>')]
    peer = [_root(PEER_PERSONA, '<a href="/settings/profile">settings</a>')]
    executors, calls, _ = _executors({SOURCE_PERSONA: {}, PEER_PERSONA: {}})
    explorer = BehavioralReadExplorer(
        target_origin=ORIGIN,
        source_persona_id=SOURCE_PERSONA,
        peer_persona_id=PEER_PERSONA,
        executors=executors,
    )

    result = await explorer.explore(source, peer, stop_when=lambda *_args: False)

    assert calls == []
    assert result.diagnostics["frontier_exhausted"] is True
    assert result.diagnostics["requests_attempted"] == 0
