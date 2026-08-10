"""Bounded, reversible lifecycle-omission proof tests."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

import pytest

from core.behavior.receipts import BehavioralReceiptStore
from core.behavior.state_transition_proof import (
    OWNED_STATE_TRANSITION_WORKFLOW,
    StateTransitionContract,
    execute_owned_state_transition_proof,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.wraith.bola_replay import ReplayResponse

ORIGIN = "https://example.test"
COLLECTION = f"{ORIGIN}/projects"
CAROL = "c" * 32


def _envelope() -> AuthorizationEnvelope:
    envelope = AuthorizationEnvelope(
        envelope_id="e" * 32,
        researcher_identity="researcher",
        target_handle="lifecycle-lab",
        authorized_origins=[ORIGIN],
        authorization_basis="owned acceptance lab",
        disclosure_attestation=True,
        allowed_workflows=[OWNED_STATE_TRANSITION_WORKFLOW],
    )
    envelope.sign()
    return envelope


def _contract() -> StateTransitionContract:
    return StateTransitionContract(
        initial_state="draft",
        prerequisite_action="review",
        prerequisite_state="review",
        terminal_action="publish",
        terminal_state="published",
        cleanup_action="draft",
    )


class _LifecycleTransport:
    def __init__(self, *, enforce_prerequisite: bool):
        self.enforce_prerequisite = enforce_prerequisite
        self.requests = []
        self.states = {}

    def _detail(self, object_id: str) -> str:
        state = self.states[object_id]
        return (
            f'<span class="badge badge-muted">{state}</span>'
            f'<form action="/projects/{object_id}/review"></form>'
            f'<form action="/projects/{object_id}/publish"></form>'
            f'<form action="/projects/{object_id}/draft"></form>'
        )

    async def send(self, persona, request):
        assert persona == CAROL
        self.requests.append(request)
        path = urlsplit(request.url).path
        if request.method == "POST" and path == "/projects":
            object_id = f"prj-{len(self.states) + 1}"
            self.states[object_id] = "draft"
            return ReplayResponse(200, self._detail(object_id))
        parts = path.removeprefix("/projects/").split("/", 1)
        object_id = parts[0]
        action = parts[1] if len(parts) == 2 else ""
        if request.method == "GET" and action == "":
            return ReplayResponse(200, self._detail(object_id))
        if request.method != "POST":
            raise AssertionError(f"unexpected request: {request.method} {path}")
        if action == "review":
            self.states[object_id] = "review"
        elif action == "publish":
            if self.enforce_prerequisite and self.states[object_id] != "review":
                return ReplayResponse(409, "review required")
            self.states[object_id] = "published"
        elif action == "draft":
            self.states[object_id] = "draft"
        else:
            raise AssertionError(f"unexpected action: {action}")
        return ReplayResponse(200, self._detail(object_id))


def _artifact_store():
    artifacts = {}

    def store(data):
        digest = hashlib.sha256(data).hexdigest()
        artifacts[digest] = bytes(data)
        return digest

    return artifacts, store


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("enforce_prerequisite", "confirmation", "has_finding"),
    [
        (False, "confirmed_fail_open", True),
        (True, "prerequisite_enforced", False),
    ],
)
async def test_owned_state_transition_rehearses_omits_and_cleans(
    tmp_path,
    enforce_prerequisite,
    confirmation,
    has_finding,
):
    transport = _LifecycleTransport(enforce_prerequisite=enforce_prerequisite)
    artifacts, store_artifact = _artifact_store()
    receipts = BehavioralReceiptStore(tmp_path / "receipts")

    result = await execute_owned_state_transition_proof(
        collection_url=COLLECTION,
        contract=_contract(),
        envelope=_envelope(),
        persona_id=CAROL,
        transport=transport,
        store_artifact=store_artifact,
        receipt_store=receipts,
    )

    assert result.status == "completed"
    assert result.reused is False
    assert result.proof["confirmation_status"] == confirmation
    assert bool(result.proof["finding_ref"]) is has_finding
    assert result.proof["cleanup_complete"] is True
    assert result.proof["requests_sent"] == 17
    assert len(result.proof["correlation_ids"]) == 17
    assert len(result.proof["artifact_refs"]) == 17
    assert set(transport.states.values()) == {"draft"}
    assert len(transport.requests) == 17
    assert len(artifacts) > 1

    persisted = (
        tmp_path / "receipts" / f"{result.receipt_id}.json"
    ).read_text()
    assert COLLECTION not in persisted
    assert CAROL not in persisted
    assert "prj-" not in persisted
    assert "Sentinel lifecycle" not in persisted


@pytest.mark.asyncio
async def test_completed_state_transition_replays_without_target_traffic(tmp_path):
    transport = _LifecycleTransport(enforce_prerequisite=False)
    _, store_artifact = _artifact_store()
    receipts = BehavioralReceiptStore(tmp_path / "receipts")
    kwargs = {
        "collection_url": COLLECTION,
        "contract": _contract(),
        "envelope": _envelope(),
        "persona_id": CAROL,
        "transport": transport,
        "store_artifact": store_artifact,
        "receipt_store": receipts,
    }
    first = await execute_owned_state_transition_proof(**kwargs)
    request_count = len(transport.requests)
    second = await execute_owned_state_transition_proof(**kwargs)

    assert second.status == "already_executed"
    assert second.reused is True
    assert second.receipt_id == first.receipt_id
    assert second.proof == first.proof
    assert len(transport.requests) == request_count
