"""Single-persona owned proof and restart-safe receipt tests."""

from __future__ import annotations

import hashlib

import pytest

from core.behavior.interaction_boundary import (
    INTERACTION_ACQUISITION_WORKFLOW,
    InteractionAcquisitionConfig,
)
from core.behavior.owned_read_proof import (
    OWNED_READ_PROOF_WORKFLOW,
    execute_owned_read_proof,
)
from core.behavior.receipts import BehavioralReceiptStore
from core.foundry.authorization import AuthorizationEnvelope
from core.wraith.bola_replay import ReplayResponse

ORIGIN = "https://example.test"
PAGE = f"{ORIGIN}/documents/doc-owned-1"
PROOF = f"{PAGE}/export"
ALICE = "a" * 32


def _control():
    return {
        "tag": "a",
        "role": "link",
        "input_type": "",
        "form_method": "none",
        "destination": "same_origin",
        "locator": [
            {"tag": "html", "sibling_index": 1},
            {"tag": "body", "sibling_index": 1},
            {"tag": "a", "sibling_index": 1},
        ],
        "locator_truncated": False,
        "visible": True,
        "disabled": False,
        "content_editable": False,
        "aria_expanded": False,
        "aria_haspopup": False,
        "sensitive_form": False,
        "download": False,
        "scripted_handler": False,
        "submitter": False,
    }


def _envelope():
    envelope = AuthorizationEnvelope(
        envelope_id="c" * 32,
        researcher_identity="researcher",
        target_handle="owned-lab",
        authorized_origins=[ORIGIN],
        authorization_basis="owned acceptance lab",
        disclosure_attestation=True,
        allowed_workflows=[
            INTERACTION_ACQUISITION_WORKFLOW,
            OWNED_READ_PROOF_WORKFLOW,
        ],
    )
    envelope.sign()
    return envelope


class _Transport:
    def __init__(self):
        self.requests = []

    async def send(self, persona, request):
        self.requests.append((persona, request))
        return ReplayResponse(
            200,
            "<html>private owned export evidence</html>",
            {"X-Lab-Correlation-Id": "lab:owned-proof-1"},
        )


@pytest.mark.asyncio
async def test_owned_read_proof_sends_once_then_replays_without_browser(tmp_path):
    controls = (_control(),)
    snapshot_calls = []
    resolver_calls = []
    artifacts = {}
    transport = _Transport()
    envelope = _envelope()

    async def snapshot(persona_id):
        snapshot_calls.append(persona_id)
        return PAGE, controls

    async def resolve(persona_id, locator, peer_persona_id):
        resolver_calls.append((persona_id, locator, peer_persona_id))
        return {
            "current_url": PAGE,
            "destination_url": PROOF,
            "control": controls[0],
            "catalog_controls": controls,
            "peer_catalog_controls": (),
        }

    def store_artifact(data):
        digest = hashlib.sha256(data).hexdigest()
        artifacts[digest] = bytes(data)
        return digest

    store = BehavioralReceiptStore(tmp_path / "receipts")
    first = await execute_owned_read_proof(
        proof_url=PROOF,
        envelope=envelope,
        persona_id=ALICE,
        snapshot=snapshot,
        resolve_navigation=resolve,
        transport=transport,
        store_artifact=store_artifact,
        receipt_store=store,
        acquisition_config=InteractionAcquisitionConfig(enabled=True),
    )

    assert first.status == "completed"
    assert first.reused is False
    assert first.proof["correlation_ids"] == ["lab:owned-proof-1"]
    assert first.proof["artifact_ref"].removeprefix("sha256:") in artifacts
    assert len(transport.requests) == 1
    assert transport.requests[0][0] == ALICE
    assert transport.requests[0][1].method == "GET"
    assert transport.requests[0][1].url == PROOF

    async def unavailable_snapshot(_persona_id):
        raise AssertionError("completed outer receipt must bypass the browser")

    async def unavailable_resolver(*_args):
        raise AssertionError("completed outer receipt must bypass resolution")

    second = await execute_owned_read_proof(
        proof_url=PROOF,
        envelope=envelope,
        persona_id=ALICE,
        snapshot=unavailable_snapshot,
        resolve_navigation=unavailable_resolver,
        transport=transport,
        store_artifact=lambda _data: (_ for _ in ()).throw(
            AssertionError("completed outer receipt must not create evidence")
        ),
        receipt_store=store,
        acquisition_config=InteractionAcquisitionConfig(enabled=True),
    )

    assert second.status == "already_executed"
    assert second.reused is True
    assert second.receipt_id == first.receipt_id
    assert second.proof == first.proof
    assert len(transport.requests) == 1
    assert snapshot_calls == [ALICE]
    assert len(resolver_calls) == 3

    persisted = (tmp_path / "receipts" / f"{first.receipt_id}.json").read_text()
    assert "private owned export evidence" not in persisted
    assert PROOF not in persisted
    assert ALICE not in persisted
