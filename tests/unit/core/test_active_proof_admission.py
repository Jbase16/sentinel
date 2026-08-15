"""R0 containment tests for Wraith capability/exfiltration admission."""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from core.foundry.authorization import create_envelope
from core.server.routers.scans import ScanRequest, _should_run_active_verification
from core.wraith.active_proof import (
    CAPABILITY_WORKFLOW,
    UNION_EXFILTRATION_WORKFLOW,
    OwnedLabManifest,
    run_capability_acquisition,
    run_union_exfiltration,
)


LOCAL_ORIGIN = "http://127.0.0.1:8766"


def _manifest(*, origin: str = LOCAL_ORIGIN, workflows=None) -> OwnedLabManifest:
    envelope = create_envelope(
        researcher_identity="r0-test-operator",
        target_handle="sentinel-local-acceptance-lab",
        authorized_origins=[origin],
        authorization_basis="operator-owned local acceptance lab",
        allowed_workflows=list(
            workflows or [CAPABILITY_WORKFLOW, UNION_EXFILTRATION_WORKFLOW]
        ),
        disclosure_attestation=True,
    )
    return OwnedLabManifest(
        envelope_id=envelope.envelope_id,
        target_origin=origin,
        authorization_signature=envelope.attestation_signature,
    )


def _local_vulnerable_lab():
    app = FastAPI()

    @app.post("/api/login")
    async def vulnerable_login(request: Request):
        body = await request.json()
        principal = str(body.get("email") or body.get("username") or "")
        if " OR " in principal:
            return JSONResponse({"token": "lab-token-12345678901234567890"})
        return JSONResponse({"error": "denied"}, status_code=401)

    @app.get("/search")
    async def vulnerable_search(request: Request):
        query = str(request.query_params.get("q") or "")
        column_probe = re.search(r"UNION SELECT ((?:NULL,?)+)\s*--", query)
        if column_probe:
            columns = column_probe.group(1).rstrip(",").count("NULL")
            if columns != 3:
                return PlainTextResponse(
                    "SQLITE_ERROR: SELECTs do not have the same number of result columns",
                    status_code=500,
                )
            return PlainTextResponse("SQLITE_ERROR: downstream parse stopped", status_code=500)
        if "email,password" in query and "FROM Users" in query:
            return PlainTextResponse(
                '{"data":[{"name":"owned-lab@example.test",'
                '"description":"0192023a7bbd73250516f069df18b500"}]}'
            )
        if "FROM " in query:
            return PlainTextResponse("SQLITE_ERROR: no such table", status_code=500)
        return PlainTextResponse('{"data":[]}')

    return app


def _local_secure_lab():
    app = FastAPI()

    @app.post("/{path:path}")
    async def secure_login(path: str):
        if path == "api/login":
            return JSONResponse({"error": "denied"}, status_code=401)
        return JSONResponse({"error": "not found"}, status_code=404)

    @app.get("/search")
    async def secure_search():
        return PlainTextResponse('{"data":[]}')

    return app


def _lab_transport(app: FastAPI, dispatched: list):
    async def raw_send(method: str, url: str, body=None):
        dispatched.append((method, url))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=LOCAL_ORIGIN,
            follow_redirects=False,
        ) as client:
            response = await client.request(method, url, json=body)
        return response.status_code, {
            "headers": dict(response.headers),
            "text": response.text,
        }

    return raw_send


@pytest.fixture(autouse=True)
def _isolate_authorization_store(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINELFORGE_AUTHZ_STORE", str(tmp_path / "authorizations"))
    monkeypatch.delenv("SENTINEL_PROOF_MODE", raising=False)


def test_scan_request_parses_the_explicit_owned_lab_manifest():
    manifest = _manifest()
    request = ScanRequest(
        target=LOCAL_ORIGIN,
        mode="owned_lab",
        owned_lab_manifest=manifest.model_dump(),
    )
    assert request.owned_lab_manifest == manifest
    assert request.owned_lab_manifest.manifest_ref.startswith("owned_lab_manifest:")
    assert _should_run_active_verification(request.mode, passive_only=False) is True
    assert _should_run_active_verification(request.mode, passive_only=True) is False


@pytest.mark.asyncio
async def test_bug_bounty_refuses_capability_and_exfiltration_without_dispatch(tmp_path):
    dispatched = []
    raw_send = _lab_transport(_local_vulnerable_lab(), dispatched)
    manifest = _manifest()
    receipt_root = tmp_path / "receipts"

    capability = await run_capability_acquisition(
        scan_mode="bug_bounty",
        target=LOCAL_ORIGIN,
        manifest=manifest,
        raw_send=raw_send,
        receipt_root=receipt_root,
    )
    exfiltration = await run_union_exfiltration(
        scan_mode="bug_bounty",
        target=LOCAL_ORIGIN,
        manifest=manifest,
        url=f"{LOCAL_ORIGIN}/search?q=apple",
        param="q",
        raw_send=raw_send,
        receipt_root=receipt_root,
    )

    assert capability.admitted is False
    assert exfiltration.admitted is False
    assert capability.reason == "active_proof_requires_owned_lab_mode"
    assert exfiltration.reason == "active_proof_requires_owned_lab_mode"
    assert dispatched == []
    receipts = [json.loads(path.read_text()) for path in receipt_root.glob("*.json")]
    assert len(receipts) == 2
    assert {item["state"] for item in receipts} == {"denied"}
    assert all(item["result"] == {"requests_sent": 0} for item in receipts)
    assert all(item["conduct"] == [] for item in receipts)


@pytest.mark.asyncio
async def test_public_target_is_refused_even_when_labeled_owned_lab(tmp_path):
    dispatched = []
    public_origin = "https://public.example.test"
    outcome = await run_capability_acquisition(
        scan_mode="owned_lab",
        target=public_origin,
        manifest=_manifest(origin=public_origin),
        raw_send=_lab_transport(_local_vulnerable_lab(), dispatched),
        receipt_root=tmp_path / "receipts",
    )
    assert outcome.admitted is False
    assert outcome.reason == "owned_lab_active_proof_requires_loopback_target"
    assert dispatched == []


@pytest.mark.asyncio
async def test_owned_lab_mode_without_valid_signed_manifest_dispatches_nothing(tmp_path):
    dispatched = []
    raw_send = _lab_transport(_local_vulnerable_lab(), dispatched)
    missing = await run_capability_acquisition(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=None,
        raw_send=raw_send,
        receipt_root=tmp_path / "missing-receipt",
    )
    valid = _manifest()
    forged = OwnedLabManifest(
        envelope_id=valid.envelope_id,
        target_origin=valid.target_origin,
        authorization_signature="0" * 64,
    )
    tampered = await run_union_exfiltration(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=forged,
        url=f"{LOCAL_ORIGIN}/search?q=apple",
        param="q",
        raw_send=raw_send,
        receipt_root=tmp_path / "tampered-receipt",
    )
    assert missing.reason == "active_proof_requires_owned_lab_manifest"
    assert tampered.reason == "owned_lab_authorization_signature_mismatch"
    assert missing.admitted is False
    assert tampered.admitted is False
    assert dispatched == []


@pytest.mark.asyncio
async def test_manifest_envelope_must_authorize_the_exact_active_workflow(tmp_path):
    dispatched = []
    outcome = await run_union_exfiltration(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=_manifest(workflows=[CAPABILITY_WORKFLOW]),
        url=f"{LOCAL_ORIGIN}/search?q=apple",
        param="q",
        raw_send=_lab_transport(_local_vulnerable_lab(), dispatched),
        receipt_root=tmp_path / "receipts",
    )
    assert outcome.admitted is False
    assert outcome.reason == "owned_lab_authorization_denied"
    assert dispatched == []


@pytest.mark.asyncio
async def test_environment_can_tighten_owned_lab_active_proof_to_zero_dispatch(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("SENTINEL_PROOF_MODE", "passive")
    dispatched = []
    outcome = await run_capability_acquisition(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=_manifest(),
        raw_send=_lab_transport(_local_vulnerable_lab(), dispatched),
        receipt_root=tmp_path / "receipts",
    )
    assert outcome.admitted is False
    assert outcome.reason == "active_proof_posture_was_tightened_below_lab"
    assert dispatched == []


@pytest.mark.asyncio
async def test_active_proof_refuses_when_durable_receipt_root_is_unsafe(tmp_path):
    receipt_target = tmp_path / "real-receipts"
    receipt_target.mkdir()
    receipt_link = tmp_path / "receipt-link"
    receipt_link.symlink_to(receipt_target, target_is_directory=True)
    dispatched = []
    outcome = await run_capability_acquisition(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=_manifest(),
        raw_send=_lab_transport(_local_vulnerable_lab(), dispatched),
        receipt_root=receipt_link,
    )
    assert outcome.admitted is False
    assert outcome.reason == "durable_active_proof_receipt_unavailable"
    assert dispatched == []


@pytest.mark.asyncio
async def test_signed_owned_lab_manifest_runs_bounded_proofs_and_writes_receipts(tmp_path):
    dispatched = []
    raw_send = _lab_transport(_local_vulnerable_lab(), dispatched)
    receipt_root = tmp_path / "receipts"
    manifest = _manifest()

    capability = await run_capability_acquisition(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=manifest,
        scope_filter=lambda url: url.startswith(LOCAL_ORIGIN),
        raw_send=raw_send,
        receipt_root=receipt_root,
    )
    exfiltration = await run_union_exfiltration(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=manifest,
        url=f"{LOCAL_ORIGIN}/search?q=apple",
        param="q",
        scope_filter=lambda url: url.startswith(LOCAL_ORIGIN),
        raw_send=raw_send,
        receipt_root=receipt_root,
    )

    assert capability.admitted is True
    assert capability.value is not None
    assert capability.value.acquirer == "login_sqli"
    assert exfiltration.admitted is True
    assert exfiltration.value is not None
    assert exfiltration.value.row_count == 1
    assert capability.requests_sent > 0
    assert exfiltration.requests_sent > 0
    assert {method for method, _ in dispatched} == {"GET", "POST"}
    assert all(url.startswith(LOCAL_ORIGIN) for _, url in dispatched)

    paths = sorted(receipt_root.glob("*.json"))
    assert len(paths) == 2
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
    receipts = [json.loads(path.read_text()) for path in paths]
    assert {item["state"] for item in receipts} == {"completed"}
    assert all(item["policy_digest"] for item in receipts)
    assert all(item["ownership_registry_ref"].startswith("ownership_registry:") for item in receipts)
    assert all(item["proof_budget"]["allow_delete"] is False for item in receipts)
    assert all(item["provenance_root"] for item in receipts)
    assert all(len(item["conduct"]) == item["result"]["requests_sent"] for item in receipts)
    assert all(
        item["result"]["requests_sent"] <= item["proof_budget"]["max_total_requests"]
        for item in receipts
    )
    assert all(item["manifest_ref"] == manifest.manifest_ref for item in receipts)
    serialized = "\n".join(path.read_text() for path in paths)
    assert "lab-token-12345678901234567890" not in serialized
    assert "0192023a7bbd73250516f069df18b500" not in serialized
    assert "UNION SELECT" not in serialized


@pytest.mark.asyncio
async def test_signed_manifest_runs_against_secure_twin_without_fabricating_proof(tmp_path):
    dispatched = []
    raw_send = _lab_transport(_local_secure_lab(), dispatched)
    manifest = _manifest()
    capability = await run_capability_acquisition(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=manifest,
        max_attempts=3,
        raw_send=raw_send,
        receipt_root=tmp_path / "capability-receipts",
    )
    exfiltration = await run_union_exfiltration(
        scan_mode="owned_lab",
        target=LOCAL_ORIGIN,
        manifest=manifest,
        url=f"{LOCAL_ORIGIN}/search?q=apple",
        param="q",
        max_attempts=2,
        raw_send=raw_send,
        receipt_root=tmp_path / "exfil-receipts",
    )
    assert capability.admitted is True
    assert exfiltration.admitted is True
    assert capability.value is None
    assert exfiltration.value is None
    assert dispatched
