from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from core.behavior.omission_confirmation import OmissionCapabilityFinding
from core.errors import ErrorCode, SentinelError
from core.server.routers.scans import (
    BehavioralOneClickProfile,
    ScanRequest,
    _bounded_behavioral_phase_summary,
    begin_scan_logic,
    _run_behavioral_one_click_phase,
)
from core.server.state import ApplicationState


ENVELOPE_ID = "1" * 32
SOURCE_PERSONA_ID = "2" * 32
PEER_PERSONA_ID = "3" * 32


class _FindingStore:
    def __init__(self):
        self.added = []

    async def add_finding_async(self, finding, *, persist):
        self.added.append((finding, persist))
        return finding

    def get_all(self):
        return [finding for finding, _persist in self.added]


class _Session:
    def __init__(self):
        self.id = "behavioral-direct-session"
        self.findings = _FindingStore()
        self.logs = []

    def log(self, message):
        self.logs.append(message)


class _RunnerSession(_Session):
    def __init__(self, target):
        super().__init__()
        self.id = "behavioral-scan-session"
        self.target = target
        self.knowledge = {}
        self.status = "created"
        self.end_time = None
        self.issues = SimpleNamespace(get_all=lambda: [])

    def set_external_log_sink(self, _sink):
        return None

    def close_log_file(self):
        return None

    def close(self):
        return None

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
        }


class _RunnerEventBus:
    def __init__(self):
        self.events = []

    def emit_scan_started(self, *_args, **_kwargs):
        return None

    def emit(self, event):
        self.events.append(event)

    def emit_scan_completed(self, *_args, **_kwargs):
        return None


def _request() -> ScanRequest:
    return ScanRequest(
        target="https://example.test/app",
        mode="bug_bounty",
        behavioral_one_click=BehavioralOneClickProfile(
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
            peer_persona_id=PEER_PERSONA_ID,
        ),
    )


def test_behavioral_one_click_requires_bug_bounty_mode():
    with pytest.raises(
        ValidationError,
        match="behavioral_one_click requires bug_bounty scan mode",
    ):
        ScanRequest(
            target="https://example.test/app",
            behavioral_one_click={
                "envelope_id": ENVELOPE_ID,
                "source_persona_id": SOURCE_PERSONA_ID,
                "peer_persona_id": PEER_PERSONA_ID,
            },
        )


def test_behavioral_one_click_requires_distinct_personas():
    with pytest.raises(
        ValidationError,
        match="behavioral one-click personas must be distinct",
    ):
        BehavioralOneClickProfile(
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
            peer_persona_id=SOURCE_PERSONA_ID,
        )


def test_anonymous_passive_profile_forbids_persona_identities():
    profile = BehavioralOneClickProfile(
        mode="anonymous_passive",
        envelope_id=ENVELOPE_ID,
    )
    assert profile.is_anonymous_passive is True
    assert profile.source_persona_id is None
    assert profile.peer_persona_id is None

    with pytest.raises(
        ValidationError,
        match="anonymous passive one-click forbids persona identities",
    ):
        BehavioralOneClickProfile(
            mode="anonymous_passive",
            envelope_id=ENVELOPE_ID,
            source_persona_id=SOURCE_PERSONA_ID,
        )


def test_paired_persona_profile_still_requires_both_identities():
    with pytest.raises(
        ValidationError,
        match="paired-persona one-click requires both persona identities",
    ):
        BehavioralOneClickProfile(envelope_id=ENVELOPE_ID)


def test_behavioral_phase_summary_is_bounded_and_redacted():
    summary = _bounded_behavioral_phase_summary(
        phase_status="confirmed_finding",
        result={
            "status": "completed",
            "orchestration_receipt": {
                "receipt_id": "receipt:abc",
                "state": "completed",
                "reused": True,
                "reservation_token": "must-not-escape",
            },
            "execution": {
                "status": "completed",
                "cleanup_steps_completed": 2,
                "raw_response": "must-not-escape",
            },
            "capture_pair": {"raw": "must-not-escape"},
        },
        finding={
            "id": "finding-1",
            "type": "cross_principal_object_access",
            "metadata": {"secret": "must-not-escape"},
        },
    )

    assert summary == {
        "status": "confirmed_finding",
        "result_status": "completed",
        "finding_id": "finding-1",
        "finding_type": "cross_principal_object_access",
        "receipt_id": "receipt:abc",
        "receipt_state": "completed",
        "receipt_reused": True,
        "cleanup_status": "completed",
        "cleanup_steps_completed": 2,
        "profile_mode": None,
        "observation_classification": None,
        "observation_count": None,
        "adaptive_execution_status": None,
        "independent_proof_status": None,
        "reason": None,
    }
    assert "must-not-escape" not in str(summary)


@pytest.mark.asyncio
async def test_behavioral_one_click_runs_exact_profile_and_adds_finding(
    monkeypatch,
):
    from core.server.routers import foundry

    session = _Session()
    finding = {
        "id": "behavioral-finding",
        "type": "State-machine prerequisite enforcement failure",
    }

    async def execute(request, _):
        assert request.target_url == "https://example.test/app"
        assert request.envelope_id == ENVELOPE_ID
        assert request.source_persona_id == SOURCE_PERSONA_ID
        assert request.peer_persona_id == PEER_PERSONA_ID
        assert _ is True
        return {"status": "completed", "finding": finding}

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )

    result = await _run_behavioral_one_click_phase(
        _request(),
        session=session,
    )

    assert result == {"status": "completed", "finding": finding}
    assert session.findings.added == [(finding, True)]
    assert "before ordinary scan traffic" in session.logs[0]
    assert "behavioral-finding" in session.logs[1]


@pytest.mark.asyncio
async def test_behavioral_one_click_restores_cached_omission_finding(
    monkeypatch,
):
    from core.server.routers import foundry

    session = _Session()
    finding = OmissionCapabilityFinding.build(
        confirmation_id=f"fresh_omission_confirmation:{'4' * 64}",
        experiment_id=f"omission_experiment:{'5' * 64}",
        terminal_operation_id=f"action:{'6' * 64}",
        lifecycle_id=f"owned_lifecycle:{'7' * 64}",
        provenance_root="8" * 64,
    )

    async def execute(_request, _):
        return {
            "status": "already_executed",
            "kind": "fresh_omission_confirmation",
            "finding_authority": True,
            "finding_ref": finding.finding_id,
            "confirmation_id": finding.confirmation_id,
            "experiment_id": finding.experiment_id,
            "terminal_operation_id": finding.terminal_operation_id,
            "lifecycle_id": finding.lifecycle_id,
            "provenance_root": finding.provenance_root,
        }

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        execute,
    )

    await _run_behavioral_one_click_phase(_request(), session=session)

    restored, persist = session.findings.added[0]
    assert restored["id"] == finding.finding_id
    assert restored["metadata"]["finding_authority"] is True
    assert persist is True


@pytest.mark.asyncio
async def test_behavioral_one_click_denial_fails_before_scan_traffic(
    monkeypatch,
):
    from core.server.routers import foundry

    state = ApplicationState()
    state.scan_state = {"session_id": "behavioral-direct-session"}
    monkeypatch.setattr(ApplicationState, "_instance", state)
    session = _Session()

    async def deny(_request, _):
        raise HTTPException(status_code=409, detail="signed workflow missing")

    monkeypatch.setattr(
        foundry,
        "run_behavioral_authorization_from_url_endpoint",
        deny,
    )

    with pytest.raises(SentinelError) as raised:
        await _run_behavioral_one_click_phase(_request(), session=session)

    assert raised.value.code == ErrorCode.AUTH_PERMISSION_DENIED
    assert raised.value.details == {
        "phase": "behavioral_one_click",
        "status_code": 409,
        "reason": "signed workflow missing",
    }
    assert session.findings.added == []
    assert state.scan_state["behavioral_one_click"] == {
        "status": "refused",
        "result_status": None,
        "finding_id": None,
        "finding_type": None,
        "receipt_id": None,
        "receipt_state": None,
        "receipt_reused": None,
        "cleanup_status": None,
        "cleanup_steps_completed": None,
        "profile_mode": None,
        "observation_classification": None,
        "observation_count": None,
        "adaptive_execution_status": None,
        "independent_proof_status": None,
        "reason": "signed workflow missing",
    }


@pytest.mark.asyncio
async def test_scan_without_behavioral_profile_is_unchanged():
    session = SimpleNamespace()
    request = ScanRequest(target="https://example.test")

    assert (
        await _run_behavioral_one_click_phase(request, session=session)
        is None
    )


@pytest.mark.asyncio
async def test_anonymous_passive_profile_surfaces_observation_without_finding(
    monkeypatch,
):
    from core.server.routers import scans

    state = ApplicationState()
    state.scan_state = {"session_id": "behavioral-direct-session"}
    monkeypatch.setattr(ApplicationState, "_instance", state)
    session = _Session()
    result = {
        "kind": "passive_visibility_observation",
        "mode": "behavioral_anonymous_passive_visibility_v1",
        "status": "completed",
        "finding_authority": False,
        "finding_confirmed": False,
        "observation": {
            "classification": "preexisting_passive_visibility",
            "discovered_public_page_count": 1,
        },
        "execution": {"status": "completed", "mutations": 0},
        "adaptive_execution": {"status": "skipped"},
        "independent_proof": {"status": "skipped"},
        "orchestration_receipt": None,
    }

    async def execute(_request, *, session):
        assert session is not None
        return result

    monkeypatch.setattr(
        scans,
        "_run_anonymous_passive_one_click_phase",
        execute,
    )
    request = ScanRequest(
        target="https://example.test/",
        mode="bug_bounty",
        behavioral_one_click={
            "mode": "anonymous_passive",
            "envelope_id": ENVELOPE_ID,
        },
    )

    observed = await _run_behavioral_one_click_phase(request, session=session)

    assert observed == result
    assert session.findings.added == []
    summary = state.scan_state["behavioral_one_click"]
    assert summary["status"] == "passive_visibility_observed"
    assert summary["observation_classification"] == (
        "preexisting_passive_visibility"
    )
    assert summary["observation_count"] == 1
    assert summary["adaptive_execution_status"] == "skipped"
    assert summary["independent_proof_status"] == "skipped"
    assert summary["receipt_id"] is None


@pytest.mark.asyncio
async def test_anonymous_passive_scan_skips_reasoning_tools_and_verification(
    monkeypatch,
):
    state = ApplicationState()
    monkeypatch.setattr(ApplicationState, "_instance", state)

    database = MagicMock()
    database.init = AsyncMock()
    database.blackbox.enqueue = AsyncMock()
    database.blackbox.flush = AsyncMock()
    monkeypatch.setattr(
        "core.server.routers.scans.Database.instance",
        lambda: database,
    )
    monkeypatch.setattr("core.base.session.ScanSession", _RunnerSession)
    monkeypatch.setattr(
        "core.toolkit.tools.get_installed_tools",
        lambda: {"nuclei_safe": object()},
    )
    event_bus = _RunnerEventBus()
    monkeypatch.setattr("core.cortex.events.get_event_bus", lambda: event_bus)

    async def execute(_request, *, session):
        return {
            "kind": "passive_visibility_observation",
            "status": "completed",
            "finding_authority": False,
            "finding_confirmed": False,
            "execution": {"status": "completed", "mutations": 0},
        }

    monkeypatch.setattr(
        "core.server.routers.scans._run_behavioral_one_click_phase",
        execute,
    )
    reasoning_called = False

    async def forbidden_reasoning(**_kwargs):
        nonlocal reasoning_called
        reasoning_called = True
        raise AssertionError("passive-only scan must not start ordinary reasoning")

    monkeypatch.setattr(
        "core.cortex.reasoning.reasoning_engine.start_scan",
        forbidden_reasoning,
    )

    session_id = await begin_scan_logic(
        ScanRequest(
            target="https://example.test/",
            mode="bug_bounty",
            scope=["example.test"],
            scope_strict=True,
            behavioral_one_click={
                "mode": "anonymous_passive",
                "envelope_id": ENVELOPE_ID,
            },
        )
    )
    await state.active_scan_task

    session = await state.get_session(session_id)
    assert state.scan_state["status"] == "completed"
    assert session.status == "completed"
    assert reasoning_called is False


@pytest.mark.asyncio
async def test_behavioral_refusal_precedes_reasoning_and_tool_dispatch(
    monkeypatch,
):
    state = ApplicationState()
    monkeypatch.setattr(ApplicationState, "_instance", state)

    database = MagicMock()
    database.init = AsyncMock()
    database.blackbox.enqueue = AsyncMock()
    database.blackbox.flush = AsyncMock()
    monkeypatch.setattr(
        "core.server.routers.scans.Database.instance",
        lambda: database,
    )
    monkeypatch.setattr(
        "core.base.session.ScanSession",
        _RunnerSession,
    )
    monkeypatch.setattr(
        "core.toolkit.tools.get_installed_tools",
        lambda: {},
    )

    event_bus = _RunnerEventBus()
    monkeypatch.setattr(
        "core.cortex.events.get_event_bus",
        lambda: event_bus,
    )

    async def refuse(_request, *, session):
        assert session.id == "behavioral-scan-session"
        raise SentinelError(
            ErrorCode.AUTH_PERMISSION_DENIED,
            "behavioral admission refused",
        )

    reasoning_called = False

    async def forbidden_reasoning(**_kwargs):
        nonlocal reasoning_called
        reasoning_called = True
        raise AssertionError("ordinary reasoning must not start")

    monkeypatch.setattr(
        "core.server.routers.scans._run_behavioral_one_click_phase",
        refuse,
    )
    monkeypatch.setattr(
        "core.cortex.reasoning.reasoning_engine.start_scan",
        forbidden_reasoning,
    )

    session_id = await begin_scan_logic(
        ScanRequest(
            target="https://example.test/app",
            mode="bug_bounty",
            scope=["example.test"],
            scope_strict=True,
            behavioral_one_click={
                "envelope_id": ENVELOPE_ID,
                "source_persona_id": SOURCE_PERSONA_ID,
                "peer_persona_id": PEER_PERSONA_ID,
            },
        )
    )
    await state.active_scan_task

    session = await state.get_session(session_id)
    assert state.scan_state["status"] == "error"
    assert session.status == "error"
    assert reasoning_called is False
    assert event_bus.events[-1].payload["error_code"] == (
        ErrorCode.AUTH_PERMISSION_DENIED.value
    )
