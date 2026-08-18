from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.ai.ai_engine import AIEngine
from core.base.config import SentinelConfig, StorageConfig
from core.base.context import ScopeContext
from core.base.scope import AssetType, ScopeDecision, ScopeRegistry, ScopeRule
from core.base.task_router import TaskRouter
from core.engine.scanner_engine import ScannerEngine
from core.epistemic.events import EventType
from core.epistemic.ledger import (
    Citation,
    ConfirmationLevel,
    EvidenceLedger,
    FindingProposal,
    ObservationEnvelope,
)
from core.identity import scan_admission_binding


ORIGIN = "https://scanner.example.test"


class _FakeStdout:
    def __init__(self, lines: list[str]) -> None:
        self._lines = [f"{line}\n".encode() for line in lines]

    async def readline(self) -> bytes:
        if self._lines:
            return self._lines.pop(0)
        return b""


class _FakeProc:
    def __init__(self, lines: list[str]) -> None:
        self.stdout = _FakeStdout(lines)
        self.stdin = None
        self.returncode = None

    async def wait(self) -> int:
        self.returncode = 0
        return 0

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = 0


class _FakeAI:
    def __init__(self) -> None:
        self.calls = 0

    async def process_tool_output(self, **kwargs):
        self.calls += 1
        observation_id = kwargs["observation_id"]
        return {
            "summary": "AI interpretation",
            "proposals": [
                FindingProposal(
                    title="Exposed admin surface",
                    severity="HIGH",
                    description="AI inferred exploitability from a path string.",
                    citations=[Citation(observation_id=observation_id)],
                    source="ai",
                    confirmation_level=ConfirmationLevel.CONFIRMED.value,
                )
            ],
            "next_steps": [],
        }


@pytest.mark.asyncio
async def test_scanner_refuses_sessionless_global_fallback() -> None:
    stream = ScannerEngine().scan(ORIGIN, selected_tools=[])
    with pytest.raises(RuntimeError, match="explicit ScanSession"):
        await stream.__anext__()


@pytest.mark.asyncio
async def test_ai_interprets_existing_observation_without_writing_evidence() -> None:
    engine = AIEngine.__new__(AIEngine)
    engine.client = None
    engine.ensure_client = MagicMock()
    config = MagicMock()
    config.ai.fallback_enabled = False
    with (
        patch("core.ai.ai_engine.get_config", return_value=config),
        patch("core.ai.ai_engine.EvidenceStore.instance") as evidence_store,
    ):
        result = await engine.process_tool_output(
            tool_name="nikto",
            stdout="/admin [Status: 200]",
            stderr="",
            rc=0,
            metadata={"session_id": "session-wo07", "target": ORIGIN},
            observation_id="obs-canonical",
        )

    assert result["evidence_id"] == "obs-canonical"
    evidence_store.assert_not_called()


@pytest.mark.asyncio
async def test_scanner_output_stays_passive_and_ai_is_not_promoted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path))
    registry = ScopeRegistry()
    registry.add_rule(ScopeRule(AssetType.ORIGIN, ORIGIN, ScopeDecision.ALLOW))
    admission_id, admission_ref = scan_admission_binding(
        session_id="session-wo07",
        target=ORIGIN,
        request_material={"target": ORIGIN, "mode": "owned_lab"},
        policy_material={"allow_methods": ["GET"]},
    )
    session = SimpleNamespace(
        id="session-wo07",
        session_id="session-wo07",
        scan_id="session-wo07",
        knowledge={},
        scope_context=ScopeContext(
            registry=registry,
            scan_id="session-wo07",
            authorization_envelope_id=admission_id,
            authorization_envelope_ref=admission_ref,
        ),
    )
    fake_ai = _FakeAI()
    routed_results = []

    with (
        patch("core.base.sequence.GlobalSequenceAuthority") as sequence,
        patch("core.data.findings_store.findings_store") as legacy_findings,
    ):
        sequence.instance.return_value.run_id = "run-wo07"
        ledger = EvidenceLedger(config)
        router = TaskRouter(ai=fake_ai, ledger=ledger)
        router.emit_ui_event = MagicMock()
        original_handle = router.handle_tool_output

        async def capture_route(*args, **kwargs):
            result = await original_handle(*args, **kwargs)
            routed_results.append(result)
            return result

        router.handle_tool_output = capture_route
        engine = ScannerEngine(session=session)
        fake_proc = _FakeProc(["/admin [Status: 200]"])

        async def fake_create_subprocess_exec(*_args, **_kwargs):
            return fake_proc

        monkeypatch.setattr(
            asyncio, "create_subprocess_exec", fake_create_subprocess_exec
        )
        monkeypatch.setattr(
            "core.engine.scanner_engine.ScannerBridge.classify",
            lambda *_args: [
                {
                    "type": "admin_surface",
                    "severity": "MEDIUM",
                    "message": "/admin returned 200",
                    "target": ORIGIN,
                    "tool": "nikto",
                }
            ],
        )
        monkeypatch.setattr(
            "core.engine.scanner_engine.TaskRouter.instance",
            lambda: router,
        )
        with (
            patch.object(
                ledger,
                "record_observation",
                side_effect=AssertionError("legacy observation path used"),
            ),
            patch.object(
                ledger,
                "evaluate_and_promote",
                side_effect=AssertionError("legacy promotion path used"),
            ),
            patch.object(
                ledger,
                "_update_findings_store",
                side_effect=AssertionError("legacy findings store used"),
            ),
        ):
            findings = await engine._run_tool_task(
                exec_id="nikto:wo07",
                tool="nikto",
                target=ORIGIN,
                queue=asyncio.Queue(),
                args=["-h", "{target}"],
                cancel_flag=asyncio.Event(),
            )

    assert len(routed_results) == 1
    assert fake_ai.calls == 1
    assert findings == []
    assert len(ledger._observations) == 1
    assert all(
        isinstance(item, ObservationEnvelope) for item in ledger._observations.values()
    )
    assert ledger._findings == {}
    assert [item.event_type for item in ledger._event_log] == [EventType.OBSERVED]
    assert {item.payload["session_id"] for item in ledger._event_log} == {
        "session-wo07"
    }

    proposals = routed_results[0]["proposals"]
    scanner_proposal = next(item for item in proposals if item.source == "scanner")
    ai_proposal = next(item for item in proposals if item.source == "ai")
    assert scanner_proposal.confirmation_level == ConfirmationLevel.PROBABLE.value
    assert ai_proposal.confirmation_level == ConfirmationLevel.HYPOTHESIZED.value
    assert all(item.title != ai_proposal.title for item in ledger._findings.values())
    legacy_findings.add_finding.assert_not_called()
    legacy_findings.bulk_add.assert_not_called()
