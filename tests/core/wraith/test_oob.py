import asyncio
from datetime import datetime, timezone

import pytest

from core.toolkit.internal_tool import InternalToolContext
from core.toolkit.internal_tools.oob_probe import WraithOOBProbeTool
from core.wraith.mutation_engine import MutationResponse
from core.wraith.oob_detector import InteractionType, OOBEvidence


class _FakeMutationEngine:
    def __init__(self, rate_limit_ms: int = 0, policy_runtime=None):
        self.sent = []

    async def send(self, request):
        self.sent.append(request)
        return MutationResponse(
            status_code=200,
            headers={},
            body="ok",
            body_length=2,
            elapsed_ms=5.0,
            url=str(request.url),
        )

    async def close(self):
        return None


class _FakeOOBManager:
    def __init__(self, provider):
        self.provider = provider
        self.payload_registry = {}

    def generate_interaction_id(self, payload_id: str) -> str:
        return "abcd1234abcd1234"

    def register_payload(self, payload_id: str, interaction_id: str, metadata=None) -> None:
        self.payload_registry[payload_id] = {"interaction_id": interaction_id, "metadata": metadata or {}}

    def create_oob_payload(self, vuln_class, interaction_id: str, base_domain: str) -> str:
        return f"http://{interaction_id}.{base_domain}/ssrf-check"

    def poll_interactions(self, timeout_s: float = 30.0, interval_s: float = 2.0):
        # Emit evidence for the single registered payload.
        payload_id = next(iter(self.payload_registry.keys()))
        interaction_id = self.payload_registry[payload_id]["interaction_id"]
        return [
            OOBEvidence(
                interaction_type=InteractionType.DNS,
                source_ip="127.0.0.1",
                timestamp=datetime.now(timezone.utc),
                raw_data={"type": "dns"},
                payload_id=payload_id,
                correlation_id="corr-1",
                interaction_id=interaction_id,
                domain=str(getattr(self.provider, "base_domain", "example")),
            )
        ]


@pytest.mark.anyio
async def test_wraith_oob_probe_emits_finding_on_callback(monkeypatch):
    monkeypatch.setattr("core.toolkit.internal_tools.oob_probe.MutationEngine", _FakeMutationEngine)
    monkeypatch.setattr("core.toolkit.internal_tools.oob_probe.OOBManager", _FakeOOBManager)

    tool = WraithOOBProbeTool()
    ctx = InternalToolContext(
        target="https://example.com",
        scan_id="scan-oob",
        session_id="sess-oob",
        existing_findings=[
            {
                "tool": "nuclei_mutating",
                "severity": "HIGH",
                "metadata": {"url": "https://example.com/redirect?next=%2Fhome"},
            }
        ],
        knowledge={"oob": {"provider": "interactsh", "base_domain": "oob.test"}},
        mode="bounty",
    )

    q: asyncio.Queue[str] = asyncio.Queue()
    findings = await tool.execute("https://example.com", ctx, q)
    assert len(findings) == 1
    assert findings[0]["type"] == "ssrf"
    assert findings[0]["confirmation_level"] == "confirmed"
