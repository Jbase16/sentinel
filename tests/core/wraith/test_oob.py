import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from core.cortex.capability_tiers import CapabilityGate, ExecutionMode
from core.toolkit.internal_tool import InternalToolContext
from core.toolkit.internal_tools.oob_probe import WraithOOBProbeTool
from core.wraith.execution_policy import ExecutionPolicyRuntime
from core.wraith.mutation_engine import MutationResponse
from core.wraith.oob_detector import InteractionType, InteractshProvider, OOBEvidence


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

    async def poll_interactions_async(
        self,
        *,
        client,
        policy_runtime=None,
        tier_hint=None,
        timeout_s: float = 30.0,
        interval_s: float = 2.0,
    ):
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


@pytest.mark.anyio
async def test_interactsh_async_poll_uses_runtime_budget_and_external_allowlist():
    target = "https://example.com"
    gate = CapabilityGate(mode=ExecutionMode.BOUNTY)
    gate.add_scope_target(target)
    gate.reset_target_budget(target, max_tokens=10, max_time_seconds=60.0)

    runtime = ExecutionPolicyRuntime(
        tool_name="wraith_oob_probe",
        scope_target=target,
        execution_mode=ExecutionMode.BOUNTY,
        safe_mode=False,
        same_origin_only=True,
        rate_limit_ms=0,
        max_requests=4,
        max_retries_per_request=0,
        max_retries_total=0,
        capability_gate=gate,
        allowed_external_hosts={"interactsh.com"},
        max_external_calls=4,
    )

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "interactsh.com"
        assert request.url.path == "/log"
        assert request.url.params.get("url") == "oob.test"
        return httpx.Response(200, request=request, json={"interactions": []})

    provider = InteractshProvider(base_domain="oob.test", api_url="https://interactsh.com")
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    try:
        interactions = await provider.get_interactions_async(client=client, policy_runtime=runtime)
    finally:
        await client.aclose()

    assert interactions == []
    metrics = runtime.metrics()
    assert metrics["attempts_total"] == 1
    assert metrics["external_calls"] == 1
    assert metrics["capability_charges"] == 1
    assert gate.get_budget(target).remaining_tokens == 5
