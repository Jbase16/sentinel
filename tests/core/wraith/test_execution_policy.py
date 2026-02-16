import httpx
import pytest

from core.cortex.capability_tiers import CapabilityGate, ExecutionMode
from core.wraith.execution_policy import ExecutionPolicyRuntime, PolicyViolation


def _ok_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, request=request, text="ok")


@pytest.mark.anyio
async def test_research_mode_blocks_mutating_tier():
    runtime = ExecutionPolicyRuntime(
        tool_name="wraith_verify",
        scope_target="https://example.com",
        execution_mode=ExecutionMode.RESEARCH,
        safe_mode=False,
        same_origin_only=True,
        rate_limit_ms=0,
        max_requests=10,
        max_retries_per_request=1,
        max_retries_total=5,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(_ok_response))
    try:
        with pytest.raises(PolicyViolation):
            await runtime.execute_http(
                client=client,
                method="GET",
                url="https://example.com/api/users?id=1",
                request_kwargs={},
                payload_tier_required=3,
            )
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_same_origin_enforced():
    runtime = ExecutionPolicyRuntime(
        tool_name="wraith_verify",
        scope_target="https://example.com",
        execution_mode=ExecutionMode.BOUNTY,
        safe_mode=False,
        same_origin_only=True,
        rate_limit_ms=0,
        max_requests=10,
        max_retries_per_request=1,
        max_retries_total=5,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(_ok_response))
    try:
        with pytest.raises(PolicyViolation):
            await runtime.execute_http(
                client=client,
                method="GET",
                url="https://evil.example.net/api",
                request_kwargs={},
                payload_tier_required=3,
            )
    finally:
        await client.aclose()


@pytest.mark.anyio
async def test_retry_and_budget_accounting():
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, request=request, text="retry")
        return httpx.Response(200, request=request, text="ok")

    runtime = ExecutionPolicyRuntime(
        tool_name="httpx",
        scope_target="https://example.com",
        execution_mode=ExecutionMode.RESEARCH,
        safe_mode=False,
        same_origin_only=True,
        rate_limit_ms=0,
        max_requests=5,
        max_retries_per_request=2,
        max_retries_total=2,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    try:
        resp = await runtime.execute_http(
            client=client,
            method="GET",
            url="https://example.com/health",
            request_kwargs={},
            payload_tier_required=2,
        )
    finally:
        await client.aclose()

    metrics = runtime.metrics()
    assert resp.status_code == 200
    assert calls["n"] == 2
    assert metrics["retries_total"] == 1
    assert metrics["attempts_total"] == 2


def test_external_allowlist_enforced():
    runtime = ExecutionPolicyRuntime(
        tool_name="wraith_oob_probe",
        scope_target="https://example.com",
        execution_mode=ExecutionMode.BOUNTY,
        safe_mode=False,
        same_origin_only=True,
        rate_limit_ms=0,
        max_requests=5,
        max_retries_per_request=1,
        max_retries_total=1,
        allowed_external_hosts={"interactsh.com"},
        max_external_calls=1,
    )

    runtime.authorize_external_url("https://interactsh.com/log")
    with pytest.raises(PolicyViolation):
        runtime.authorize_external_url("https://interactsh.com/log")


@pytest.mark.anyio
async def test_capability_gate_charged_per_request():
    target = "https://example.com"
    gate = CapabilityGate(mode=ExecutionMode.BOUNTY)
    gate.add_scope_target(target)
    gate.reset_target_budget(target, max_tokens=10, max_time_seconds=60.0)

    runtime = ExecutionPolicyRuntime(
        tool_name="wraith_verify",
        scope_target=target,
        execution_mode=ExecutionMode.BOUNTY,
        safe_mode=False,
        same_origin_only=True,
        rate_limit_ms=0,
        max_requests=10,
        max_retries_per_request=0,
        max_retries_total=0,
        capability_gate=gate,
    )

    client = httpx.AsyncClient(transport=httpx.MockTransport(_ok_response))
    try:
        await runtime.execute_http(
            client=client,
            method="GET",
            url="https://example.com/api/users?id=1",
            request_kwargs={},
            payload_tier_required=3,
        )
        await runtime.execute_http(
            client=client,
            method="GET",
            url="https://example.com/api/users?id=2",
            request_kwargs={},
            payload_tier_required=3,
        )
        with pytest.raises(PolicyViolation):
            await runtime.execute_http(
                client=client,
                method="GET",
                url="https://example.com/api/users?id=3",
                request_kwargs={},
                payload_tier_required=3,
            )
    finally:
        await client.aclose()

    budget = gate.get_budget(target)
    assert budget.remaining_tokens == 0
    assert runtime.metrics()["capability_charges"] == 2
