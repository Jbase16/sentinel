"""R0 P0-2 proofs: canonical scope and per-hop egress containment."""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import httpx
import pytest

from core.base.config import NetworkConfig
from core.base.context import ScopeContext
from core.base.exceptions import ScopePolicyViolationError
from core.base.execution_policy import ExecutionPolicy as TransportExecutionPolicy
from core.base.scope import AssetType, ScopeDecision, ScopeRegistry, ScopeRule
from core.foundry.authorization import AuthorizationEnvelope
from core.net.adapter import SentinelHTTPClient
from core.net.egress import same_origin_authorizer, scope_context_authorizer
from core.net.http_factory import create_async_client
from core.toolkit.registry import TOOLS
from core.wraith.bola_replay import ReplayRequest, SNDReplayTransport


def test_redirect_to_cloud_metadata_is_blocked_before_second_transport_hop() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.host == "allowed.example":
            return httpx.Response(
                302,
                headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )
        raise AssertionError("metadata redirect escaped the per-hop broker")

    async def exercise() -> None:
        registry = ScopeRegistry(bounty_mode=True)
        registry.add_rule(
            ScopeRule(
                AssetType.URL,
                "https://allowed.example/start",
                ScopeDecision.ALLOW,
            )
        )
        context = ScopeContext(
            registry=registry,
            policy=TransportExecutionPolicy(),
            mode="BOUNTY",
            strict_scope=True,
        )
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
        ) as underlying:
            client = SentinelHTTPClient(context, underlying_client=underlying)
            with pytest.raises(ScopePolicyViolationError):
                await client.get(
                    "https://allowed.example/start",
                    follow_redirects=True,
                )

    asyncio.run(exercise())
    assert calls == ["https://allowed.example/start"]


def test_exact_url_scope_binds_scheme_host_and_effective_port() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200)

    registry = ScopeRegistry(bounty_mode=True)
    registry.add_rule(
        ScopeRule(
            AssetType.URL,
            "https://allowed.example/resource",
            ScopeDecision.ALLOW,
        )
    )

    assert (
        registry.resolve("https://allowed.example:443/resource").verdict
        == ScopeDecision.ALLOW
    )
    assert (
        registry.resolve("https://ALLOWED.EXAMPLE.:443/resource").verdict
        == ScopeDecision.ALLOW
    )
    assert (
        registry.resolve("http://allowed.example:8080/resource").verdict
        == ScopeDecision.DENY
    )

    async def exercise() -> None:
        context = ScopeContext(
            registry=registry,
            policy=TransportExecutionPolicy(),
            mode="BOUNTY",
            strict_scope=True,
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as underlying:
            with pytest.raises(ScopePolicyViolationError):
                await SentinelHTTPClient(context, underlying).get(
                    "http://allowed.example:8080/resource"
                )

    asyncio.run(exercise())
    assert calls == []


def test_foundry_wildcard_requires_leading_dot_boundary_and_same_origin() -> None:
    envelope = AuthorizationEnvelope(
        envelope_id="r0-p0-2",
        researcher_identity="local-test",
        target_handle="owned-lab",
        authorized_origins=["https://*.example.com"],
    )

    assert envelope.authorizes_origin("https://api.example.com") is True
    assert envelope.authorizes_origin("https://badexample.com") is False
    assert envelope.authorizes_origin("http://api.example.com:8080") is False


def test_cross_origin_redirect_does_not_forward_auth_or_cookie_headers() -> None:
    observed: list[tuple[str, str | None, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(
            (
                request.url.host or "",
                request.headers.get("authorization"),
                request.headers.get("cookie"),
            )
        )
        if request.url.host == "app.example":
            return httpx.Response(
                302,
                headers={"location": "https://cdn.example/landing"},
            )
        return httpx.Response(200, content=b"ok")

    async def exercise() -> None:
        registry = ScopeRegistry(bounty_mode=True)
        for origin in ("https://app.example", "https://cdn.example"):
            registry.add_rule(
                ScopeRule(AssetType.ORIGIN, origin, ScopeDecision.ALLOW)
            )
        context = ScopeContext(
            registry=registry,
            policy=TransportExecutionPolicy(),
            mode="BOUNTY",
            strict_scope=True,
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=False,
        ) as underlying:
            await SentinelHTTPClient(context, underlying_client=underlying).get(
                "https://app.example/start",
                headers={
                    "Authorization": "Bearer secret",
                    "Cookie": "session=secret",
                },
                follow_redirects=True,
            )

    asyncio.run(exercise())
    assert observed == [
        ("app.example", "Bearer secret", "session=secret"),
        ("cdn.example", None, None),
    ]


def test_strict_scope_filter_uses_verdict_and_fails_closed_on_unknown() -> None:
    registry = ScopeRegistry(bounty_mode=True)
    registry.add_rule(
        ScopeRule(AssetType.ORIGIN, "https://allowed.example", ScopeDecision.ALLOW)
    )
    authorize = scope_context_authorizer(
        ScopeContext(
            registry=registry,
            policy=TransportExecutionPolicy(),
            mode="BOUNTY",
            strict_scope=True,
        )
    )

    assert authorize("https://allowed.example/path") is True
    assert authorize("https://unknown.example/path") is False


def test_transport_defaults_are_passive_and_redirects_are_broker_only() -> None:
    policy = TransportExecutionPolicy()

    assert policy.allow_methods == ["GET", "HEAD", "OPTIONS"]
    assert policy.allow_authentication is False
    assert "DELETE" not in policy.allow_methods
    assert NetworkConfig().follow_redirects is False

    bounty = TransportExecutionPolicy.for_scan_mode("bug_bounty")
    owned_lab = TransportExecutionPolicy.for_scan_mode("owned_lab")
    assert "DELETE" not in bounty.allow_methods
    assert "DELETE" in owned_lab.allow_methods

    with pytest.raises(ValueError, match="EgressBroker"):
        create_async_client(follow_redirects=True)

    curl_profile = TOOLS["httpx"].cmd_template
    assert "-L" not in curl_profile
    assert curl_profile[curl_profile.index("--max-redirs") + 1] == "0"


def test_native_browser_replay_is_scope_bound_and_redirect_manual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[dict] = []

    class FakeNodeManager:
        async def send_command(self, command: dict, *, timeout: float) -> dict:
            commands.append(command)
            return {"status": 200, "body": "ok", "headers": {}}

    monkeypatch.setitem(
        sys.modules,
        "core.server.routers.driver",
        SimpleNamespace(node_manager=FakeNodeManager()),
    )

    async def exercise() -> None:
        transport = SNDReplayTransport(
            scope_filter=same_origin_authorizer("https://allowed.example"),
        )
        with pytest.raises(ScopePolicyViolationError):
            await transport.send(
                "alice",
                ReplayRequest("GET", "http://169.254.169.254/latest/meta-data/"),
            )
        with pytest.raises(ValueError, match="cannot follow redirects"):
            await transport.send(
                "alice",
                ReplayRequest(
                    "GET",
                    "https://allowed.example/object/1",
                    redirect_mode="follow",
                ),
            )
        response = await transport.send(
            "alice",
            ReplayRequest("GET", "https://allowed.example/object/1"),
        )
        assert response.status == 200

    asyncio.run(exercise())
    assert len(commands) == 1
    assert commands[0]["args"]["redirect_mode"] == "manual"
