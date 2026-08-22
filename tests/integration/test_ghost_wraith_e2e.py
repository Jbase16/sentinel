"""Integration proofs for Ghost's passive, scope-gated capture path.

The interception hook records admitted exchanges for later offline analysis.
It does not run strategy, execute mutations, or promote findings inline.
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from mitmproxy import http

from core.base.context import ScopeContext
from core.base.scope import AssetType, ScopeDecision, ScopeRegistry, ScopeRule
from core.ghost.flow import FlowMapper
from core.ghost.proxy import GhostAddon


ADMITTED_ORIGIN = "http://127.0.0.1:3003"


@pytest.fixture(autouse=True)
def isolated_flow_mapper():
    FlowMapper._instance = None
    try:
        yield
    finally:
        FlowMapper._instance = None


def _session():
    registry = ScopeRegistry()
    registry.add_rule(
        ScopeRule(AssetType.ORIGIN, ADMITTED_ORIGIN, ScopeDecision.ALLOW)
    )
    findings = Mock()
    findings.add_finding = Mock()
    return SimpleNamespace(
        scope_context=ScopeContext(registry=registry),
        findings=findings,
        knowledge={},
        log=Mock(),
    )


def _flow(url: str) -> http.HTTPFlow:
    flow = Mock(spec=http.HTTPFlow)
    flow.request = Mock()
    flow.request.pretty_url = url
    flow.request.method = "GET"
    flow.request.host = "127.0.0.1"
    flow.request.headers = {"accept": "application/json"}
    flow.request.content = b""
    flow.request.query = {"user_id": "101"}
    flow.request.urlencoded_form = {}

    flow.response = Mock()
    flow.response.status_code = 200
    flow.response.headers = {"content-type": "application/json"}
    flow.response.content = b'{"id":101,"role":"user"}'
    flow.response.text = flow.response.content.decode()
    flow.metadata = {}
    return flow


def _addon(session) -> GhostAddon:
    addon = GhostAddon(session)
    addon.shadow_spec = Mock()
    addon.session_bridge = Mock()
    addon.lazarus.should_process = Mock(return_value=False)
    return addon


@pytest.mark.asyncio
async def test_ghost_passively_captures_admitted_exchange_without_promotion():
    session = _session()
    addon = _addon(session)
    mapper = FlowMapper.instance()
    flow_id = mapper.start_recording("admitted loopback flow")
    flow = _flow(f"{ADMITTED_ORIGIN}/api/users?user_id=101")
    response_bytes = flow.response.content

    addon.request(flow)
    await addon.response(flow)

    steps = mapper.active_flows[flow_id].steps
    assert len(steps) == 1
    assert steps[0].method == "GET"
    assert steps[0].url == flow.request.pretty_url
    assert steps[0].params == {"user_id": "101"}
    assert steps[0].response_status == 200
    assert steps[0].response_body == response_bytes.decode()
    assert flow.response.content == response_bytes
    session.findings.add_finding.assert_not_called()


def test_ghost_rejects_unadmitted_exchange_before_capture():
    session = _session()
    addon = _addon(session)
    mapper = FlowMapper.instance()
    flow_id = mapper.start_recording("scope rejection")
    flow = _flow("http://127.0.0.2:3003/admin")

    addon.request(flow)

    assert flow.response.status_code == 403
    assert mapper.active_flows[flow_id].steps == []
    addon.shadow_spec.observe.assert_not_called()
    addon.session_bridge.observe_request.assert_not_called()
    session.findings.add_finding.assert_not_called()
