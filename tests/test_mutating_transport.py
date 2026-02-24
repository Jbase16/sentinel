import pytest
from typing import Dict, Any

from core.web.transport import MutatingTransport, BaselineHandle
from core.web.contracts.models import WebMission, BaselineSignature, DeltaVector
from core.web.contracts.events import EventEnvelope, EventType
from core.web.contracts.enums import WebMethod, WebAuthMode, VulnerabilityClass, DeltaSeverity
from core.web.contracts.ids import MissionId, ScanId, SessionId, RequestId, PrincipalId
from core.web.context import WebContext
from core.web.event_bus import StrictEventBus


class MockPolicy:
    def __init__(self):
        self.call_count = 0
        self.last_url = None

    def assert_url_allowed(self, mission: WebMission, url: str) -> None:
        pass

    def http_request(
        self,
        mission: WebMission,
        ctx: WebContext,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes, int, int]:
        self.call_count += 1
        self.last_url = url
        return (200, {"Server": "Mock"}, b"html body", 10, 50)


class MockDiffer:
    def baseline(self, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> BaselineSignature:
        return BaselineSignature(
            status_code=status,
            body_hash="abc123hash",
            normalized_hash="normhash",
            ttfb_ms=ttfb_ms,
            total_ms=total_ms
        )

    def diff(self, base: BaselineSignature, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> DeltaVector:
        return DeltaVector(
            status_delta=status - base.status_code,
            structural_delta=0.0,
            severity=DeltaSeverity.INFO
        )


class MockUnderlyingBus:
    def __init__(self):
        self.events = []

    def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        self.events.append((event_type, payload))


@pytest.fixture
def fixtures():
    mission = WebMission(
        mission_id=MissionId(value="m-12345678"),
        scan_id=ScanId(value="s-12345678"),
        session_id=SessionId(value="ss-12345678"),
        origin="http://target.local",
        allowed_origins=["http://target.local"]
    )
    ctx = WebContext(principal_id=PrincipalId(value="p-12345678"))
    
    policy = MockPolicy()
    differ = MockDiffer()
    underlying = MockUnderlyingBus()
    strict_bus = StrictEventBus(underlying_bus=underlying, strict_mode=True)
    
    transport = MutatingTransport(policy=policy, differ=differ, bus=strict_bus)
    
    return mission, ctx, policy, differ, underlying, strict_bus, transport


def test_baseline_caches_network_calls(fixtures):
    mission, ctx, policy, differ, underlying, strict_bus, transport = fixtures
    url = "http://target.local/api"

    h1 = transport.establish_baseline(mission, ctx, WebMethod.GET, url)
    assert policy.call_count == 1
    assert h1.url == url

    # Second call for the same key shouldn't trigger network
    h2 = transport.establish_baseline(mission, ctx, WebMethod.GET, url)
    assert policy.call_count == 1
    assert h1.baseline_id == h2.baseline_id


def test_mutate_without_baseline_raises(fixtures):
    mission, ctx, policy, differ, underlying, strict_bus, transport = fixtures

    fake_baseline = BaselineSignature(
        status_code=200,
        body_hash="fake1234",
        normalized_hash="fake1234"
    )
    fake_handle = BaselineHandle(
        baseline_id="fake-key",
        signature=fake_baseline,
        request_id=RequestId(value="req-00000000"),
        principal_id=ctx.principal_id,
        method=WebMethod.GET,
        url="http://target.local"
    )

    with pytest.raises(ValueError, match="Mutation requested without a registered, valid BaselineHandle."):
        transport.mutate(
            mission=mission,
            ctx=ctx,
            handle=fake_handle,
            vuln_class=VulnerabilityClass.REFLECTION,
            mutation_label="test_reflect",
            budget_index=1,
            mutated_url="http://target.local/?q=canary",
            mutated_method=WebMethod.GET
        )


def test_mutate_fires_events_and_computes_delta(fixtures):
    mission, ctx, policy, differ, underlying, strict_bus, transport = fixtures
    url = "http://target.local/api"
    mutated_url = "http://target.local/api?q=canary"

    # Establish
    h1 = transport.establish_baseline(mission, ctx, WebMethod.GET, url)
    assert policy.call_count == 1

    # Mutate
    result = transport.mutate(
        mission=mission,
        ctx=ctx,
        handle=h1,
        vuln_class=VulnerabilityClass.REFLECTION,
        mutation_label="test_reflect",
        budget_index=1,
        mutated_url=mutated_url,
        mutated_method=WebMethod.GET
    )

    # 1 baseline + 1 mutate network hit
    assert policy.call_count == 2
    assert policy.last_url == mutated_url
    assert result.delta is not None

    # Strict Event Bus should have fully validated and dispatched our events
    event_types = [e[0] for e in underlying.events]
    assert EventType.WEB_MUTATION_ATTEMPT in event_types
    assert EventType.WEB_DELTA_DETECTED in event_types


def test_strict_event_bus_validates(fixtures):
    mission, ctx, policy, differ, underlying, strict_bus, transport = fixtures

    # Emit bad envelope (missing mission_id)
    with pytest.raises(ValueError):
        strict_bus.emit(EventEnvelope(
            event_type=EventType.WEB_AUTH_SUCCESS,
            scan_id=ScanId(value="s-12345678"),
            session_id=SessionId(value="ss-12345678"),
            # missing mission_id, though pydantic might catch it first if we construct it natively
            # but assume we somehow got an invalid dict or payload
        ))
        
    # Let's test payload validation. We'll construct a valid envelope but inject bad payload data
    # (Pydantic envelope validates basic dict, strict bus validates strict draft 2020-12 structure).
    envelope = EventEnvelope(
        event_type=EventType.WEB_AUTH_SUCCESS,
        mission_id=MissionId(value="m-12345678"),
        scan_id=ScanId(value="s-12345678"),
        session_id=SessionId(value="ss-12345678"),
        payload={"bad_key": True} # Missing required auth fields!
    )
    
    with pytest.raises(ValueError, match="Strict Event validation failure"):
        strict_bus.emit(envelope)
