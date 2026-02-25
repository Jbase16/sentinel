import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("auth_isolation_test")

from pydantic import HttpUrl

from core.web.contracts.models import WebMission, PrincipalProfile
from core.web.contracts.enums import WebAuthMode
from core.web.contracts.ids import MissionId, ScanId, SessionId, PrincipalId
from core.web.context import WebContext
from core.web.auth_manager import AuthManager
from core.web.event_bus import UnderlyingBus
from core.web.transport import MutatingTransport

class LoggingBus(UnderlyingBus):
    def __init__(self):
        self.events: List[tuple[str, dict]] = []
        self.event_counts: Dict[str, int] = {}
        
    def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        self.events.append((event_type, payload))
        self.event_counts[event_type] = self.event_counts.get(event_type, 0) + 1
        logger.info(f"EMITTED EVENT: {event_type}")

def test_isolation():
    target_url = "http://localhost:8081"
    
    mission = WebMission(
        mission_id=MissionId(value="m-auth-test"),
        scan_id=ScanId(value="s-auth-test"),
        session_id=SessionId(value="ss-auth-test"),
        origin=HttpUrl(target_url), # type: ignore
        allowed_origins=[target_url],
        auth_mode=WebAuthMode.FORM_LOGIN,
        principal_count=2
    )

    ctx_a = WebContext(principal_id=PrincipalId(value="p-alice123"))
    prof_a = PrincipalProfile(
        principal_id=ctx_a.principal_id,
        login_url=HttpUrl("http://localhost:8081/login"), # type: ignore
        username="alice",
        password="password!"
    )

    ctx_b = WebContext(principal_id=PrincipalId(value="p-bob12345"))
    prof_b = PrincipalProfile(
        principal_id=ctx_b.principal_id,
        login_url=HttpUrl("http://localhost:8081/login"), # type: ignore
        username="bob",
        password="password!"
    )

    bus = LoggingBus()
    from core.web.event_bus import StrictEventBus
    strict_bus = StrictEventBus(underlying_bus=bus, strict_mode=True)
    
    auth_mgr = AuthManager(bus=strict_bus)

    # 1. Login as A
    auth_mgr.bootstrap(mission, ctx_a, prof_a)
    
    # 2. Login as B
    auth_mgr.bootstrap(mission, ctx_b, prof_b)

    # 3. Confirm cookie jars differ
    logger.info(f"Alice Cookies: {ctx_a.client.cookies}")
    logger.info(f"Bob Cookies:   {ctx_b.client.cookies}")
    assert ctx_a.client.cookies != ctx_b.client.cookies, "Cookie Jars MUST differ"
    assert "sess_alice" in str(ctx_a.client.cookies), "Alice's session cookie not found"
    assert "sess_bob" in str(ctx_b.client.cookies), "Bob's session cookie not found"

    # 4. Confirm CSRF tokens differ
    assert "csrf_alice" in str(ctx_a.client.cookies)
    assert "csrf_bob" in str(ctx_b.client.cookies)

    # 5. Confirm baseline keys differ (if testing transport context injection)
    from core.web.contracts.enums import WebMethod
    
    # We can test by mocking ExecutionPolicy and running establish_baseline
    class MockPolicy:
        def assert_url_allowed(self, m, u): pass
        def http_request(self, mission, ctx, method, url, headers=None, body=None):
            return 200, {}, b"OK", 10, 20

    from core.web.diff.baseline import BaselineBuilder
    from core.web.diff.delta import DeltaEngine
    class RealDiffer:
        def __init__(self):
            self.b = BaselineBuilder()
            self.d = DeltaEngine()
        def baseline(self, status, headers, body, ttfb, total):
            return self.b.build(status, headers, body, ttfb, total)
        def diff(self, base, status, headers, body, ttfb, total):
            return self.d.diff(base, status, headers, body, ttfb, total)

    t = MutatingTransport(policy=MockPolicy(), differ=RealDiffer(), bus=strict_bus)
    
    h_a = t.establish_baseline(mission, ctx_a, WebMethod.GET, "http://localhost:8081/profile")
    h_b = t.establish_baseline(mission, ctx_b, WebMethod.GET, "http://localhost:8081/profile")

    assert h_a.baseline_id != h_b.baseline_id, "Baseline keys MUST differ between principals"

    assert bus.event_counts.get("WEB_AUTH_ESTABLISHED", 0) == 2, "Expected 2 auth events"

    logger.info("All Principal Isolation Tests Passed!")

if __name__ == "__main__":
    test_isolation()
