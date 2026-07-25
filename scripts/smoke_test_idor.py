import time
import os
import glob
import json
import logging
import shutil
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smoke_test_idor")

import httpx
from pydantic import HttpUrl

from core.web.contracts.models import WebMission, PrincipalProfile
from core.web.contracts.enums import VulnerabilityClass, WebAuthMode
from core.web.contracts.ids import MissionId, ScanId, SessionId, PrincipalId
from core.web.context import WebContext
from core.web.orchestrator import WebOrchestrator
from core.web.crawler import ExecutionPolicy
from core.web.event_bus import UnderlyingBus
from core.web.auth_manager import AuthManager

class HttpxPolicy(ExecutionPolicy):
    
    def assert_url_allowed(self, mission: WebMission, url: str) -> None:
        pass
        
    def http_get(self, mission: WebMission, ctx: WebContext, url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        resp = ctx.client.get(url, headers=headers)
        return resp.status_code, dict(resp.headers), resp.content

    def http_request(
        self,
        mission: WebMission,
        ctx: WebContext,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes, int, int]:
        start = time.perf_counter()
        
        req = ctx.client.build_request(method, url, headers=headers, content=body)
        resp = ctx.client.send(req)
        end = time.perf_counter()
        total_ms = int((end - start) * 1000)
        ttfb_ms = total_ms // 2
        return resp.status_code, dict(resp.headers), resp.content, ttfb_ms, total_ms


class LoggingBus(UnderlyingBus):
    def __init__(self):
        self.events: List[tuple[str, dict]] = []
        self.event_counts: Dict[str, int] = {}
        
    def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        self.events.append((event_type, payload))
        self.event_counts[event_type] = self.event_counts.get(event_type, 0) + 1
        logger.info(f"EMITTED EVENT: {event_type}")


def run_smoke_test():
    # Clean up previous artifacts
    if os.path.exists("artifacts"):
        shutil.rmtree("artifacts")
        
    target_url = "http://localhost:8081"
    
    mission = WebMission(
        mission_id=MissionId(value="m-idor-test"),
        scan_id=ScanId(value="s-idor-test"),
        session_id=SessionId(value="ss-idor-test"),
        origin=HttpUrl(target_url), # type: ignore
        allowed_origins=[target_url],
        max_depth=2,
        max_pages=50,
        exploit_ceiling=200,
        auth_mode=WebAuthMode.FORM_LOGIN,
        principal_count=2,
        allow_secret_artifacts=True
    )
    
    ctx_a = WebContext(principal_id=PrincipalId(value="p-owner123"))
    prof_a = PrincipalProfile(
        principal_id=ctx_a.principal_id,
        login_url=HttpUrl(f"{target_url}/login"), # type: ignore
        username="owner",
        password="password!"
    )

    ctx_b = WebContext(principal_id=PrincipalId(value="p-attk123"))
    prof_b = PrincipalProfile(
        principal_id=ctx_b.principal_id,
        login_url=HttpUrl(f"{target_url}/login"), # type: ignore
        username="attacker",
        password="password!"
    )
    
    policy = HttpxPolicy()
    bus = LoggingBus()
    
    from core.web.event_bus import StrictEventBus
    strict_bus = StrictEventBus(underlying_bus=bus, strict_mode=True)
    
    auth_mgr = AuthManager(bus=strict_bus)
    auth_mgr.bootstrap(mission, ctx_a, prof_a)
    auth_mgr.bootstrap(mission, ctx_b, prof_b)
    
    orchestrator = WebOrchestrator(policy=policy, underlying_bus=bus)
    
    logger.info("Starting Multi-Principal IDOR Orchestrator run")
    results = orchestrator.run_multi_principal_scan(mission, ctx_a, ctx_b)
    
    logger.info(f"Mutation Results Count: {len(results)}")
    
    assert bus.event_counts.get("WEB_EVIDENCE_BUNDLE_CREATED", 0) > 0, "Missing evidence bundle event"
    assert bus.event_counts.get("WEB_FINDING_CONFIRMED", 0) > 0, "Missing finding confirmed event"

    evidence_files = glob.glob("artifacts/evidence/*.json")
    assert len(evidence_files) > 0, f"Expected > 0 evidence files, found {len(evidence_files)}"
    
    with open(evidence_files[0], "r") as f:
        bundle = json.load(f)
        assert len(bundle["request_sequence"]) == 2, "Expected baseline and mutated exchange in sequence"
        assert bundle["finding_id"]["value"].startswith("f-"), "Expected deterministic finding_id"
        assert len(bundle["affected_principals"]) == 2, "Expected 2 affected principals"
        assert bundle["vuln_class"] == VulnerabilityClass.IDOR.value, "Expected IDOR vuln class"
        
    replay_files = glob.glob("artifacts/replays/*.py")
    assert len(replay_files) > 0, f"Expected > 0 replay files, found {len(replay_files)}"
        
    logger.info("All IDOR Evidence Generation Assertions Passed!")


if __name__ == "__main__":
    run_smoke_test()
