import time
import os
import glob
import json
import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smoke_test")

import httpx
from pydantic import HttpUrl

from core.web.contracts.models import WebMission
from core.web.contracts.ids import MissionId, ScanId, SessionId, PrincipalId
from core.web.context import WebContext
from core.web.orchestrator import WebOrchestrator
from core.web.crawler import ExecutionPolicy
from core.web.event_bus import UnderlyingBus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smoke_test")


class HttpxPolicy(ExecutionPolicy):
    def __init__(self):
        # We use a synchronous client to fit the ExecutionPolicy synchronous signature
        self.client = httpx.Client(verify=False, follow_redirects=True)
    
    def assert_url_allowed(self, mission: WebMission, url: str) -> None:
        pass # In a real scenario we check against mission.allowed_origins
        
    def http_get(self, mission: WebMission, ctx: WebContext, url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        resp = self.client.get(url, headers=headers)
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
        req = self.client.build_request(method, url, headers=headers, content=body)
        resp = self.client.send(req)
        end = time.perf_counter()
        total_ms = int((end - start) * 1000)
        # Fake ttfb for now, just total_ms / 2
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
    target_url = "http://localhost:8081"
    
    mission = WebMission(
        mission_id=MissionId(value="m-smoke123"),
        scan_id=ScanId(value="s-smoke123"),
        session_id=SessionId(value="ss-smoke123"),
        origin=HttpUrl(target_url), # type: ignore
        allowed_origins=[target_url],
        max_depth=2,
        max_pages=50,
        exploit_ceiling=200
    )
    
    ctx = WebContext(principal_id=PrincipalId(value="p-smoke123"))
    policy = HttpxPolicy()
    bus = LoggingBus()
    
    orchestrator = WebOrchestrator(policy=policy, underlying_bus=bus)
    
    logger.info("Starting Orchestrator run on Juice Shop")
    results = orchestrator.run_single_principal_scan(mission, ctx)
    
    logger.info(f"Mutation Results Count: {len(results)}")
    logger.info("Event Counts:")
    for etype, count in bus.event_counts.items():
        logger.info(f"  {etype}: {count}")
        
    assert bus.event_counts.get("WEB_EVIDENCE_BUNDLE_CREATED", 0) == 1, "Missing evidence bundle event"
    assert bus.event_counts.get("WEB_FINDING_CONFIRMED", 0) == 1, "Missing finding confirmed event"

    evidence_files = glob.glob("artifacts/evidence/*.json")
    assert len(evidence_files) == 1, f"Expected 1 evidence file, found {len(evidence_files)}"
    
    with open(evidence_files[0], "r") as f:
        bundle = json.load(f)
        assert len(bundle["request_sequence"]) == 2, "Expected baseline and mutated exchange in sequence"
        assert bundle["vulnerable_param"]["name"] == "q", "Expected 'q' param to be vulnerable"
        assert bundle["finding_id"]["value"].startswith("f-"), "Expected deterministic finding_id"
        
    replay_files = glob.glob("artifacts/replays/*.py")
    assert len(replay_files) == 1, f"Expected 1 replay file, found {len(replay_files)}"
    with open(replay_files[0], "r") as f:
        content = f.read()
        assert "sntnl_rflct_" in content, "Expected canary in replay script"
        
    logger.info("All Evidence Generation Assertions Passed!")


if __name__ == "__main__":
    run_smoke_test()
