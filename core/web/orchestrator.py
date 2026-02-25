from __future__ import annotations

import logging
from typing import List

from .contracts.models import WebMission
from .context import WebContext
from .surface_registry import SurfaceRegistry
from .crawler import HttpCrawler, ExecutionPolicy
from .event_bus import StrictEventBus, UnderlyingBus
from .transport import MutatingTransport, MutationResult
from .mutate.reflection import ReflectionMutator
from .evidence_service import EvidenceService

logger = logging.getLogger(__name__)


class WebOrchestrator:
    """
    Executes the single-principal discovery-to-mutation loop.
    Ties together the Crawler, SurfaceRegistry, and Mutators via the MutatingTransport.
    """
    def __init__(self, policy: ExecutionPolicy, underlying_bus: UnderlyingBus) -> None:
        self.policy = policy
        self.strict_bus = StrictEventBus(underlying_bus=underlying_bus, strict_mode=True)
        
        from .diff.baseline import BaselineBuilder
        from .diff.delta import DeltaEngine
        
        class RealDiffer:
            def __init__(self):
                self.b = BaselineBuilder()
                self.d = DeltaEngine()
            def baseline(self, status: int, headers: dict[str, str], body: bytes, ttfb: int, total: int):
                return self.b.build(status, headers, body, ttfb, total)
            def diff(self, base, status: int, headers: dict[str, str], body: bytes, ttfb: int, total: int):
                return self.d.diff(base, status, headers, body, ttfb, total)

        # Using typing.cast or ignoring typing issues since ExecutionPolicy protocols might have slight overlaps
        self.transport = MutatingTransport(policy=self.policy, differ=RealDiffer(), bus=self.strict_bus) # type: ignore
        self.crawler = HttpCrawler(policy=self.policy, bus=self.strict_bus) # type: ignore
        self.registry = SurfaceRegistry()
        
        # In a real setup, artifacts_dir would come from configuration/mission config
        self.evidence_service = EvidenceService(bus=self.strict_bus, artifacts_dir="artifacts")

    def run_single_principal_scan(self, mission: WebMission, ctx: WebContext) -> List[MutationResult]:
        """
        Executes Steps 1-4 of the core engine pipeline:
        Surface -> Registry -> Reflection -> Evidence (stubbed here as MutationResult return)
        """
        logger.info(f"Starting single-principal scan for mission {mission.mission_id}")
        
        # 1. Surface Discovery
        logger.info(f"Crawling origin: {mission.origin}")
        self.crawler.crawl(mission, ctx, self.registry)
        
        # 2. Extract registered endpoints
        urls, assets, endpoints = self.registry.snapshot()
        logger.info(f"Discovered {len(urls)} URLs, {len(endpoints)} endpoint candidates")
        
        # 3. Reflection Mutation
        results: List[MutationResult] = []
        reflection = ReflectionMutator()
        
        budget_index = 0
        for endpoint in endpoints:
            if budget_index >= mission.exploit_ceiling:
                logger.warning("Exploit ceiling reached, halting mutations.")
                break
                
            # Reflection currently only handles GET parameters deterministically
            if endpoint.method.value != "GET":
                continue
                
            endpoint_results = reflection.run(
                mission=mission,
                ctx=ctx,
                transport=self.transport,
                url=str(endpoint.url),
                method=endpoint.method,
                budget_index=budget_index
            )
            
            # Step 6 Evidence Creation for confirmed results
            for res in endpoint_results:
                self.evidence_service.confirm(
                    mission=mission,
                    contexts=[ctx],
                    vuln_class=reflection.vuln_class,
                    param_spec=res.param_spec,
                    handle=self.transport.get_registered_baseline(
                        principal_id=ctx.principal_id,
                        method=endpoint.method,
                        url=str(endpoint.url)
                    ),
                    mutation=res,
                    title="Reflected Parameter",
                    summary="Deterministic reflection canary detected in response body."
                )

            results.extend(endpoint_results)
            budget_index += len(endpoint_results)
            
        logger.info(f"Scan complete. Generated {len(results)} reflection mutation results.")
        return results

    def run_multi_principal_scan(self, mission: WebMission, ctx_a: WebContext, ctx_b: WebContext) -> List[MutationResult]:
        """
        Executes IDOR Multi-Principal scanning. 
        Crawls as Principal A, then attempts to access all discovered resources as Principal B.
        """
        from .mutate.idor import MultiPrincipalDiffEngine
        
        logger.info(f"Starting multi-principal IDOR scan for mission {mission.mission_id}")
        
        # 1. Surface Discovery under Principal A
        logger.info(f"Crawling origin as Principal A: {mission.origin}")
        self.crawler.crawl(mission, ctx_a, self.registry)
        
        urls, assets, endpoints = self.registry.snapshot()
        logger.info(f"Discovered {len(urls)} URLs, {len(endpoints)} endpoint candidates")
        
        results: List[MutationResult] = []
        idor_engine = MultiPrincipalDiffEngine()
        
        budget_index = 0
        for endpoint in endpoints:
            if budget_index >= mission.exploit_ceiling:
                logger.warning("Exploit ceiling reached, halting mutations.")
                break
                
            if endpoint.method.value != "GET":
                continue
                
            endpoint_results = idor_engine.run(
                mission=mission,
                ctx_a=ctx_a,
                ctx_b=ctx_b,
                transport=self.transport,
                url=str(endpoint.url),
                method=endpoint.method,
                budget_index=budget_index
            )
            
            for res in endpoint_results:
                self.evidence_service.confirm(
                    mission=mission,
                    contexts=[ctx_a, ctx_b],
                    vuln_class=idor_engine.vuln_class,
                    param_spec=None,
                    handle=self.transport.get_registered_baseline(
                        principal_id=ctx_a.principal_id,
                        method=endpoint.method,
                        url=str(endpoint.url)
                    ),
                    mutation=res,
                    title="Insecure Direct Object Reference (IDOR)",
                    summary="Cross-principal authorization bypass detected. Principal B successfully accessed Principal A's baseline resource with structurally identical response."
                )

            results.extend(endpoint_results)
            budget_index += 1  # 1 mutation attempt per endpoint
            
        logger.info(f"Cross-principal scan complete. Generated {len(results)} IDOR mutation results.")
        return results
