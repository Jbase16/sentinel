"""
core/orchestrator.py
The Command Deck Orchestrator.
"One Click to Rule Them All."
"""

import asyncio
import logging
from typing import Dict, List

from core.scanner_engine import ScannerEngine
from core.cortex.reasoning import reasoning_engine
from core.wraith.evasion import WraithEngine
from core.ghost.flow import FlowMapper
from core.forge.compiler import ExploitCompiler
from core.findings_store import findings_store

logger = logging.getLogger(__name__)

class Orchestrator:
    """
    Automates the entire Cyber Kill Chain.
    """
    _instance = None
    
    @staticmethod
    def instance():
        if Orchestrator._instance is None:
            Orchestrator._instance = Orchestrator()
        return Orchestrator._instance

    def __init__(self):
        self.scanner = ScannerEngine()
        self.active_missions = {}

    async def start_mission(self, target: str) -> str:
        """
        The 'Link Start' button.
        """
        mission_id = f"mission_{target}_{asyncio.get_event_loop().time()}"
        self.active_missions[mission_id] = "Running"
        
        # Spawn the autonomous loop
        asyncio.create_task(self._mission_loop(target, mission_id))
        
        return mission_id

    async def _mission_loop(self, target: str, mission_id: str):
        logger.info(f"[*] Mission {mission_id} Initialized for {target}")
        
        # Phase 1: Recon (Cortex Ingestion)
        logger.info("    > Phase 1: Deep Recon")
        await self._run_recon(target) 
        
        # Phase 2: Reasoning (Synapse)
        logger.info("    > Phase 2: Neural Reasoning")
        analysis = reasoning_engine.analyze()
        opportunities = analysis.get("opportunities", [])
        
        # Phase 3: Autonomous Exploitation (Wraith/Ghost/Forge)
        logger.info("    > Phase 3: Engagement")
        await self._engage_targets(target, opportunities)
        
        logger.info(f"[*] Mission {mission_id} Complete.")
        self.active_missions[mission_id] = "Complete"

    first_pass_context = None

    async def _run_recon(self, target: str):
        from core.scan_orchestrator import ScanOrchestrator
        from core.session import ScanSession
        
        logger.info(f"    [Orchestrator] Launching ScanOrchestrator for {target}...")
        
        # Create a new isolated session for this scan
        session = ScanSession(target)
        self.active_missions[session.id] = session # Track it
        
        # ACTIVATE GHOST PROTOCOL (The Eyes)
        # We use a fixed port for the demo, but in prod we'd find a free port
        try:
             session.start_ghost(port=8080)
             logger.info("    [Orchestrator] Ghost Protocol ACTIVE on :8080")
        except Exception as e:
             logger.warning(f"    [Orchestrator] Generic Ghost startup failed: {e}")
        
        # Use a simple logger adapter
        def adptor(msg):
             logger.info(f"      [Scanner] {msg}")
             session.log(msg) # Persist to session log

        # Inject session into orchestrator
        orch = ScanOrchestrator(session=session, log_fn=adptor)
        
        # Run the scan (triggers tools, updates findings_store/knowledge_graph)
        try:
             context = await orch.run(target)
             logger.info(f"    [Orchestrator] Scan complete. Findings: {len(context.findings)}")
             self.first_pass_context = context
        except Exception as e:
             logger.error(f"    [Orchestrator] Scan failed: {e}") 

    async def _engage_targets(self, main_target: str, opportunities: List[Dict]):
        """
        The God-Tier Logic. Decides WHICH engine to deploy.
        """
        import httpx
        
        for op in opportunities:
            tool = op.get("tool")
            sub_target = op.get("target") or main_target
            payload = op.get("payload", "")
            context = op.get("context", "")
            
            try:
                if tool == "wraith_evasion":
                    # Deploy Wraith for WAF bypass
                    logger.info(f"      [Wraith] Deploying Evasion against {sub_target}")
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        result = await WraithEngine.instance().stealth_send(
                            client=client,
                            url=sub_target,
                            method="GET",
                            base_payload=payload or "<script>alert(1)</script>",
                            payload_type=op.get("payload_type", "xss")
                        )
                        logger.info(f"      [Wraith] Result: {result.get('status')}")
                    
                elif tool == "ghost_logic":
                    # Deploy Ghost for flow recording/fuzzing
                    logger.info(f"      [Ghost] Recording Flow on {sub_target}")
                    flow_id = FlowMapper.instance().start_recording(f"flow_{sub_target}")
                    logger.info(f"      [Ghost] Started flow recording: {flow_id}")
                    
                elif tool == "forge_exploit":
                    # Deploy Forge to generate exploit
                    logger.info(f"      [Forge] Compiling Zero-Day for {sub_target}")
                    exploit_path = ExploitCompiler.instance().compile_exploit(
                        target=sub_target,
                        anomaly_context=context or f"Target endpoint: {sub_target}"
                    )
                    logger.info(f"      [Forge] Generated exploit at: {exploit_path}")
                    
                else:
                    logger.info(f"      [Standard] Running {tool} against {sub_target}")
                    
            except Exception as e:
                logger.error(f"      [Engagement] Failed {tool} on {sub_target}: {e}")
