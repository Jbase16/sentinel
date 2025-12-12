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
        
        logger.info(f"    [Orchestrator] Launching ScanOrchestrator for {target}...")
        
        # Use a simple logger adapter
        def adptor(msg):
             logger.info(f"      [Scanner] {msg}")

        orch = ScanOrchestrator(log_fn=adptor)
        
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
        for op in opportunities:
            tool = op.get("tool")
            sub_target = op.get("target") or main_target
            
            if tool == "wraith_evasion":
                # Deploy Wraith
                logger.info(f"      [Wraith] Deploying Evasion against {sub_target}")
                # await WraithEngine.instance().stealth_send(...)
                
            elif tool == "ghost_logic":
                # Deploy Ghost
                logger.info(f"      [Ghost] Fuzzing Logic on {sub_target}")
                # fid = FlowMapper.instance().start_recording(...)
                
            elif tool == "forge_exploit":
                # Deploy Forge
                logger.info(f"      [Forge] Compiling Zero-Day for {sub_target}")
                # ExploitCompiler.instance().compile_exploit(...)
                
            else:
                logger.info(f"      [Standard] Running {tool} against {sub_target}")
