"""
core/orchestrator.py
The Command Deck Orchestrator.
"One Click to Rule Them All."
"""

import asyncio
import logging
from typing import Dict, List

from core.engine.scanner_engine import ScannerEngine
from core.cortex.reasoning import reasoning_engine
from core.wraith.evasion import WraithEngine
from core.ghost.flow import FlowMapper
from core.forge.compiler import ExploitCompiler
from core.data.findings_store import findings_store
from core.base.task_router import TaskRouter
from core.utils.async_helpers import create_safe_task

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
        self.router = TaskRouter.instance()
        self.active_missions = {}

    async def start_mission(self, target: str) -> str:
        """
        The 'Link Start' button.
        """
        mission_id = f"mission_{target}_{asyncio.get_event_loop().time()}"
        self.active_missions[mission_id] = {"status": "Running", "phase": "init", "target": target}
        
        # Emit mission started event
        self._emit_progress(mission_id, "started", "Mission initialized", phase="init")
        
        # Spawn the autonomous loop with error handling
        create_safe_task(self._mission_loop(target, mission_id), name=f"mission_{mission_id}")
        
        return mission_id
    
    def _emit_progress(self, mission_id: str, status: str, message: str, phase: str = None, details: dict = None):
        """Emit mission progress events to UI via TaskRouter."""
        payload = {
            "mission_id": mission_id,
            "status": status,
            "message": message,
            "phase": phase,
            "details": details or {}
        }
        if mission_id in self.active_missions:
            self.active_missions[mission_id]["status"] = status
            if phase:
                self.active_missions[mission_id]["phase"] = phase
        self.router.emit("mission_progress", payload)

    async def _mission_loop(self, target: str, mission_id: str):
        logger.info(f"[*] Mission {mission_id} Initialized for {target}")
        
        try:
            # Phase 1: Recon (Cortex Ingestion)
            logger.info("    > Phase 1: Deep Recon")
            self._emit_progress(mission_id, "running", "Starting deep reconnaissance", phase="recon")
            await self._run_recon(target)
            self._emit_progress(mission_id, "running", "Reconnaissance complete", phase="recon", 
                              details={"findings": len(self.first_pass_context.findings) if self.first_pass_context else 0})
            
            # Phase 2: Reasoning (Synapse)
            logger.info("    > Phase 2: Neural Reasoning")
            self._emit_progress(mission_id, "running", "Analyzing attack surface", phase="reasoning")
            analysis = reasoning_engine.analyze()
            opportunities = analysis.get("opportunities", [])
            risks = analysis.get("risks", [])
            self._emit_progress(mission_id, "running", f"Found {len(opportunities)} opportunities, {len(risks)} risks", 
                              phase="reasoning", details={"opportunities": len(opportunities), "risks": len(risks)})
            
            # Phase 3: Autonomous Exploitation (Wraith/Ghost/Forge)
            logger.info("    > Phase 3: Engagement")
            self._emit_progress(mission_id, "running", f"Engaging {len(opportunities)} targets", phase="engagement")
            await self._engage_targets(target, opportunities, mission_id)
            
            logger.info(f"[*] Mission {mission_id} Complete.")
            self._emit_progress(mission_id, "complete", "Mission completed successfully", phase="complete")
            
        except Exception as e:
            logger.error(f"[*] Mission {mission_id} Failed: {e}")
            self._emit_progress(mission_id, "failed", f"Mission failed: {str(e)}", phase="error")

    first_pass_context = None

    async def _run_recon(self, target: str):
        from core.engine.scan_orchestrator import ScanOrchestrator
        from core.base.session import ScanSession
        from core.scheduler.strategos import Strategos
        from core.scheduler.modes import ScanMode
        
        logger.info(f"    [Orchestrator] Launching Strategos for {target}...")
        
        session = ScanSession(target)
        self.active_missions[session.id] = session 
        
        try:
             session.start_ghost(port=8080)
             logger.info("    [Orchestrator] Ghost Protocol ACTIVE on :8080")
        except Exception as e:
             logger.warning(f"    [Orchestrator] Generic Ghost startup failed: {e}")
        
        def adapter(msg):
             logger.info(f"      [Scanner] {msg}")
             session.log(msg) 

        detector = ScanOrchestrator(session=session, log_fn=adapter)
        brain = Strategos()
        
        # Decide Mode (Default to Standard, but could be Bug Bounty)
        mode = ScanMode.STANDARD
        
        try:
             installed_tools = list(detector._detect_installed().keys())
             logger.info(f"    [Strategos] Detected {len(installed_tools)} available tools.")
             
             # === DISPATCH CALLBACK ===
             # This is called by Strategos for each tool to run.
             # Returns findings list (Strategos handles ingestion via events).
             async def dispatch_tool(tool: str) -> List[Dict]:
                 """
                 Runs the tool via worker and returns findings.
                 """
                 logger.info(f"    [Orchestrator] Dispatching {tool} to Worker...")
                 
                 tool_worker = ScanOrchestrator(session=session, log_fn=adapter)
                 
                 # Run the single tool
                 context = await tool_worker.run(target, modules=[tool], mode=mode.value)
                 
                 # Return findings for event queue
                 if context and context.findings:
                     return context.findings
                 return []
             
             # === RUN THE MISSION ===
             result = await brain.run_mission(
                 target=target,
                 available_tools=installed_tools,
                 mode=mode,
                 dispatch_tool=dispatch_tool
             )
             
             logger.info(f"    [Orchestrator] Mission Complete: {result.reason}")
             self.first_pass_context = brain.context
        except Exception as e:
             logger.error(f"    [Orchestrator] Scan failed: {e}")  

    async def _engage_targets(self, main_target: str, opportunities: List[Dict], mission_id: str = None):
        """
        The God-Tier Logic. Decides WHICH engine to deploy.
        """
        import httpx
        
        total = len(opportunities)
        for idx, op in enumerate(opportunities, 1):
            tool = op.get("tool")
            sub_target = op.get("target") or main_target
            payload = op.get("payload", "")
            context = op.get("context", "")
            
            # Emit per-engagement progress
            if mission_id:
                self._emit_progress(mission_id, "running", f"Engaging target {idx}/{total}: {tool}", 
                                  phase="engagement", details={"tool": tool, "target": sub_target, "progress": f"{idx}/{total}"})
            
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
                if mission_id:
                    self._emit_progress(mission_id, "warning", f"Engagement failed: {tool} on {sub_target}",
                                      phase="engagement", details={"error": str(e), "tool": tool})
