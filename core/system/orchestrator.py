"""
core/system/orchestrator.py

Purpose:
    The "Cortex".
    Bootstraps the 5 Pillars, wires them together, and manages the system lifecycle.
    
    Boot Order:
    1. Observer (Listen to boot)
    2. Data/Config (Memory)
    3. Aegis/Thanatos/Sentient (Reasoning)
    4. Executor (Action)
    5. Feedback (Learning)

Magnum Opus Standards:
    - Graceful Shutdown: Ensures no data loss on exit.
    - Explicit Wiring: No global state magic (except Singleton Bus).
    - Event-Driven: Emits lifecycle events.
"""

import asyncio
import logging
from typing import Optional

# Pillar I: Data & Reasoning
from core.data.db import Database
from core.data.pressure_graph.manager import PressureGraphManager

# Pillar II: Planning
from core.thanatos.ontology_breaker import OntologyBreakerService
from core.thanatos.scope_gate import ScopeGate, ScopePolicy
from core.thanatos.axiom_synthesizer import StandardAxiomSynthesizer

# Pillar III: Observer
from core.observer import get_event_bus, EventType, EventLevel, TelemetryEvent
from core.observer.sinks import FileSink, ConsoleSink
from core.observer.feedback import FeedbackLoop, DefaultFeedbackPolicy

# Pillar IV: Governance
from core.sentient.service import SentientService
from core.sentient.ethics import EthicalGuard
from core.sentient.economics import EconomicEngine

# Pillar V: Executor
from core.executor import HttpHarness, SafetyInterlock, StandardOracleEvaluator
from core.executor.models import ExecutionOrder, ExecutionStatus

log = logging.getLogger("system.orchestrator")

class SystemOrchestrator:
    def __init__(self):
        self.bus = get_event_bus()
        self.db: Optional[Database] = None
        self.file_sink: Optional[FileSink] = None
        
        # Subsystems
        self.aegis: Optional[PressureGraphManager] = None
        self.thanatos: Optional[OntologyBreakerService] = None
        self.sentient: Optional[SentientService] = None
        self.executor_harness: Optional[HttpHarness] = None
        self.oracle: Optional[StandardOracleEvaluator] = None
        self.interlock: Optional[SafetyInterlock] = None
        
        self.feedback: Optional[FeedbackLoop] = None
        
        self._is_running = False

    async def boot(self):
        """
        Initialize the Cognitive Architecture.
        """
        print("⚡️ System Boot Sequence Initiated...")
        
        # 1. Start Observer (Eyes & Ears)
        self.file_sink = FileSink("logs/system_events.jsonl")
        await self.file_sink.start()
        
        self.bus.subscribe("*", self.file_sink.handle)
        self.bus.subscribe("*", ConsoleSink().handle)
        
        await self._emit_lifecycle("BOOT_START")

        # 2. Start Data Layer (Memory)
        self.db = Database.instance()
        await self.db.init() 
        
        # Aegis manages its own DB internal reference usually, but we pass session_id
        session_id = "live_campaign_001"
        self.aegis = PressureGraphManager(session_id=session_id)
        
        # 3. Start Reasoning Engines
        gate = ScopeGate(ScopePolicy())
        synth = StandardAxiomSynthesizer()
        
        self.thanatos = OntologyBreakerService(
            scope_gate=gate,
            synthesizer=synth
        )
        
        self.sentient = SentientService(
            ethics=EthicalGuard(),
            economics=EconomicEngine(),
        )
        
        # 4. Start Executor (Hands)
        self.interlock = SafetyInterlock()
        self.executor_harness = HttpHarness()
        self.oracle = StandardOracleEvaluator()
        
        # 5. Wire Feedback (Nerves)
        self.feedback = FeedbackLoop(
            pressure_system=self.aegis,
            economic_system=self.sentient.economics,
            policy=DefaultFeedbackPolicy()
        )
        self.feedback.start()

        await self._emit_lifecycle("BOOT_COMPLETE", status="READY")
        self._is_running = True
        log.info("System Online.")

    async def shutdown(self):
        """
        Graceful Teardown.
        """
        log.info("Initiating Shutdown...")
        await self._emit_lifecycle("SYSTEM_SHUTDOWN", reason="USER_REQUEST")

        # 1. Stop Executor
        await HttpHarness.close_client()
        
        # 2. Stop Data (Save Graph)
        if self.aegis:
            await self.aegis.save_snapshot()
        
        if self.db:
            await self.db.close()
            
        # 3. Stop Observer (Last)
        if self.file_sink:
            await self.file_sink.stop()
            
        print("💤 System Shutdown Complete.")

    async def run_campaign(self, target_url: str):
        """
        The Main Cognitive Loop against a specific Target.
        Reason -> Plan -> Decide -> Act -> Evaluate
        """
        if not self._is_running:
            raise RuntimeError("System not booted.")

        log.info(f"🚀 Starting Campaign against {target_url}")
        
        # 0. Scope Definition
        # Seed a dummy node manually
        from core.data.pressure_graph.models import PressureNode, PressureSource, RemediationState
        node = PressureNode(
            id="target_root",
            type="service",
            severity=1.0,
            exposure=1.0,
            exploitability=0.5,
            privilege_gain=0.1,
            asset_value=10.0,
            tool_reliability=1.0, 
            evidence_quality=1.0,
            corroboration_count=0,
            pressure_source=PressureSource.MANUAL,
            remediation_state=RemediationState.NONE
        )
        self.aegis.nodes["target_root"] = node
        
        # Loop limit for safety
        max_cycles = 5
        cycle = 0
        
        while cycle < max_cycles:
            cycle += 1
            log.info(f"--- Cycle {cycle}/{max_cycles} ---")
            
            # 1. REASON (Aegis)
            focus_node = "target_root" 
            
            # 2. PLAN (Thanatos)
            from core.thanatos.models import TargetHandle
            handle = TargetHandle(
                node_id=focus_node,
                endpoint=target_url,
                method="GET",
                value=5.0
            )

            test_cases = self.thanatos.hallucinate_batch(
                target=handle
            )
            
            if not test_cases:
                log.warning("Thanatos returned no ideas. Stopping.")
                break
                
            test_case = test_cases[0]
            log.info(f"Hypothesis: {test_case.hypothesis.invariant} on {test_case.target.endpoint}")

            # 3. DECIDE (Sentient)
            decision = self.sentient.decide(
                target_context={"target_value": test_case.target.value},
                risk_level=0.5 # Mock risk
            )
            
            # Enum check
            from core.sentient.models import Verdict
            if decision.verdict != Verdict.APPROVE:
                log.warning(f"Sentient BLOCKED: {decision.rationale}")
                continue # Or break? Continue allows trying next idea if list was bigger
                
            log.info(f"Sentient APPROVED: {decision.rationale}")
            
            # 4. ACT (Executor)
            order = ExecutionOrder(test_case=test_case, decision=decision)
            
            # Interlock Check
            lock_reason = self.interlock.check(order)
            if lock_reason:
                log.error(f"Interlock ENGAGED: {lock_reason}")
                break
                
            # Execute
            await self.bus.emit(TelemetryEvent(
                type=EventType.EXECUTION_STARTED, source="Orchestrator", level=EventLevel.INFO,
                payload={"order_id": order.order_id}
            ))

            result = await self.executor_harness.execute(order)
            
            await self.bus.emit(TelemetryEvent(
                type=EventType.EXECUTION_COMPLETED, source="Orchestrator", level=EventLevel.INFO,
                payload={"duration_ms": result.duration_ms},
                trace_id=order.order_id
            ))
            
            # 5. EVALUATE (Oracle)
            breach_status = self.oracle.evaluate(result, test_case.oracle)
            
            from core.executor.models import BreachStatus
            if breach_status == BreachStatus.BREACH:
                log.critical(f"🚨 BREACH CONFIRMED: {test_case.id}")
                await self.bus.emit(TelemetryEvent(
                    type=EventType.BREACH_DETECTED, source="Oracle", level=EventLevel.CRITICAL,
                    payload={"target_node_id": focus_node, "severity": 10.0},
                    trace_id=order.order_id
                ))
            elif breach_status == BreachStatus.SECURE:
                 log.info(f"Target Verified SECURE ({result.status}).")
            
            await asyncio.sleep(0.5) # Pacing
            
        log.info("Campaign Complete.")

    async def _emit_lifecycle(self, phase: str, **kwargs):
        await self.bus.emit(TelemetryEvent(
            type=EventType.SYSTEM_STARTUP if "BOOT" in phase else EventType.SYSTEM_SHUTDOWN, 
            source="Orchestrator", 
            level=EventLevel.INFO,
            payload={"phase": phase, **kwargs}
        ))
