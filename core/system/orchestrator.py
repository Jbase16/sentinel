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
import uuid
from typing import Optional

# Pillar I: Data & Reasoning
from core.data.db import Database
from core.data.pressure_graph.manager import PressureGraphManager

# Pillar II: Planning
from core.thanatos.ontology_breaker import OntologyBreakerService
from core.thanatos.scope_gate import ScopeGate, ScopePolicy
from core.thanatos.axiom_synthesizer import MutationEngine

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

# Pillar VI: Identity
from core.doppelganger.engine import DoppelgangerEngine
from core.doppelganger.models import Credential, Role

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
        self.doppelganger: Optional[DoppelgangerEngine] = None
        
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
        
        # Ensure Session Exists
        self.db.save_session({
            "id": session_id,
            "target": "integrated_test",
            "status": "active"
        })
        
        self.pg_manager = PressureGraphManager(session_id=session_id)
        # self.sentient handles decisions
        
        # 3. Start Reasoning Engines
        gate = ScopeGate(ScopePolicy())
        synth = MutationEngine()
        
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
        self.doppelganger = DoppelgangerEngine()
        
        # 5. Wire Feedback (Nerves)
        self.feedback = FeedbackLoop(
            pressure_system=self.pg_manager,
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
        if self.pg_manager:
            await self.pg_manager.save_snapshot()
        
        if self.db:
            await self.db.close()
            
        # 3. Stop Observer (Last)
        if self.file_sink:
            await self.file_sink.stop()
            
        print("💤 System Shutdown Complete.")

    async def run_campaign(self, target_url: str):
        """
        The Main Cognitive Loop against a defined Profile.
        Discovery -> Reason -> Plan -> Decide -> Act -> Evaluate
        """
        if not self._is_running:
            raise RuntimeError("System not booted.")

        log.info(f"🚀 Starting Campaign against {target_url}")
        
        # 0. Scope Definition (Profile)
        # In a real run, this comes from the "Observer" (Recon) phase.
        # Here we seed it as a static profile per user request.
        JUICE_SHOP_PROFILE = {
            "base_url": target_url,
            "surfaces": [
                {"endpoint": "/rest/products/search", "method": "GET", "value": 6.0},
                {"endpoint": "/rest/user/login", "method": "POST", "value": 9.0},
                {"endpoint": "/api/Users", "method": "GET", "value": 8.0},
                {"endpoint": "/profile", "method": "GET", "value": 7.0},
            ]
        }

        # Imports for the loop
        from core.data.pressure_graph.models import PressureNode, PressureSource, RemediationState
        from core.thanatos.models import TargetHandle
        from core.sentient.models import Verdict
        from core.executor.models import BreachStatus

        # 1. DISCOVERY & SEEDING (Aegis)
        for surface in JUICE_SHOP_PROFILE["surfaces"]:
            endpoint = surface["endpoint"]
            # Create a unique node ID for the graph
            node_id = f"service:{endpoint}" 
            
            node = PressureNode(
                id=node_id,
                type="service_endpoint",
                severity=1.0, # Baseline
                exposure=1.0,
                exploitability=0.5,
                privilege_gain=0.1,
                asset_value=surface["value"],
                tool_reliability=1.0, 
                evidence_quality=1.0,
                corroboration_count=0,
                pressure_source=PressureSource.ENGINE, 
                remediation_state=RemediationState.NONE
            )
            
            # Update Graph
            self.pg_manager.nodes[node_id] = node
            
            # Emit Discovery Event
            await self.bus.emit(TelemetryEvent(
                type=EventType.ASSET_DISCOVERED,
                source="Orchestrator",
                level=EventLevel.INFO,
                payload={
                    "node_id": node_id,
                    "endpoint": endpoint,
                    "value": surface["value"]
                }
            ))

        # 1.5 AUTHENTICATION (Doppelganger)
        # We need a valid session to avoid 401s.
        log.info("🎭 Doppelganger: Establishing Identity...")
        
        # In a real system, these come from secure config/vault
        admin_cred = Credential(
            username="admin@juice-sh.op",
            password="admin123", 
            role=Role.ADMIN
        )
        
        persona = await self.doppelganger.authenticate(admin_cred, target_url)
        if persona:
            log.info(f"🎭 Identity Established: {persona.id}")
            await self.bus.emit(TelemetryEvent(
                type=EventType.IDENTITY_ESTABLISHED,
                source="Orchestrator",
                level=EventLevel.INFO,
                payload={
                    "persona_id": persona.id,
                    "role": persona.credential.role.value if persona.credential else "UNKNOWN"
                }
            ))
        else:
            log.warning("🎭 Identity Failed: Proceeding anonymously (Expect 401s)")

        # 2. COGNITIVE LOOPS
        # We run a few cycles for EACH surface
        max_cycles_per_surface = 1 # Keep it tight for the first live run
        
        for surface in JUICE_SHOP_PROFILE["surfaces"]:
            endpoint = surface["endpoint"]
            node_id = f"service:{endpoint}"
            
            log.info(f"--- Focused on Surface: {endpoint} ---")
            
            for cycle in range(max_cycles_per_surface):
                # 2.1 PLAN (Thanatos)
                handle = TargetHandle(
                    node_id=node_id,
                    endpoint=f"{target_url}{endpoint}", # Full URL
                    method=surface["method"],
                    value=surface["value"]
                )

                test_cases = self.thanatos.generate_mutations(target=handle)
                
                if not test_cases:
                    log.warning(f"Thanatos returned no ideas for {endpoint}.")
                    continue
                    
                test_case = test_cases[0]
                log.info(f"Hypothesis: {test_case.hypothesis.invariant}")

                # 2.2 DECIDE (Sentient)
                decision = self.sentient.decide(
                    target_context={"target_value": test_case.target.value},
                    risk_level=0.5 # Mock risk
                )
                
                if decision.verdict != Verdict.APPROVE:
                    log.warning(f"Sentient BLOCKED: {decision.rationale}")
                    continue 
                
                # Emit Decision
                await self.bus.emit(TelemetryEvent(
                    type=EventType.DECISION_MADE, source="Sentient", level=EventLevel.INFO,
                    payload={"verdict": decision.verdict.value, "rationale": decision.rationale}
                ))
                
                log.info(f"Sentient APPROVED: {decision.rationale}")
                
                # 2.3 ACT (Executor)
                order_id = str(uuid.uuid4())
                
                # Contextual Headers (Doppelganger)
                # Use inject_auth to get both headers and cookies
                headers, cookies = self.doppelganger.inject_auth(None, None, persona)

                order = ExecutionOrder(
                    test_case=test_case, 
                    decision=decision,
                    idempotency_token=order_id,
                    auth_headers=headers,
                    auth_cookies=cookies,
                    target_base_url=target_url
                )
                
                # Interlock Check
                lock_reason = self.interlock.check(order)
                if lock_reason:
                    log.error(f"Interlock ENGAGED: {lock_reason}")
                    continue
                    
                # Execute
                await self.bus.emit(TelemetryEvent(
                    type=EventType.EXECUTION_STARTED, source="Orchestrator", level=EventLevel.INFO,
                    payload={"order_id": order.idempotency_token, "target": endpoint}
                ))

                result = await self.executor_harness.execute(order)
                
                await self.bus.emit(TelemetryEvent(
                    type=EventType.EXECUTION_COMPLETED, source="Orchestrator", level=EventLevel.INFO,
                    payload={"duration_ms": result.duration_ms, "status": result.status.value},
                    trace_id=order.idempotency_token
                ))
                
                # 401 Auto-Heal (One-shot)
                status_code = result.signals.get("status_code") if result.signals else None
                if status_code == 401 and persona and self.doppelganger:
                    log.warning("🎭 401 detected. Attempting session heal + single retry...")

                    refreshed = await self.doppelganger.refresh(persona, target_url)
                    if refreshed and refreshed.session_token:
                        persona = refreshed  # swap active persona reference

                        new_headers, new_cookies = self.doppelganger.inject_auth(
                            headers=None,
                            cookies=None,
                            persona=persona
                        )

                        healed_order = ExecutionOrder(
                            test_case=order.test_case,
                            decision=order.decision,
                            idempotency_token=str(uuid.uuid4()),
                            auth_headers=new_headers,
                            auth_cookies=new_cookies,
                            target_base_url=target_url
                        )

                        result = await self.executor_harness.execute(healed_order)

                
                # 2.4 EVALUATE (Oracle)
                breach_status = self.oracle.evaluate(result, test_case.oracle)
                
                if breach_status == BreachStatus.BREACH:
                    log.critical(f"🚨 BREACH CONFIRMED: {test_case.id}")
                    await self.bus.emit(TelemetryEvent(
                        type=EventType.BREACH_DETECTED, source="Oracle", level=EventLevel.CRITICAL,
                        payload={"target_node_id": node_id, "severity": 10.0},
                        trace_id=order.idempotency_token
                    ))
                elif breach_status == BreachStatus.ANOMALY:
                    log.critical(f"💣 CRASH DETECTED: {test_case.id} (Status 500+)")
                    # 1. Emit Anomaly Event
                    await self.bus.emit(TelemetryEvent(
                        type=EventType.BREACH_DETECTED, source="Oracle", level=EventLevel.CRITICAL,
                        payload={"target_node_id": node_id, "severity": 9.0, "type": "CRASH"},
                        trace_id=order.idempotency_token
                    ))
                    # 2. Reflex: Spike Exploration (Simulated for now)
                    log.warning(f"Reflex: Exploitability of {node_id} increased to 0.9")
                 
                elif breach_status == BreachStatus.SECURE:
                     log.info(f"Target Verified SECURE ({result.status}).")
                
                await asyncio.sleep(0.2) # Pacing
            
        log.info("Campaign Complete.")

    async def _emit_lifecycle(self, phase: str, **kwargs):
        # Determine strict event type
        if "BOOT" in phase or phase == "SYSTEM_STARTUP":
            evt_type = EventType.SYSTEM_STARTUP
        elif "SHUTDOWN" in phase or phase == "SYSTEM_SHUTDOWN":
            evt_type = EventType.SYSTEM_SHUTDOWN
        else:
            # Fallback for mid-lifecycle events (e.g. PAUSE, RESUME) if added later
            # For now, default to INFO or create a LifecycleChange event if needed.
            # Sticking to valid types:
            evt_type = EventType.SYSTEM_STARTUP if "START" in phase else EventType.SYSTEM_SHUTDOWN

        await self.bus.emit(TelemetryEvent(
            type=evt_type, 
            source="Orchestrator", 
            level=EventLevel.INFO,
            payload={"phase": phase, **kwargs}
        ))
