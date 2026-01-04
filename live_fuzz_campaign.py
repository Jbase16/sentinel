"""
live_fuzz_campaign.py

Purpose:
    Execute a targeted Thanatos V1 Fuzzing Campaign against Juice Shop.
    Focus: /api/BasketItems (Authenticated Fuzzing).
    
    Goals:
    1. Authenticate as Admin.
    2. Mutate Basket operations (Boundary, Type, Auth).
    3. Detect Anomalies/Breaches.
    4. Verify Aegis Pressure Updates.
"""

import asyncio
import logging
from typing import Optional

from core.system.orchestrator import SystemOrchestrator
from core.observer import EventType

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger("live_fuzz")

# Filter noisier logs
logging.getLogger("httpx").setLevel(logging.WARNING)

async def run_live_fuzz():
    log.info("--- 💀 SentinelForge: Live Fuzzing Campaign 💀 ---")
    
    orchestrator = SystemOrchestrator()
    await orchestrator.boot()
    
    target_url = "http://localhost:3000"
    
    # Custom Profile for Fuzzing
    # Overriding the default static profile in orchestrator for this test
    # Ideally, Orchestrator would accept a 'profile' arg, but for V1 we will patch/inject or just use what's there.
    # Actually, Orchestrator.run_campaign defines the profile internally.
    # To be "surgical", we will modify the internal profile before running, OR subclass.
    # Let's simple-patch the profile in the instance if possible, or just accept the default content?
    # The default content has /rest/products/search, /rest/user/login, /api/Users, /profile.
    # We want /api/BasketItems.
    
    # 🐒 Monkey-Patching for the Campaign (V1 Hack for Surgical Targeting)
    BASKE_PROFILE = {
        "base_url": target_url,
        "surfaces": [
            {"endpoint": "/api/BasketItems", "method": "POST", "value": 7.0},
            {"endpoint": "/rest/user/login", "method": "POST", "value": 9.0}, # Keep login for auth test
        ]
    }
    
    # We'll just execute run_campaign. 
    # Since we can't easily patch the method locals, we'll sub-class or just create a custom runner here
    # that reuses the components. 
    # Actually, Orchestrator is designed to be the runner.
    # Let's execute the default campaign for now, but I'll update the Orchestrator's profile temporarily
    # by modifying the file? No, that's messy.
    
    # BETTER APPROACH: Use the components directly to show granular control, 
    # mirroring what Orchestrator does but just for this target.
    
    log.info("🎯 Targeting: /api/BasketItems")
    
    # 1. Auth
    from core.doppelganger.models import Credential, Role
    admin_cred = Credential("admin@juice-sh.op", "admin123", Role.ADMIN)
    persona = await orchestrator.doppelganger.authenticate(admin_cred, target_url)
    
    if not persona:
        log.error("❌ Auth Failed. Aborting.")
        await orchestrator.shutdown()
        return

    log.info(f"✅ Authenticated as {persona.id}")

    # 2. Plan (Thanatos)
    from core.thanatos.models import TargetHandle
    handle = TargetHandle(
        node_id="service:/api/BasketItems",
        endpoint="/api/BasketItems",
        method="POST",
        value=7.0
    )
    
    mutations = orchestrator.thanatos.generate_mutations(handle)
    log.info(f"🧬 Generated {len(mutations)} mutations.")
    
    # 3. Execute
    from core.executor.models import ExecutionOrder
    from core.sentient.models import SentientDecision, Verdict
    from core.observer.events import TelemetryEvent, EventLevel
    import uuid

    # Mock decision (Always Approve)
    decision = SentientDecision(Verdict.APPROVE, "Fuzzing Authorized", 0.1, 0.0)
    
    for test_case in mutations:
        log.info(f"🚀 Executing: {test_case.mutation.op.value} -> {test_case.oracle.name}")
        
        headers, cookies = orchestrator.doppelganger.inject_auth(None, None, persona)
        
        order = ExecutionOrder(
            test_case=test_case,
            decision=decision,
            idempotency_token=str(uuid.uuid4()),
            auth_headers=headers,
            auth_cookies=cookies,
            target_base_url=target_url
        )
        
        result = await orchestrator.executor_harness.execute(order)
        
        # 4. Evaluate (Oracle)
        verdict = orchestrator.oracle.evaluate(result, test_case.oracle)
        log.info(f"⚖️ Verdict: {verdict.value} (Status: {result.signals.get('status_code')})")
        
        if verdict.value != "SECURE":
            log.warning(f"🚨 FOUND {verdict.value}!")
            # Emit event to trigger feedback loop
            await orchestrator.bus.emit(TelemetryEvent(
                type=EventType.BREACH_DETECTED,
                source="LiveFuzz",
                level=EventLevel.CRITICAL,
                payload={
                    "target_node_id": handle.node_id,
                    "severity": 9.0 if verdict.value == "ANOMALY" else 10.0,
                    "type": verdict.value
                }
            ))
            
            # Explicit Feedback Call (since the bus listener might not be fully wired in this script)
            orchestrator.pg_manager.increase_pressure(
                handle.node_id, 
                9.0,
                reason="LiveFuzz Breach"
            )
            
        await asyncio.sleep(0.1)

    log.info("🏁 Campaign Complete.")
    await orchestrator.shutdown()

if __name__ == "__main__":
    asyncio.run(run_live_fuzz())
