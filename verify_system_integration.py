import asyncio
import logging
from core.system.orchestrator import SystemOrchestrator

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
log = logging.getLogger("verify_integration")

async def test_full_campaign():
    log.info("--- 🛡️ Starting SentinelForge Autonomous Campaign ---")
    
    cortex = SystemOrchestrator()
    
    try:
        # 1. Boot
        await cortex.boot()
        
        # 2. Run Campaign against OWASP Juice Shop
        target = "http://localhost:3000"
        log.info(f"Targeting: {target}")
        
        await cortex.run_campaign(target)
        
    except KeyboardInterrupt:
        log.warning("User interrupted campaign.")
    except Exception as e:
        log.error(f"Campaign Crashed: {e}", exc_info=True)
    finally:
        # 3. Shutdown
        await cortex.shutdown()

if __name__ == "__main__":
    asyncio.run(test_full_campaign())
