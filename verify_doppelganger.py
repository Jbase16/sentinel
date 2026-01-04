import asyncio
import logging
from core.doppelganger.models import Credential, Role
from core.doppelganger.engine import DoppelgangerEngine

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
log = logging.getLogger("verify_doppelganger")

async def test_login():
    log.info("--- 🎭 Verifying Doppelganger Identity Engine ---")
    
    engine = DoppelgangerEngine()
    
    # 1. Credentials (Default Juice Shop Admin)
    # Note: Juice Shop often comes pre-seeded with admin/admin123 or we might need to register.
    # Let's try a standard known default or a test user.
    # Actually, let's try to register first if login fails? 
    # For now, let's assume the user has created 'admin@juice-sh.op' / 'admin123'
    # Or 'test@test.com' / 'test12345'
    
    # Let's try the classic admin default
    cred = Credential(
        username="admin@juice-sh.op",
        password="admin123",
        role=Role.ADMIN
    )
    
    target = "http://localhost:3000"
    
    # 2. Authenticate
    persona = await engine.authenticate(cred, target)
    
    if persona:
        log.info(f"SUCCESS: Persona Authenticated!")
        log.info(f"Token: {persona.session_token[:20]}...")
        log.info(f"Headers: {persona.get_auth_headers()}")
    else:
        log.error("FAILURE: Could not authenticate.")

if __name__ == "__main__":
    asyncio.run(test_login())
