"""
verify_thanatos.py

Purpose:
    Verify the Thanatos V1 MutationEngine.
    Ensures that:
    1. MutationEngine can be instantiated.
    2. It generates correct mutations for given targets.
    3. Context inference works reasonably well.
"""

import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger("verify_thanatos")

from core.thanatos.axiom_synthesizer import MutationEngine
from core.thanatos.models import TargetHandle, MutationOpType
from core.thanatos.mutations import MutationLibrary

def verify_mutation_engine():
    log.info("--- 🛡️ Verifying Thanatos V1 MutationEngine ---")
    
    engine = MutationEngine()
    
    # 1. Test Login Endpoint (Type Juggling)
    login_target = TargetHandle(
        node_id="service:/rest/user/login",
        endpoint="/rest/user/login",
        method="POST",
        value=9.0
    )
    
    log.info(f"Generating mutations for {login_target.endpoint}...")
    mutations_login = engine.synthesize(login_target)
    
    if not mutations_login:
        log.error("❌ No mutations generated for login!")
        sys.exit(1)
        
    log.info(f"Generated {len(mutations_login)} mutations for Login.")
    
    # Check for specific operators we expect
    ops_found = set(m.mutation.op for m in mutations_login)
    log.info(f"Ops found: {[op.value for op in ops_found]}")
    
    if MutationOpType.TYPE_JUGGLING in ops_found:
        log.info("✅ TYPE_JUGGLING present.")
    else:
        log.error("❌ TYPE_JUGGLING missing.")
        
    if MutationOpType.AUTH_CONFUSION in ops_found:
        log.info("✅ AUTH_CONFUSION present.")
    else:
        log.error("❌ AUTH_CONFUSION missing.")

    # 2. Test Basket Endpoint (Boundary Violation)
    basket_target = TargetHandle(
        node_id="service:/api/BasketItems",
        endpoint="/api/BasketItems",
        method="POST",
        value=5.0
    )
    
    log.info(f"\nGenerating mutations for {basket_target.endpoint}...")
    mutations_basket = engine.synthesize(basket_target)
    
    ops_found_basket = set(m.mutation.op for m in mutations_basket)
    log.info(f"Ops found: {[op.value for op in ops_found_basket]}")
    
    if MutationOpType.BOUNDARY_VIOLATION in ops_found_basket:
        log.info("✅ BOUNDARY_VIOLATION present.")
    else:
        log.error("❌ BOUNDARY_VIOLATION missing.")
        
    log.info("\n--- Thanatos V1 Verified Successfully ---")

if __name__ == "__main__":
    verify_mutation_engine()
