"""
Integration Test: Ghost -> Strategy -> Wraith E2E Pipeline

Target: localhost:3003 (Vulnerable Docker Container)

This test verifies the "Search & Destroy" loop:
1. Ghost intercepts traffic to target
2. Strategy Engine analyzes traffic and proposes attacks (Heuristic & AI)
3. Wraith Automator receives hypotheses and verifies them
"""
import unittest
import asyncio
import httpx
from unittest.mock import Mock, patch
import logging
import json
import sys
import os

# Setup path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from core.base.session import ScanSession

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TARGET_URL = "http://localhost:3003"

class TestGhostWraithE2E(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        """Sets up a ScanSession with Ghost Proxy running."""
        # 0. Initialize Database & Sequence Authority
        from core.base.sequence import GlobalSequenceAuthority
        from core.data.db import Database
        
        # Reset first to ensure clean state
        GlobalSequenceAuthority.reset_for_testing()
        
        # Initialize (this will also init Database if needed)
        await GlobalSequenceAuthority.initialize_from_db()
        
        self.session = ScanSession(target=TARGET_URL)
        
        # PERSIST SESSION TO DB (Required for Foreign Keys)
        Database.instance().save_session(self.session.to_dict())
        
        # Start Ghost on random port
        self.session.start_ghost(port=0)
        
        # Wait for proxy to start
        await asyncio.sleep(2)
        
        # Configure Proxy Client
        self.proxy_url = f"http://127.0.0.1:{self.session.ghost.port}"
        logger.info(f"Test Client using Proxy: {self.proxy_url}")
        
        self.client = httpx.AsyncClient(
            proxy=self.proxy_url,
            verify=False,
            timeout=10.0
        )

    async def asyncTearDown(self):
        """Cleanup session, client, singletons, and background tasks."""
        try:
            await self.client.aclose()
            if self.session:
                self.session.stop_ghost()
        except Exception as e:
            logger.warning(f"Error during basic teardown: {e}")
            
        # 1. Cleanup Global Signals (Prevent New Tasks from Spawning)
        try:
            from core.data.issues_store import issues_store
            from core.data.killchain_store import killchain_store
            
            # Manually clear observers to prevent dead objects from receiving signals
            if hasattr(issues_store.issues_changed, '_observers'):
                issues_store.issues_changed._observers.clear()
            if hasattr(killchain_store.edges_changed, '_observers'):
                killchain_store.edges_changed._observers.clear()
        except Exception as e:
            logger.warning(f"Error clearing signals: {e}")
        
        # 2. CANCEL ALL BACKGROUND TASKS (Prevents Zombie DB writes)
        try:
            # multiple passes to catch tasks spawned during cancellation
            for _ in range(2): 
                tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
                if not tasks:
                    break
                for task in tasks:
                    task.cancel()
                
                # Wait for them to finish cancelling
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.warning(f"Error cancelling tasks: {e}")

        # 3. Cleanup Database Singleton
        try:
            from core.base.sequence import GlobalSequenceAuthority
            GlobalSequenceAuthority.reset_for_testing()
            
            from core.data.db import Database
            db = Database.instance()
            await db.close()
            Database._instance = None
        except Exception as e:
            logger.warning(f"Error closing DB: {e}")
        
        # Cleanup BlackBox Singleton
        try:
            from core.data.blackbox import BlackBox
            bb = BlackBox.instance()
            if bb._worker_task:
                bb._worker_task.cancel()
                try:
                    await bb._worker_task
                except asyncio.CancelledError:
                    pass
            BlackBox._instance = None
        except Exception as e:
            logger.warning(f"Error stoppping BlackBox: {e}")

    async def test_ghost_heuristic_chain(self):
        """
        Test 1: Heuristic Workflow (End-to-End)
        
        Flow:
        1. Send GET /?user_id=1&admin=false thru Proxy
        2. Ghost intercepts -> Strategy analyzes
        3. Strategy (Heuristic) detects IDOR & PrivEsc patterns
        4. Findings created
        """
        logger.info("Starting Heuristic Chain Test...")
        
        # 1. Send Traffic
        try:
            # We assume localhost:3003 is up. If not, this might fail or just 502.
            resp = await self.client.get(f"{TARGET_URL}/?user_id=101&admin=false&debug=0")
            logger.info(f"Traffic sent. Status: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Request failed (target might be down), but Ghost should still see it: {e}")

        # Give async Strategy time to think
        await asyncio.sleep(2)
        
        # 2. Verify Findings
        findings = self.session.findings.get_all()
        logger.info(f"Total Findings: {len(findings)}")
        
        # Filter for Strategy findings
        strategy_findings = [f for f in findings if f.get("tool") == "neural_strategy"]
        logger.info(f"Strategy Findings: {len(strategy_findings)}")
        
        # Check for specific heuristic detections
        found_idor = False
        found_privesc = False
        
        for f in strategy_findings:
            vuln_type = f.get("type", "")
            param = f.get("metadata", {}).get("parameter", "")
            
            logger.info(f"Finding: {vuln_type} on {param}")
            
            if "idor" in vuln_type and "user_id" in param:
                found_idor = True
            
            if "privilege_escalation" in vuln_type and "admin" in param:
                found_privesc = True

        if not found_idor or not found_privesc:
            logger.error("Test Failed. Dumping Session Logs:")
            for log in self.session.logs:
                logger.error(log)

        self.assertTrue(found_idor, "Should have detected IDOR on 'user_id'")
        self.assertTrue(found_privesc, "Should have detected Privilege Escalation on 'admin'")

    async def test_ghost_neural_chain(self):
        """
        Test 2: Neural Strategy Workflow (Mocked AI)
        
        Flow:
        1. Send normal GET /search?q=test thru Proxy
        2. Mock AI to say "This looks like SQLi"
        3. Strategy (Neural) accepts hypothesis
        4. Finding created
        """
        logger.info("Starting Neural Chain Test...")
        
        mock_ai_response = {
            "vectors": [
                {
                    "vuln_class": "SQLi",
                    "parameter": "q",
                    "hypothesis": "Parameter q flows to a WHERE clause.",
                    "suggested_payloads": ["' OR 1=1--", "admin'--"]
                }
            ]
        }
        
        # Mock the AI Engine's client generate method
        with patch("core.ai.ai_engine.AIEngine.instance") as mock_ai_cls:
            # Setup the mock instance
            mock_instance = mock_ai_cls.return_value
            
            # When Strategy calls client.generate, return our JSON
            mock_instance.client.generate.return_value = json.dumps(mock_ai_response)
            
            # Force Strategy to use THIS mock instance
            # The StrategyEngine is initialized inside GhostAddon -> ghost_session
            # We need to swap the AI engine inside the ALREADY running session's strategy
            self.session.ghost.master.addons.get("ghostaddon").strategy.ai = mock_instance
            
            # 1. Send Traffic
            try:
                await self.client.get(f"{TARGET_URL}/search?q=test_query")
            except Exception:
                pass 
                
            # Give Strategy time to process
            await asyncio.sleep(2)
            
            # 2. Verify Findings
            findings = self.session.findings.get_all()
            strategy_findings = [f for f in findings if f.get("tool") == "neural_strategy"]
            
            found_sqli = False
            for f in strategy_findings:
                if "sqli" in f.get("type", "") and "q" in f.get("metadata", {}).get("parameter", ""):
                    found_sqli = True
                    logger.info(f"Neural Finding Verified: {f['value']}")
                    
            self.assertTrue(found_sqli, "Neural Strategy should have detected SQLi via Mocked AI")

if __name__ == "__main__":
    unittest.main()
