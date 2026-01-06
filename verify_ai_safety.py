
import logging
import time
import unittest
from unittest.mock import MagicMock, patch
from core.ai.ai_engine import AIEngine, CircuitBreaker, CircuitBreakerOpenError

# Configure logging to suppress noise during test
logging.basicConfig(level=logging.CRITICAL)

class TestAISafety(unittest.TestCase):
    def setUp(self):
        # Reset singleton for fresh state
        AIEngine._instance = None
        self.engine = AIEngine.instance()
        
        # Mock the raw client
        self.mock_client = MagicMock()
        self.engine.client = self.mock_client
        
        # Reset circuit breaker
        self.engine.circuit_breaker = CircuitBreaker(failure_threshold=3, timeout=1.0)

    def test_safe_generate_success(self):
        """Test that safe_generate works normally when backend is healthy."""
        print("\n--- Test: Safe Generate Success ---")
        self.mock_client.generate.return_value = '{"response": "ok"}'
        
        result = self.engine.safe_generate("test prompt")
        
        self.assertEqual(result, '{"response": "ok"}')
        self.assertEqual(self.engine.circuit_breaker.failure_count, 0)
        print("✅ Success case passed")

    def test_safe_generate_failure_handling(self):
        """Test that exception in client is caught and returns None."""
        print("\n--- Test: Failure Handling ---")
        self.mock_client.generate.side_effect = Exception("Connection Refused")
        
        result = self.engine.safe_generate("fail me")
        
        self.assertIsNone(result)
        self.assertEqual(self.engine.circuit_breaker.failure_count, 1)
        print("✅ Falure handling passed (returned None, incremented count)")

    def test_circuit_breaker_activation(self):
        """Test that CB opens after threshold failures."""
        print("\n--- Test: Circuit Breaker Activation ---")
        self.mock_client.generate.side_effect = Exception("Down")
        
        # Trip the breaker (threshold = 3)
        for i in range(3):
            self.engine.safe_generate(f"fail {i}")
            
        self.assertTrue(self.engine.circuit_breaker.is_open())
        print("✅ Breaker opened after 3 failures")
        
        # Next call should fail FAST without touching client
        self.mock_client.generate.reset_mock()
        result = self.engine.safe_generate("blocked")
        
        self.assertIsNone(result)
        self.mock_client.generate.assert_not_called()
        print("✅ Breaker blocked call (client not touched)")

    def test_circuit_breaker_recovery(self):
        """Test that CB closes after timeout."""
        print("\n--- Test: Circuit Breaker Recovery ---")
        # 1. Trip it
        self.mock_client.generate.side_effect = Exception("Down")
        for _ in range(3):
            self.engine.safe_generate("fail")
            
        self.assertTrue(self.engine.circuit_breaker.is_open())
        
        # 2. Add delay > timeout (1.0s)
        print("   Waiting for timeout...")
        time.sleep(1.1)
        
        # 3. Next call should be allowed (Half-Open state logic)
        self.mock_client.generate.side_effect = None
        self.mock_client.generate.return_value = "Recovered"
        
        result = self.engine.safe_generate("retry")
        
        self.assertEqual(result, "Recovered")
        self.assertFalse(self.engine.circuit_breaker.is_open())
        self.assertEqual(self.engine.circuit_breaker.failure_count, 0)
        print("✅ Breaker recovered after timeout")

if __name__ == '__main__':
    unittest.main()
