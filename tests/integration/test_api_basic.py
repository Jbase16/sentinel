"""Module test_api_basic: inline documentation for /Users/jason/Developer/sentinelforge/tests/integration/test_api_basic.py."""
#
# PURPOSE:
# This module is part of the integration package in SentinelForge.
# [Specific purpose based on module name: test_api_basic]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

import sys
import os
import time
import threading
import json
import urllib.request
import unittest

# Ensure we can import core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.server.api import serve

class TestCoreAPI(unittest.TestCase):
    @classmethod
    @classmethod
    def setUpClass(cls):
        """Function setUpClass."""
        # Start API in a separate thread
        cls.port = 8766 # Use a test port
        cls.server_thread = threading.Thread(target=serve, args=(cls.port,), daemon=True)
        cls.server_thread.start()
        # Give it a moment to bind
        time.sleep(1)

    def test_01_ping(self):
        """Function test_01_ping."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/ping") as resp:
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "ok")

    def test_02_status_structure(self):
        """Function test_02_status_structure."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/status") as resp:
            data = json.loads(resp.read().decode())
            self.assertIn("ai", data)
            self.assertIn("tools", data)
            self.assertIn("installed", data["tools"])
            self.assertIn("missing", data["tools"])
            print(f"\n[Test] Detected Tools: {data['tools']['installed']}")
            print(f"[Test] Missing Tools: {data['tools']['missing']}")

    def test_03_ai_status(self):
         """Function test_03_ai_status."""
         with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/status") as resp:
            data = json.loads(resp.read().decode())
            ai = data.get("ai", {})
            self.assertIn("connected", ai)
            print(f"[Test] AI Connected: {ai['connected']}")

if __name__ == '__main__':
    unittest.main()
