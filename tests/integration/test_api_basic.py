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
from unittest.mock import MagicMock, patch

# Patch get_config GLOBALLY for this module before any other imports rely on it (if possible)
import core.base.config
original_get_config = core.base.config.get_config

def mock_get_config():
    # Return a minimal safe config
    conf = MagicMock()
    conf.security.require_auth = True
    conf.security.api_token = "test-token-12345"
    conf.api_host = "127.0.0.1"
    conf.api_port = 8766
    conf.storage.db_path = "/tmp/sentinel_test.db"
    return conf

# We need to patch it such that 'core.server.api' sees it.
core.base.config.get_config = mock_get_config

class TestCoreAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Function setUpClass."""
        # Generate a test token
        cls.token_path = os.path.expanduser("~/.sentinelforge/api_token")
        os.makedirs(os.path.dirname(cls.token_path), exist_ok=True)
        cls.test_token = "test-token-12345"
        with open(cls.token_path, "w") as f:
            f.write(cls.test_token)

        # Start API in a separate thread
        cls.port = 8766 # Use a test port
        cls.server_thread = threading.Thread(target=serve, args=(cls.port,), daemon=True)
        cls.server_thread.start()
        # Give it a moment to bind
        time.sleep(1)

    def _get_auth_request(self, url):
         req = urllib.request.Request(url)
         req.add_header("Authorization", f"Bearer {self.test_token}")
         return req

    def test_01_ping(self):
        """Function test_01_ping."""
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/v1/ping") as resp:
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "ok")

    def test_02_status_structure(self):
        """Function test_02_status_structure."""
        req = self._get_auth_request(f"http://127.0.0.1:{self.port}/v1/status")
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                self.assertIn("ai", data)
                self.assertIn("tools", data)
                self.assertIn("installed", data["tools"])
                self.assertIn("missing", data["tools"])
                print(f"\n[Test] Detected Tools: {data['tools']['installed']}")
                print(f"[Test] Missing Tools: {data['tools']['missing']}")
        except urllib.error.HTTPError as e:
            print(f"\n[Test] HTTP {e.code} Error Body: {e.read().decode()}")
            raise e

    def test_03_ai_status(self):
         """Function test_03_ai_status."""
         req = self._get_auth_request(f"http://127.0.0.1:{self.port}/v1/status")
         try:
             with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                ai = data.get("ai", {})
                self.assertIn("connected", ai)
                print(f"[Test] AI Connected: {ai['connected']}")
         except urllib.error.HTTPError as e:
            print(f"\n[Test] HTTP {e.code} Error Body: {e.read().decode()}")
            raise e

if __name__ == '__main__':
    unittest.main()
