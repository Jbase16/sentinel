
import unittest
from unittest.mock import patch, MagicMock
from core.toolkit.diagnostics import check_missing_tools, DiagnosticIssue
from core.toolkit.registry import ToolDefinition

class TestToolDiagnostics(unittest.TestCase):
    def test_missing_tool_detection(self):
        """Verify check_missing_tools identifies missing binaries and provides hints."""
        
        # Mock TOOLS registry
        mock_tools = {
            "fake_tool": ToolDefinition(
                name="fake_tool",
                label="Fake Tool", # Required field
                description="A fake tool",
                binary_name="fake_binary_that_does_not_exist_12345",
                cmd_template=["fake_binary"]
            ),
            "installed_tool": ToolDefinition(
                name="installed_tool",
                label="Installed Tool", # Required field
                description="A tool that exists",
                binary_name="ls", 
                cmd_template=["ls"]
            )
        }
        
        # Mock INSTALLERS for hint generation
        mock_installers = {
            "fake_tool": {
                "strategies": [{"cmd": ["brew", "install", "fake_tool"]}]
            }
        }
        
        with patch("core.toolkit.diagnostics.TOOLS", mock_tools), \
             patch("core.toolkit.diagnostics.INSTALLERS", mock_installers):
            
            # 1. Check specific missing tool
            issues = check_missing_tools(["fake_tool"])
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0].tool_name, "fake_tool")
            self.assertIn("fake_binary_that_does_not_exist_12345", issues[0].message)
            self.assertEqual(issues[0].install_hint, "brew install fake_tool")
            
            # 2. Check installed tool
            issues = check_missing_tools(["installed_tool"])
            self.assertEqual(len(issues), 0, "Should not report installed tool")
            
            # 3. Check all (mixed)
            issues = check_missing_tools()
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0].tool_name, "fake_tool")

if __name__ == '__main__':
    unittest.main()
