
import unittest
from core.toolkit.installer import CommandValidator

class TestCommandInjection(unittest.TestCase):
    def test_validator_rejects_shell_operators(self):
        """Ensure CommandValidator rejects classic shell operators in args."""
        
        # Safe cases
        safe = ["-p", "80,443", "--scans", "basic"]
        CommandValidator.validate_safe_args(safe) # Should not raise
        
        # Unsafe cases
        unsafe_vectors = [
            ["target; rm -rf /"],
            ["target && bad_command"],
            ["target || true"],
            ["target | bash"],
            ["target > /etc/passwd"], # Redirection (should likely be banned too?)
            ["target &"],
        ]
        
        # NOTE: Current implementation bans {";", "|", "&", "&&", "||"}
        # It does NOT ban ">" or "<" or "$()" or "`".
        # Since we run without shell=True, > is passed literally to the command,
        # which usually causes the command to fail (e.g. nmap interprets it as a target).
        # But we should probably verify that assumption or explicitly ban them if we want to be strict.
        
        for vector in unsafe_vectors:
            with self.assertRaises(ValueError, msg=f"Should reject: {vector}"):
                CommandValidator.validate_safe_args(vector)

    def test_validator_edge_cases(self):
        """Test edge cases for injection."""
        with self.assertRaises(ValueError):
            CommandValidator.validate_safe_args([";"])
            
if __name__ == '__main__':
    unittest.main()
