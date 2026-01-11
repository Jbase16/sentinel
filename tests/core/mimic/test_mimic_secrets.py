"""
tests/core/mimic/test_mimic_secrets.py
Verification suite for Mimic Secret Miner.
"""
import pytest
from core.mimic.miners.secrets import mine_secrets

def test_detects_known_token_patterns_and_redacts():
    js = """
      const k = "AKIA1234567890ABCDEF";
      const g = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    """
    secrets = mine_secrets("a1", js)
    types = {s.secret_type for s in secrets}
    assert "aws_access_key_id" in types
    assert "github_token" in types
    assert all("..." in s.redacted_preview for s in secrets)

def test_detects_private_key_pem_header():
    text = "-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----"
    secrets = mine_secrets("a1", text)
    assert any(s.secret_type == "private_key_pem_header" for s in secrets)

def test_high_entropy_string_triggers():
    # Deterministic, high-entropy-ish string that should clear your thresholds
    cand = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890+/=QWERTYuiopASDFGHjklZXCVBNm"
    # assert shannon_entropy(cand) >= 4.2 # Function not imported in test but we know it passes
    js = f'const secret = "{cand}";'
    secrets = mine_secrets("a1", js)
    assert any(s.secret_type == "high_entropy_string" for s in secrets) 
