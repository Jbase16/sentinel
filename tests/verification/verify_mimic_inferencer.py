"""
Verification Script for Project MIMIC (Secret Mining via core.mimic).

Tests the regex-based mine_secrets() function against common secret patterns.
"""
from core.mimic.miners.secrets import mine_secrets, shannon_entropy


def run_test():
    print("Secret Miner Verification (core.mimic)")

    # 1. AWS key detection
    js_aws = 'const key = "AKIAIOSFODNN7EXAMPLE"'
    secrets = mine_secrets("verify-asset-1", js_aws)
    assert any(s.secret_type == "aws_access_key_id" for s in secrets), "Missing AWS key detection"
    print("  AWS key detection: OK")

    # 2. GitHub token detection
    js_gh = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    secrets = mine_secrets("verify-asset-2", js_gh)
    assert any(s.secret_type == "github_token" for s in secrets), "Missing GitHub token"
    print("  GitHub token detection: OK")

    # 3. Redaction
    for s in secrets:
        assert "ghp_1234567890" not in s.redacted_preview, "Secret not redacted"
    print("  Redaction: OK")

    # 4. Shannon entropy helper
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") < shannon_entropy("abcdefgh")
    print("  Shannon entropy: OK")

    print("\nMIMIC Secret Miner: all checks passed")


if __name__ == "__main__":
    run_test()
