"""
Unit tests for core.mimic route and secret mining.

Tests the regex-based miners that extract routes and secrets from JavaScript.
"""
import pytest
from core.mimic.miners.routes import mine_routes
from core.mimic.miners.secrets import mine_secrets


# ---------------------------------------------------------------------------
# Route Mining
# ---------------------------------------------------------------------------

def test_mine_routes_fetch():
    """Detect fetch() calls with URL arguments."""
    js = '''
    fetch("/api/users")
    fetch('/api/orders')
    '''
    routes = mine_routes("test-asset", js)
    paths = {r.route for r in routes}
    assert "/api/users" in paths
    assert "/api/orders" in paths


def test_mine_routes_axios():
    """Detect axios HTTP method calls."""
    js = '''
    axios.get("/api/products")
    axios.post("/api/checkout")
    '''
    routes = mine_routes("test-asset", js)
    found = {(r.route, r.method) for r in routes}
    assert ("/api/products", "GET") in found
    assert ("/api/checkout", "POST") in found


def test_mine_routes_xhr():
    """Detect XMLHttpRequest.open() calls."""
    js = '''
    xhr.open("PUT", "/api/user/profile")
    '''
    routes = mine_routes("test-asset", js)
    assert any(r.route == "/api/user/profile" and r.method == "PUT" for r in routes)


def test_mine_routes_hidden_detection():
    """Routes matching /admin, /internal, /debug should be flagged hidden."""
    js = '''
    fetch("/admin/settings")
    fetch("/api/public")
    fetch("/internal/metrics")
    fetch("/debug/config")
    '''
    routes = mine_routes("test-asset", js)
    hidden = {r.route for r in routes if r.hidden}
    visible = {r.route for r in routes if not r.hidden}

    assert "/admin/settings" in hidden
    assert "/internal/metrics" in hidden
    assert "/debug/config" in hidden
    assert "/api/public" in visible


def test_mine_routes_deduplication():
    """Same route should not appear twice."""
    js = '''
    fetch("/api/users")
    fetch("/api/users")
    '''
    routes = mine_routes("test-asset", js)
    paths = [r.route for r in routes]
    assert paths.count("/api/users") == 1


# ---------------------------------------------------------------------------
# Secret Mining
# ---------------------------------------------------------------------------

def test_mine_secrets_aws_key():
    """Detect AWS access key patterns."""
    js = 'const key = "AKIAIOSFODNN7EXAMPLE"'
    secrets = mine_secrets("test-asset", js)
    assert any(s.secret_type == "aws_access_key_id" for s in secrets)


def test_mine_secrets_github_token():
    """Detect GitHub personal access tokens."""
    js = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
    secrets = mine_secrets("test-asset", js)
    assert any(s.secret_type == "github_token" for s in secrets)


def test_mine_secrets_redaction():
    """Secrets should have redacted previews, not raw values."""
    js = 'const key = "AKIAIOSFODNN7EXAMPLE"'
    secrets = mine_secrets("test-asset", js)
    for s in secrets:
        # Redacted preview should not contain the full key
        assert "AKIAIOSFODNN7EXAMPLE" not in s.redacted_preview
        assert "..." in s.redacted_preview or "*" in s.redacted_preview


def test_mine_secrets_private_key():
    """Detect PEM private key headers."""
    js = 'const key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA..."'
    secrets = mine_secrets("test-asset", js)
    assert any(s.secret_type == "private_key_pem_header" for s in secrets)
