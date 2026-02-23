"""
tests/unit/test_scope_registry.py
Verify strictly normalized bounds: Punycode, IPv6 CIDR, path precedence, etc.
"""
import pytest
import ipaddress
import socket
from core.base.scope import (
    ScopeRegistry, ScopeRule, AssetType, ScopeDecision, ScopeTarget
)

def test_normalization_basics():
    registry = ScopeRegistry()
    target = registry.normalize("example.com")
    assert target.host == "example.com"
    assert target.scheme == "http"
    assert target.port == 80
    assert target.path == "/"

    target = registry.normalize("https://sub.example.com:8443/test/path")
    assert target.host == "sub.example.com"
    assert target.scheme == "https"
    assert target.port == 8443
    assert target.path == "/test/path"

def test_normalization_punycode_and_confusables():
    registry = ScopeRegistry()
    
    # Punycode normalization
    target = registry.normalize("https://xn--e1awd7f.com")
    assert target.host == "xn--e1awd7f.com"  # Keep valid punycode as ASCII
    
    # Unicode domain should be converted to ASCII punycode via IDNA
    bizarre = "m\u00fcnchen.de"
    target = registry.normalize(f"http://{bizarre}")
    assert target.host == "xn--mnchen-3ya.de"

def test_ipv6_normalization():
    registry = ScopeRegistry()
    
    # IPv6 URL requires brackets
    target = registry.normalize("http://[2001:db8::1]:8080/path")
    assert target.is_ipv6 is True
    assert target.host == "2001:db8::1"
    assert target.port == 8080
    assert target.ip == "2001:db8::1"

def test_wildcard_matching_rules():
    registry = ScopeRegistry(bounty_mode=True)
    registry.add_rule(ScopeRule(AssetType.WILDCARD, "*.example.com", ScopeDecision.ALLOW))
    
    # Should match subdomains
    assert registry.resolve("sub.example.com").verdict == ScopeDecision.ALLOW
    assert registry.resolve("deep.sub.example.com").verdict == ScopeDecision.ALLOW
    
    # "example.com" itself is NOT a subdomain of example.com unless prefix matches empty differently. 
    assert registry.resolve("example.com").verdict == ScopeDecision.DENY
    
    # Evil confusable: example.com.evil.com ends with .evil.com, won't match .example.com
    assert registry.resolve("example.com.evil.com").verdict == ScopeDecision.DENY

def test_rule_precedence_hard_deny():
    registry = ScopeRegistry(bounty_mode=True)
    registry.add_rule(ScopeRule(AssetType.WILDCARD, "*.example.com", ScopeDecision.ALLOW))
    registry.add_rule(ScopeRule(AssetType.DOMAIN, "admin.example.com", ScopeDecision.DENY))
    
    assert registry.resolve("test.example.com").verdict == ScopeDecision.ALLOW
    # Hard DENY (more specific DOMAIN over WILDCARD) wins
    assert registry.resolve("admin.example.com").verdict == ScopeDecision.DENY

def test_path_precedence():
    registry = ScopeRegistry(bounty_mode=True)
    registry.add_rule(ScopeRule(AssetType.DOMAIN, "example.com", ScopeDecision.ALLOW))
    registry.add_rule(ScopeRule(AssetType.PATH, "/admin", ScopeDecision.DENY))
    
    # Host is allowed, path is benign -> ALLOW
    assert registry.resolve("example.com/api/test").verdict == ScopeDecision.ALLOW
    
    # Host is allowed, path is denied -> DENY
    assert registry.resolve("example.com/admin/login").verdict == ScopeDecision.DENY

def test_path_allow_requires_host_allow_in_bounty_mode():
    registry = ScopeRegistry(bounty_mode=True)
    # Target only has a path allow rule
    registry.add_rule(ScopeRule(AssetType.PATH, "/public", ScopeDecision.ALLOW))
    
    # Because host is not explicitly allowed, it should DENY in bounty mode
    # "Path rules apply only when scheme+host match is already in-scope"
    assert registry.resolve("example.com/public").verdict == ScopeDecision.DENY

def test_unresolved_host_bounty_mode(monkeypatch):
    registry = ScopeRegistry(resolve_dns=True, bounty_mode=True)
    registry.add_rule(ScopeRule(AssetType.DOMAIN, "unresolvable.local", ScopeDecision.ALLOW))
    
    def mock_gethostbyname(host):
        raise socket.gaierror("Name or service not known")
        
    monkeypatch.setattr(socket, "gethostbyname", mock_gethostbyname)
    
    decision = registry.resolve("http://unresolvable.local")
    assert decision.verdict == ScopeDecision.DENY
    assert decision.reason_code == "DNS_FAIL"

def test_ipv6_cidr_matching():
    registry = ScopeRegistry(bounty_mode=True)
    registry.add_rule(ScopeRule(AssetType.CIDR, "2001:db8::/32", ScopeDecision.ALLOW))
    registry.add_rule(ScopeRule(AssetType.CIDR, "2001:db8::1/128", ScopeDecision.DENY))
    
    # Allowed block
    assert registry.resolve("http://[2001:db8:85a3::8a2e:370:7334]").verdict == ScopeDecision.ALLOW
    # Explicit DENY from more specific CIDR? Wait, CIDR has same specificity (10) as CIDR.
    # DENY comes first in same specificity. So it will be evaluated first!
    assert registry.resolve("http://[2001:db8::1]").verdict == ScopeDecision.DENY
