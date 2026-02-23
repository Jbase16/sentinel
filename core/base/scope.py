"""
core/base/scope.py
The foundational invariant for network bounds.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

class AssetType(str, Enum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    CIDR = "cidr"
    URL = "url"
    PATH = "path"

class ScopeDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class ScopeTarget:
    """Tightly normalized input representation."""
    raw: str
    host: str
    ip: Optional[str]
    scheme: str
    port: int
    path: str
    is_ipv6: bool = False

@dataclass
class ScopeRule:
    """A single in-scope or out-of-scope definition."""
    asset_type: AssetType
    target: str
    decision: ScopeDecision
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    regex: Optional[re.Pattern] = None
    network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None
    
    def __post_init__(self):
        # Precompute regex and network if not set
        if self.asset_type == AssetType.WILDCARD and not self.regex:
            # *.example.com matches a.example.com and sub.example.com, but NOT example.com.
            escaped = re.escape(self.target.replace('*.', ''))
            self.regex = re.compile(f"^.+\\.{escaped}$", re.IGNORECASE)
        elif self.asset_type == AssetType.CIDR and not self.network:
            try:
                self.network = ipaddress.ip_network(self.target, strict=False)
            except ValueError:
                pass

    @property
    def specificity(self) -> int:
        levels = {
            AssetType.URL: 50,
            AssetType.PATH: 40,
            AssetType.DOMAIN: 30,
            AssetType.WILDCARD: 20,
            AssetType.CIDR: 10,
        }
        return levels.get(self.asset_type, 0)

@dataclass
class ScopeCheckDecision:
    raw_target: str
    normalized_host: str
    normalized_ip: Optional[str]
    port: int
    scheme: str
    path: str
    verdict: ScopeDecision
    matched_rule_id: Optional[str] = None
    reason_code: str = "NO_MATCH"
    mode: str = "NORMAL"

class ScopeRegistry:
    """
    Central authority holding scope rules.
    Exposes exactly one critical method: `resolve(target: str) -> ScopeCheckDecision`.
    """
    
    def __init__(self, resolve_dns: bool = False, bounty_mode: bool = False):
        self._rules: List[ScopeRule] = []
        self._resolve_dns = resolve_dns
        self._bounty_mode = bounty_mode

    def add_rule(self, rule: ScopeRule) -> None:
        self._rules.append(rule)
        # Sort rules so highest specificity is evaluated first.
        # For equal specificity, DENY comes before ALLOW. (DENY=deny, ALLOW=allow -> 'deny' > 'allow')
        self._rules.sort(
            key=lambda r: (r.specificity, 1 if r.decision == ScopeDecision.DENY else 0),
            reverse=True
        )

    def normalize(self, raw: str) -> ScopeTarget:
        """Parses input into a tightly normalized ScopeTarget."""
        target = str(raw).strip()
        if not target:
            return ScopeTarget(raw, "", None, "", 0, "")
            
        # Add basic slashes if it looks like a naked host/IP
        if "://" not in target:
            target = f"http://{target}"
            
        try:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            scheme = parsed.scheme.lower() if parsed.scheme else "http"
            port = parsed.port
            if not port:
                port = 443 if scheme == "https" else 80
            path = parsed.path or "/"
            
            # Unicode/punycode normalization
            if host:
                try:
                    host = host.encode('idna').decode('ascii').lower()
                except Exception:
                    host = host.lower()
                
            ip_str = None
            is_ipv6 = False
            
            # Check if host is an IP
            if host:
                try:
                    # Strip brackets for IPv6
                    clean_host = host.strip("[]")
                    ip_obj = ipaddress.ip_address(clean_host)
                    ip_str = str(ip_obj)
                    is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
                    host = clean_host 
                except ValueError:
                    if self._resolve_dns:
                        try:
                            ip_str = socket.gethostbyname(host)
                        except socket.gaierror:
                            pass
            
            return ScopeTarget(
                raw=raw,
                host=host,
                ip=ip_str,
                scheme=scheme,
                port=port,
                path=path,
                is_ipv6=is_ipv6
            )
        except Exception:
            return ScopeTarget(raw, "", None, "", 0, "")

    def evaluate(self, target: ScopeTarget) -> ScopeCheckDecision:
        if not target.host:
            return ScopeCheckDecision(
                target.raw, target.host, target.ip, target.port, target.scheme, target.path,
                verdict=ScopeDecision.DENY if self._bounty_mode else ScopeDecision.UNKNOWN,
                reason_code="INVALID_TARGET",
                mode="BOUNTY" if self._bounty_mode else "NORMAL"
            )
            
        if self._resolve_dns and target.host and not target.ip:
            # DNS resolution failed
            return ScopeCheckDecision(
                target.raw, target.host, target.ip, target.port, target.scheme, target.path,
                verdict=ScopeDecision.DENY if self._bounty_mode else ScopeDecision.UNKNOWN,
                reason_code="DNS_FAIL",
                mode="BOUNTY" if self._bounty_mode else "NORMAL"
            )

        # Find all matching rules
        matches = [rule for rule in self._rules if self._rule_matches(rule, target)]
        
        if not matches:
            return ScopeCheckDecision(
                target.raw, target.host, target.ip, target.port, target.scheme, target.path,
                verdict=ScopeDecision.DENY if self._bounty_mode else ScopeDecision.UNKNOWN,
                reason_code="NO_MATCH",
                mode="BOUNTY" if self._bounty_mode else "NORMAL"
            )
            
        # The rules are sorted by descending specificity, and DENY > ALLOW.
        primary_match = matches[0]
        
        # Path rules apply only when scheme+host match is already in-scope by a host/IP rule
        if primary_match.asset_type == AssetType.PATH and primary_match.decision == ScopeDecision.ALLOW:
            host_allowed = any(r.asset_type in (AssetType.DOMAIN, AssetType.WILDCARD, AssetType.CIDR, AssetType.URL) and r.decision == ScopeDecision.ALLOW for r in matches)
            if not host_allowed:
                host_denied = next((r for r in matches if r.asset_type in (AssetType.DOMAIN, AssetType.WILDCARD, AssetType.CIDR) and r.decision == ScopeDecision.DENY), None)
                if host_denied:
                    return ScopeCheckDecision(
                        target.raw, target.host, target.ip, target.port, target.scheme, target.path,
                        verdict=ScopeDecision.DENY,
                        matched_rule_id=host_denied.id,
                        reason_code="MATCH_DENY",
                        mode="BOUNTY" if self._bounty_mode else "NORMAL"
                    )
                if self._bounty_mode:
                    return ScopeCheckDecision(
                        target.raw, target.host, target.ip, target.port, target.scheme, target.path,
                        verdict=ScopeDecision.DENY,
                        reason_code="NO_HOST_MATCH",
                        mode="BOUNTY" if self._bounty_mode else "NORMAL"
                    )

        return ScopeCheckDecision(
            target.raw, target.host, target.ip, target.port, target.scheme, target.path,
            verdict=primary_match.decision,
            matched_rule_id=primary_match.id,
            reason_code="MATCH_ALLOW" if primary_match.decision == ScopeDecision.ALLOW else "MATCH_DENY",
            mode="BOUNTY" if self._bounty_mode else "NORMAL"
        )

    def _rule_matches(self, rule: ScopeRule, target: ScopeTarget) -> bool:
        if rule.asset_type == AssetType.DOMAIN:
            return rule.target == target.host
        elif rule.asset_type == AssetType.WILDCARD:
            if rule.regex:
                return bool(rule.regex.match(target.host))
        elif rule.asset_type == AssetType.CIDR:
            if target.ip and rule.network:
                try:
                    ip_obj = ipaddress.ip_address(target.ip)
                    return ip_obj in rule.network
                except ValueError:
                    pass
            return False
        elif rule.asset_type == AssetType.URL:
            normalized_rule = self.normalize(rule.target)
            return normalized_rule.host == target.host and normalized_rule.path == target.path
        elif rule.asset_type == AssetType.PATH:
            return target.path.startswith(rule.target)
        return False
        
    def resolve(self, raw: str) -> ScopeCheckDecision:
        normalized = self.normalize(raw)
        return self.evaluate(normalized)
