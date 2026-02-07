"""Module normalizer: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/normalizer.py."""
import ipaddress
import os
import socket
from enum import Enum
from urllib.parse import urlparse, urlunparse


class TargetClassification(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    LOOPBACK = "loopback"
    FILE = "file"


def is_file_target(target: str) -> bool:
    """
    Detect explicit file targets.
    Only treats file:// URLs or existing absolute paths as file targets.
    """
    candidate = (target or "").strip()
    if not candidate:
        return False

    try:
        parsed = urlparse(candidate)
    except Exception:
        parsed = None

    if parsed and parsed.scheme == "file":
        return True

    if os.path.isabs(candidate) and os.path.isfile(candidate):
        return True

    return False


def classify_target(target: str) -> TargetClassification:
    """
    Classify a scan target for control-flow decisions.

    NOTE: Use this at scan start to determine whether DNS recon is meaningful.
    """
    if is_file_target(target):
        return TargetClassification.FILE

    if is_localhost_target(target):
        return TargetClassification.LOOPBACK

    host = extract_host(target)
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return TargetClassification.LOOPBACK
        return TargetClassification.IP
    except ValueError:
        return TargetClassification.DOMAIN


def ensure_url(target: str) -> str:
    """
    Ensure a target is a valid URL with a scheme (https://).
    
    Example: "example.com" → "https://example.com"
    """
    target = (target or "").strip()
    # Conditional branch.
    if not target:
        return target
    
    # Add https:// if no protocol specified
    if "://" not in target:
        target = f"https://{target}"
    
    # Parse and rebuild to handle edge cases
    parsed = urlparse(target)
    # Conditional branch.
    if not parsed.netloc and parsed.path:
        parsed = urlparse(f"{parsed.scheme or 'https'}://{parsed.path}")
    
    return urlunparse(parsed)


def extract_host(target: str) -> str:
    """
    Extract the hostname from a URL or return the input if already a hostname.
    
    Example: "https://www.example.com:443/path" → "www.example.com"
    """
    parsed = urlparse(ensure_url(target))
    host = parsed.hostname or target
    return host.lower().rstrip(".")


def extract_domain(target: str) -> str:
    """
    Extract the domain from a URL (same as host for most cases).
    
    Example: "https://www.example.com" → "www.example.com"
    """
    return extract_host(target)


def extract_ip(target: str) -> str:
    """
    Resolve a hostname to an IP address using DNS.
    
    Example: "example.com" → "93.184.216.34"
    """
    host = extract_host(target)
    # Error handling block.
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def normalize_target(raw: str, mode: str) -> str:
    """
    Normalize a target based on what format the tool expects.
    
    Args:
        raw: User-provided target (could be URL, domain, IP, etc.)
        mode: One of "host", "domain", "ip", "url"
    
    Returns:
        Normalized target string suitable for the tool
    """
    # Conditional branch.
    if mode == "host":
        return extract_host(raw)
    # Conditional branch.
    if mode == "domain":
        return extract_domain(raw)
    # Conditional branch.
    if mode == "ip":
        return extract_ip(raw)
    return ensure_url(raw)


def is_localhost_target(target: str) -> bool:
    """Check if target resolves to loopback."""
    host = extract_host(target).lower()
    return host in ("localhost", "localhost.localdomain", "::1") or host.startswith("127.")


def is_private_target(target: str) -> bool:
    """Check if target is localhost or RFC1918 private address space."""
    if is_localhost_target(target):
        return True
    host = extract_host(target)
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False
