"""Module registry: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/registry.py."""
import logging
from typing import Dict, List, Optional
from pathlib import Path

from core.toolkit.normalizer import normalize_target

logger = logging.getLogger(__name__)

# Navigate to repository root (sentinelforge/)
# __file__ = core/toolkit/registry.py
# parents[0] = core/toolkit
# parents[1] = core
# parents[2] = sentinelforge/ (repo root)
REPO_ROOT = Path(__file__).resolve().parents[2]
WORDLIST_DIR = REPO_ROOT / "assets" / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"

# Fallback: use inline wordlist if directory doesn't exist
if not WORDLIST_DIR.exists():
    logger.warning(f"Wordlist directory not found: {WORDLIST_DIR}, tools may fail without wordlists")


def get_wordlist_path(name: str = "common.txt") -> Optional[str]:
    """
    Get the path to a wordlist file, with fallback to default.

    Returns None if neither the requested wordlist nor the default exists.
    """
    if WORDLIST_DIR.exists():
        candidate = WORDLIST_DIR / name
        if candidate.exists():
            return str(candidate.resolve())

        # Try default wordlist as fallback
        if DEFAULT_WORDLIST.exists():
            return str(DEFAULT_WORDLIST.resolve())

    # No wordlist directory available
    logger.warning(f"Wordlist not found: {name}, wordlist directory missing")
    return None


# Initialize common wordlist path (may be None if directory doesn't exist)
COMMON_WORDLIST = get_wordlist_path("common.txt")


# Each tool is defined as a dictionary with:
# - label: Human-readable description (shown in UI)
# - cmd: Command-line arguments as a list (with {target} placeholder)
# - aggressive: Boolean flag (if True, requires user approval before running)
# - target_type: How to normalize the target ("host", "domain", "ip", "url")
# - binary: (optional) Override for executable name (if different from command)

TOOLS: Dict[str, Dict] = {
    "nmap": {
        "label": "Nmap (fast service/port scan)",
        "cmd": [
            "nmap", "-sV", "-T4", "-F", "--open",
            "--host-timeout", "60s", "-n", "{target}",
        ],
        "aggressive": False,
        "target_type": "host",
    },
    "subfinder": {
        "label": "subfinder (subdomain discovery)",
        "cmd": ["subfinder", "-silent", "-d", "{target}"],
        "aggressive": False,
        "target_type": "domain",
    },
    "httpx": {
        "label": "httpx (HTTP probing)",
        "cmd": ["httpx", "{target}"],
        "aggressive": False,
        "target_type": "url",
    },
    "hakrevdns": {
        "label": "hakrevdns (reverse DNS)",
        "cmd": ["hakrevdns", "-d", "{target}"],
        "aggressive": False,
        "target_type": "host",
    },
    "wafw00f": {
        "label": "wafw00f (WAF detection)",
        "cmd": ["wafw00f", "{target}"],
        "aggressive": False,
        "target_type": "url",
    },
    "dirsearch": {
        "label": "dirsearch (content discovery)",
        "cmd": ["dirsearch", "-u", "{target}", "-w", COMMON_WORDLIST, "-q"],
        "aggressive": True,
        "target_type": "url",
    },
    "testssl": {
        "label": "testssl.sh (TLS/SSL config)",
        "cmd": ["testssl.sh", "{target}"],
        "aggressive": False,
        "target_type": "host",
    },
    "whatweb": {
        "label": "whatweb (fingerprint tech stack)",
        "cmd": ["whatweb", "{target}"],
        "aggressive": False,
        "target_type": "url",
    },
    "nuclei": {
        "label": "nuclei (vulnerability templates)",
        "cmd": ["nuclei", "-target", "{target}", "-severity", "low,medium,high,critical"],
        "aggressive": True,
        "target_type": "url",
    },
    "nikto": {
        "label": "Nikto (web vulnerability scanner)",
        "cmd": ["nikto", "-h", "{target}"],
        "aggressive": True,
        "target_type": "url",
    },
    "gobuster": {
        "label": "Gobuster (directory brute force)",
        "cmd": ["gobuster", "dir", "-u", "{target}", "-w", COMMON_WORDLIST],
        "aggressive": True,
        "target_type": "url",
    },
    "feroxbuster": {
        "label": "Feroxbuster (recursive discovery)",
        "cmd": ["feroxbuster", "-u", "{target}", "-w", COMMON_WORDLIST, "-n"],
        "aggressive": True,
        "target_type": "url",
    },
    "jaeles": {
        "label": "Jaeles (web vuln automation)",
        "cmd": ["jaeles", "scan", "-u", "{target}"],
        "aggressive": True,
        "target_type": "url",
    },
    "assetfinder": {
        "label": "assetfinder (attack surface discovery)",
        "cmd": ["assetfinder", "-subs-only", "{target}"],
        "aggressive": False,
        "target_type": "domain",
    },
    "hakrawler": {
        "label": "hakrawler (endpoint crawler)",
        "cmd": ["hakrawler", "-subs", "-u"],
        "aggressive": False,
        "target_type": "url",
        "binary": "hakrawler",
        "stdin": True,
    },
    "naabu": {
        "label": "naabu (fast port scan)",
        "cmd": ["naabu", "-host", "{target}"],
        "aggressive": False,
        "target_type": "host",
    },
    "dnsx": {
        "label": "dnsx (DNS resolver)",
        "cmd": ["dnsx", "-silent", "-resp", "-a", "-aaaa"],
        "aggressive": False,
        "target_type": "domain",
        "binary": "dnsx",
        "stdin": True,
    },
    "masscan": {
        "label": "masscan (very fast port scan)",
        "cmd": ["masscan", "{target}", "-p1-65535", "--max-rate", "5000"],
        "aggressive": True,
        "target_type": "ip",
    },
    "amass": {
        "label": "amass (in-depth enumeration)",
        "cmd": ["amass", "enum", "-d", "{target}"],
        "aggressive": False,
        "target_type": "domain",
    },
    "subjack": {
        "label": "subjack (subdomain takeover)",
        "cmd": ["subjack", "-d", "{target}", "-ssl"],
        "aggressive": True,
        "target_type": "domain",
    },
    "sslyze": {
        "label": "sslyze (TLS scanner)",
        "cmd": ["sslyze", "{target}"],
        "aggressive": False,
        "target_type": "host",
    },
    "wfuzz": {
        "label": "wfuzz (parameter fuzzing)",
        "cmd": ["wfuzz", "-c", "-w", COMMON_WORDLIST, "{target}/FUZZ"],
        "aggressive": True,
        "target_type": "url",
    },
    "httprobe": {
        "label": "httprobe (HTTP availability)",
        "cmd": ["httprobe"],
        "aggressive": False,
        "target_type": "host",
        "binary": "httprobe",
        "stdin": True,
    },
    "pshtt": {
        "label": "pshtt (HTTPS observatory)",
        "cmd": ["pshtt", "{target}"],
        "aggressive": False,
        "target_type": "domain",
    },
    "eyewitness": {
        "label": "EyeWitness (screenshot/report)",
        "cmd": ["eyewitness", "--single", "{target}", "--web"],
        "aggressive": False,
        "target_type": "url",
    },
}


def get_tool_command(name: str, target: str, override: Dict | None = None) -> tuple[List[str], str | None]:
    """
    Generate the full command-line arguments for a tool.

    Args:
        name: Tool name
        target: User-provided target (URL, domain, IP, etc.)
        override: Optional tool definition override (for testing)

    Returns:
        Tuple of (command_list, stdin_input).
        - command_list: List of command-line arguments ready for execution
        - stdin_input: String to pipe to stdin, or None if tool doesn't use stdin
    """
    tdef = override or TOOLS[name]
    normalized = normalize_target(target, tdef.get("target_type", "url"))

    cmd: List[str] = []
    # Loop over items.
    for part in tdef["cmd"]:
        if "{target}" in part:
            cmd.append(part.replace("{target}", normalized))
        elif part is not None:  # Filter out None values (e.g., missing wordlist)
            cmd.append(part)

    # If tool uses stdin, the normalized target is piped via stdin
    stdin_input = normalized if tdef.get("stdin") else None

    return cmd, stdin_input
