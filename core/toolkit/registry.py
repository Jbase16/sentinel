"""Module registry: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/registry.py."""
from typing import Dict, List
from pathlib import Path

from core.toolkit.normalizer import normalize_target

BASE_DIR = Path(__file__).resolve().parents[1]  # Navigate up to core/
WORDLIST_DIR = BASE_DIR / "assets" / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"


def get_wordlist_path(name: str = "common.txt") -> str:
    """Get the path to a wordlist file, with fallback to default."""
    candidate = WORDLIST_DIR / name
    if candidate.exists():
        return str(candidate.resolve())
    if DEFAULT_WORDLIST.exists():
        return str(DEFAULT_WORDLIST.resolve())
    return str(candidate.resolve())


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
        "cmd": ["bash", "-lc", "printf '%s\\n' {target} | hakrawler -subs -u"],
        "aggressive": False,
        "target_type": "url",
        "binary": "hakrawler",
    },
    "naabu": {
        "label": "naabu (fast port scan)",
        "cmd": ["naabu", "-host", "{target}"],
        "aggressive": False,
        "target_type": "host",
    },
    "dnsx": {
        "label": "dnsx (DNS resolver)",
        "cmd": ["bash", "-lc", "printf '%s\\n' {target} | dnsx -silent -resp -a -aaaa"],
        "aggressive": False,
        "target_type": "domain",
        "binary": "dnsx",
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
        "cmd": ["bash", "-lc", "printf '%s\\n' {target} | httprobe"],
        "aggressive": False,
        "target_type": "host",
        "binary": "httprobe",
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


def get_tool_command(name: str, target: str, override: Dict | None = None) -> List[str]:
    """
    Generate the full command-line arguments for a tool.
    
    Args:
        name: Tool name
        target: User-provided target (URL, domain, IP, etc.)
        override: Optional tool definition override (for testing)
    
    Returns:
        List of command-line arguments ready for execution
    """
    tdef = override or TOOLS[name]
    normalized = normalize_target(target, tdef.get("target_type", "url"))
    
    cmd: List[str] = []
    for part in tdef["cmd"]:
        if "{target}" in part:
            cmd.append(part.replace("{target}", normalized))
        else:
            cmd.append(part)
    
    return cmd
