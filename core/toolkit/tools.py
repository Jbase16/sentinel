# core/tools.py
# Full dictionary-based tool registry for AraUltra

import shutil
import socket
import sys
import os
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from typing import Dict, List

# Ensure common user paths are in PATH for tool discovery
_EXTRA_PATHS = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
]

# Add all Python user bin paths
import glob
for p in glob.glob(os.path.expanduser("~/Library/Python/*/bin")):
    _EXTRA_PATHS.append(p)

for p in _EXTRA_PATHS:
    if p not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + p

# -------------------------------------------------------------------
# File paths
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
WORDLIST_DIR = BASE_DIR / "assets" / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"

def _wordlist_path(name: str = "common.txt") -> str:
    candidate = WORDLIST_DIR / name
    if candidate.exists():
        return str(candidate.resolve())
    if DEFAULT_WORDLIST.exists():
        return str(DEFAULT_WORDLIST.resolve())
    return str(candidate.resolve())

COMMON_WORDLIST = _wordlist_path("common.txt")



# -------------------------------------------------------------------
# Target normalization helpers
# -------------------------------------------------------------------
def _ensure_url(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return target
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if not parsed.netloc and parsed.path:
        parsed = urlparse(f"{parsed.scheme or 'https'}://{parsed.path}")
    return urlunparse(parsed)

def _extract_host(target: str) -> str:
    parsed = urlparse(_ensure_url(target))
    host = parsed.hostname or target
    return host.lower().rstrip(".")

def _extract_domain(target: str) -> str:
    return _extract_host(target)

def _extract_ip(target: str) -> str:
    host = _extract_host(target)
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host

def _normalize_target(raw: str, mode: str) -> str:
    if mode == "host":
        return _extract_host(raw)
    if mode == "domain":
        return _extract_domain(raw)
    if mode == "ip":
        return _extract_ip(raw)
    return _ensure_url(raw)

# -------------------------------------------------------------------
# DICTIONARY-BASED TOOL DEFINITIONS
# -------------------------------------------------------------------
TOOLS: Dict[str, Dict] = {
    "nmap": {
        "label": "Nmap (fast service/port scan)",
        "cmd": [
            "nmap", "-sV", "-T4", "-F",
            "--open",
            "--host-timeout", "60s",
            "-n",
            "{target}",
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
        "cmd": [
            "httpx", 
            "{target}"
        ],
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
        "cmd": ["testssl", "{target}"],
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
        "cmd": ["nuclei", "-target", "{target}", "-severity",
                "low,medium,high,critical"],
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
        "cmd": ["gobuster", "dir", "-u", "{target}", "-w",
                COMMON_WORDLIST],
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
        "cmd": [
            "bash", "-lc",
            "printf '%s\\n' {target} | hakrawler -subs -u"
        ],
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
        "cmd": [
            "bash", "-lc",
            "printf '%s\\n' {target} | dnsx -silent -resp -a -aaaa"
        ],
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
        "cmd": [
            "bash", "-lc",
            "printf '%s\\n' {target} | httprobe"
        ],
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
        "target_type": "url",
    },
}

# -------------------------------------------------------------------
# Install helpers (best-effort; macOS Homebrew-first)
# -------------------------------------------------------------------
INSTALLERS: Dict[str, Dict] = {
    # Homebrew formulas (brew tap projectdiscovery/tap for nuclei, naabu, etc.)
    "nmap": {"cmd": ["brew", "install", "nmap"]},
    "subfinder": {"cmd": ["brew", "tap", "projectdiscovery/tap/subfinder", "||", "brew", "install", "subfinder"]},
    "httpx": {"cmd": ["brew", "tap", "projectdiscovery/tap/httpx", "||", "brew", "install", "httpx"]},
    "nuclei": {"cmd": ["brew", "tap", "projectdiscovery/tap/nuclei", "||", "brew", "install", "nuclei"]},
    "nikto": {"cmd": ["brew", "install", "nikto"]},
    "naabu": {"cmd": ["brew", "tap", "projectdiscovery/tap/naabu", "||", "brew", "install", "naabu"]},
    "whatweb": {"cmd": ["pip", "install", "whatweb"]},
    "wafw00f": {"cmd": ["pip", "install", "wafw00f"]},
    "assetfinder": {"cmd": ["brew", "tap", "tomnomnom/tools", "&&", "brew", "install", "assetfinder"]},
    "hakrawler": {"cmd": ["pip", "install", "hakrawler"]},
    "dnsx": {"cmd": ["brew", "tap", "projectdiscovery/tap/dnsx", "||", "brew", "install", "dnsx"]},
    "amass": {"cmd": ["brew", "install", "amass"]},
    "subjack": {"cmd": ["pip", "install", "subjack"]},
    "sslyze": {"cmd": ["brew", "install", "sslyze"]},
    "httprobe": {"cmd": ["pip", "install", "httprobe"]},
    # Python/pip utilities
    "dirsearch": {"cmd": ["pip", "install", "dirsearch"]},
    "feroxbuster": {"cmd": ["brew", "install", "feroxbuster"]},
    "gobuster": {"cmd": ["brew", "install", "gobuster"]},
    "jaeles": {"cmd": ["pip", "install", "jaeles"]},
    "pshtt": {"cmd": ["pip", "install", "pshtt"]},
    "wfuzz": {"cmd": ["pip", "install", "wfuzz"]},
    "testssl": {"cmd": ["brew", "install", "testssl"]},
    "hakrevdns": {"cmd": ["pip", "install", "hakrevdns"]},
    "eyewitness": {"cmd": ["pip", "install", "eyewitness"]},
    "masscan": {"cmd": ["brew", "install", "masscan"]},
}

async def install_tool(name: str) -> Dict[str, str]:
    import asyncio
    import shutil
    import subprocess
    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "unknown", "message": "No installer mapping"}
    cmd = spec["cmd"]
    
    # Prepend environment variables for non-interactive mode
    env_vars = "NONINTERACTIVE=1 "
    
    # Handle shell pipes in command (e.g. "||" for fallback)
    # We prepend the env var to the command string
    cmd_str = env_vars + " ".join(cmd)
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            shell=True
        )
        out, _ = await proc.communicate()
        output = out.decode(errors="ignore")[-1000:] if out else "" # Capture last 1000 chars
        
        if proc.returncode == 0:
            return {"tool": name, "status": "installed", "message": output}
        
        # Check if tool actually exists after install attempt
        if shutil.which(name):
            return {"tool": name, "status": "installed", "message": f"Successfully installed {name}\nLogs:\n{output}"}
            
        return {"tool": name, "status": "error", "message": f"Installation failed (rc={proc.returncode}):\n{output}"}
    except Exception as e:
        return {"tool": name, "status": "error", "message": str(e)}

async def install_tools(names: List[str]) -> List[Dict[str, str]]:
    """Install multiple tools sequentially (not in parallel) to avoid resource contention."""
    results = []
    for n in names:
        results.append(await install_tool(n))
    return results

# -------------------------------------------------------------------
# API exposed to the scanner/engine
# -------------------------------------------------------------------
def get_installed_tools() -> Dict[str, Dict]:
    """Return only tools that are genuinely installed in PATH - no shims/fallbacks"""
    installed = {}
    for name, tdef in TOOLS.items():
        cmd = tdef["cmd"]
        exe = tdef.get("binary") or cmd[0]
        if shutil.which(exe):
            installed[name] = tdef
    return installed

def get_tool_command(name: str, target: str, override: Dict | None = None) -> List[str]:
    tdef = override or TOOLS[name]
    normalized = _normalize_target(target, tdef.get("target_type", "url"))
    cmd: List[str] = []
    for part in tdef["cmd"]:
        if "{target}" in part:
            cmd.append(part.replace("{target}", normalized))
        else:
            cmd.append(part)
    return cmd

# -------------------------------------------------------------------
# Callback plumbing
# -------------------------------------------------------------------
from core.base.task_router import TaskRouter

def tool_callback_factory(tool_name: str):
    def callback(stdout, stderr, rc, metadata):
        TaskRouter.instance().handle_tool_output(
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            metadata=metadata
        )
    return callback