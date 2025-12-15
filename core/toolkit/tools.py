# ============================================================================
# core/toolkit/tools.py
# TOOL REGISTRY & INSTALLATION SYSTEM
# ============================================================================
# 
# PURPOSE:
# This module defines all security scanning tools that Sentinel can use.
# It handles:
# - Tool definitions (commands, parameters, target types)
# - Tool discovery (checking if tools are installed in PATH)
# - Tool installation/uninstallation (via Homebrew or pip)
# - Command generation (converting targets to proper command-line args)
#
# KEY CONCEPTS FOR JUNIOR DEVELOPERS:
# - TOOLS dict: Maps tool names to their definitions (commands, flags, target types)
# - Target normalization: Converts user input (URL/domain/IP) to the right format for each tool
# - Async installation: Tools are installed one at a time to avoid conflicts
# - PATH manipulation: We add common binary directories so tools can be found
#
# ============================================================================

import shutil  # For checking if executables exist (shutil.which)
import socket  # For DNS resolution (converting domains to IPs)
import sys
import os
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from typing import Dict, List

# ============================================================================
# PATH SETUP - Ensure tools can be found
# ============================================================================
# Problem: macOS GUI apps don't inherit the full shell PATH
# Solution: Manually add common tool installation directories
# This ensures tools installed via Homebrew, Go, pip, etc. are discoverable

_EXTRA_PATHS = [
    os.path.expanduser("~/go/bin"),           # Go tools (subfinder, httpx, etc.)
    os.path.expanduser("~/.local/bin"),       # Python user bin
    "/opt/homebrew/bin",                      # Homebrew on Apple Silicon
    "/usr/local/bin",                         # Homebrew on Intel Macs
]

# Also add all Python user bin paths (e.g., ~/Library/Python/3.11/bin)
import glob
for p in glob.glob(os.path.expanduser("~/Library/Python/*/bin")):
    _EXTRA_PATHS.append(p)

# Append paths to the system PATH if not already present
for p in _EXTRA_PATHS:
    if p not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + p

# ============================================================================
# FILE PATHS - Wordlist locations for brute-force tools
# ============================================================================
BASE_DIR = Path(__file__).resolve().parents[1]  # Navigate up from core/toolkit/ to core/
WORDLIST_DIR = BASE_DIR / "assets" / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"

def _wordlist_path(name: str = "common.txt") -> str:
    """
    Get the path to a wordlist file, with fallback to default.
    
    Purpose: Tools like dirsearch and gobuster need wordlists for brute-forcing.
    We check if the requested wordlist exists, otherwise use common.txt.
    """
    candidate = WORDLIST_DIR / name
    if candidate.exists():
        return str(candidate.resolve())
    if DEFAULT_WORDLIST.exists():
        return str(DEFAULT_WORDLIST.resolve())
    return str(candidate.resolve())  # Return path even if it doesn't exist (tool will fail with clear error)

COMMON_WORDLIST = _wordlist_path("common.txt")


# ============================================================================
# TARGET NORMALIZATION - Convert user input to tool-specific formats
# ============================================================================
# Why we need this:
# - User might input: "example.com", "https://example.com", "192.168.1.1"
# - Different tools expect different formats:
#   - nmap wants IPs or hostnames (no protocol)
#   - httpx wants full URLs (with https://)
#   - subfinder wants domains only (no www. prefix)
# These functions standardize the input for each tool type.

def _ensure_url(target: str) -> str:
    """
    Ensure a target is a valid URL with a scheme (https://).
    
    Example: "example.com" → "https://example.com"
    """
    target = (target or "").strip()
    if not target:
        return target
    
    # Add https:// if no protocol specified
    if "://" not in target:
        target = f"https://{target}"
    
    # Parse and rebuild to handle edge cases (e.g., "example.com/path" without protocol)
    parsed = urlparse(target)
    if not parsed.netloc and parsed.path:
        # Handle case like "example.com" being parsed as path instead of netloc
        parsed = urlparse(f"{parsed.scheme or 'https'}://{parsed.path}")
    
    return urlunparse(parsed)


def _extract_host(target: str) -> str:
    """
    Extract the hostname from a URL or return the input if it's already a hostname.
    
    Example: "https://www.example.com:443/path" → "www.example.com"
    """
    parsed = urlparse(_ensure_url(target))
    host = parsed.hostname or target
    return host.lower().rstrip(".")  # Lowercase and remove trailing dot


def _extract_domain(target: str) -> str:
    """
    Extract the domain from a URL (same as host for most cases).
    
    Example: "https://www.example.com" → "www.example.com"
    Note: We don't strip "www." because subfinder needs the exact domain.
    """
    return _extract_host(target)


def _extract_ip(target: str) -> str:
    """
    Resolve a hostname to an IP address using DNS.
    
    Example: "example.com" → "93.184.216.34"
    
    Why this is useful:
    - Tools like masscan require IP addresses, not hostnames
    - DNS resolution happens once at command generation, not during the scan
    """
    host = _extract_host(target)
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        # DNS resolution failed (domain doesn't exist or network issue)
        # Return the original host so the tool can fail with a clear error
        return host


def _normalize_target(raw: str, mode: str) -> str:
    """
    Normalize a target based on what format the tool expects.
    
    Args:
        raw: User-provided target (could be URL, domain, IP, etc.)
        mode: One of "host", "domain", "ip", "url"
    
    Returns:
        Normalized target string suitable for the tool
    
    Example:
        _normalize_target("https://example.com/path", "host") → "example.com"
        _normalize_target("example.com", "url") → "https://example.com"
        _normalize_target("example.com", "ip") → "93.184.216.34"
    """
    if mode == "host":
        return _extract_host(raw)
    if mode == "domain":
        return _extract_domain(raw)
    if mode == "ip":
        return _extract_ip(raw)
    # Default: return as full URL
    return _ensure_url(raw)


# ============================================================================
# TOOL DEFINITIONS - The heart of the tool registry
# ============================================================================
# Each tool is defined as a dictionary with:
# - label: Human-readable description (shown in UI)
# - cmd: Command-line arguments as a list (with {target} placeholder)
# - aggressive: Boolean flag (if True, requires user approval before running)
# - target_type: How to normalize the target ("host", "domain", "ip", "url")
# - binary: (optional) Override for executable name (if different from command)
#
# IMPORTANT: The {target} placeholder gets replaced with the normalized target
# at runtime. See get_tool_command() for the replacement logic.

TOOLS: Dict[str, Dict] = {
    "nmap": {
        "label": "Nmap (fast service/port scan)",
        "cmd": [
            "nmap",           # The nmap command
            "-sV",            # Version detection (identify service versions)
            "-T4",            # Timing template (4 = aggressive, faster scanning)
            "-F",             # Fast mode (scan fewer ports)
            "--open",         # Only show open ports (hide closed/filtered)
            "--host-timeout", "60s",  # Give up on a host after 60 seconds
            "-n",             # No DNS resolution (faster)
            "{target}",       # Placeholder: replaced with normalized target
        ],
        "aggressive": False,  # Safe tool (read-only reconnaissance)
        "target_type": "host",  # Expects hostname or IP (not full URL)
    },
    "subfinder": {
        "label": "subfinder (subdomain discovery)",
        "cmd": ["subfinder", "-silent", "-d", "{target}"],
        "aggressive": False,
        "target_type": "domain",  # Expects domain name only
    },
    "httpx": {
        "label": "httpx (HTTP probing)",
        "cmd": [
            "httpx", 
            "{target}"  # httpx accepts URLs or hosts
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
        "aggressive": True,  # Sends many requests (could trigger rate limits/WAF)
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
        "aggressive": True,  # Active vulnerability scanning (could trigger alerts)
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
            "bash", "-lc",  # Use login shell to ensure PATH is set
            "printf '%s\\n' {target} | hakrawler -subs -u"  # Pipe target into hakrawler
        ],
        "aggressive": False,
        "target_type": "url",
        "binary": "hakrawler",  # Override: we use bash to run it, but check for hakrawler in PATH
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
        "aggressive": True,  # Very noisy (scans all 65k ports)
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
        # FIXED: Removed duplicate "target_type" key
    },
}

# ============================================================================
# INSTALLATION HELPERS - macOS Homebrew + pip
# ============================================================================
# Each tool has an associated installer command.
# We prefer Homebrew for CLI tools and pip for Python packages.
# 
# Note: Some tools require tapping (adding) external Homebrew repositories first.
# We use "||" (shell OR) to make tapping idempotent (tap OR install).

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

# ============================================================================
# ASYNC INSTALLATION - One tool at a time to avoid conflicts
# ============================================================================

async def install_tool(name: str) -> Dict[str, str]:
    """
    Install a single tool using Homebrew or pip.
    
    Process:
    1. Notify UI that installation is starting
    2. Look up the installer command from INSTALLERS dict
    3. Run the command in a subprocess
    4. Check if the tool exists in PATH after installation
    5. Notify UI of the result
    
    Args:
        name: Tool name (must exist in INSTALLERS dict)
    
    Returns:
        Dict with keys: tool, status ("installed" or "error"), message (output/error)
    
    Why async?
    - Installation can take 10-60 seconds per tool
    - We don't want to block the API server while installing
    - The UI can show progress updates via TaskRouter events
    """
    import asyncio
    import shutil
    import subprocess
    
    # Import here to avoid circular dependency at module load time
    # (tools.py is imported by scanner_engine, which is imported by api, which imports task_router)
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        # Fallback if TaskRouter is not available (e.g., during testing)
        TaskRouter = None
    
    # Notify UI: Installation starting (fires SSE event that UI can listen to)
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "installing"})
        except Exception:
            pass  # Don't fail installation if UI notification fails

    # Look up the installer command
    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "unknown", "message": "No installer mapping"}
    cmd = spec["cmd"]
    
    # Prepend environment variables for non-interactive mode
    env_vars = "NONINTERACTIVE=1 "
    
    # Resolve 'pip' to the current python executable to avoid path issues
    # and ensure we install into the active venv
    final_cmd_parts = []
    for part in cmd:
        if part == "pip":
            final_cmd_parts.extend([sys.executable, "-m", "pip"])
        else:
            final_cmd_parts.append(part)
            
    # Handle shell pipes in command (e.g. "||" for fallback)
    # We prepend the env var to the command string
    cmd_str = env_vars + " ".join(final_cmd_parts)
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            shell=True,
            env=dict(os.environ)  # CRITICAL: Pass the modified PATH as a pure dict
        )
        out, _ = await proc.communicate()
        output = out.decode(errors="ignore")[-1000:] if out else ""  # Keep last 1000 chars
        
        # Determine status based on return code and PATH check
        status = "error"
        msg = f"Installation failed (rc={proc.returncode}):\n{output}"

        if proc.returncode == 0:
            status = "installed"
            msg = output
        
        # Double-check: Is the tool actually in PATH?
        # Sometimes brew returns 0 even if the tool isn't available
        if shutil.which(name):
            status = "installed"
            msg = f"Successfully installed {name}\nLogs:\n{output}"
            
        # Notify UI: Result
        if TaskRouter:
            try:
                TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": status})
            except Exception:
                pass

        return {"tool": name, "status": status, "message": msg}
        
    except Exception as e:
        # Subprocess failed to start (command not found, permission denied, etc.)
        return {"tool": name, "status": "error", "message": str(e)}


async def install_tools(names: List[str]) -> List[Dict[str, str]]:
    """
    Install multiple tools sequentially (NOT in parallel).
    
    Why sequential?
    - Homebrew/pip can conflict if multiple installations run simultaneously
    - Package managers use file locks to prevent corruption
    - Sequential is slower but more reliable
    
    Args:
        names: List of tool names to install
    
    Returns:
        List of result dicts (one per tool)
    """
    results = []
    for n in names:
        results.append(await install_tool(n))
    return results


# ============================================================================
# ASYNC UNINSTALLATION - Remove tools via Homebrew or pip
# ============================================================================

async def uninstall_tool(name: str) -> Dict[str, str]:
    """
    Uninstall a single tool.
    
    Process:
    1. Look up the installer command from INSTALLERS dict
    2. Derive the uninstaller command heuristically:
       - "brew install X" → "brew uninstall X"
       - "pip install X" → "pip uninstall -y X"
    3. Run the uninstaller command
    4. Notify UI of the result
    
    Args:
        name: Tool name
    
    Returns:
        Dict with keys: tool, status, message
    """
    import asyncio
    
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        TaskRouter = None
    
    # Notify UI
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "uninstalling"})
        except Exception:
            pass

    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "unknown", "message": "No installer mapping found to infer uninstaller"}
    
    install_cmd = spec["cmd"]
    uninstall_cmd = []
    
    # Heuristic to derive uninstall command
    if "brew" in install_cmd:
        uninstall_cmd = ["brew", "uninstall", name]
    elif "pip" in install_cmd:
        # Use current python executable
        uninstall_cmd = [sys.executable, "-m", "pip", "uninstall", "-y", name]
    else:
        return {"tool": name, "status": "error", "message": "Cannot determine uninstaller for this tool"}

    cmd_str = "NONINTERACTIVE=1 " + " ".join(uninstall_cmd)
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            shell=True,
            env=dict(os.environ) # CRITICAL: Pass modified PATH
        )
        out, _ = await proc.communicate()
        output = out.decode(errors="ignore")[-500:]
        
        status = "error"
        if proc.returncode == 0:
            status = "uninstalled"
        
        # Notify UI
        if TaskRouter:
            try:
                TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": status})
            except Exception:
                pass

        return {"tool": name, "status": status, "message": output}
        
    except Exception as e:
        return {"tool": name, "status": "error", "message": str(e)}


async def uninstall_tools(names: List[str]) -> List[Dict[str, str]]:
    """
    Uninstall multiple tools sequentially.
    
    Args:
        names: List of tool names
    
    Returns:
        List of result dicts
    """
    results = []
    for n in names:
        results.append(await uninstall_tool(n))
    return results


# ============================================================================
# PUBLIC API - Used by the scanner and API server
# ============================================================================

def get_installed_tools() -> Dict[str, Dict]:
    """
    Return only tools that are genuinely installed in PATH.
    
    Process:
    - Iterate through all tools in TOOLS dict
    - For each tool, check if the executable exists using shutil.which()
    - Return a dict of installed tools (subset of TOOLS)
    
    Why we check PATH instead of trusting installation status:
    - Tools might be uninstalled outside of Sentinel
    - Tools might be installed in non-standard locations
    - PATH might change between app launches
    
    Returns:
        Dict mapping tool names to their definitions (only for installed tools)
    """
    installed = {}
    for name, tdef in TOOLS.items():
        # Get the executable name (either from "binary" key or first element of "cmd")
        cmd = tdef["cmd"]
        exe = tdef.get("binary") or cmd[0]
        
        # Check if executable exists in PATH
        if shutil.which(exe):
            installed[name] = tdef
            
    return installed


def get_tool_command(name: str, target: str, override: Dict | None = None) -> List[str]:
    """
    Generate the full command-line arguments for a tool.
    
    Process:
    1. Look up the tool definition (or use override if provided)
    2. Normalize the target based on target_type
    3. Replace {target} placeholder in the command with normalized target
    
    Args:
        name: Tool name
        target: User-provided target (URL, domain, IP, etc.)
        override: Optional tool definition override (for testing)
    
    Returns:
        List of command-line arguments ready for execution
    
    Example:
        get_tool_command("nmap", "https://example.com:443/path")
        → ["nmap", "-sV", "-T4", "-F", "--open", "--host-timeout", "60s", "-n", "example.com"]
    """
    # Get tool definition (or use override for testing)
    tdef = override or TOOLS[name]
    
    # Normalize target based on what this tool expects
    normalized = _normalize_target(target, tdef.get("target_type", "url"))
    
    # Replace {target} placeholder in all command arguments
    cmd: List[str] = []
    for part in tdef["cmd"]:
        if "{target}" in part:
            cmd.append(part.replace("{target}", normalized))
        else:
            cmd.append(part)
    
    return cmd


# ============================================================================
# CALLBACK PLUMBING - Integration with TaskRouter
# ============================================================================
# This section connects tool execution to the AI analysis pipeline.
# When a tool finishes, its output is sent to TaskRouter.handle_tool_output(),
# which triggers AIEngine analysis, findings extraction, and UI updates.
#
# IMPORTANT: This import is at the bottom to avoid circular dependencies.
# The import chain is:
#   tools.py → task_router.py → ai_engine.py → findings_store.py
# If we import TaskRouter at the top of tools.py, we create a cycle.

from core.base.task_router import TaskRouter


def tool_callback_factory(tool_name: str):
    """
    Create a callback function for a specific tool.
    
    Purpose:
    - Scanner engine needs a way to report tool results back to the system
    - We create a callback that captures the tool name and calls TaskRouter
    
    Args:
        tool_name: Name of the tool (e.g., "nmap", "httpx")
    
    Returns:
        A callback function with signature: callback(stdout, stderr, rc, metadata)
    
    Usage:
        callback = tool_callback_factory("nmap")
        callback(stdout="...", stderr="...", rc=0, metadata={"target": "example.com"})
    """
    def callback(stdout, stderr, rc, metadata):
        """
        Tool completion callback.
        
        Args:
            stdout: Tool's standard output (string)
            stderr: Tool's standard error (string)
            rc: Return code (int, 0 = success)
            metadata: Dict with scan metadata (target, session_id, etc.)
        """
        # Forward to TaskRouter, which will:
        # 1. Send output to AIEngine for analysis
        # 2. Extract findings and store them
        # 3. Emit UI events for real-time updates
        TaskRouter.instance().handle_tool_output(
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            rc=rc,
            metadata=metadata
        )
    return callback
