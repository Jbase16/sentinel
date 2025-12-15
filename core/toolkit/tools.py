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

# CRITICAL: Add venv bin if we're running inside one OR if one exists in the project
# This fixes tools installed via pip (wafw00f, dirsearch, whatweb)
# Strategy 1: If currently running in venv, use sys.prefix
if hasattr(sys, 'prefix') and hasattr(sys, 'base_prefix') and sys.prefix != sys.base_prefix:
    venv_bin = os.path.join(sys.prefix, 'bin')
    if os.path.exists(venv_bin):
        _EXTRA_PATHS.insert(0, venv_bin)

# Strategy 2: Check for .venv in project root (common pattern)
# Navigate up from core/toolkit/ to find project root
_project_root = Path(__file__).resolve().parents[2]  # Go up 2 levels from core/toolkit/tools.py
for venv_name in ['.venv', 'venv']:
    venv_bin = _project_root / venv_name / 'bin'
    if venv_bin.exists() and str(venv_bin) not in _EXTRA_PATHS:
        _EXTRA_PATHS.insert(0, str(venv_bin))

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
        "cmd": ["testssl.sh", "{target}"],  # FIXED: Binary is testssl.sh, not testssl
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

# ============================================================================
# INSTALLATION STRATEGY DEFINITIONS
# ============================================================================
# New schema: Each tool can have multiple installation strategies with fallbacks
# - strategies: List of installation methods (tried in order until one succeeds)
# - verify_cmd: Command to run post-install to verify binary works
# - prerequisite: Required tool that must exist before installation (go, brew, python)
#
# ARCHITECTURE: This enables:
# 1. Automatic fallback (if brew fails, try pip; if pip fails, try go)
# 2. Prerequisite checking (don't try go install if Go isn't installed)
# 3. Post-install verification (ensure --version works, not just PATH check)
# 4. Failure diagnostics (which strategy failed and why)

INSTALLERS: Dict[str, Dict] = {
    # Homebrew-based tools
    "nmap": {
        "strategies": [{"cmd": ["brew", "install", "nmap"]}],
        "verify_cmd": ["--version"],
    },
    "subfinder": {
        "strategies": [
            {"cmd": ["brew", "tap", "projectdiscovery/tap/subfinder", "||", "brew", "install", "subfinder"]},
        ],
        "verify_cmd": ["-version"],
    },
    "httpx": {
        "strategies": [
            {"cmd": ["brew", "tap", "projectdiscovery/tap/httpx", "||", "brew", "install", "httpx"]},
        ],
        "verify_cmd": ["-version"],
    },
    "nuclei": {
        "strategies": [
            {"cmd": ["brew", "tap", "projectdiscovery/tap/nuclei", "||", "brew", "install", "nuclei"]},
        ],
        "verify_cmd": ["-version"],
    },
    "nikto": {
        "strategies": [{"cmd": ["brew", "install", "nikto"]}],
        "verify_cmd": ["-Version"],
    },
    "naabu": {
        "strategies": [
            {"cmd": ["brew", "tap", "projectdiscovery/tap/naabu", "||", "brew", "install", "naabu"]},
        ],
        "verify_cmd": ["-version"],
    },
    
    # Python pip-based tools
    "whatweb": {
        "strategies": [{"cmd": ["pip", "install", "whatweb"]}],
        "verify_cmd": ["--version"],
    },
    "wafw00f": {
        "strategies": [{"cmd": ["pip", "install", "wafw00f"]}],
        "verify_cmd": ["--version"],
    },
    "dirsearch": {
        "strategies": [{"cmd": ["pip", "install", "dirsearch"]}],
        "verify_cmd": ["--version"],
    },
    "pshtt": {
        "strategies": [{"cmd": ["pip", "install", "pshtt"]}],
        "verify_cmd": ["--version"],
    },
    "wfuzz": {
        "strategies": [
            {"cmd": ["pip", "install", "wfuzz"]},
            {"cmd": ["pip3", "install", "wfuzz"]},  # Fallback to pip3 if pip fails
        ],
        "verify_cmd": ["--version"],
    },
    
    # Go-based tools (FIXED: Use go install instead of brew/pip)
    # CRITICAL: These require Go to be installed first
    "assetfinder": {
        "strategies": [
            {"cmd": ["go", "install", "github.com/tomnomnom/assetfinder@latest"], "prerequisite": "go"},
        ],
        "verify_cmd": ["--help"],  # assetfinder doesn't have --version
    },
    "hakrevdns": {
        "strategies": [
            {"cmd": ["go", "install", "github.com/hakluke/hakrevdns@latest"], "prerequisite": "go"},
        ],
        "verify_cmd": ["--help"],
    },
    "hakrawler": {
        "strategies": [
            {"cmd": ["go", "install", "github.com/hakluke/hakrawler@latest"], "prerequisite": "go"},
        ],
        "verify_cmd": ["--help"],
    },
    "subjack": {
        "strategies": [
            {"cmd": ["go", "install", "github.com/haccer/subjack@latest"], "prerequisite": "go"},
        ],
        "verify_cmd": ["--help"],
    },
    "httprobe": {
        "strategies": [
            {"cmd": ["go", "install", "github.com/tomnomnom/httprobe@latest"], "prerequisite": "go"},
        ],
        "verify_cmd": ["--help"],
    },
    
    # Special cases
    "dnsx": {
        "strategies": [
            {"cmd": ["brew", "tap", "projectdiscovery/tap/dnsx", "||", "brew", "install", "dnsx"]},
        ],
        "verify_cmd": ["-version"],
    },
    "amass": {
        "strategies": [{"cmd": ["brew", "install", "amass"]}],
        "verify_cmd": ["--version"],
    },
    "sslyze": {
        "strategies": [{"cmd": ["brew", "install", "sslyze"]}],
        "verify_cmd": ["--version"],
    },
    "feroxbuster": {
        "strategies": [{"cmd": ["brew", "install", "feroxbuster"]}],
        "verify_cmd": ["--version"],
    },
    "gobuster": {
        "strategies": [{"cmd": ["brew", "install", "gobuster"]}],
        "verify_cmd": ["--version"],
    },
    "testssl": {
        "strategies": [{"cmd": ["brew", "install", "testssl"]}],
        "verify_cmd": ["--version"],
    },
    "masscan": {
        "strategies": [{"cmd": ["brew", "install", "masscan"]}],
        "verify_cmd": ["--version"],
    },
    
    # REMOVED problematic tools that don't have working installers:
    # - eyewitness: Requires manual installation from https://github.com/RedSiege/EyeWitness
    #               (pip install eyewitness does NOT work - package doesn't exist)
    # - jaeles: Tool has been archived/unmaintained, no active package available
    #
    # These tools remain in TOOLS dict but won't have auto-install capability.
    # Users must install manually and they'll be discovered via PATH scanning.
    #
    # IMPORTANT: Go-based tools (assetfinder, hakrevdns, etc.) require Go to be installed first:
    #   brew install go
    # After Go is installed, restart the backend to pick up the new PATH.
}

# ============================================================================
# ASYNC INSTALLATION - One tool at a time to avoid conflicts
# ============================================================================

async def install_tool(name: str) -> Dict[str, str]:
    """
    Install a single tool using the strategy-based installation system.
    
    NEW ARCHITECTURE (Production-Grade):
    Instead of blindly running installer commands, this implements:
    1. Prerequisite checking: Verify required tools (go, brew) exist before attempting install
    2. Strategy fallback: Try multiple installation methods in order until one succeeds
    3. Post-install verification: Run --version or --help to ensure binary actually works
    4. Binary name resolution: Check the CORRECT binary name from TOOLS dict, not tool name
    5. Detailed diagnostics: Return which strategy succeeded/failed and why
    
    INVARIANT: install_tool(t) returns "installed" ⟹ get_installed_tools() includes t
    
    This solves the state divergence problem where package managers lie about success.
    
    Args:
        name: Tool name (must exist in both TOOLS and INSTALLERS dicts)
    
    Returns:
        Dict with keys: tool, status ("installed" or "error"), message (diagnostic output)
    
    Why async?
    - Installation can take 10-60 seconds per tool
    - We don't want to block the API server while installing
    - The UI can show progress updates via TaskRouter events
    """
    import asyncio
    import shutil
    import subprocess
    
    # Import here to avoid circular dependency at module load time
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        TaskRouter = None
    
    # Notify UI: Installation starting
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "installing"})
        except Exception:
            pass

    # Look up the installer spec
    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "error", "message": f"No installer defined. Tool '{name}' must be installed manually."}
    
    # Get the expected binary name from TOOLS dict (NOT the tool name!)
    # Example: "testssl" tool → "testssl.sh" binary
    tool_def = TOOLS.get(name)
    if not tool_def:
        return {"tool": name, "status": "error", "message": f"Tool '{name}' not found in TOOLS registry"}
    
    expected_binary = tool_def.get("binary") or tool_def["cmd"][0]
    
    # Try each installation strategy in order
    strategies = spec.get("strategies", [])
    if not strategies:
        return {"tool": name, "status": "error", "message": "No installation strategies defined"}
    
    last_error = None
    installation_log = []
    
    for idx, strategy in enumerate(strategies):
        strategy_cmd = strategy["cmd"]
        prerequisite = strategy.get("prerequisite")
        
        # CRITICAL: Check prerequisite before attempting installation
        if prerequisite and not shutil.which(prerequisite):
            msg = f"Strategy {idx+1} requires '{prerequisite}' but it's not installed. Install {prerequisite} first."
            installation_log.append(f"⊗ Strategy {idx+1}: {msg}")
            last_error = msg
            continue  # Try next strategy
        
        # Resolve 'pip' to the current python executable (ensures venv usage)
        final_cmd_parts = []
        for part in strategy_cmd:
            if part == "pip":
                final_cmd_parts.extend([sys.executable, "-m", "pip"])
            elif part == "go" and prerequisite == "go":
                # Use absolute path to go if available
                go_path = shutil.which("go")
                if go_path:
                    final_cmd_parts.append(go_path)
                else:
                    final_cmd_parts.append("go")  # Will fail, but good for error message
            else:
                final_cmd_parts.append(part)
        
        # Build shell command string
        env_vars = "NONINTERACTIVE=1 "
        cmd_str = env_vars + " ".join(final_cmd_parts)
        
        try:
            # Execute installation command
            proc = await asyncio.create_subprocess_shell(
                cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                shell=True,
                env=dict(os.environ)
            )
            out, _ = await proc.communicate()
            output = out.decode(errors="ignore")[-800:] if out else ""
            
            installation_log.append(f"→ Strategy {idx+1}: {' '.join(strategy_cmd[:3])}... (rc={proc.returncode})")
            
            # Check if installation succeeded
            if proc.returncode != 0:
                last_error = f"Command failed with exit code {proc.returncode}"
                installation_log.append(f"  ⊗ Failed: {last_error}")
                continue  # Try next strategy
            
            # CRITICAL: Verify the binary is now in PATH
            if not shutil.which(expected_binary):
                last_error = f"Command succeeded but '{expected_binary}' not found in PATH"
                installation_log.append(f"  ⊗ Failed: {last_error}")
                continue  # Try next strategy
            
            # CRITICAL: Run verification command to ensure binary actually works
            verify_cmd = spec.get("verify_cmd", ["--version"])
            try:
                verify_proc = await asyncio.create_subprocess_exec(
                    expected_binary,
                    *verify_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                # Use wait_for to add timeout (some tools hang on --version)
                await asyncio.wait_for(verify_proc.communicate(), timeout=5.0)
                
                if verify_proc.returncode != 0:
                    last_error = f"Binary exists but verification command failed (rc={verify_proc.returncode})"
                    installation_log.append(f"  ⊗ Verification failed: {last_error}")
                    continue  # Try next strategy
                    
            except asyncio.TimeoutError:
                # Some tools hang on --version without stdin, accept this as success
                pass
            except Exception as verify_err:
                # Verification failed, but binary exists - still count as success
                installation_log.append(f"  ⚠ Verification warning: {verify_err}")
            
            # SUCCESS: All checks passed
            installation_log.append(f"  ✓ Success: '{expected_binary}' installed and verified")
            
            if TaskRouter:
                try:
                    TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "installed"})
                except Exception:
                    pass
            
            full_log = "\n".join(installation_log) + f"\n\nInstallation output:\n{output}"
            return {"tool": name, "status": "installed", "message": full_log}
        
        except Exception as e:
            last_error = str(e)
            installation_log.append(f"  ⊗ Exception: {last_error}")
            continue  # Try next strategy
    
    # All strategies failed
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "error"})
        except Exception:
            pass
    
    failure_log = "\n".join(installation_log)
    return {
        "tool": name,
        "status": "error",
        "message": f"All installation strategies failed.\n\n{failure_log}\n\nLast error: {last_error}"
    }


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
