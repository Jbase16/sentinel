"""Module registry: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/registry.py."""
import logging
import os
import shutil
import sys
from typing import Dict, List, Optional
from pathlib import Path

from core.toolkit.normalizer import normalize_target

from typing import Dict, List, Optional, Any
from pathlib import Path
from pydantic import BaseModel, Field

from core.toolkit.normalizer import normalize_target

logger = logging.getLogger(__name__)


def find_binary(binary: str) -> Optional[str]:
    """
    Find a binary in system PATH or in the project's venv bin directory.

    This is necessary because pip-installed tools go to .venv/bin/ which
    may not be in the system PATH, but they're still usable by the scanner.

    Returns:
        Path to the binary if found, None otherwise.
    """
    # First check system PATH
    path = shutil.which(binary)
    if path:
        return path

    # Check venv bin directory (where pip installs console scripts)
    # Look for venv relative to this file's location (project root)
    project_root = Path(__file__).parent.parent.parent
    venv_bin = project_root / ".venv" / "bin" / binary
    if venv_bin.exists() and os.access(venv_bin, os.X_OK):
        return str(venv_bin)

    # Also check the current Python's venv (sys.prefix)
    if hasattr(sys, 'prefix') and sys.prefix != sys.base_prefix:
        venv_bin_alt = Path(sys.prefix) / "bin" / binary
        if venv_bin_alt.exists() and os.access(venv_bin_alt, os.X_OK):
            return str(venv_bin_alt)
    
    # Check Common System Paths (Homebrew, MacPorts, Linux)
    # This covers cases where PATH might be stripped or weird in the subprocess
    common_paths = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/sbin",
    ]
    for base in common_paths:
        candidate = Path(base) / binary
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)

    return None

# Navigate to repository root (sentinelforge/)
REPO_ROOT = Path(__file__).resolve().parents[2]
WORDLIST_DIR = REPO_ROOT / "assets" / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"

class WordlistManager:
    """
    Ensures a valid wordlist is always available.
    Strategy:
    1. Check Repo Asset (assets/wordlists/common.txt)
    2. Check System Paths (Kali/Linux standards, Homebrew)
    3. Emergency Synthesis (Write minimal list to disk)
    """
    
    # Common system locations (Kali, Ubuntu, macOS/Homebrew)
    SYSTEM_PATHS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", 
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/wfuzz/general/common.txt",
        "/opt/homebrew/share/wordlists/dirb/common.txt",
        "/usr/local/share/wordlists/dirb/common.txt",
    ]

    # Minimal emergency list (Top 100 high-impact paths)
    # This ensures tools ran by the agent never fail due to missing files.
    EMERGENCY_CONTENT = "\n".join([
        ".env", ".git/config", ".git/HEAD", ".vscode/sftp.json", "sftp-config.json",
        "wp-admin", "wp-config.php", "config.php", "config.json", "config.yml",
        "admin", "administrator", "login", "dashboard", "panel",
        "backup", "backup.sql", "database.sql", "dump.sql",
        "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/config",
        "server-status", "nginx.conf", "httpd.conf",
        "api", "api/v1", "v1", "swagger.json", "graphql",
        "robots.txt", "sitemap.xml",
    ])

    @classmethod
    def get_path(cls, name: str = "common.txt") -> str:
        """
        Get a guaranteed path to a wordlist.
        Never returns None. If nothing exists, it creates one.
        """
        # 1. Repo Asset (Priority 1)
        if WORDLIST_DIR.exists():
            candidate = WORDLIST_DIR / name
            if candidate.exists():
                return str(candidate.resolve())
            
            # Try default repo path if named one missing
            if DEFAULT_WORDLIST.exists():
                return str(DEFAULT_WORDLIST.resolve())

        # 2. System Paths (Priority 2)
        for path_str in cls.SYSTEM_PATHS:
            p = Path(path_str)
            if p.exists():
                logger.info(f"Using system wordlist: {p}")
                return str(p.resolve())
        
        # 3. Emergency Synthesis (Defcon 1)
        return cls._synthesize(name)

    @classmethod
    def _synthesize(cls, name: str) -> str:
        """Write emergency wordlist to disk."""
        target_dir = WORDLIST_DIR
        target_file = target_dir / "emergency.txt"
        
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            if not target_file.exists():
                logger.warning(f"Synthesis: Creating emergency wordlist at {target_file}")
                target_file.write_text(cls.EMERGENCY_CONTENT, encoding="utf-8")
            return str(target_file.resolve())
        except Exception as e:
            logger.error(f"Failed to synthesize wordlist: {e}")
            import tempfile
            fd, path = tempfile.mkstemp(prefix="sentinel_emergency_", text=True)
            with os.fdopen(fd, 'w') as f:
                f.write(cls.EMERGENCY_CONTENT)
            return path

# Initialize common wordlist path (Guaranteed to be a string path now)
COMMON_WORDLIST = WordlistManager.get_path("common.txt")


# --------------------------------------------------------------------------
# Tool Registry Definition
# --------------------------------------------------------------------------

class ToolDefinition(BaseModel):
    """
    Defines the capabilities and execution requirements of a security tool.

    Supports two tool types:
      - "subprocess" (default): External binary executed via asyncio.create_subprocess_exec.
      - "internal": Python-based tool that runs in-process via InternalTool.execute().

    Internal tools set tool_type="internal" and provide a handler instance.
    The cmd_template field is ignored for internal tools (set to ["internal"]).
    """
    name: str = Field(..., description="Unique identifier for the tool")
    label: str = Field(..., description="Human-readable description")
    cmd_template: List[str] = Field(..., description="Command template with {target} placeholder")
    aggressive: bool = Field(False, description="If True, requires explicit user approval")
    target_type: str = Field("url", description="Type of target input: host, domain, ip, url")
    binary_name: Optional[str] = Field(default=None, description="Expected binary name if different from first cmd arg")
    stdin_input: bool = Field(default=False, description="If True, target is passed via stdin")
    tool_type: str = Field("subprocess", description="subprocess or internal")
    handler: Optional[Any] = Field(default=None, exclude=True, description="InternalTool instance for internal tools")

    model_config = {"arbitrary_types_allowed": True}


class ToolRegistry:
    """
    Central registry for all available security tools.
    """
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        return list(self._tools.values())
    
    def items(self):
        """Compatibility helper for dict-like iteration."""
        return self._tools.items()

    def keys(self):
        return self._tools.keys()

    def values(self):
        return self._tools.values()

    def __iter__(self):
        return iter(self._tools)

    def __getitem__(self, key: str) -> ToolDefinition:
        return self._tools[key]
    
    def __contains__(self, key: str) -> bool:
        return key in self._tools

    def __len__(self) -> int:
        return len(self._tools)


# Instantiate the registry
TOOLS = ToolRegistry()

# Populate Registry
_tool_data = [
    ToolDefinition(
        name="nmap",
        label="Nmap (fast service/port scan)",
        cmd_template=[
            "nmap", "-sV", "-T4", "-F", "--open",
            "--host-timeout", "60s", "-n", "{target}",
        ],
        aggressive=False,
        target_type="host"
    ),
    ToolDefinition(
        name="subfinder",
        label="subfinder (subdomain discovery)",
        cmd_template=["subfinder", "-silent", "-d", "{target}"],
        aggressive=False,
        target_type="domain"
    ),
    ToolDefinition(
        name="httpx",
        label="httpx (Headed probing via curl)",
        cmd_template=[
            "curl", "-s", "-I", "-L", "-m", "5",
            "{target}"
        ],
        aggressive=False,
        target_type="url"
    ),
    ToolDefinition(
        name="wafw00f",
        label="wafw00f (WAF detection)",
        cmd_template=["wafw00f", "{target}"],
        aggressive=False,
        target_type="url"
    ),
    ToolDefinition(
        name="dirsearch",
        label="dirsearch (content discovery)",
        cmd_template=["dirsearch", "-u", "{target}", "-w", COMMON_WORDLIST, "-q"],
        aggressive=True,
        target_type="url"
    ),
    ToolDefinition(
        name="testssl",
        label="testssl.sh (TLS/SSL config)",
        cmd_template=["testssl.sh", "{target}"],
        aggressive=False,
        target_type="host"
    ),
    ToolDefinition(
        name="whatweb",
        label="whatweb (fingerprint tech stack)",
        cmd_template=["whatweb", "{target}"],
        aggressive=False,
        target_type="url"
    ),
    ToolDefinition(
        name="nuclei_safe",
        label="nuclei (safe profile: low severity)",
        # Use JSONL output so raw_classifier can reliably parse findings.
        # Omit raw request/response pairs to keep output bounded.
        cmd_template=[
            "nuclei",
            "-target",
            "{target}",
            "-severity",
            "low",
            "-jsonl",
            "-omit-raw",
            "-nc",
        ],
        aggressive=True,
        target_type="url",
        binary_name="nuclei",
    ),
    ToolDefinition(
        name="nuclei_mutating",
        label="nuclei (mutating profile: medium/high/critical)",
        # Use JSONL output so raw_classifier can reliably parse findings.
        # Omit raw request/response pairs to keep output bounded.
        cmd_template=[
            "nuclei",
            "-target",
            "{target}",
            "-severity",
            "medium,high,critical",
            "-jsonl",
            "-omit-raw",
            "-nc",
        ],
        aggressive=True,
        target_type="url",
        binary_name="nuclei",
    ),
    ToolDefinition(
        name="nuclei",
        label="nuclei (legacy alias: safe profile)",
        # Legacy alias maintained for CLI compatibility. Keep output parseable.
        cmd_template=[
            "nuclei",
            "-target",
            "{target}",
            "-severity",
            "low",
            "-jsonl",
            "-omit-raw",
            "-nc",
        ],
        aggressive=True,
        target_type="url",
        binary_name="nuclei",
    ),
    ToolDefinition(
        name="nikto",
        label="Nikto (web vulnerability scanner)",
        cmd_template=["nikto", "-h", "{target}"],
        aggressive=True,
        target_type="url"
    ),
    ToolDefinition(
        name="gobuster",
        label="Gobuster (directory brute force)",
        cmd_template=["gobuster", "dir", "-u", "{target}", "-w", COMMON_WORDLIST],
        aggressive=True,
        target_type="url"
    ),
    ToolDefinition(
        name="feroxbuster",
        label="Feroxbuster (recursive discovery)",
        cmd_template=["feroxbuster", "-u", "{target}", "-w", COMMON_WORDLIST, "-n"],
        aggressive=True,
        target_type="url"
    ),
    ToolDefinition(
        name="naabu",
        label="naabu (fast port scan)",
        cmd_template=["naabu", "-host", "{target}"],
        aggressive=False,
        target_type="host"
    ),
    ToolDefinition(
        name="dnsx",
        label="dnsx (DNS resolver)",
        cmd_template=["dnsx", "-silent", "-resp", "-a", "-aaaa"],
        aggressive=False,
        target_type="domain",
        binary_name="dnsx",
        stdin_input=True
    ),
    ToolDefinition(
        name="masscan",
        label="masscan (very fast port scan)",
        cmd_template=["masscan", "{target}", "-p1-65535", "--max-rate", "5000"],
        aggressive=True,
        target_type="ip"
    ),
    ToolDefinition(
        name="amass",
        label="amass (in-depth enumeration)",
        cmd_template=["amass", "enum", "-d", "{target}"],
        aggressive=False,
        target_type="domain"
    ),
    ToolDefinition(
        name="sslyze",
        label="sslyze (TLS scanner)",
        cmd_template=["sslyze", "{target}"],
        aggressive=False,
        target_type="host"
    ),
    ToolDefinition(
        name="httprobe",
        label="httprobe (HTTP availability)",
        cmd_template=["httprobe"],
        aggressive=False,
        target_type="host",
        binary_name="httprobe",
        stdin_input=True
    ),
    ToolDefinition(
        name="pshtt",
        label="pshtt (HTTPS observatory)",
        cmd_template=["pshtt", "{target}"],
        aggressive=False,
        target_type="domain"
    ),
]

for tool in _tool_data:
    TOOLS.register(tool)

# --------------------------------------------------------------------------
# Internal (In-Process) Tools
# --------------------------------------------------------------------------

# Internal tools run inside the ScannerEngine process and are always "installed".
# They provide the exploitation/verification layer without shelling out.
try:
    from core.toolkit.internal_tools.wraith_verify import WraithVerifyTool
    from core.toolkit.internal_tools.persona_diff import WraithPersonaDiffTool
    from core.toolkit.internal_tools.oob_probe import WraithOOBProbeTool
    from core.toolkit.internal_tools.api_discoverer import APIDiscovererTool

    TOOLS.register(
        ToolDefinition(
            name="wraith_verify",
            label="wraith_verify (MutationEngine targeted verification)",
            cmd_template=["internal"],
            aggressive=False,
            target_type="url",
            tool_type="internal",
            handler=WraithVerifyTool(),
        )
    )
    TOOLS.register(
        ToolDefinition(
            name="wraith_persona_diff",
            label="wraith_persona_diff (differential auth replay across personas)",
            cmd_template=["internal"],
            aggressive=False,
            target_type="url",
            tool_type="internal",
            handler=WraithPersonaDiffTool(),
        )
    )
    TOOLS.register(
        ToolDefinition(
            name="wraith_oob_probe",
            label="wraith_oob_probe (OOB canary injection + callback correlation)",
            cmd_template=["internal"],
            aggressive=False,
            target_type="url",
            tool_type="internal",
            handler=WraithOOBProbeTool(),
        )
    )
    TOOLS.register(
        ToolDefinition(
            name="api_discoverer",
            label="api_discoverer (API endpoint discovery via probing + spec parsing)",
            cmd_template=["internal"],
            aggressive=False,
            target_type="url",
            tool_type="internal",
            handler=APIDiscovererTool(),
        )
    )
except Exception as e:
    # Internal tools are optional; failure to import should not block the entire registry.
    logger.warning(f"Failed to register internal tools: {e}")

# Tools that require a public domain name (useless against localhost/RFC1918)
TOOLS_REQUIRING_PUBLIC_DOMAIN = {"amass", "subfinder", "dnsx", "assetfinder"}
# Tools that require root/sudo privileges
TOOLS_REQUIRING_ROOT = {"masscan"}
# TLS/SSL tools — only meaningful when target scheme is https or port 443 discovered
TOOLS_REQUIRING_TLS = {"testssl", "pshtt", "sslyze"}
# Host-wide port scanners — on loopback these find the host's ports, not the app's
TOOLS_HOST_WIDE_PORT_SCAN = {"naabu", "nmap", "masscan"}


def get_tool_command(name: str, target: str, override: Optional[ToolDefinition] = None) -> tuple[List[str], str | None]:
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
    tdef = override or TOOLS.get(name)
    if not tdef:
        raise ValueError(f"Tool not found: {name}")

    normalized = normalize_target(target, tdef.target_type)

    cmd: List[str] = []
    # Loop over items using the new object attribute
    for part in tdef.cmd_template:
        if "{target}" in part:
            cmd.append(part.replace("{target}", normalized))
        elif part is not None:  # Filter out None values
            cmd.append(part)

    # Resolve binary to absolute path so subprocess finds it even when
    # the binary lives in /opt/homebrew/bin or a venv but not system PATH
    if cmd and not cmd[0].startswith('/'):
        resolved = find_binary(tdef.binary_name or cmd[0])
        if resolved:
            cmd[0] = resolved

    # If tool uses stdin, the normalized target is piped via stdin
    stdin_input = normalized if tdef.stdin_input else None

    return cmd, stdin_input
