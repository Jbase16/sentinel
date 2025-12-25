"""Module installer: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/installer.py."""
import asyncio
import os
import shutil
import sys
import logging
import signal
from typing import Dict, List, Optional, Tuple, NamedTuple

from core.toolkit.registry import TOOLS

logger = logging.getLogger(__name__)

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
            {"cmd": ["pip3", "install", "wfuzz"]},
        ],
        "verify_cmd": ["--version"],
    },
    
    # Go-based tools
    "assetfinder": {
        "strategies": [
            {"cmd": ["go", "install", "github.com/tomnomnom/assetfinder@latest"], "prerequisite": "go"},
        ],
        "verify_cmd": ["--help"],
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
    
    # Homebrew special cases
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
}

class CommandSegment(NamedTuple):
    """Represents a single command within a chain."""
    cmd: List[str]
    operator_before: Optional[str]  # "&&", "||", or None


class CommandValidator:
    """
    Validates the structure of command chains to ensure they form a valid execution graph.
    Enforces contract invariants (token structure, operator placement) rather than
    checking for shell injection characters, as execution is already tokenized.
    """
    OPERATORS = {"&&", "||"}

    @staticmethod
    def validate_tokens(tokens: List[str]) -> None:
        if not tokens:
            raise ValueError("Empty command token list")

        last_was_op = True  # disallow operator as first token

        for i, tok in enumerate(tokens):
            if tok in CommandValidator.OPERATORS:
                if last_was_op:
                    raise ValueError(f"Invalid operator placement near '{tok}' at index {i}")
                last_was_op = True
            else:
                last_was_op = False

        if last_was_op:
            raise ValueError("Command cannot end with operator")

    @staticmethod
    def validate_segments(segments: List['CommandSegment'], allow_missing: Optional[set] = None) -> None:
        allow_missing = allow_missing or set()
        
        for seg in segments:
            if not seg.cmd:
                raise ValueError("Empty command segment")
            
            # Use specific check for the executable of each segment
            # This fails fast if the required tool (e.g. brew, go) creates a command that is invalid
            exe = seg.cmd[0]
            
            if exe in allow_missing:
                continue
                
            if not shutil.which(exe) and not os.path.exists(exe):
                # We raise ValueError here to catch it during chain construction/validation
                raise ValueError(f"Executable not found: {exe}")


class CommandChain:
    """
    Robust command chain parser and executor.
    
    Handles sequences of commands joined by && (AND) and || (OR) operators
    without relying on shell=True, preventing injection vulnerabilities.
    """
    
    def __init__(self, raw_tokens: List[str]):
        """Function __init__."""
        self.segments: List[CommandSegment] = self._parse(raw_tokens)
        
        # Validate post-parsing to ensure the graph is sound
        CommandValidator.validate_tokens(raw_tokens)
        CommandValidator.validate_segments(self.segments, allow_missing={"pip", "pip3", "go", "brew", "git"})
        
    def _parse(self, tokens: List[str]) -> List[CommandSegment]:
        """Parse raw token list into CommandSegments."""
        segments = []
        current_cmd = []
        last_op = None
        
        for token in tokens:
            if token in ("&&", "||"):
                if current_cmd:
                    segments.append(CommandSegment(current_cmd, last_op))
                    current_cmd = []
                last_op = token
            else:
                current_cmd.append(token)
                
        if current_cmd:
            segments.append(CommandSegment(current_cmd, last_op))
            
        return segments

    async def execute(self, env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
        """
        Execute the chain logic.
        
        Returns:
            Tuple[int, str]: (Final Exit Code, Combined Output)
        """
        last_rc = 0
        output_buffer = []
        run_next = True
        
        for i, segment in enumerate(self.segments):
            # Calculate if we should run this segment based on the previous result and operator
            should_run = True
            
            if segment.operator_before == "&&":
                if last_rc != 0:
                    should_run = False
            elif segment.operator_before == "||":
                if last_rc == 0:
                    should_run = False
            
            if not should_run:
                # If we skip, we preserve the last_rc (standard shell behavior)
                continue
                
            # Execute Segment
            cmd_pretty = " ".join(segment.cmd)
            try:
                # Resolve special binaries like 'pip' or 'go' if needed, but the caller
                # usually pre-resolves them. If not, we could do it here.
                # Assuming caller handles binary resolution (e.g. 'pip' -> sys.executable -m pip)
                
                # Check binary existence before running to give better error message
                exe = segment.cmd[0]
                if not shutil.which(exe) and not os.path.exists(exe):
                     msg = f"executable not found: {exe}"
                     output_buffer.append(f"⊗ {msg}")
                     last_rc = 127
                     continue

                proc = await asyncio.create_subprocess_exec(
                    *segment.cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env=env
                )
                
                stdout, _ = await proc.communicate()
                out_str = stdout.decode(errors="ignore") if stdout else ""
                
                output_buffer.append(out_str)
                last_rc = proc.returncode or 0 
                # Note: proc.returncode is None if still running, but communicate() ensures completion
                
            except (OSError, asyncio.TimeoutError) as e:
                output_buffer.append(f"⊗ Error executing '{cmd_pretty}': {e}")
                last_rc = 1
            except Exception as e: # Catch-all for unexpected logic errors
                 output_buffer.append(f"⊗ Unexpected error executing '{cmd_pretty}': {e}")
                 last_rc = 1

        return last_rc, "\n".join(output_buffer)

def _emit_ui_event(tool_name: str, status: str) -> None:
    """Helper to emit UI events safely."""
    try:
        from core.base.task_router import TaskRouter
        TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": tool_name, "status": status})
    except (ImportError, Exception):
        # TaskRouter might not be available or initialized; ignore failures
        pass

async def install_tool(name: str) -> Dict[str, str]:
    """
    Install a single tool using the strategy-based installation system.
    
    Returns:
        Dict with keys: tool, status ("installed" or "error"), message
    """
    _emit_ui_event(name, "installing")

    spec = INSTALLERS.get(name)
    # Conditional branch.
    if not spec:
        _emit_ui_event(name, "error")
        return {"tool": name, "status": "error", "message": f"No installer defined for '{name}'"}
    
    tool_def = TOOLS.get(name)
    # Conditional branch.
    if not tool_def:
        _emit_ui_event(name, "error")
        return {"tool": name, "status": "error", "message": f"Tool '{name}' not in registry"}
    
    expected_binary = tool_def.get("binary") or tool_def["cmd"][0]
    strategies = spec.get("strategies", [])
    
    if not strategies:
        _emit_ui_event(name, "error")
        return {"tool": name, "status": "error", "message": "No installation strategies defined"}
    
    last_error = None
    installation_log = []
    
    for idx, strategy in enumerate(strategies):
        strategy_cmd = strategy["cmd"]
        prerequisite = strategy.get("prerequisite")
        
        # Check prerequisite
        if prerequisite and not shutil.which(prerequisite):
            msg = f"Strategy {idx+1} requires '{prerequisite}' but it's not installed"
            installation_log.append(f"⊗ Strategy {idx+1}: {msg}")
            last_error = msg
            continue
        
        # Resolve pip to python -m pip and handle others
        resolved_cmd_parts = []
        for part in strategy_cmd:
            if part == "pip":
                resolved_cmd_parts.extend([sys.executable, "-m", "pip"])
            elif part == "go" and prerequisite == "go":
                go_path = shutil.which("go")
                resolved_cmd_parts.append(go_path if go_path else "go")
            else:
                resolved_cmd_parts.append(part)

        # Execute using CommandChain
        env_vars = os.environ.copy()
        env_vars["NONINTERACTIVE"] = "1"
        
        chain = CommandChain(resolved_cmd_parts)
        rc, output = await chain.execute(env=env_vars)
        
        installation_log.append(output)

        if rc != 0:
            last_error = f"Strategy failed with exit code {rc}"
            installation_log.append(f"  ⊗ Failed: {last_error}")
            continue
        
        # Verify binary existence
        if not shutil.which(expected_binary):
            last_error = f"Command succeeded but '{expected_binary}' not found in PATH"
            installation_log.append(f"  ⊗ Failed: {last_error}")
            continue
        
        # Verify binary works
        verify_cmd = spec.get("verify_cmd", ["--version"])
        try:
            # We use a direct subprocess call here as it's a simple, single command
            verify_proc = await asyncio.create_subprocess_exec(
                expected_binary,
                *verify_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(verify_proc.communicate(), timeout=5.0)
            
            if verify_proc.returncode != 0:
                last_error = f"Verification failed: '{expected_binary} {' '.join(verify_cmd)}' returned {verify_proc.returncode}"
                installation_log.append(f"  ⊗ Verification failed: {last_error}")
                continue # Try next strategy
                
        except asyncio.TimeoutError:
            last_error = f"Verification timed out for '{expected_binary}'"
            installation_log.append(f"  ⊗ {last_error}")
            continue
        except (OSError, Exception) as verify_err:
            last_error = f"Verification error: {verify_err}"
            installation_log.append(f"  ⊗ {last_error}")
            continue
        
        # Success
        installation_log.append(f"  ✓ Success: '{expected_binary}' installed and verified")
        _emit_ui_event(name, "installed")
        return {"tool": name, "status": "installed", "message": "\n".join(installation_log)}

    # If all strategies failed
    _emit_ui_event(name, "error")
    return {
        "tool": name,
        "status": "error",
        "message": f"All strategies failed.\n\n" + "\n".join(installation_log) + f"\n\nLast error: {last_error}"
    }


async def install_tools(names: List[str]) -> List[Dict[str, str]]:
    """Install multiple tools sequentially."""
    results = []
    for n in names:
        results.append(await install_tool(n))
    return results


async def uninstall_tool(name: str) -> Dict[str, str]:
    """Uninstall a single tool."""
    _emit_ui_event(name, "uninstalling")

    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "unknown", "message": "No installer mapping found"}
    
    strategies = spec.get("strategies", [])
    if not strategies:
        return {"tool": name, "status": "error", "message": "No strategies to infer uninstaller"}
    
    install_cmd = strategies[0]["cmd"]
    uninstall_cmd = []
    
    # Simple inference of uninstall command
    if "brew" in install_cmd:
        uninstall_cmd = ["brew", "uninstall", name]
    elif "pip" in install_cmd:
        uninstall_cmd = [sys.executable, "-m", "pip", "uninstall", "-y", name]
    else:
        return {"tool": name, "status": "error", "message": "Cannot determine uninstaller"}

    cmd_env = os.environ.copy()
    cmd_env["NONINTERACTIVE"] = "1"
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *uninstall_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=cmd_env
        )
        out, _ = await proc.communicate()
        output = out.decode(errors="ignore") if out else ""
        
        status = "uninstalled" if proc.returncode == 0 else "error"
        _emit_ui_event(name, status)

        return {"tool": name, "status": status, "message": output}
        
    except (OSError, asyncio.TimeoutError) as e:
        _emit_ui_event(name, "error")
        return {"tool": name, "status": "error", "message": str(e)}


async def uninstall_tools(names: List[str]) -> List[Dict[str, str]]:
    """Uninstall multiple tools sequentially."""
    results = []
    for n in names:
        results.append(await uninstall_tool(n))
    return results
