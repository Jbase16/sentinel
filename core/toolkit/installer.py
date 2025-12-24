"""Module installer: inline documentation for /Users/jason/Developer/sentinelforge/core/toolkit/installer.py."""
import asyncio
import os
import shutil
import sys
from typing import Dict, List

from core.toolkit.registry import TOOLS

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


async def install_tool(name: str) -> Dict[str, str]:
    """
    Install a single tool using the strategy-based installation system.
    
    Returns:
        Dict with keys: tool, status ("installed" or "error"), message
    """
    # Error handling block.
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        TaskRouter = None
    
    # Conditional branch.
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "installing"})
        except Exception:
            pass

    spec = INSTALLERS.get(name)
    # Conditional branch.
    if not spec:
        return {"tool": name, "status": "error", "message": f"No installer defined for '{name}'"}
    
    tool_def = TOOLS.get(name)
    # Conditional branch.
    if not tool_def:
        return {"tool": name, "status": "error", "message": f"Tool '{name}' not in registry"}
    
    expected_binary = tool_def.get("binary") or tool_def["cmd"][0]
    
    strategies = spec.get("strategies", [])
    # Conditional branch.
    if not strategies:
        return {"tool": name, "status": "error", "message": "No installation strategies defined"}
    
    last_error = None
    installation_log = []
    
    # Loop over items.
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

        # Parse command chain (handling && and ||)
        chain = []
        current_segment = []
        # Default operator for the first segment is "always run" (represented as None or implied)
        # We store tuples: (operator_before_this_cmd, cmd_list)
        # operator can be "&&", "||", or None (start)
        
        last_op = None
        for part in resolved_cmd_parts:
            if part in ("&&", "||"):
                if current_segment:
                    chain.append((last_op, current_segment))
                    current_segment = []
                last_op = part
            else:
                current_segment.append(part)
        if current_segment:
            chain.append((last_op, current_segment))

        # Execute chain
        chain_output = []
        
        # Track overall success of the chain. 
        # For a single command, success = (rc == 0).
        # For A && B, success = A ok AND B ok.
        # For A || B, success = A ok OR (A fail AND B ok).
        
        # We'll execute sequentially.
        # skip_next: set to True if the previous result dictates skipping the next command.
        
        last_rc = 0
        run_next = True
        
        for i, (op, cmd_parts) in enumerate(chain):
            if not run_next:
                # If we are skipping, we still need to check if the NEXT operator resets things?
                # Standard shell logic:
                # If A fails in A && B, we skip B.
                # If we then have ... || C, does C run? Yes. (A && B) || C.
                # Here we assume a simple left-to-right binding without precedence grouping for now, similar to shell.
                
                # Logic:
                # If op is && and last_rc != 0: skip
                # If op is || and last_rc == 0: skip
                pass

            # Determine if we should run this segment based on previous result
            if op == "&&":
                if last_rc != 0:
                    run_next = False
            elif op == "||":
                if last_rc == 0:
                    run_next = False
            
            # Re-evaluate run_next for the current step (if it was false, can it become true? no, strictly chaining here)
            # Actually, standard shell:
            # false && echo hi -> skip echo
            # false || echo hi -> run echo
            
            should_run = True
            if op == "&&" and last_rc != 0:
                should_run = False
            elif op == "||" and last_rc == 0:
                should_run = False
            
            if not should_run:
                # If we skip, we preserve the last_rc? Or does the skipped command count as... ?
                # In shell, the exit code remains that of the last executed command.
                continue

            # Execute
            cmd_pretty = " ".join(cmd_parts)
            try:
                env_vars = os.environ.copy()
                env_vars["NONINTERACTIVE"] = "1"
                
                program = cmd_parts[0]
                args = cmd_parts[1:]
                
                proc = await asyncio.create_subprocess_exec(
                    program,
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env=env_vars
                )
                out, _ = await proc.communicate()
                output_chunk = out.decode(errors="ignore") if out else ""
                chain_output.append(output_chunk)
                
                last_rc = proc.returncode
                installation_log.append(f"→ Exe: {cmd_pretty} (rc={last_rc})")
            
            except Exception as e:
                last_rc = 1 # Treat exception as failure
                last_error = str(e)
                installation_log.append(f"  ⊗ Exe Error: {cmd_pretty} -> {e}")

        # Final checks
        # Check if the strategy as a whole 'succeeded'.
        # If the last executed command succeeded, we consider it a success?
        # Or should we be stricter? 
        # For "brew tap || brew install", if tap fails (rc!=0), we run install. If install succeeds (rc=0), total=0.
        # If tap succeeds (rc=0), we skip install, total=0.
        # So last_rc is a good proxy.
        
        if last_rc != 0:
            last_error = f"Strategy failed with exit code {last_rc}"
            installation_log.append(f"  ⊗ Failed: {last_error}")
            continue
        
        if not shutil.which(expected_binary):
            last_error = f"Command succeeded but '{expected_binary}' not found in PATH"
            installation_log.append(f"  ⊗ Failed: {last_error}")
            continue
        
        # Verify binary works
        verify_cmd = spec.get("verify_cmd", ["--version"])
        try:
            verify_proc = await asyncio.create_subprocess_exec(
                expected_binary,
                *verify_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(verify_proc.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
        except Exception as verify_err:
            installation_log.append(f"  ⚠ Verification warning: {verify_err}")
        
        installation_log.append(f"  ✓ Success: '{expected_binary}' installed")
        
        if TaskRouter:
            try:
                TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "installed"})
            except Exception:
                pass
        
        return {"tool": name, "status": "installed", "message": "\n".join(installation_log)}
    
    # Conditional branch.
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "error"})
        except Exception:
            pass
    
    return {
        "tool": name,
        "status": "error",
        "message": f"All strategies failed.\n\n{chr(10).join(installation_log)}\n\nLast error: {last_error}"
    }


async def install_tools(names: List[str]) -> List[Dict[str, str]]:
    """Install multiple tools sequentially."""
    results = []
    # Loop over items.
    for n in names:
        results.append(await install_tool(n))
    return results


async def uninstall_tool(name: str) -> Dict[str, str]:
    """Uninstall a single tool."""
    # Error handling block.
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        TaskRouter = None
    
    # Conditional branch.
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "uninstalling"})
        except Exception:
            pass

    spec = INSTALLERS.get(name)
    # Conditional branch.
    if not spec:
        return {"tool": name, "status": "unknown", "message": "No installer mapping found"}
    
    strategies = spec.get("strategies", [])
    # Conditional branch.
    if not strategies:
        return {"tool": name, "status": "error", "message": "No strategies to infer uninstaller"}
    
    install_cmd = strategies[0]["cmd"]
    uninstall_cmd = []
    
    # Conditional branch.
    if "brew" in install_cmd:
        uninstall_cmd = ["brew", "uninstall", name]
    elif "pip" in install_cmd:
        uninstall_cmd = [sys.executable, "-m", "pip", "uninstall", "-y", name]
    else:
        return {"tool": name, "status": "error", "message": "Cannot determine uninstaller"}

    cmd_env = os.environ.copy()
    cmd_env["NONINTERACTIVE"] = "1"
    
    # Error handling block.
    try:
        proc = await asyncio.create_subprocess_exec(
            *uninstall_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=cmd_env
        )
        out, _ = await proc.communicate()
        output = out.decode(errors="ignore")[-500:]
        
        status = "uninstalled" if proc.returncode == 0 else "error"
        
        if TaskRouter:
            try:
                TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": status})
            except Exception:
                pass

        return {"tool": name, "status": status, "message": output}
        
    except Exception as e:
        return {"tool": name, "status": "error", "message": str(e)}


async def uninstall_tools(names: List[str]) -> List[Dict[str, str]]:
    """Uninstall multiple tools sequentially."""
    results = []
    # Loop over items.
    for n in names:
        results.append(await uninstall_tool(n))
    return results
