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
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        TaskRouter = None
    
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "installing"})
        except Exception:
            pass

    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "error", "message": f"No installer defined for '{name}'"}
    
    tool_def = TOOLS.get(name)
    if not tool_def:
        return {"tool": name, "status": "error", "message": f"Tool '{name}' not in registry"}
    
    expected_binary = tool_def.get("binary") or tool_def["cmd"][0]
    
    strategies = spec.get("strategies", [])
    if not strategies:
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
        
        # Resolve pip to python -m pip
        final_cmd_parts = []
        for part in strategy_cmd:
            if part == "pip":
                final_cmd_parts.extend([sys.executable, "-m", "pip"])
            elif part == "go" and prerequisite == "go":
                go_path = shutil.which("go")
                final_cmd_parts.append(go_path if go_path else "go")
            else:
                final_cmd_parts.append(part)
        
        env_vars = "NONINTERACTIVE=1 "
        cmd_str = env_vars + " ".join(final_cmd_parts)
        
        try:
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
            
            if proc.returncode != 0:
                last_error = f"Command failed with exit code {proc.returncode}"
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
        
        except Exception as e:
            last_error = str(e)
            installation_log.append(f"  ⊗ Exception: {last_error}")
            continue
    
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
    for n in names:
        results.append(await install_tool(n))
    return results


async def uninstall_tool(name: str) -> Dict[str, str]:
    """Uninstall a single tool."""
    try:
        from core.base.task_router import TaskRouter
    except ImportError:
        TaskRouter = None
    
    if TaskRouter:
        try:
            TaskRouter.instance().emit_ui_event("tool_install_progress", {"tool": name, "status": "uninstalling"})
        except Exception:
            pass

    spec = INSTALLERS.get(name)
    if not spec:
        return {"tool": name, "status": "unknown", "message": "No installer mapping found"}
    
    strategies = spec.get("strategies", [])
    if not strategies:
        return {"tool": name, "status": "error", "message": "No strategies to infer uninstaller"}
    
    install_cmd = strategies[0]["cmd"]
    uninstall_cmd = []
    
    if "brew" in install_cmd:
        uninstall_cmd = ["brew", "uninstall", name]
    elif "pip" in install_cmd:
        uninstall_cmd = [sys.executable, "-m", "pip", "uninstall", "-y", name]
    else:
        return {"tool": name, "status": "error", "message": "Cannot determine uninstaller"}

    cmd_str = "NONINTERACTIVE=1 " + " ".join(uninstall_cmd)
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            shell=True,
            env=dict(os.environ)
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
    for n in names:
        results.append(await uninstall_tool(n))
    return results
