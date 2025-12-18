"""Module runner: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/runner.py."""
#
# PURPOSE:
# This module is part of the engine package in SentinelForge.
# [Specific purpose based on module name: runner]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

# core/runner.py
# Tool execution + recon phase orchestrator

from __future__ import annotations

import subprocess
from typing import Callable, Dict, List, Tuple

from core.toolkit.tools import get_tool_command, get_installed_tools
from core.recon.behavioral import BehavioralRecon

OutputCallback = Callable[[str], None]


def run_tool(name: str, target: str, on_output: OutputCallback) -> Tuple[int, str]:
    """Function run_tool."""
    cmd = get_tool_command(name, target)
    on_output(f"[{name}] Executing: {' '.join(cmd)}")

    # Error handling block.
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
    except FileNotFoundError:
        msg = f"[{name}] NOT INSTALLED or not in PATH."
        on_output(msg)
        return 127, msg

    combined = []

    # Conditional branch.
    if proc.stdout:
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line:
                continue
            combined.append(line)
            on_output(f"[{name}] {line}")

    exit_code = proc.wait()
    on_output(f"[{name}] Exit code: {exit_code}")
    return exit_code, "\n".join(combined)


def run_all_tools(target: str, on_output: OutputCallback) -> Dict[str, Dict[str, object]]:
    """Function run_all_tools."""
    results: Dict[str, Dict[str, object]] = {}
    installed = get_installed_tools()

    # Conditional branch.
    if not installed:
        on_output("No supported tools found in PATH.")
        return results

    on_output(f"Installed tools: {', '.join(installed.keys())}")

    # Loop over items.
    for name in installed:
        on_output(f"--- Running {name} ---")
        exit_code, output = run_tool(name, target, on_output)
        results[name] = {
            "exit": exit_code,
            "output": output,
        }

    on_output("All tool runs completed.")
    return results


class PhaseRunner:
    """
    Coordinates advanced recon phases (behavioral probes, API diffing, etc.).
    Designed to be awaited from async contexts (e.g., scanner worker threads).
    """

    def __init__(self, target: str, on_output: OutputCallback):
        """Function __init__."""
        self.target = target
        self.on_output = on_output
        self.results: Dict[str, List[dict]] = {}

    async def run_all_phases(self) -> Dict[str, List[dict]]:
        """AsyncFunction run_all_phases."""
        phases = [
            ("behavioral-suite", self._run_behavioral_phase),
        ]

        # Loop over items.
        for label, handler in phases:
            self.on_output(f"[phase] Starting {label} analysis…")
            try:
                phase_map = await handler()
                for phase_name, findings in phase_map.items():
                    self.results[phase_name] = findings
                    self.on_output(f"[phase] {phase_name} complete ({len(findings)} findings).")
            except Exception as exc:  # pragma: no cover
                self.on_output(f"[phase] {label} error: {exc}")

        return self.results

    async def _run_behavioral_phase(self) -> Dict[str, List[dict]]:
        """AsyncFunction _run_behavioral_phase."""
        recon = BehavioralRecon(self.on_output)
        findings = await recon.run(self.target)
        buckets: Dict[str, List[dict]] = {
            "behavioral": [],
            "behavioral-timing": [],
            "tls-active": [],
        }

        # Loop over items.
        for item in findings:
            families = item.get("families", [])
            placed = False
            if any(fam.startswith("recon-phase:behavior-timing") for fam in families):
                buckets["behavioral-timing"].append(item)
                placed = True
            if any(fam.startswith("recon-phase:tls-active") for fam in families):
                buckets["tls-active"].append(item)
                placed = True
            if not placed:
                buckets["behavioral"].append(item)

        return {name: bucket for name, bucket in buckets.items() if bucket}
