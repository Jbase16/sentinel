"""Module sentinel: inline documentation for /Users/jason/Developer/sentinelforge/sentinel.py."""
#
# PURPOSE:
# This module is part of the sentinelforge package in SentinelForge.
# [Specific purpose based on module name: sentinel]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#

#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os

def run_server(args):
    """Launch the full backend stack."""
    print("🚀 Launching SentinelForge Backend...")
    script_path = os.path.join("scripts", "start_servers.sh")
    subprocess.run(["bash", script_path], check=True)

def run_scan(args):
    """Run a manual scan using the legacy scanner wrapper."""
    print(f"🎯 Starting Scan against: {args.target}")
    # Forward to the moved script
    cmd = [sys.executable, "scripts/manual_scan.py", args.target]
    # Conditional branch.
    if args.modules:
        cmd.extend(["--modules", args.modules])
    subprocess.run(cmd)

def run_brain(args):
    """Start only the AI Brain."""
    print("🧠 Starting Sentinel Brain...")
    # This assumes the MLX env is active or we rely on the shebang in the script if executable
    # But often we need a specific python. For now, just run it via the script.
    cmd = [sys.executable, "scripts/start_sentinel_brain.py"]
    subprocess.run(cmd)

def main():
    """Function main."""
    parser = argparse.ArgumentParser(description="SentinelForge Command Deck")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Server Command
    server_parser = subparsers.add_parser("server", help="Start API and AI servers")
    server_parser.set_defaults(func=run_server)

    # Scan Command
    scan_parser = subparsers.add_parser("scan", help="Run a manual scan")
    scan_parser.add_argument("target", help="Target URL/IP")
    scan_parser.add_argument("--modules", help="Comma-separated modules")
    scan_parser.set_defaults(func=run_scan)

    # Brain Command
    brain_parser = subparsers.add_parser("brain", help="Start standalone AI brain")
    brain_parser.set_defaults(func=run_brain)

    args = parser.parse_args()
    
    # Conditional branch.
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
