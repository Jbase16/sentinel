"""
SentinelForge CLI — unified entrypoint for controlling the system.

Usage examples:
    python -m sentinelforge.cli.sentinel start
    python -m sentinelforge.cli.sentinel scan
"""

import argparse


def main():
    parser = argparse.ArgumentParser(description="SentinelForge Command Interface")
    parser.add_argument("command", choices=["start", "scan", "debug"], help="Command to run")
    args = parser.parse_args()

    if args.command == "start":
        print("🚀 Starting SentinelForge backend...")
        import uvicorn
        from core.base.config import get_config
        
        config = get_config()
        uvicorn.run(
            "core.server.api:app",
            host=config.api_host,
            port=config.api_port,
            reload=config.debug
        )
    elif args.command in {"scan", "debug"}:
        parser.error(f"{args.command} is not implemented; no action was taken")

if __name__ == "__main__":
    main()
