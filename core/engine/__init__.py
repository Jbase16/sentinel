"""Module __init__: inline documentation for /Users/jason/Developer/sentinelforge/core/engine/__init__.py."""
#
# PURPOSE:
# Manages the execution of security tools and coordinates scanning workflows.
# Think of this as the "hands" that actually run nmap, httpx, and other tools.
#
# MODULES IN THIS PACKAGE:
# - **orchestrator.py**: High-level scan coordination (manages entire scan lifecycle)
# - **executor.py**: Low-level tool execution (runs commands, captures output)
# - **runner.py**: Process management for security tools
# - **pty_manager.py**: Pseudo-terminal management for interactive tools
# - **headless_runner.py**: Headless browser automation (Puppeteer/Playwright)
# - **scan_orchestrator.py**: Session-aware scan orchestration
# - **scanner_engine.py**: Core scanning logic
#
# WORKFLOW:
# User requests scan → Orchestrator plans → Executor runs tools → Output captured → AI analyzes
#
# KEY CONCEPTS:
# - **Orchestration**: High-level workflow management (what tools to run, in what order)
# - **Execution**: Low-level process spawning and output capture
# - **PTY (Pseudo-Terminal)**: Virtual terminal for interactive command-line tools
# - **Async Execution**: Tools run concurrently without blocking
#
