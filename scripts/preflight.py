#!/usr/bin/env python3
"""
SentinelForge pre-flight checker.

Runs a series of cheap diagnostic checks against the local rig. Exits 0 if
every required check passes, non-zero with a short remediation hint on the
first failure.

Usage:
    python3 scripts/preflight.py                       # base checks
    python3 scripts/preflight.py --check-backend       # also probe API
    python3 scripts/preflight.py --check-lab           # also probe lab target
    python3 scripts/preflight.py --scope FILE          # also parse a scope file
    python3 scripts/preflight.py --all                 # all of the above

Each check prints one line: ``[OK] name — detail`` or ``[!! ] name — detail``.
The intent is that you run this BEFORE a scan and read one screen of output.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# ANSI colors — only emit if stdout is a TTY
_IS_TTY = sys.stdout.isatty()
GREEN = "\033[32m" if _IS_TTY else ""
RED = "\033[31m" if _IS_TTY else ""
YELLOW = "\033[33m" if _IS_TTY else ""
DIM = "\033[2m" if _IS_TTY else ""
RESET = "\033[0m" if _IS_TTY else ""

OLLAMA_URL = os.environ.get("SENTINEL_OLLAMA_URL", "http://localhost:11434")
SENTINEL_MODEL = os.environ.get("SENTINEL_AI_MODEL", "sentinel-9b-god-tier")
API_HOST = os.environ.get("SENTINEL_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("SENTINEL_API_PORT", "8765"))
TOKEN_PATH = Path.home() / ".sentinelforge" / "api_token"
LAB_URL = "http://127.0.0.1:3000"


# ---------------------------------------------------------------------------
# Result type and printers
# ---------------------------------------------------------------------------

class CheckResult:
    __slots__ = ("name", "passed", "detail", "remediation")

    def __init__(self, name: str, passed: bool, detail: str, remediation: str = ""):
        self.name = name
        self.passed = passed
        self.detail = detail
        self.remediation = remediation


def _print_result(r: CheckResult) -> None:
    if r.passed:
        prefix = f"{GREEN}[OK]{RESET}"
    else:
        prefix = f"{RED}[!!]{RESET}"
    print(f"{prefix} {r.name:<32} {DIM}—{RESET} {r.detail}")
    if not r.passed and r.remediation:
        print(f"     {YELLOW}fix:{RESET} {r.remediation}")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_python_version() -> CheckResult:
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 11):
        return CheckResult("python version", True, f"{major}.{minor}")
    return CheckResult(
        "python version",
        False,
        f"{major}.{minor} (need >= 3.11)",
        remediation="install Python 3.11+ and re-run with python3.11 scripts/preflight.py",
    )


def check_core_imports() -> CheckResult:
    missing: List[str] = []
    required = ("fastapi", "aiosqlite", "pydantic", "httpx", "uvicorn", "cryptography")
    for mod in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if not missing:
        return CheckResult("core python deps", True, "all importable")
    return CheckResult(
        "core python deps",
        False,
        f"missing: {', '.join(missing)}",
        remediation="pip install -r requirements.txt",
    )


def check_ollama_reachable() -> CheckResult:
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2.0) as resp:
            if resp.status == 200:
                return CheckResult("ollama reachable", True, OLLAMA_URL)
            return CheckResult(
                "ollama reachable", False, f"http {resp.status}",
                remediation="check Ollama logs",
            )
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError) as exc:
        return CheckResult(
            "ollama reachable", False, f"{OLLAMA_URL} unreachable ({exc})",
            remediation="start Ollama: `ollama serve` (or `brew services start ollama`)",
        )


def check_model_loaded() -> CheckResult:
    """Verify the Sentinel model is in Ollama's local registry."""
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2.0) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        return CheckResult(
            "sentinel model loaded", False, f"could not query Ollama: {exc}",
            remediation="resolve the ollama-reachable check first",
        )

    names = {m.get("name", "").split(":")[0] for m in data.get("models", [])}
    if SENTINEL_MODEL in names or f"{SENTINEL_MODEL}:latest" in {m.get("name", "") for m in data.get("models", [])}:
        return CheckResult("sentinel model loaded", True, SENTINEL_MODEL)

    return CheckResult(
        "sentinel model loaded",
        False,
        f"model '{SENTINEL_MODEL}' not in Ollama registry",
        remediation=(
            "from repo root: `ollama create sentinel-9b-god-tier -f Modelfile` "
            "(ensure ./models/sentinel-9b-god-tier-Q4_K_M.gguf exists first)"
        ),
    )


def check_token_file() -> CheckResult:
    if not TOKEN_PATH.exists():
        return CheckResult(
            "api token file",
            True,
            f"absent (will be created on first backend start at {TOKEN_PATH})",
        )
    try:
        mode = TOKEN_PATH.stat().st_mode & 0o777
        size = TOKEN_PATH.stat().st_size
    except OSError as exc:
        return CheckResult(
            "api token file", False, f"unreadable: {exc}",
            remediation=f"chmod 600 {TOKEN_PATH}",
        )

    if size < 16:
        return CheckResult(
            "api token file", False, f"suspiciously short ({size} bytes)",
            remediation=f"delete {TOKEN_PATH} — backend will regenerate on next start",
        )

    if mode & 0o077:
        return CheckResult(
            "api token file",
            False,
            f"permissions too loose: {oct(mode)} (should be 0o600)",
            remediation=f"chmod 600 {TOKEN_PATH}",
        )

    return CheckResult("api token file", True, f"{size} bytes, mode {oct(mode)}")


def check_modelfile_path() -> CheckResult:
    """Verify the Modelfile's gguf reference is a relative path that could
    resolve from the repo root."""
    repo_root = Path(__file__).resolve().parent.parent
    modelfile = repo_root / "Modelfile"
    if not modelfile.exists():
        return CheckResult(
            "modelfile",
            False,
            "Modelfile missing from repo root",
            remediation="check `git status`",
        )
    first_line = next(
        (line for line in modelfile.read_text().splitlines() if line.startswith("FROM ")),
        None,
    )
    if first_line is None:
        return CheckResult(
            "modelfile", False, "Modelfile has no FROM directive",
            remediation="restore from git",
        )
    path_str = first_line[5:].strip()
    if Path(path_str).is_absolute():
        return CheckResult(
            "modelfile",
            False,
            f"FROM uses absolute path: {path_str}",
            remediation="parameterize to relative path so others can build the model",
        )
    return CheckResult("modelfile", True, f"FROM {path_str}")


def check_backend(host: str, port: int) -> CheckResult:
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/v1/health", timeout=2.0) as resp:
            body = json.loads(resp.read())
            status = body.get("status", "unknown")
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError) as exc:
        return CheckResult(
            "sentinel backend",
            False,
            f"http://{host}:{port} unreachable ({exc})",
            remediation="start backend: `bash scripts/start_backend.sh` (in another terminal)",
        )

    if status == "ready":
        return CheckResult("sentinel backend", True, f"ready @ {host}:{port}")
    return CheckResult(
        "sentinel backend",
        False,
        f"status={status}",
        remediation="wait for startup to finish, or check backend logs",
    )


def check_lab_target(url: str) -> CheckResult:
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            if 200 <= resp.status < 400:
                return CheckResult("calibration lab", True, f"{url} up (http {resp.status})")
            return CheckResult(
                "calibration lab", False, f"{url} returned http {resp.status}",
                remediation="check `docker compose ps` in scripts/lab",
            )
    except (urllib.error.URLError, socket.timeout, ConnectionRefusedError) as exc:
        return CheckResult(
            "calibration lab",
            False,
            f"{url} unreachable ({exc})",
            remediation="cd scripts/lab && docker compose up -d",
        )


def check_scope_file(path_str: str) -> CheckResult:
    p = Path(path_str)
    if not p.exists():
        return CheckResult(
            "scope file", False, f"{p} not found",
            remediation=f"create {p} or use scripts/lab/juice-shop-scope.txt",
        )
    rules = []
    try:
        for raw in p.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            rules.append(line)
    except OSError as exc:
        return CheckResult(
            "scope file", False, f"unreadable: {exc}",
            remediation=f"chmod +r {p}",
        )
    if not rules:
        return CheckResult(
            "scope file", False, f"{p} has no non-comment rules",
            remediation="add at least one allow rule",
        )
    return CheckResult("scope file", True, f"{p}: {len(rules)} rules")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelForge pre-flight checks")
    parser.add_argument("--check-backend", action="store_true", help="probe the API server")
    parser.add_argument("--check-lab", action="store_true", help="probe the calibration lab")
    parser.add_argument("--scope", type=str, default=None, help="validate a scope file")
    parser.add_argument("--all", action="store_true", help="run every optional check")
    args = parser.parse_args()

    if args.all:
        args.check_backend = True
        args.check_lab = True
        if args.scope is None:
            args.scope = str(Path(__file__).resolve().parent / "lab" / "juice-shop-scope.txt")

    print(f"{DIM}SentinelForge pre-flight — {os.uname().nodename}{RESET}")
    print()

    checks: List[Callable[[], CheckResult]] = [
        check_python_version,
        check_core_imports,
        check_modelfile_path,
        check_ollama_reachable,
        check_model_loaded,
        check_token_file,
    ]

    failures = 0
    for fn in checks:
        result = fn()
        _print_result(result)
        if not result.passed:
            failures += 1

    if args.check_backend:
        result = check_backend(API_HOST, API_PORT)
        _print_result(result)
        if not result.passed:
            failures += 1

    if args.check_lab:
        result = check_lab_target(LAB_URL)
        _print_result(result)
        if not result.passed:
            failures += 1

    if args.scope:
        result = check_scope_file(args.scope)
        _print_result(result)
        if not result.passed:
            failures += 1

    print()
    if failures == 0:
        print(f"{GREEN}all checks passed{RESET} — you're ready to scan.")
        return 0

    print(f"{RED}{failures} check(s) failed{RESET} — fix the issues above before scanning.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
