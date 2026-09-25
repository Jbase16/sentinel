"""Regression proof for the reviewed local security-check baseline."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "local-security-check.sh"
pytestmark = pytest.mark.subprocess_spawn


def test_local_security_check_accepts_reviewed_baseline() -> None:
    env = os.environ.copy()
    env["PATH"] = f"{ROOT / '.venv' / 'bin'}:/usr/bin:/bin"
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
