"""Regression proof for the reviewed local security-check baseline."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "local-security-check.sh"
pytestmark = pytest.mark.subprocess_spawn


def test_local_security_check_accepts_reviewed_baseline() -> None:
    env = os.environ.copy()
    env["PATH"] = f"{ROOT / '.venv' / 'bin'}:{os.environ.get('PATH', os.defpath)}"
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.fixture
def gate_tree(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    for name in ("core", "scripts", "tools", "sentinelforge", "bin"):
        (tmp_path / name).mkdir()
    for name in (
        "local-security-check.sh",
        "security-check-baseline.txt",
        "security-lint-baseline.json",
        "security_gate_findings.py",
    ):
        shutil.copy2(ROOT / "scripts" / name, tmp_path / "scripts" / name)

    bandit = tmp_path / "bin" / "bandit"
    bandit.write_text('#!/bin/sh\ncat "$FAKE_BANDIT_REPORT"\nexit "$FAKE_BANDIT_STATUS"\n')
    bandit.chmod(0o755)
    ruff = tmp_path / "bin" / "ruff"
    ruff.write_text('#!/bin/sh\ncat "$FAKE_RUFF_REPORT"\nexit "$FAKE_RUFF_STATUS"\n')
    ruff.chmod(0o755)

    report = tmp_path / "bandit.json"
    report.write_text('{"results": []}')
    ruff_report = tmp_path / "ruff.json"
    ruff_report.write_text("[]")
    env = os.environ.copy()
    env["PATH"] = f"{tmp_path / 'bin'}:{os.environ.get('PATH', os.defpath)}"
    env["FAKE_BANDIT_REPORT"] = str(report)
    env["FAKE_BANDIT_STATUS"] = "0"
    env["FAKE_RUFF_REPORT"] = str(ruff_report)
    env["FAKE_RUFF_STATUS"] = "0"
    return tmp_path, env


def run_gate(root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(root / "scripts" / "local-security-check.sh")],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_new_secret_blocks_local_gate(gate_tree: tuple[Path, dict[str, str]]) -> None:
    root, env = gate_tree
    (root / "scripts" / "planted.py").write_text('api_key = "long-dummy-value-not-a-secret"\n')
    result = run_gate(root, env)
    assert result.returncode != 0
    assert "NEW potential hardcoded secret" in result.stdout


def test_new_bandit_finding_blocks_local_gate(gate_tree: tuple[Path, dict[str, str]]) -> None:
    root, env = gate_tree
    source = root / "core" / "planted.py"
    source.write_text("value = 1\n")
    report = root / "bandit.json"
    report.write_text(
        '{"results": [{"filename": "' + str(source) + '", '
        '"line_number": 1, "test_id": "B324", "issue_text": "planted finding"}]}'
    )
    env["FAKE_BANDIT_STATUS"] = "1"
    result = run_gate(root, env)
    assert result.returncode != 0
    assert "NEW bandit" in result.stdout


def test_new_ruff_finding_blocks_local_gate(gate_tree: tuple[Path, dict[str, str]]) -> None:
    root, env = gate_tree
    source = root / "tools" / "planted.py"
    source.write_text("value = missing_name\n")
    report = root / "ruff.json"
    report.write_text(
        '[{"filename": "' + str(source) + '", '
        '"location": {"row": 1}, "code": "F821", "message": "Undefined name"}]'
    )
    env["FAKE_RUFF_STATUS"] = "1"
    result = run_gate(root, env)
    assert result.returncode != 0
    assert "NEW ruff" in result.stdout


def test_nested_syntax_error_blocks_local_gate(gate_tree: tuple[Path, dict[str, str]]) -> None:
    root, env = gate_tree
    nested = root / "core" / "server" / "routers"
    nested.mkdir(parents=True)
    (nested / "broken.py").write_text("def broken(:\n")
    result = run_gate(root, env)
    assert result.returncode != 0
    assert "Python syntax: failed" in result.stdout
