from __future__ import annotations

import re
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CORE_ROOT = REPOSITORY_ROOT / "core"

REMOVED_RUNTIME_PATHS = (
    REPOSITORY_ROOT / "assets/laws/constitution.cal",
    CORE_ROOT / "cortex/policy_watcher.py",
    CORE_ROOT / "scheduler/laws.py",
)

FORBIDDEN_PRODUCTION_REFERENCES = re.compile(
    r"from core\.cal|import core\.cal|core\.cal\."
    r"|\bCALParser\b|\bsafe_eval\b|\bget_reasoning_engine\b"
    r"|\bget_validated_claims\b|\breasoning_session\b"
    r"|\bload_cal_policy\b|\bload_cal_file\b|\bload_policies_from_db\b"
    r"|\bget_policy_watcher\b|\bPolicyFileWatcher\b"
    r"|constitution\.cal|\bcal_source\b"
)


def test_cal_runtime_has_no_production_files_or_callers() -> None:
    for path in REMOVED_RUNTIME_PATHS:
        assert not path.exists(), f"legacy CAL runtime path remains: {path}"

    cal_package = CORE_ROOT / "cal"
    assert not list(cal_package.glob("*.py")), "legacy CAL package still contains Python code"

    references = []
    for source in sorted(CORE_ROOT.rglob("*.py")):
        for line_number, line in enumerate(source.read_text().splitlines(), start=1):
            if FORBIDDEN_PRODUCTION_REFERENCES.search(line):
                references.append(
                    f"{source.relative_to(REPOSITORY_ROOT)}:{line_number}:{line.strip()}"
                )
    assert references == []


def test_api_startup_cannot_load_executable_policy_text() -> None:
    startup = (CORE_ROOT / "server/api.py").read_text()

    assert "policy_watcher" not in startup
    assert "constitution.cal" not in startup
    assert "load_policies_from_db" not in startup
    assert "load_cal" not in startup
