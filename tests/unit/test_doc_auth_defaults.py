"""Guard the documented default-on API authentication contract."""

import re
from pathlib import Path


DOCS = Path(__file__).resolve().parents[2] / "docs"


def test_docs_do_not_describe_api_auth_as_default_off():
    contradictory_lines = []
    for path in DOCS.rglob("*.md"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "require_auth" not in line.lower() or "terminal_require_auth" in line.lower():
                continue
            if re.search(r"(?i)\brequire_auth\b\s*:\s*`?false\b", line):
                contradictory_lines.append(f"{path}:{number}: {line}")
            elif "default" in line.lower() and "false" in line.lower():
                contradictory_lines.append(f"{path}:{number}: {line}")

    assert not contradictory_lines, "\n".join(contradictory_lines)

    authentication = (DOCS / "AUTHENTICATION.md").read_text(encoding="utf-8")
    auth_row = next(
        line for line in authentication.splitlines() if "| `SENTINEL_REQUIRE_AUTH` |" in line
    )
    assert "`True`" in auth_row.split("|")[3]

    startup = (DOCS / "STARTUP_TROUBLESHOOTING.md").read_text(encoding="utf-8")
    assert "- `require_auth`: `true`" in startup
