"""Fail the local gate on new Bandit or Ruff findings over reviewed debt."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


def inventory(report: Path, tool: str, root: Path) -> tuple[Counter[str], dict[str, str]]:
    payload = json.loads(report.read_text())
    if tool == "bandit" and payload.get("errors"):
        raise ValueError(f"Bandit reported scan errors: {payload['errors']}")
    findings = payload if tool == "ruff" else payload["results"]
    counts: Counter[str] = Counter()
    examples: dict[str, str] = {}
    for finding in findings:
        path = Path(finding["filename"]).resolve()
        relative = path.relative_to(root).as_posix()
        line_number = (
            finding["location"]["row"] if tool == "ruff" else finding["line_number"]
        )
        source = path.read_text().splitlines()[line_number - 1].strip()
        rule = finding["code"] if tool == "ruff" else finding["test_id"]
        message = finding["message"] if tool == "ruff" else finding["issue_text"]
        digest = hashlib.sha256(f"{message}\0{source}".encode()).hexdigest()
        key = f"{relative}\t{rule}\t{digest}"
        counts[key] += 1
        examples[key] = f"{relative}:{line_number}: {rule} {message}"
    return counts, examples


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=("bandit", "ruff"))
    parser.add_argument("report", type=Path)
    parser.add_argument("baseline", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        known = Counter(json.loads(args.baseline.read_text())[args.tool])
        found, examples = inventory(args.report, args.tool, root)
    except (OSError, ValueError, KeyError, IndexError) as error:
        print(f"{args.tool} report or baseline is invalid: {error}", file=sys.stderr)
        return 1

    new = found - known
    if new:
        for key, count in sorted(new.items()):
            print(f"NEW {args.tool}: {examples[key]} ({count} occurrence(s))")
        return 1
    print(f"{args.tool}: no new findings ({sum(found.values())} existing findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
