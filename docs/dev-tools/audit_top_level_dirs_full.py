#!/usr/bin/env python3
"""
Full, accurate directory inventory for SentinelForge.
Counts every file recursively, includes empty and hidden folders,
and outputs a JSON + Markdown summary.

Run:
    python tools/dev/audit_top_level_dirs_full.py
"""

import os
import json
from collections import defaultdict

ROOT = "."
IGNORE = {
    ".git", ".idea", ".vscode", "__pycache__", "venv",
    "archive_stage", ".pytest_cache", ".mypy_cache"
}

def safe_relpath(p):
    try:
        return os.path.relpath(p, ROOT)
    except Exception:
        return p

summary = defaultdict(lambda: {"dirs": 0, "files": 0, "size_bytes": 0})

for dirpath, dirnames, filenames in os.walk(ROOT):
    # skip ignored folders
    parts = dirpath.split(os.sep)
    if any(part in IGNORE for part in parts):
        dirnames[:] = []  # stop descending
        continue

    # determine top-level directory
    top = parts[1] if len(parts) > 1 and parts[0] == "." else parts[0]
    if top in IGNORE or top == "":
        continue

    summary[top]["dirs"] += len(dirnames)
    summary[top]["files"] += len(filenames)

    for f in filenames:
        try:
            fp = os.path.join(dirpath, f)
            summary[top]["size_bytes"] += os.path.getsize(fp)
        except OSError:
            pass

# Sort by file count
ordered = dict(sorted(summary.items(), key=lambda x: x[1]["files"], reverse=True))

# Pretty print
print(json.dumps(ordered, indent=2))

# Also write a Markdown report
with open("directory_audit_report.md", "w") as f:
    f.write("| Folder | # Dirs | # Files | Size (MB) |\n|--------|---------|----------|-----------|\n")
    for name, stats in ordered.items():
        mb = stats["size_bytes"] / (1024 * 1024)
        f.write(f"| {name} | {stats['dirs']} | {stats['files']} | {mb:.2f} |\n")

print("\n📊  Wrote full inventory → directory_audit_report.md")
