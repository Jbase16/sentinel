#!/usr/bin/env python3
"""
Accurate recursive size audit for SentinelForge.
Follows symlinks, excludes noise, and outputs JSON + Markdown.
"""

import os
import json
from collections import defaultdict

ROOT = "."
IGNORE_DIRS = {
    ".git", ".idea", ".vscode", "__pycache__", ".pytest_cache",
    ".mypy_cache", "venv", ".venv", "archive_stage"
}
IGNORE_FILES = {".DS_Store", "Thumbs.db"}
EXCLUDE_EXTS = {".zip", ".log", ".tar", ".gz", ".dmg"}

summary = defaultdict(lambda: {"dirs": 0, "files": 0, "size_bytes": 0})

for dirpath, dirnames, filenames in os.walk(ROOT, followlinks=True):
    parts = dirpath.split(os.sep)
    # Skip ignored directories completely
    if any(part in IGNORE_DIRS for part in parts):
        dirnames[:] = []
        continue

    # Determine top-level directory
    if dirpath == ".":
        continue  # skip root pseudo-entry
    parts = dirpath.split(os.sep)
    top = parts[1] if parts[0] == "." and len(parts) > 1 else parts[0]

    # Skip ignored tops entirely
    if top in IGNORE_DIRS or top.startswith("."):
        continue


    summary[top]["dirs"] += len(dirnames)

    for f in filenames:
        if f in IGNORE_FILES or any(f.endswith(ext) for ext in EXCLUDE_EXTS):
            continue
        fp = os.path.join(dirpath, f)
        try:
            size = os.stat(fp, follow_symlinks=True).st_size
            summary[top]["size_bytes"] += size
            summary[top]["files"] += 1
        except (FileNotFoundError, PermissionError):
            continue

# Convert to human readable
ordered = dict(sorted(summary.items(), key=lambda x: x[1]["size_bytes"], reverse=True))
print(json.dumps(ordered, indent=2))

with open("directory_audit_report_fixed.md", "w") as f:
    f.write("| Folder | # Dirs | # Files | Size (MB) |\n|--------|---------|----------|-----------|\n")
    for name, stats in ordered.items():
        mb = stats["size_bytes"] / (1024 * 1024)
        f.write(f"| {name} | {stats['dirs']} | {stats['files']} | {mb:.2f} |\n")

print("\n📊 Wrote accurate inventory → directory_audit_report_fixed.md")
