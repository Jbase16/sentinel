#!/usr/bin/env python3
"""
Safe first-stage cleanup for SentinelForge.
Moves junk to archive_stage and removes truly empty directories.
Never deletes files without moving them first.
"""

import os
import shutil

ARCHIVE = "archive_stage"
os.makedirs(ARCHIVE, exist_ok=True)

def move_if_exists(path):
    if os.path.exists(path):
        print(f"🧳 Moving {path} → {ARCHIVE}/")
        shutil.move(path, ARCHIVE)

# 1. Archive large backup zips
for f in os.listdir("."):
    if f.startswith("sentinelforge_backup_") and f.endswith(".zip"):
        move_if_exists(f)

# 2. Remove empty directories
for d in ["artifacts", "path"]:
    if os.path.isdir(d) and not any(os.scandir(d)):
        print(f"🗑️ Removing empty dir: {d}/")
        os.rmdir(d)

# 3. Warn about weird hidden dirs
for hidden in [".zenflow", ".zencoder"]:
    if os.path.isdir(hidden):
        print(f"⚠️ Review {hidden}/ manually; moving to archive if obsolete.")
        move_if_exists(hidden)

# 4. Create or update .gitignore entries
gitignore_lines = {"venv/", ".venv/", "__pycache__/", "*.zip"}
if os.path.exists(".gitignore"):
    with open(".gitignore", "r") as f:
        existing = set(line.strip() for line in f)
else:
    existing = set()

new_lines = existing | gitignore_lines
with open(".gitignore", "w") as f:
    f.write("\n".join(sorted(new_lines)) + "\n")

print("\n✅ Cleanup stage one complete.")
