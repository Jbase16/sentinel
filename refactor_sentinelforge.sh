#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------------------------------
# SentinelForge Refactor Script
# Safely reorganizes your repo into a clean, modern structure.
# Creates a ZIP backup before touching anything.
# --------------------------------------------------------------------

ROOT_DIR="$(pwd)"
BACKUP_DIR="sentinelforge_backup_$(date +%Y%m%d_%H%M%S).zip"

echo "🧱 SentinelForge Repository Refactor Starting..."
echo "📦 Creating backup archive: ${BACKUP_DIR}"
zip -r "${BACKUP_DIR}" . > /dev/null
echo "✅ Backup complete. Stored at ${ROOT_DIR}/${BACKUP_DIR}"
echo

# Ensure we're in the right place
if [ ! -d "core" ]; then
  echo "❌ Error: Please run this script from the SentinelForge project root (where core/ exists)."
  exit 1
fi

# --------------------------------------------------------------------
# 1️⃣ Create new folder structure
# --------------------------------------------------------------------
echo "📁 Creating new folder structure..."
mkdir -p sentinelforge/cli
mkdir -p tools/dev
mkdir -p tools/ops
mkdir -p docs

# --------------------------------------------------------------------
# 2️⃣ Move old top-level scripts into /tools
# --------------------------------------------------------------------
echo "🚚 Moving standalone scripts into /tools/dev..."
for f in add_all_comments.py debug_imports.py repro_import.py; do
  if [ -f "$f" ]; then
    mv "$f" tools/dev/
    echo "   → moved $f → tools/dev/"
  fi
done

if [ -d "scripts" ]; then
  echo "🚚 Moving scripts/ → tools/ops/..."
  mv scripts/* tools/ops/ 2>/dev/null || true
  rmdir scripts 2>/dev/null || true
fi

# --------------------------------------------------------------------
# 3️⃣ Move sentinel.py into CLI entrypoint
# --------------------------------------------------------------------
if [ -f "sentinel.py" ]; then
  echo "🚀 Moving sentinel.py → sentinelforge/cli/"
  mv sentinel.py sentinelforge/cli/sentinel.py
else
  echo "⚠️ sentinel.py not found — skipping CLI move."
fi

# --------------------------------------------------------------------
# 4️⃣ Add CLI scaffolding
# --------------------------------------------------------------------
echo "📄 Creating CLI scaffolding..."
cat > sentinelforge/cli/__init__.py <<'EOF'
"""SentinelForge command-line entrypoint package."""
EOF

cat > sentinelforge/cli/sentinel.py <<'EOF'
"""
SentinelForge CLI — unified entrypoint for controlling the system.

Usage examples:
    python -m sentinelforge.cli.sentinel start
    python -m sentinelforge.cli.sentinel scan
"""

import argparse
from sentinelforge.core.engine.orchestrator import Orchestrator

def main():
    parser = argparse.ArgumentParser(description="SentinelForge Command Interface")
    parser.add_argument("command", choices=["start", "scan", "debug"], help="Command to run")
    args = parser.parse_args()

    if args.command == "start":
        print("🚀 Starting SentinelForge backend...")
        orch = Orchestrator()
        orch.run_all()
    elif args.command == "scan":
        print("🔍 Running a manual scan...")
    elif args.command == "debug":
        print("🧠 Launching debug mode...")

if __name__ == "__main__":
    main()
EOF

# --------------------------------------------------------------------
# 5️⃣ Add package runner
# --------------------------------------------------------------------
echo "🏁 Adding core/__main__.py..."
cat > core/__main__.py <<'EOF'
from sentinelforge.cli.sentinel import main

if __name__ == "__main__":
    main()
EOF

# --------------------------------------------------------------------
# 6️⃣ Add structure linter
# --------------------------------------------------------------------
echo "🧹 Adding /tools/lint_structure.py..."
cat > tools/lint_structure.py <<'EOF'
"""
Verifies that the SentinelForge project structure is still clean and consistent.
"""

import os

ALLOWED_ROOT = {"sentinelforge", "Dockerfile", "docker-compose.yml", "README.md",
                "requirements.txt", "tests", "ui", "docs", "tools"}

def main():
    for item in os.listdir("."):
        if item not in ALLOWED_ROOT:
            print(f"⚠️  Unexpected item at project root: {item}")

if __name__ == "__main__":
    main()
EOF

# --------------------------------------------------------------------
# 7️⃣ Add developer guide
# --------------------------------------------------------------------
echo "🧾 Adding docs/DEVELOPMENT_GUIDE.md..."
cat > docs/DEVELOPMENT_GUIDE.md <<'EOF'
# SentinelForge Developer Guide

## Folder Overview
| Folder | Purpose |
|---------|----------|
| `core/` | Core system logic (AI, Cortex, Engine, Scheduler, etc.) |
| `cli/` | Command-line entrypoint for running SentinelForge |
| `tools/` | Developer scripts and operations helpers |
| `tests/` | Unit, integration, and verification tests |
| `ui/` | Swift user interface |
| `docs/` | Architecture and design documentation |

## Running the System
```bash
python -m sentinelforge.cli.sentinel start
