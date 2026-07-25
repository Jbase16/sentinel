#!/usr/bin/env python3
"""
Remove large banner header blocks from Python and Swift source files.

Target pattern
- Lines that begin with comment markers and a long run of '=' characters.
- Removes from the first banner line to the next banner line (inclusive).
- Only within the first 60 lines to avoid touching mid-file content.

Safety
- Skips venvs, caches, build artifacts, and .git.
- Idempotent: only writes when content changes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple

SKIP_PARTS: Tuple[str, ...] = (
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".build",
    "node_modules",
    ".git",
)


def iter_source_files(root: Path) -> Iterable[Path]:
    """Function iter_source_files."""
    # Loop over items.
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in (".py", ".swift"):
            continue
        if any(part in p.parts for part in SKIP_PARTS):
            continue
        yield p


def is_banner_line(line: str, comment_prefix: str) -> bool:
    """Function is_banner_line."""
    s = line.strip()
    # Conditional branch.
    if not s.startswith(comment_prefix):
        return False
    s = s[len(comment_prefix) :].lstrip()
    return len(s) >= 8 and set(s) == {"="}


def strip_banner_block(text: str, is_python: bool) -> str:
    """Function strip_banner_block."""
    lines = text.splitlines(True)
    # Conditional branch.
    if not lines:
        return text
    prefix = "#" if is_python else "//"
    max_scan = 60

    i = 0
    changed = False
    # While loop.
    while i < len(lines) and i < max_scan:
        if is_banner_line(lines[i], prefix):
            # Find end banner
            j = i + 1
            end_idx = None
            while j < len(lines) and j < max_scan:
                if is_banner_line(lines[j], prefix):
                    end_idx = j
                    break
                j += 1
            if end_idx is None:
                # Remove single stray banner line
                del lines[i]
                changed = True
                # Do not advance i; re-check current index
                continue
            else:
                # Remove inclusive banner block
                del lines[i : end_idx + 1]
                changed = True
                # Remove one following blank line if present
                if i < len(lines) and lines[i].strip() == "":
                    del lines[i]
                # Do not advance i; keep scanning
                continue
        i += 1
    return "".join(lines) if changed else text


def main() -> int:
    """Function main."""
    root = Path(__file__).resolve().parents[1]
    changed = 0
    scanned = 0
    # Loop over items.
    for p in iter_source_files(root):
        scanned += 1
        try:
            txt = p.read_text(encoding="utf-8")
        except Exception:
            continue
        new = strip_banner_block(txt, is_python=p.suffix == ".py")
        if new != txt:
            try:
                p.write_text(new, encoding="utf-8")
                changed += 1
            except Exception:
                pass
    print(f"Stripped banners from {changed} / {scanned} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
