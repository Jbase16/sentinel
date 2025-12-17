#!/usr/bin/env python3
"""
Annotate Python and Swift source files with concise, human-friendly inline comments.

Goals
- Add short docstrings for Python classes/functions missing them (no giant headers).
- Add Swift `///` doc comments above types and functions where missing.
- Preserve behavior and formatting; avoid touching already documented members.

Safety
- Purely additive comments/docstrings; does not modify executable logic.
- Skips virtualenvs, caches, build artifacts, and third-party directories.

Usage
  python scripts/annotate_inline_comments.py [repo_root]

Default root is the parent directory of this script (project root).
"""

from __future__ import annotations

import ast
import os
import sys
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
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        # Filter by extension
        if path.suffix not in (".py", ".swift"):
            continue
        # Skip certain directories
        parts = path.parts
        if any(skip in parts for skip in SKIP_PARTS):
            continue
        yield path


def file_has_any_comment(path: Path) -> bool:
    """Detect if a file already contains comments (anywhere).

    For Python: look for lines starting with '#', ignoring shebang.
    For Swift: look for lines starting with '//' or '///'.
    """
    try:
        txt = path.read_text(encoding="utf-8")
    except Exception:
        return False
    for line in txt.splitlines():
        s = line.lstrip()
        if path.suffix == ".py":
            if s.startswith("#"):
                # Ignore shebang strictly at first line
                if not s.startswith("#!"):
                    return True
        elif path.suffix == ".swift":
            if s.startswith("//"):
                return True
    return False


# -------------------------- Python annotation ---------------------------

class _DocInserter(ast.NodeVisitor):
    """Collect insertion points for missing class/func docstrings.

    We compute target line numbers and indentation from first body node.
    """

    def __init__(self):
        self.inserts: list[tuple[int, str]] = []  # (insert_before_line_1based, text)
        self._func_inserts: list[tuple[ast.AST, str]] = []
        self._class_inserts: list[tuple[ast.AST, str]] = []

    @staticmethod
    def _has_docstring(node: ast.AST) -> bool:
        """Function _has_docstring."""
        try:
            return bool(ast.get_docstring(node, clean=False))
        except Exception:
            return False

    def _add_insert(self, node: ast.AST, label: str, lines: list[str]):
        """Function _add_insert."""
        if not getattr(node, "body", None):
            return
        first_body = node.body[0]
        # Determine indentation from first body line
        line_idx = max(0, first_body.lineno - 1)
        indent = ""
        if 0 <= line_idx < len(lines):
            indent = lines[line_idx][: len(lines[line_idx]) - len(lines[line_idx].lstrip(" \t"))]
        # Prepare a very short docstring
        doc = f'{indent}"""{label}."""\n'
        # Insert before first body node
        self.inserts.append((first_body.lineno, doc))

    def visit_ClassDef(self, node: ast.ClassDef):
        """Function visit_ClassDef."""
        if not self._has_docstring(node):
            label = f"Class {node.name}"
            self._class_inserts.append((node, label))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Function visit_FunctionDef."""
        self._handle_func_like(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Function visit_AsyncFunctionDef."""
        self._handle_func_like(node)
        self.generic_visit(node)

    def _handle_func_like(self, node):
        # Skip dunders and trivial builtins
        """Function _handle_func_like."""
        name = getattr(node, "name", "func")
        if name.startswith("__") and name.endswith("__"):
            return
        # If already documented, skip
        if self._has_docstring(node):
            return
        # Label based on name only; keep to a single line, non-intrusive
        label = f"{type(node).__name__.replace('FunctionDef','Function')} {name}"
        self._func_inserts.append((node, label))

    def prepare(self, lines: list[str]):
        # Resolve _func_inserts here to know indentation reliably
        """Function prepare."""
        for node, label in getattr(self, "_func_inserts", []):
            self._add_insert(node, label, lines)
        for node, label in getattr(self, "_class_inserts", []):
            self._add_insert(node, label, lines)

    def run(self, source: str) -> str:
        """Function run."""
        lines = source.splitlines(True)  # keepends
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source

        self._func_inserts = []
        self._class_inserts = []
        self.visit(tree)
        self.prepare(lines)

        if not self.inserts:
            return source

        # Apply inserts in reverse line order to keep offsets stable
        for lineno, text in sorted(self.inserts, key=lambda x: -x[0]):
            idx = max(0, min(len(lines), lineno - 1))
            lines.insert(idx, text)
        return "".join(lines)


def annotate_python(path: Path) -> bool:
    """Function annotate_python."""
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return False

    # If file already has any comments, skip entire file per user preference
    if file_has_any_comment(path):
        return False

    # Ensure brief module-level docstring exists at top
    module_doc_added = False
    try:
        tree = ast.parse(src)
        has_module_doc = bool(ast.get_docstring(tree, clean=False))
    except SyntaxError:
        has_module_doc = True  # do not touch unusual files

    if not has_module_doc:
        lines = src.splitlines(True)
        insert_at = 0
        # Respect shebang and coding declarations
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if insert_at < len(lines) and "coding" in lines[insert_at][:50]:
            insert_at += 1
        module_name = path.stem
        rel = str(path)
        doc = f'"""Module {module_name}: inline documentation for {rel}."""\n'
        lines.insert(insert_at, doc)
        src = "".join(lines)
        module_doc_added = True

    inserter = _DocInserter()
    new_src = inserter.run(src)
    if module_doc_added or new_src != src:
        path.write_text(new_src, encoding="utf-8")
        return True
    return False


# --------------------------- Swift annotation ---------------------------

def is_doc_line(line: str) -> bool:
    """Function is_doc_line."""
    s = line.lstrip()
    return s.startswith("///") or s.startswith("//:")


def swift_entity_label(signature: str) -> str:
    """Function swift_entity_label."""
    sig = signature.strip()
    # Get token after keyword (class|struct|enum|protocol|func)
    for kw in ("class", "struct", "enum", "protocol", "actor", "func"):
        if sig.startswith(kw + " "):
            rest = sig[len(kw) + 1 :]
            name = rest.split("(", 1)[0].split(":", 1)[0].split("<", 1)[0].strip()
            if kw == "func":
                return f"Function {name}"
            return f"{kw.title()} {name}"
    return "Declaration"


def annotate_swift(path: Path) -> bool:
    """Function annotate_swift."""
    # If file already has any comments, skip entire file per user preference
    if file_has_any_comment(path):
        return False

    try:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(True)
    except Exception:
        return False

    changed = False
    # Add a tiny file-level doc at the top if first non-empty line isn't a comment
    k = 0
    while k < len(lines) and lines[k].strip() == "":
        k += 1
    if k < len(lines):
        first = lines[k].lstrip()
        if not first.startswith("//") and not first.startswith("///"):
            lines.insert(0, f"/// File {path.name}: inline overview.\n")
            changed = True
    else:
        # Empty file
        lines.append(f"/// File {path.name}: inline overview.\n")
        changed = True
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        # Match probable declarations (simple heuristic)
        if stripped.startswith(("class ", "struct ", "enum ", "protocol ", "actor ", "func ")):
            # Look back to see if a doc comment exists immediately above
            j = i - 1
            while j >= 0 and lines[j].strip() == "":
                j -= 1
            has_doc = j >= 0 and is_doc_line(lines[j])
            if not has_doc:
                indent = line[: len(line) - len(stripped)]
                label = swift_entity_label(stripped)
                doc = f"{indent}/// {label}.\n"
                lines.insert(i, doc)
                changed = True
                i += 1  # skip the inserted doc line
        i += 1

    if changed:
        path.write_text("".join(lines), encoding="utf-8")
    return changed


def main(argv: list[str]) -> int:
    """Function main."""
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    annotated = 0
    scanned = 0
    for file in iter_source_files(root):
        scanned += 1
        if file.suffix == ".py":
            if annotate_python(file):
                annotated += 1
        elif file.suffix == ".swift":
            if annotate_swift(file):
                annotated += 1
    print(f"Annotated {annotated} / {scanned} source files with inline comments.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
