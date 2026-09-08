"""AST helpers for test contracts that constrain production import consumers.

The detector intentionally recognizes imports, not textual mentions.  In addition
to regular ``import`` and ``from`` statements, it recognizes literal calls to
``importlib.import_module`` and ``__import__``.  This keeps comments, docstrings,
ordinary strings, and similarly named modules from widening consumer allowlists.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
from typing import Iterable, Iterator


def _matches_module(imported: str, target: str) -> bool:
    return imported == target or imported.startswith(f"{target}.")


def _literal_string(
    node: ast.AST,
    constants: dict[str, str],
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left, constants)
        right = _literal_string(node.right, constants)
        if left is not None and right is not None:
            return left + right
    return None


def _module_constants(tree: ast.AST) -> dict[str, str]:
    constants: dict[str, str] = {}
    for statement in getattr(tree, "body", ()):
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                value = _literal_string(statement.value, constants)
                if value is not None:
                    constants[target.id] = value
        elif isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            if statement.value is not None:
                value = _literal_string(statement.value, constants)
                if value is not None:
                    constants[statement.target.id] = value
    return constants


def _resolve_static_from(
    node: ast.ImportFrom,
    *,
    current_module: str | None,
) -> str:
    if node.level == 0:
        return node.module or ""
    if current_module is None:
        return ""
    package = current_module.rpartition(".")[0]
    if not package:
        return ""
    relative_name = f"{'.' * node.level}{node.module or ''}"
    try:
        return importlib.util.resolve_name(relative_name, package)
    except (ImportError, ValueError):
        return ""


def _static_imports(
    tree: ast.AST,
    *,
    current_module: str | None,
) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_static_from(node, current_module=current_module)
            if not base:
                continue
            yield base
            for alias in node.names:
                if alias.name != "*":
                    yield f"{base}.{alias.name}"


def _dynamic_imports(tree: ast.AST) -> Iterator[str]:
    importlib_names: set[str] = set()
    import_module_names: set[str] = set()
    constants = _module_constants(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_module_names.add(alias.asname or alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        is_import_module = bool(
            isinstance(node.func, ast.Name) and node.func.id in import_module_names
        ) or bool(
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in importlib_names
        )
        is_builtin_import = (
            isinstance(node.func, ast.Name) and node.func.id == "__import__"
        )
        if not (is_import_module or is_builtin_import):
            continue

        imported = _literal_string(node.args[0], constants)
        if imported is None:
            continue
        if imported.startswith(".") and is_import_module:
            package_node = node.args[1] if len(node.args) > 1 else None
            if package_node is None:
                package_node = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "package"
                    ),
                    None,
                )
            package = (
                _literal_string(package_node, constants)
                if package_node is not None
                else None
            )
            if package is None:
                continue
            try:
                imported = importlib.util.resolve_name(imported, package)
            except (ImportError, ValueError):
                continue
        yield imported


def source_imports_module(
    source: str,
    target_module: str,
    *,
    current_module: str | None = None,
) -> bool:
    """Return whether *source* semantically imports *target_module*.

    Dynamic detection is deliberately limited to module names represented by
    literal strings (including simple module-level string constants and string
    concatenation), because arbitrary runtime expressions cannot be resolved by
    a static test contract.
    """

    if not isinstance(target_module, str) or not target_module:
        raise ValueError("target_module must be a non-empty module name")
    tree = ast.parse(source)
    imports = (
        *_static_imports(tree, current_module=current_module),
        *_dynamic_imports(tree),
    )
    return any(_matches_module(imported, target_module) for imported in imports)


def _path_module(path: Path, repository_root: Path) -> str:
    relative = path.resolve().relative_to(repository_root.resolve()).with_suffix("")
    return ".".join(relative.parts)


def find_module_consumers(
    paths: Iterable[Path],
    target_module: str,
    *,
    repository_root: Path,
    exclude: Iterable[Path] = (),
) -> tuple[Path, ...]:
    """Return sorted Python paths that semantically import *target_module*."""

    excluded = {path.resolve() for path in exclude}
    consumers = []
    for path in paths:
        resolved = path.resolve()
        if resolved in excluded:
            continue
        source = path.read_text(encoding="utf-8")
        if source_imports_module(
            source,
            target_module,
            current_module=_path_module(path, repository_root),
        ):
            consumers.append(path)
    return tuple(sorted(consumers, key=lambda item: item.as_posix()))


__all__ = ["find_module_consumers", "source_imports_module"]
