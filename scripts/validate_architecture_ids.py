#!/usr/bin/env python3
"""Validate canonical architecture IDs and any explicitly supplied source files."""

from __future__ import annotations

import argparse
from pathlib import Path

from core.contracts.architecture_ids import IdentifierRegistry, default_registry_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()

    repository_root = Path(__file__).resolve().parents[1]
    registry = IdentifierRegistry.load(default_registry_path(repository_root))
    registry.validate_historical_sources(repository_root)
    for path in args.paths:
        resolved = path.resolve()
        try:
            relative_path = resolved.relative_to(repository_root).as_posix()
        except ValueError:
            relative_path = path.as_posix()
        registry.validate_source(relative_path, resolved.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
