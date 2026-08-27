"""Canonical phase, slice, scenario, and scoped historical identifiers."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping


_CANONICAL_ID = re.compile(
    r"^(?:C\d+|R\d+[A-Z]\d+|(?:OCB|DB)-R\d+|(?:LAB|OCB|DB)-S\d{2}|LAB-R\d+-S\d{2})$"
)
_BARE_ID = re.compile(r"(?<![A-Za-z0-9-])([RS]\d+)(?![A-Za-z0-9])")


class IdentifierRegistryError(ValueError):
    """The registry or a source reference violates the canonical-ID contract."""


@dataclass(frozen=True)
class IdentifierRegistry:
    canonical_ids: frozenset[str]
    historical_aliases: Mapping[str, Mapping[str, str]]

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "IdentifierRegistry":
        if payload.get("schema_version") != 1:
            raise IdentifierRegistryError("unsupported canonical ID registry schema")

        records = payload.get("canonical_ids")
        if not isinstance(records, list):
            raise IdentifierRegistryError("canonical_ids must be a list")

        identifiers: list[str] = []
        for record in records:
            identifier = record.get("id") if isinstance(record, Mapping) else None
            if not isinstance(identifier, str) or not _CANONICAL_ID.fullmatch(identifier):
                raise IdentifierRegistryError(f"invalid canonical ID: {identifier!r}")
            identifiers.append(identifier)
        duplicates = sorted({item for item in identifiers if identifiers.count(item) > 1})
        if duplicates:
            raise IdentifierRegistryError(
                f"colliding canonical IDs: {', '.join(duplicates)}"
            )

        aliases: dict[str, dict[str, str]] = {}
        for source in payload.get("historical_sources", []):
            if not isinstance(source, Mapping):
                raise IdentifierRegistryError("historical source must be an object")
            path = source.get("path")
            mapping = source.get("aliases")
            if not isinstance(path, str) or not isinstance(mapping, Mapping):
                raise IdentifierRegistryError("historical source requires path and aliases")
            if path in aliases:
                raise IdentifierRegistryError(f"duplicate historical source: {path}")
            aliases[path] = {}
            for alias, canonical in mapping.items():
                if not isinstance(alias, str) or not _BARE_ID.fullmatch(alias):
                    raise IdentifierRegistryError(f"invalid historical alias: {alias!r}")
                if canonical not in identifiers:
                    raise IdentifierRegistryError(
                        f"historical alias {alias} references unknown ID {canonical!r}"
                    )
                aliases[path][alias] = canonical

        return cls(frozenset(identifiers), aliases)

    @classmethod
    def load(cls, path: Path) -> "IdentifierRegistry":
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def validate_source(self, source_path: str, text: str) -> None:
        """Reject bare IDs unless the exact legacy source registers the alias."""

        allowed = self.historical_aliases.get(Path(source_path).as_posix(), {})
        violations = sorted({match.group(1) for match in _BARE_ID.finditer(text)} - allowed.keys())
        if violations:
            raise IdentifierRegistryError(
                f"{source_path} introduces bare or unregistered IDs: "
                f"{', '.join(violations)}"
            )

    def validate_historical_sources(self, repository_root: Path) -> None:
        for relative_path in self.historical_aliases:
            path = repository_root / relative_path
            if not path.is_file():
                raise IdentifierRegistryError(f"historical source is missing: {relative_path}")
            self.validate_source(relative_path, path.read_text(encoding="utf-8"))


def default_registry_path(repository_root: Path) -> Path:
    return repository_root / "docs/architecture/CANONICAL_ID_REGISTRY.json"
