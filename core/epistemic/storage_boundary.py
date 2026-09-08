"""Fail-closed location checks for durable production evidence.

R5D10 recovery depends on evidence surviving branch and worktree disposal.  A
Git ignore rule is not a durability boundary: an operator can relocate
``SENTINEL_DATA_DIR`` (or a receipt override) into any linked worktree.  This
module therefore validates resolved filesystem locations before capability
traffic is eligible for dispatch.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import threading
from typing import Iterable, Optional

from core.base.config import SentinelConfig


class EvidenceStorageBoundaryError(RuntimeError):
    """A production evidence location is inside a Git worktree."""


class EvidenceStorageAnchor:
    """Pin production evidence locations to their admitted filesystem objects.

    Canonical path strings alone do not detect an ancestor that is renamed and
    replaced by a new directory at the same pathname.  The anchor records the
    nearest existing directory for every configured evidence location and
    compares its device/inode identity on every persistence boundary.  As
    deeper evidence directories are durably created, :meth:`seal` advances the
    pins without releasing the already-validated ancestors.

    Direct file stores should additionally perform writes relative to their
    pinned directory descriptor.  SQLite and the canonical audit adapter are
    path-based, so their R5D10 callers revalidate this anchor immediately
    before and after each adapter call.
    """

    def __init__(self, paths: Iterable[Path]) -> None:
        locations = tuple(_absolute_lexical(Path(value)) for value in paths)
        if not locations:
            raise ValueError("evidence storage anchor requires at least one path")
        self._locations = locations
        self._lock = threading.RLock()
        self._resolved_locations = require_outside_git_worktrees(locations)
        self._pins = self._capture_pins(self._resolved_locations)

    @property
    def resolved_locations(self) -> tuple[Path, ...]:
        return self._resolved_locations

    @staticmethod
    def _nearest_directory(location: Path) -> Path:
        candidate = location if location.is_dir() else location.parent
        while not candidate.is_dir():
            parent = candidate.parent
            if parent == candidate:
                raise EvidenceStorageBoundaryError(
                    f"production_evidence_anchor_has_no_directory:{location}"
                )
            candidate = parent
        return candidate

    @staticmethod
    def _directory_identity(directory: Path) -> tuple[int, int]:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceStorageBoundaryError(
                    f"production_evidence_anchor_is_not_directory:{directory}"
                )
            return metadata.st_dev, metadata.st_ino
        finally:
            os.close(descriptor)

    @classmethod
    def _capture_pins(
        cls,
        locations: Iterable[Path],
    ) -> tuple[tuple[Path, tuple[int, int]], ...]:
        directories = {cls._nearest_directory(location) for location in locations}
        return tuple(
            (directory, cls._directory_identity(directory))
            for directory in sorted(directories, key=str)
        )

    def assert_unchanged(self) -> tuple[Path, ...]:
        """Fail closed if a location, worktree boundary, or directory changed."""

        with self._lock:
            current = require_outside_git_worktrees(self._locations)
            if current != self._resolved_locations:
                raise EvidenceStorageBoundaryError(
                    "production_evidence_location_changed_after_admission"
                )
            for directory, expected in self._pins:
                try:
                    actual = self._directory_identity(directory)
                except OSError as exc:
                    raise EvidenceStorageBoundaryError(
                        "production_evidence_anchor_unavailable_after_admission:"
                        f"{directory}"
                    ) from exc
                if actual != expected:
                    raise EvidenceStorageBoundaryError(
                        "production_evidence_anchor_changed_after_admission:"
                        f"{directory}"
                    )
            return current

    def seal(self) -> tuple[Path, ...]:
        """Pin newly created evidence directories after validating old pins."""

        with self._lock:
            current = self.assert_unchanged()
            new_pins = self._capture_pins(current)
            existing = dict(self._pins)
            for directory, identity in new_pins:
                prior = existing.get(directory)
                if prior is not None and prior != identity:
                    raise EvidenceStorageBoundaryError(
                        f"production_evidence_anchor_changed_while_sealing:{directory}"
                    )
                existing[directory] = identity
            self._pins = tuple(sorted(existing.items(), key=lambda item: str(item[0])))
            return current


def _absolute_lexical(path: Path) -> Path:
    """Return an absolute path without resolving away future symlink changes."""

    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return expanded


def _resolved(path: Path) -> Path:
    """Resolve existing symlinks while also supporting not-yet-created paths."""

    return Path(path).expanduser().resolve(strict=False)


def enclosing_git_worktree(path: Path) -> Optional[Path]:
    """Return the nearest worktree root, including linked-worktree ``.git`` files."""

    candidate = _resolved(path)
    for parent in (candidate, *candidate.parents):
        marker = parent / ".git"
        if marker.is_dir() or marker.is_file():
            return parent
    return None


def require_outside_git_worktrees(paths: Iterable[Path]) -> tuple[Path, ...]:
    """Validate and return canonical locations without creating any of them."""

    resolved: list[Path] = []
    for value in paths:
        location = _resolved(Path(value))
        worktree = enclosing_git_worktree(location)
        if worktree is not None:
            raise EvidenceStorageBoundaryError(
                f"production_evidence_root_is_inside_git_worktree:{location}:{worktree}"
            )
        resolved.append(location)
    return tuple(resolved)


def production_evidence_roots(
    config: SentinelConfig,
    *,
    behavioral_receipt_root: Optional[Path] = None,
) -> tuple[Path, ...]:
    """Enumerate roots used by the R5D10 production path.

    The configured storage base owns SQLite (and WAL/SHM companions), CAS
    blobs and temporary publications, canonical journal rows, audit JSONL, and
    reconciliation state.  Behavioral receipts may use an independent override
    and therefore require a separate check.  Existing Family-D store overrides
    are included when explicitly configured so a single production admission
    cannot straddle a worktree boundary.
    """

    base_dir = Path(config.storage.base_dir)
    db_path = Path(config.storage.db_path)
    evidence_path = Path(config.storage.evidence_path)
    roots: list[Path] = [
        base_dir,
        db_path,
        Path(f"{db_path}-wal"),
        Path(f"{db_path}-shm"),
        evidence_path,
        evidence_path / "blobs",
        base_dir / "audit.jsonl",
    ]
    if behavioral_receipt_root is not None:
        roots.append(Path(behavioral_receipt_root))
    for variable in (
        "SENTINELFORGE_CAPABILITY_CONSUMPTIONS",
        "SENTINELFORGE_CAPABILITY_EXECUTION_RECEIPTS",
    ):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    return tuple(roots)


def require_production_evidence_outside_worktrees(
    config: SentinelConfig,
    *,
    behavioral_receipt_root: Optional[Path] = None,
) -> tuple[Path, ...]:
    """Enforce the R5D10 location boundary before target dispatch."""

    return require_outside_git_worktrees(
        production_evidence_roots(
            config,
            behavioral_receipt_root=behavioral_receipt_root,
        )
    )


__all__ = [
    "EvidenceStorageAnchor",
    "EvidenceStorageBoundaryError",
    "enclosing_git_worktree",
    "production_evidence_roots",
    "require_outside_git_worktrees",
    "require_production_evidence_outside_worktrees",
]
