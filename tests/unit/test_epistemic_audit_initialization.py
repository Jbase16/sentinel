"""Focused durability and concurrency checks for the epistemic audit header."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import threading

import pytest

import core.epistemic.ledger as ledger_module
from core.epistemic.events import EpistemicEvent, EventType
from core.epistemic.ledger import EvidenceLedger


def _audit_only(path: Path) -> EvidenceLedger:
    ledger = EvidenceLedger.__new__(EvidenceLedger)
    ledger._audit_path = path
    return ledger


def _header(*, created: float = 1_788_800_000.0) -> bytes:
    return (
        json.dumps({"type": "header", "version": "1.0", "created": created}) + "\n"
    ).encode("utf-8")


def _event(index: int) -> EpistemicEvent:
    return EpistemicEvent(
        id=f"event-{index}",
        event_type=EventType.OBSERVED,
        entity_id=f"observation-{index}",
        payload={"index": index},
        timestamp=1_788_800_000.0 + index,
        run_id="r5d10-audit-initialization",
    )


def test_audit_header_is_fsynced_before_atomic_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    ledger = _audit_only(audit_path)
    operations: list[tuple[str, int]] = []
    real_fsync = os.fsync
    real_link = os.link

    def traced_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        operation = (
            "directory_fsync" if stat.S_ISDIR(metadata.st_mode) else "file_fsync"
        )
        operations.append((operation, metadata.st_ino))
        real_fsync(descriptor)

    def traced_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool,
    ) -> None:
        source_metadata = os.stat(
            source,
            dir_fd=src_dir_fd,
            follow_symlinks=False,
        )
        assert ("file_fsync", source_metadata.st_ino) in operations
        source_descriptor = os.open(source, os.O_RDONLY, dir_fd=src_dir_fd)
        try:
            published_bytes = os.read(source_descriptor, 4096)
        finally:
            os.close(source_descriptor)
        assert published_bytes.endswith(b"\n")
        published = json.loads(published_bytes)
        assert set(published) == {"type", "version", "created"}
        assert published["type"] == "header"
        assert published["version"] == "1.0"
        assert type(published["created"]) is float
        assert published["created"] > 0
        assert not audit_path.exists()
        operations.append(("link", source_metadata.st_ino))
        real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(ledger_module.os, "fsync", traced_fsync)
    monkeypatch.setattr(ledger_module.os, "link", traced_link)

    ledger._ensure_audit_log()

    assert [operation for operation, _inode in operations] == [
        "file_fsync",
        "link",
        "directory_fsync",
    ]
    assert json.loads(audit_path.read_text().strip())["type"] == "header"
    assert not list(tmp_path.glob(".audit.jsonl.*.tmp"))


def test_existing_valid_audit_header_is_validated_without_replacement(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    existing = _header() + b'{"id":"existing-event"}\n'
    audit_path.write_bytes(existing)
    audit_path.chmod(0o600)
    original_inode = audit_path.stat().st_ino

    _audit_only(audit_path)._ensure_audit_log()

    assert audit_path.stat().st_ino == original_inode
    assert audit_path.read_bytes() == existing
    assert not list(tmp_path.glob(".audit.jsonl.*.tmp"))


@pytest.mark.parametrize(
    "contents",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"{}\n", id="missing-fields"),
        pytest.param(b"not-json\n", id="malformed-json"),
        pytest.param(b'{"type":"event"}\n', id="event-first"),
        pytest.param(
            b'{"type":"header","version":"1.0","created":1.0}',
            id="missing-newline",
        ),
        pytest.param(
            b'{"type":"header","version":"2.0","created":1.0}\n',
            id="wrong-version",
        ),
        pytest.param(
            b'{"type":"header","version":"1.0","created":true}\n',
            id="boolean-created",
        ),
        pytest.param(
            b'{"type":"header","type":"header","version":"1.0","created":1.0}\n',
            id="duplicate-field",
        ),
    ],
)
def test_preexisting_empty_or_corrupt_audit_log_is_rejected_without_replacement(
    tmp_path: Path,
    contents: bytes,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_bytes(contents)
    audit_path.chmod(0o600)
    original_inode = audit_path.stat().st_ino

    with pytest.raises(ValueError, match="canonical audit header"):
        _audit_only(audit_path)._ensure_audit_log()

    assert audit_path.stat().st_ino == original_inode
    assert audit_path.read_bytes() == contents
    assert not list(tmp_path.glob(".audit.jsonl.*.tmp"))


def test_concurrent_initializers_publish_one_header_before_all_events(
    tmp_path: Path,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    worker_count = 16
    barrier = threading.Barrier(worker_count)

    def initialize_and_append(index: int) -> None:
        ledger = _audit_only(audit_path)
        barrier.wait()
        ledger._ensure_audit_log()
        ledger._append_audit_event(_event(index))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        list(executor.map(initialize_and_append, range(worker_count)))

    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert records[0]["type"] == "header"
    assert sum(record.get("type") == "header" for record in records) == 1
    assert {record.get("id") for record in records[1:]} == {
        f"event-{index}" for index in range(worker_count)
    }
    assert len(records) == worker_count + 1
    assert not list(tmp_path.glob(".audit.jsonl.*.tmp"))
