"""Durability and path-safety specimens for canonical evidence CAS."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from core.base.config import SentinelConfig, StorageConfig
from core.epistemic import cas as cas_module
from core.epistemic.cas import ContentAddressableStorage


_CAS_WORKER = """
import sys
import time
from pathlib import Path

from core.base.config import SentinelConfig, StorageConfig
from core.epistemic.cas import ContentAddressableStorage

base_dir = Path(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
ready = Path(sys.argv[3])
start = Path(sys.argv[4])
ready.touch()
deadline = time.monotonic() + 10
while not start.exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("CAS race start signal was not published")
    time.sleep(0.001)
config = SentinelConfig(storage=StorageConfig(base_dir=base_dir))
print(ContentAddressableStorage(config).store(payload), flush=True)
"""


@pytest.mark.subprocess_spawn
def test_cas_separate_process_race_publishes_one_verified_blob(tmp_path):
    payload = b"r5d10-concurrent-canonical-evidence"
    expected = hashlib.sha256(payload).hexdigest()
    base_dir = tmp_path / "data"
    start = tmp_path / "start"
    ready = tuple(tmp_path / f"ready-{index}" for index in range(4))
    repository_root = Path(__file__).resolve().parents[2]
    workers = tuple(
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _CAS_WORKER,
                str(base_dir),
                payload.hex(),
                str(marker),
                str(start),
            ],
            cwd=repository_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for marker in ready
    )
    try:
        deadline = time.monotonic() + 10
        while not all(marker.exists() for marker in ready):
            exited = tuple(worker for worker in workers if worker.poll() is not None)
            if exited:
                stdout, stderr = exited[0].communicate()
                pytest.fail(
                    f"CAS race worker exited before start: {stdout!r} {stderr!r}"
                )
            if time.monotonic() >= deadline:
                pytest.fail("CAS race workers did not become ready")
            time.sleep(0.001)
        start.touch()
        completed = tuple(worker.communicate(timeout=10) for worker in workers)
        for worker, (_stdout, stderr) in zip(workers, completed, strict=True):
            assert worker.returncode == 0, stderr
        results = tuple(stdout.strip() for stdout, _stderr in completed)
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
                worker.wait()

    assert results == (expected,) * 4
    config = SentinelConfig(storage=StorageConfig(base_dir=base_dir))
    cas = ContentAddressableStorage(config)
    assert cas.load(expected) == payload
    assert sorted(item.name for item in cas.blob_dir.iterdir()) == [expected]


def test_cas_rejects_final_symlink_and_corrupt_existing_content(tmp_path):
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    cas = ContentAddressableStorage(config)
    payload = b"r5d10-addressed-evidence"
    address = hashlib.sha256(payload).hexdigest()
    outside = tmp_path / "outside"
    outside.write_bytes(payload)
    (cas.blob_dir / address).symlink_to(outside)

    with pytest.raises(OSError):
        cas.store(payload)
    assert cas.load(address) is None

    (cas.blob_dir / address).unlink()
    corrupt = cas.blob_dir / address
    corrupt.write_bytes(b"different")
    os.chmod(corrupt, 0o600)
    with pytest.raises(ValueError, match="does not match"):
        cas.store(payload)
    assert cas.load(address) is None


def test_cas_rejects_blob_directory_swap_after_it_is_pinned(tmp_path):
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    cas = ContentAddressableStorage(config)
    moved = config.storage.evidence_path / "original-blobs"
    cas.blob_dir.rename(moved)
    cas.blob_dir.mkdir(mode=0o700)

    with pytest.raises(ValueError, match="changed after admission"):
        cas.store(b"must-not-be-redirected")


def test_cas_rejects_zero_progress_write_without_publishing(tmp_path, monkeypatch):
    config = SentinelConfig(storage=StorageConfig(base_dir=tmp_path / "data"))
    cas = ContentAddressableStorage(config)
    monkeypatch.setattr(cas_module.os, "write", lambda _descriptor, _data: 0)

    with pytest.raises(OSError, match="CAS write made no progress"):
        cas.store(b"must-not-publish-partial-content")

    assert tuple(cas.blob_dir.iterdir()) == ()
