"""R5F4: passive, unwired durable local schedule and decision storage.

No production entry point imports this module. It adds no authority of any kind.
The evaluator runs a deterministic offline logical schedule, with no real
concurrency, threads, async execution, or clock. Its result is not independent
evidence of an observed target-side effect. Running-workflow effect proof and
native OCB-S22 are deferred to the active tail.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .concurrency_invariant_contract import (
    _fields,
    _hash_ref,
    _passive_flags,
    _revalidate,
)
from .concurrency_invariant_ledger import ConcurrencyScheduleResult
from .receipts import BehavioralReceiptStore, ReceiptStoreError, _MAX_RECEIPT_BYTES

CONCURRENCY_INVARIANT_STORE_ENV = "SENTINELFORGE_CONCURRENCY_INVARIANT_STORE"
CONCURRENCY_INVARIANT_STORE_MODE = "behavioral_concurrency_invariant_store_v1"


class ConcurrencyInvariantStoreError(RuntimeError):
    """A local schedule/decision record could not be safely retained or read."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


@dataclass(frozen=True)
class DurableConcurrencySchedule:
    result: ConcurrencyScheduleResult
    durable_written: bool

    def __post_init__(self) -> None:
        if (
            type(self.result) is not ConcurrencyScheduleResult
            or type(self.durable_written) is not bool
        ):
            raise ConcurrencyInvariantStoreError("concurrency_durable_result_invalid")
        _revalidate(self.result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "result": self.result.to_dict(),
            "durable_written": self.durable_written,
            **_passive_flags(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DurableConcurrencySchedule:
        value = _fields(value, {"result", "durable_written", *_passive_flags()})
        result = cls(
            ConcurrencyScheduleResult.from_dict(value["result"]),
            value["durable_written"],
        )
        if value != result.to_dict():
            raise ConcurrencyInvariantStoreError(
                "concurrency_durable_result_flags_invalid"
            )
        return result


class ConcurrencyInvariantScheduleStore:
    """Exclusive-publication full result store; default-off without a caller."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(CONCURRENCY_INVARIANT_STORE_ENV)
        if override:
            return Path(override)
        data = os.environ.get("SENTINEL_DATA_DIR")
        return (
            Path(data) / "concurrency_invariant_store"
            if data
            else Path.home() / ".sentinelforge" / "concurrency_invariant_store"
        )

    def _prepare_root(self) -> Path:
        try:
            return BehavioralReceiptStore(self._root())._prepare_root()
        except (OSError, ReceiptStoreError) as exc:
            raise ConcurrencyInvariantStoreError(
                "concurrency_store_root_unsafe"
            ) from exc

    @staticmethod
    def _file_name(result_id: str) -> str:
        if not _hash_ref(result_id, "concurrency_schedule_result"):
            raise ConcurrencyInvariantStoreError("concurrency_result_reference_invalid")
        return f"concurrency-schedule-{result_id.split(':', 1)[1]}.json"

    @staticmethod
    def _read(path: Path, result_id: str) -> ConcurrencyScheduleResult:
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            BehavioralReceiptStore._validate_file_info(os.fstat(descriptor))
            handle = os.fdopen(descriptor, "r", encoding="utf-8")
            descriptor = -1
            with handle:
                payload = handle.read(_MAX_RECEIPT_BYTES + 1)
            value = _fields(json.loads(payload), {"mode", "result"})
            if value["mode"] != CONCURRENCY_INVARIANT_STORE_MODE:
                raise ConcurrencyInvariantStoreError("concurrency_store_mode_invalid")
            result = ConcurrencyScheduleResult.from_dict(value["result"])
            expected = {
                "schema_version": 1,
                "mode": CONCURRENCY_INVARIANT_STORE_MODE,
                "result": result.to_dict(),
            }
            if result.result_id != result_id or payload != _canonical_json(expected):
                raise ConcurrencyInvariantStoreError(
                    "concurrency_store_address_or_encoding_mismatch"
                )
            return result
        except ConcurrencyInvariantStoreError:
            raise
        except (
            OSError,
            ReceiptStoreError,
            UnicodeError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ) as exc:
            raise ConcurrencyInvariantStoreError(
                "concurrency_store_result_unreadable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def load(self, result_id: str) -> ConcurrencyScheduleResult | None:
        name = self._file_name(result_id)
        try:
            self._root().lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConcurrencyInvariantStoreError(
                "concurrency_store_root_unreadable"
            ) from exc
        root = self._prepare_root()
        path = root / name
        try:
            path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ConcurrencyInvariantStoreError(
                "concurrency_store_path_unreadable"
            ) from exc
        return self._read(path, result_id)

    def persist(self, result: ConcurrencyScheduleResult) -> DurableConcurrencySchedule:
        if type(result) is not ConcurrencyScheduleResult:
            raise ConcurrencyInvariantStoreError(
                "concurrency_store_requires_complete_result"
            )
        _revalidate(result)
        payload = _canonical_json(
            {
                "schema_version": 1,
                "mode": CONCURRENCY_INVARIANT_STORE_MODE,
                "result": result.to_dict(),
            }
        )
        if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise ConcurrencyInvariantStoreError("concurrency_store_size_cap_exceeded")
        root = self._prepare_root()
        path = root / self._file_name(result.result_id)
        written = True
        try:
            BehavioralReceiptStore._link_exclusive(path, payload)
            BehavioralReceiptStore._fsync_directory(root)
        except FileExistsError:
            written = False
        except (OSError, ReceiptStoreError) as exc:
            raise ConcurrencyInvariantStoreError(
                "concurrency_store_publication_failed"
            ) from exc
        retained = self._read(path, result.result_id)
        if retained != result:
            raise ConcurrencyInvariantStoreError("concurrency_store_collision_mismatch")
        return DurableConcurrencySchedule(retained, written)
