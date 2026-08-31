"""Durable, append-only persistence for R5D6 capability-execution receipts.

R5D7 stores the public projection of an already-minted R5D6 receipt through the
audited filesystem primitives used by ``BehavioralReceiptStore``.  Reload returns
an inert ``StoredExecutionReceipt`` with no live decision context.  Identical
concurrent writes converge on one byte-identical file; distinct receipt identities
remain distinct append-only records.

This module performs local filesystem I/O only.  It reads no clock, sends no target
traffic, dispatches no action, evaluates no effect, constructs no finding, verifies
no cleanup, and remains production-unwired.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .capability_execution_receipt import (
    CAPABILITY_EXECUTION_RECEIPT_MODE,
    CapabilityExecutionOutcome,
    CapabilityExecutionReceipt,
    _canonical_epoch,
    _hash_ref,
)
from .receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    _MAX_RECEIPT_BYTES,
    re_full_sha256,
    request_fingerprint,
)


CAPABILITY_EXECUTION_RECEIPT_STORE_ENV = "SENTINELFORGE_CAPABILITY_EXECUTION_RECEIPTS"
CAPABILITY_EXECUTION_RECEIPT_STORE_MODE = (
    "behavioral_capability_execution_receipt_store_v1"
)


class CapabilityExecutionReceiptStoreError(RuntimeError):
    """Persisted execution-receipt state is unsafe or cannot be published."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _capability_store_key(capability_ref: str) -> str:
    return request_fingerprint(
        {
            "schema_version": 1,
            "capability_ref": capability_ref,
        }
    )


def _execution_receipt_payload(
    *,
    capability_ref: str,
    liveness_ref: str,
    consumption_ref: str,
    observed_epoch: str,
    outcome: CapabilityExecutionOutcome,
    mode: str,
) -> Dict[str, Any]:
    return {
        "capability_ref": capability_ref,
        "liveness_ref": liveness_ref,
        "consumption_ref": consumption_ref,
        "observed_epoch": observed_epoch,
        "outcome": outcome.value,
        "mode": mode,
    }


def _execution_receipt_id(payload: Mapping[str, Any]) -> str:
    return f"capability_execution_receipt:{request_fingerprint(payload)}"


def _parse_canonical_epoch(value: object) -> float:
    if type(value) is not str:
        raise ValueError("stored execution receipt epoch must be a canonical string")
    try:
        parsed = float(value)
        canonical = _canonical_epoch(parsed)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            "stored execution receipt epoch must be a canonical string"
        ) from exc
    if canonical != value:
        raise ValueError("stored execution receipt epoch must be a canonical string")
    return parsed


@dataclass(frozen=True)
class StoredExecutionReceipt:
    """Hash-verified public receipt projection with no live decision context."""

    receipt_id: str
    capability_ref: str
    liveness_ref: str
    consumption_ref: str
    observed_epoch: float
    outcome: CapabilityExecutionOutcome
    mode: str = CAPABILITY_EXECUTION_RECEIPT_MODE
    target_dispatch_authority: bool = False
    execution_effect_authority: bool = False
    finding_promotion_authority: bool = False
    target_cleanup_authority: bool = False
    reloaded: bool = True

    def __post_init__(self) -> None:
        if type(self.outcome) is not CapabilityExecutionOutcome:
            raise TypeError("outcome must be a CapabilityExecutionOutcome")
        if type(self.reloaded) is not bool:
            raise TypeError("reloaded must be a bool")
        try:
            observed_epoch = _canonical_epoch(self.observed_epoch)
        except ValueError as exc:
            raise ValueError("stored execution receipt is invalid") from exc
        payload = _execution_receipt_payload(
            capability_ref=self.capability_ref,
            liveness_ref=self.liveness_ref,
            consumption_ref=self.consumption_ref,
            observed_epoch=observed_epoch,
            outcome=self.outcome,
            mode=self.mode,
        )
        refs = (
            (self.receipt_id, "capability_execution_receipt"),
            (self.capability_ref, "issued_capability_contract"),
            (self.liveness_ref, "runtime_liveness_decision"),
            (self.consumption_ref, "capability_consumption_decision"),
        )
        if (
            self.receipt_id != _execution_receipt_id(payload)
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or self.mode != CAPABILITY_EXECUTION_RECEIPT_MODE
            or self.target_dispatch_authority is not False
            or self.execution_effect_authority is not False
            or self.finding_promotion_authority is not False
            or self.target_cleanup_authority is not False
            or self.reloaded is not True
        ):
            raise ValueError("stored execution receipt is invalid")

    @classmethod
    def _from_dict(cls, value: Mapping[str, Any]) -> "StoredExecutionReceipt":
        expected_fields = {
            "schema_version",
            "receipt_id",
            "capability_ref",
            "liveness_ref",
            "consumption_ref",
            "observed_epoch",
            "outcome",
            "mode",
            "target_dispatch_authority",
            "execution_effect_authority",
            "finding_promotion_authority",
            "target_cleanup_authority",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected_fields
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or type(value.get("receipt_id")) is not str
            or type(value.get("capability_ref")) is not str
            or type(value.get("liveness_ref")) is not str
            or type(value.get("consumption_ref")) is not str
            or type(value.get("outcome")) is not str
            or type(value.get("mode")) is not str
        ):
            raise CapabilityExecutionReceiptStoreError(
                "durable execution receipt projection is invalid"
            )
        try:
            return cls(
                receipt_id=value["receipt_id"],
                capability_ref=value["capability_ref"],
                liveness_ref=value["liveness_ref"],
                consumption_ref=value["consumption_ref"],
                observed_epoch=_parse_canonical_epoch(value["observed_epoch"]),
                outcome=CapabilityExecutionOutcome(value["outcome"]),
                mode=value["mode"],
                target_dispatch_authority=value["target_dispatch_authority"],
                execution_effect_authority=value["execution_effect_authority"],
                finding_promotion_authority=value["finding_promotion_authority"],
                target_cleanup_authority=value["target_cleanup_authority"],
                reloaded=True,
            )
        except (TypeError, ValueError) as exc:
            raise CapabilityExecutionReceiptStoreError(
                "durable execution receipt projection is invalid"
            ) from exc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "receipt_id": self.receipt_id,
            **_execution_receipt_payload(
                capability_ref=self.capability_ref,
                liveness_ref=self.liveness_ref,
                consumption_ref=self.consumption_ref,
                observed_epoch=_canonical_epoch(self.observed_epoch),
                outcome=self.outcome,
                mode=self.mode,
            ),
            "target_dispatch_authority": self.target_dispatch_authority,
            "execution_effect_authority": self.execution_effect_authority,
            "finding_promotion_authority": self.finding_promotion_authority,
            "target_cleanup_authority": self.target_cleanup_authority,
        }


@dataclass(frozen=True)
class DurableExecutionReceiptResult:
    """An inert stored projection and whether this call created its file."""

    record: StoredExecutionReceipt
    durable_written: bool

    def __post_init__(self) -> None:
        if type(self.record) is not StoredExecutionReceipt:
            raise TypeError("record must be a StoredExecutionReceipt")
        if type(self.durable_written) is not bool:
            raise TypeError("durable_written must be a bool")
        replace(self.record)


class CapabilityExecutionReceiptStore:
    """Append-only store for public R5D6 receipt projections."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(CAPABILITY_EXECUTION_RECEIPT_STORE_ENV)
        if override:
            return Path(override)
        data_dir = os.environ.get("SENTINEL_DATA_DIR")
        if data_dir:
            return Path(data_dir) / "capability_execution_receipts"
        return Path.home() / ".sentinelforge" / "capability_execution_receipts"

    @staticmethod
    def _file_name(capability_ref: str, receipt_id: str) -> str:
        return f"execution-{_capability_store_key(capability_ref)}-{receipt_id}.json"

    def _prepare_root(self) -> Path:
        root = self._root()
        try:
            return BehavioralReceiptStore(root)._prepare_root()
        except (OSError, ReceiptStoreError) as exc:
            raise CapabilityExecutionReceiptStoreError(
                "capability execution receipt root is unsafe"
            ) from exc

    def _existing_root(self) -> Optional[Path]:
        root = self._root()
        try:
            root.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CapabilityExecutionReceiptStoreError(
                "capability execution receipt root cannot be inspected safely"
            ) from exc
        return self._prepare_root()

    def _receipt_paths(
        self,
        root: Path,
        capability_ref: str,
    ) -> list[tuple[str, Path]]:
        prefix = f"execution-{_capability_store_key(capability_ref)}-"
        paths: Dict[str, Path] = {}
        try:
            with os.scandir(root) as entries:
                names = sorted(
                    entry.name for entry in entries if entry.name.startswith(prefix)
                )
        except OSError as exc:
            raise CapabilityExecutionReceiptStoreError(
                "capability execution receipt root cannot be read safely"
            ) from exc
        for name in names:
            remainder = name[len(prefix) :]
            receipt_id, extension = os.path.splitext(remainder)
            if (
                extension != ".json"
                or not _hash_ref(receipt_id, "capability_execution_receipt")
                or not re_full_sha256(receipt_id.partition(":")[2])
                or name != self._file_name(capability_ref, receipt_id)
                or receipt_id in paths
            ):
                raise CapabilityExecutionReceiptStoreError(
                    "capability execution receipt name is invalid"
                )
            paths[receipt_id] = root / name
        return sorted(paths.items())

    @staticmethod
    def _read_record(
        path: Path,
        *,
        expected_capability_ref: str,
        expected_receipt_id: str,
    ) -> tuple[StoredExecutionReceipt, str]:
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
            if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
                raise CapabilityExecutionReceiptStoreError(
                    "durable execution receipt exceeds the size cap"
                )
            value = json.loads(payload)
            if not isinstance(value, Mapping) or payload != _canonical_json(value):
                raise CapabilityExecutionReceiptStoreError(
                    "durable execution receipt encoding is invalid"
                )
            record = StoredExecutionReceipt._from_dict(value)
            if (
                record.capability_ref != expected_capability_ref
                or record.receipt_id != expected_receipt_id
            ):
                raise CapabilityExecutionReceiptStoreError(
                    "durable execution receipt name binding is invalid"
                )
            return record, payload
        except CapabilityExecutionReceiptStoreError:
            raise
        except (OSError, ReceiptStoreError, UnicodeError, ValueError, TypeError) as exc:
            raise CapabilityExecutionReceiptStoreError(
                "durable execution receipt cannot be read safely"
            ) from exc
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def load(self, capability_ref: str) -> tuple[StoredExecutionReceipt, ...]:
        """Load every hash-verified stored receipt for one capability reference."""

        if type(capability_ref) is not str:
            raise TypeError("capability_ref must be a string")
        if not _hash_ref(capability_ref, "issued_capability_contract"):
            raise ValueError("capability_ref must be an issued capability reference")
        root = self._existing_root()
        if root is None:
            return ()
        return tuple(
            self._read_record(
                path,
                expected_capability_ref=capability_ref,
                expected_receipt_id=receipt_id,
            )[0]
            for receipt_id, path in self._receipt_paths(root, capability_ref)
        )

    def persist(
        self,
        receipt: CapabilityExecutionReceipt,
    ) -> DurableExecutionReceiptResult:
        """Validate and atomically persist one already-minted R5D6 receipt."""

        if type(receipt) is not CapabilityExecutionReceipt:
            raise TypeError("receipt must be a CapabilityExecutionReceipt")
        try:
            validated = replace(receipt)
            projection = validated.to_dict()
            record = StoredExecutionReceipt._from_dict(projection)
        except (RuntimeError, TypeError, ValueError) as exc:
            raise CapabilityExecutionReceiptStoreError(
                "capability execution receipt is invalid"
            ) from exc
        payload = _canonical_json(projection)
        if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise CapabilityExecutionReceiptStoreError(
                "durable execution receipt exceeds the size cap"
            )

        root = self._prepare_root()
        path = root / self._file_name(record.capability_ref, record.receipt_id)
        try:
            BehavioralReceiptStore._link_exclusive(path, payload)
            BehavioralReceiptStore._fsync_directory(root)
        except FileExistsError:
            existing, existing_payload = self._read_record(
                path,
                expected_capability_ref=record.capability_ref,
                expected_receipt_id=record.receipt_id,
            )
            if existing_payload != payload:
                raise CapabilityExecutionReceiptStoreError(
                    "existing durable execution receipt bytes do not match"
                )
            return DurableExecutionReceiptResult(
                record=existing,
                durable_written=False,
            )
        except CapabilityExecutionReceiptStoreError:
            raise
        except (OSError, ReceiptStoreError) as exc:
            raise CapabilityExecutionReceiptStoreError(
                "durable execution receipt cannot be published safely"
            ) from exc
        return DurableExecutionReceiptResult(record=record, durable_written=True)


def persist_execution_receipt(
    receipt: CapabilityExecutionReceipt,
    *,
    store_root: Optional[Path] = None,
) -> DurableExecutionReceiptResult:
    """Persist one receipt without wiring the R5D7 store into production."""

    return CapabilityExecutionReceiptStore(store_root).persist(receipt)


__all__ = [
    "CAPABILITY_EXECUTION_RECEIPT_STORE_ENV",
    "CAPABILITY_EXECUTION_RECEIPT_STORE_MODE",
    "CapabilityExecutionReceiptStore",
    "CapabilityExecutionReceiptStoreError",
    "DurableExecutionReceiptResult",
    "StoredExecutionReceipt",
    "persist_execution_receipt",
]
