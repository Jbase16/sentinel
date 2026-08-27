"""Durable, atomic R5D4 persistence for R5D3 capability consumption.

The store composes the one R5D3 ``evaluate_consumption`` transition definition with
the audited filesystem primitives used by ``BehavioralReceiptStore``.  Each accepted
use publishes an immutable, canonical ledger snapshot at a content-addressed use-slot
path through the receipt store's fully-written exclusive hard-link boundary.  A
concurrent loser reloads and re-evaluates through R5D3 before making a bounded retry.

This module performs local filesystem I/O only.  It sends no request, reads no target
clock, drives no backend, provisions no callback, completes no execution receipt,
constructs no finding, and grants no target or execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .capability_consumption_ledger import (
    CapabilityConsumptionLedger,
    ConsumptionDecision,
    ConsumptionLedgerDenied,
    ConsumptionOutcome,
    ConsumptionResult,
    evaluate_consumption,
)
from .capability_contract import (
    CapabilityDecision,
    IssuedCapabilityContract,
)
from .capability_confinement_freshness import ConfinementDecision
from .receipts import (
    BehavioralReceiptStore,
    ReceiptStoreError,
    _MAX_RECEIPT_BYTES,
    re_full_sha256,
    request_fingerprint,
)


CAPABILITY_CONSUMPTION_STORE_ENV = "SENTINELFORGE_CAPABILITY_CONSUMPTIONS"
CAPABILITY_CONSUMPTION_STORE_MODE = "behavioral_capability_consumption_store_v1"
_MAX_PUBLISH_ATTEMPTS = 64


class CapabilityConsumptionStoreError(RuntimeError):
    """Persisted consumption state is unsafe or cannot be advanced atomically."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _capability_store_key(capability_ref: str) -> str:
    return request_fingerprint(
        {
            "schema_version": 1,
            "capability_ref": capability_ref,
        }
    )


def _state_key(capability_ref: str, use_slot: int) -> str:
    return request_fingerprint(
        {
            "schema_version": 1,
            "capability_ref": capability_ref,
            "use_slot": use_slot,
        }
    )


@dataclass(frozen=True)
class DurableConsumptionResult:
    """R5D3's decision plus whether this call published its durable next state."""

    decision: ConsumptionDecision
    ledger: CapabilityConsumptionLedger
    store_key: str
    durable_state_written: bool

    def __post_init__(self) -> None:
        if not isinstance(self.decision, ConsumptionDecision):
            raise TypeError("decision must be a ConsumptionDecision")
        if not isinstance(self.ledger, CapabilityConsumptionLedger):
            raise TypeError("ledger must be a CapabilityConsumptionLedger")
        if not isinstance(self.store_key, str) or not re_full_sha256(self.store_key):
            raise ValueError("capability consumption store key is invalid")
        if type(self.durable_state_written) is not bool:
            raise TypeError("durable_state_written must be a bool")
        ConsumptionResult(decision=self.decision, ledger=self.ledger)
        if self.durable_state_written != (
            self.decision.outcome is ConsumptionOutcome.FIRST_CONSUMPTION
        ):
            raise ValueError("durable capability consumption result is inconsistent")


@dataclass(frozen=True)
class _StoredConsumptionState:
    state_key: str
    capability_ref: str
    use_slot: int
    ledger: CapabilityConsumptionLedger

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": CAPABILITY_CONSUMPTION_STORE_MODE,
            "state_key": self.state_key,
            "capability_ref": self.capability_ref,
            "use_slot": self.use_slot,
            "ledger": self.ledger.to_dict(),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        contract: IssuedCapabilityContract,
        expected_slot: int,
    ) -> "_StoredConsumptionState":
        expected_fields = {
            "schema_version",
            "mode",
            "state_key",
            "capability_ref",
            "use_slot",
            "ledger",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected_fields
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("mode") != CAPABILITY_CONSUMPTION_STORE_MODE
            or value.get("capability_ref") != contract.capability_id
            or type(value.get("use_slot")) is not int
            or value.get("use_slot") != expected_slot
            or expected_slot >= contract.max_uses
            or value.get("state_key")
            != _state_key(contract.capability_id, expected_slot)
            or not isinstance(value.get("ledger"), Mapping)
        ):
            raise CapabilityConsumptionStoreError(
                "durable capability consumption state is invalid"
            )
        try:
            ledger = CapabilityConsumptionLedger.from_dict(value["ledger"])
        except (ConsumptionLedgerDenied, TypeError, ValueError) as exc:
            raise CapabilityConsumptionStoreError(
                "durable capability consumption ledger is invalid"
            ) from exc
        slots = sorted(entry.use_slot for entry in ledger.entries)
        if (
            len(ledger.entries) != expected_slot + 1
            or slots != list(range(expected_slot + 1))
            or any(
                entry.capability_ref != contract.capability_id
                for entry in ledger.entries
            )
            or any(not entry.reloaded for entry in ledger.entries)
        ):
            raise CapabilityConsumptionStoreError(
                "durable capability consumption ledger is inconsistent"
            )
        return cls(
            state_key=value["state_key"],
            capability_ref=value["capability_ref"],
            use_slot=expected_slot,
            ledger=ledger,
        )


class CapabilityConsumptionStore:
    """Append-only, per-use-slot durable store for one R5D3 ledger per capability."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(CAPABILITY_CONSUMPTION_STORE_ENV)
        if override:
            return Path(override)
        data_dir = os.environ.get("SENTINEL_DATA_DIR")
        if data_dir:
            return Path(data_dir) / "capability_consumptions"
        return Path.home() / ".sentinelforge" / "capability_consumptions"

    @staticmethod
    def _file_name(capability_ref: str, use_slot: int) -> str:
        capability_key = _capability_store_key(capability_ref)
        return (
            f"capability-{capability_key}-{use_slot}-"
            f"{_state_key(capability_ref, use_slot)}.json"
        )

    def _prepare_root(self) -> Path:
        root = self._root()
        try:
            return BehavioralReceiptStore(root)._prepare_root()
        except (OSError, ReceiptStoreError) as exc:
            raise CapabilityConsumptionStoreError(
                "capability consumption root is unsafe"
            ) from exc

    def _existing_root(self) -> Optional[Path]:
        root = self._root()
        try:
            root.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CapabilityConsumptionStoreError(
                "capability consumption root cannot be inspected safely"
            ) from exc
        return self._prepare_root()

    def _state_paths(
        self,
        root: Path,
        contract: IssuedCapabilityContract,
    ) -> list[tuple[int, Path]]:
        capability_key = _capability_store_key(contract.capability_id)
        prefix = f"capability-{capability_key}-"
        paths: Dict[int, Path] = {}
        try:
            with os.scandir(root) as entries:
                names = [entry.name for entry in entries if entry.name.startswith(prefix)]
        except OSError as exc:
            raise CapabilityConsumptionStoreError(
                "capability consumption root cannot be read safely"
            ) from exc
        for name in names:
            remainder = name[len(prefix) :]
            slot_text, separator, key_suffix = remainder.partition("-")
            state_key, extension = os.path.splitext(key_suffix)
            try:
                use_slot = int(slot_text)
            except ValueError as exc:
                raise CapabilityConsumptionStoreError(
                    "capability consumption state name is invalid"
                ) from exc
            if (
                separator != "-"
                or extension != ".json"
                or slot_text != str(use_slot)
                or use_slot < 0
                or use_slot >= contract.max_uses
                or state_key != _state_key(contract.capability_id, use_slot)
                or use_slot in paths
            ):
                raise CapabilityConsumptionStoreError(
                    "capability consumption state name is invalid"
                )
            paths[use_slot] = root / name
        ordered = sorted(paths.items())
        if [slot for slot, _path in ordered] != list(range(len(ordered))):
            raise CapabilityConsumptionStoreError(
                "capability consumption state sequence is incomplete"
            )
        return ordered

    @staticmethod
    def _read_state(
        path: Path,
        *,
        contract: IssuedCapabilityContract,
        expected_slot: int,
    ) -> _StoredConsumptionState:
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
            value = json.loads(payload)
            if not isinstance(value, Mapping) or payload != _canonical_json(value):
                raise CapabilityConsumptionStoreError(
                    "durable capability consumption encoding is invalid"
                )
            return _StoredConsumptionState.from_dict(
                value,
                contract=contract,
                expected_slot=expected_slot,
            )
        except CapabilityConsumptionStoreError:
            raise
        except (OSError, ReceiptStoreError, UnicodeError, ValueError, TypeError) as exc:
            raise CapabilityConsumptionStoreError(
                "durable capability consumption state cannot be read safely"
            ) from exc
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def load(
        self,
        contract: IssuedCapabilityContract,
    ) -> CapabilityConsumptionLedger:
        """Load and integrity-check the durable ledger for one live contract."""

        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        try:
            replace(contract)
        except (TypeError, ValueError) as exc:
            raise CapabilityConsumptionStoreError(
                "capability contract is invalid"
            ) from exc
        root = self._existing_root()
        if root is None:
            return CapabilityConsumptionLedger.build()

        previous_by_slot: Dict[int, str] = {}
        latest = CapabilityConsumptionLedger.build()
        for use_slot, path in self._state_paths(root, contract):
            state = self._read_state(
                path,
                contract=contract,
                expected_slot=use_slot,
            )
            current_by_slot = {
                entry.use_slot: entry.entry_id for entry in state.ledger.entries
            }
            if any(
                current_by_slot.get(prior_slot) != entry_id
                for prior_slot, entry_id in previous_by_slot.items()
            ):
                raise CapabilityConsumptionStoreError(
                    "durable capability consumption chain is inconsistent"
                )
            previous_by_slot = current_by_slot
            latest = state.ledger
        return latest

    def _publish_state(
        self,
        root: Path,
        state: _StoredConsumptionState,
    ) -> None:
        payload = _canonical_json(state.to_dict())
        if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise CapabilityConsumptionStoreError(
                "durable capability consumption state exceeds the size cap"
            )
        path = root / self._file_name(state.capability_ref, state.use_slot)
        BehavioralReceiptStore._link_exclusive(path, payload)
        BehavioralReceiptStore._fsync_directory(root)

    def record_consumption(
        self,
        contract: IssuedCapabilityContract,
        capability_decision: CapabilityDecision,
        confinement_decision: ConfinementDecision,
    ) -> DurableConsumptionResult:
        """Atomically persist R5D3's next state, or return its durable refusal."""

        genesis = CapabilityConsumptionLedger.build()
        evaluate_consumption(
            contract,
            capability_decision,
            confinement_decision,
            genesis,
        )

        store_key = _capability_store_key(contract.capability_id)
        for _attempt in range(_MAX_PUBLISH_ATTEMPTS):
            prior = self.load(contract)
            evaluated = evaluate_consumption(
                contract,
                capability_decision,
                confinement_decision,
                prior,
            )
            if evaluated.decision.outcome is not ConsumptionOutcome.FIRST_CONSUMPTION:
                return DurableConsumptionResult(
                    decision=evaluated.decision,
                    ledger=evaluated.ledger,
                    store_key=store_key,
                    durable_state_written=False,
                )

            prior_ids = {entry.entry_id for entry in prior.entries}
            additions = tuple(
                entry
                for entry in evaluated.ledger.entries
                if entry.entry_id not in prior_ids
            )
            if (
                len(additions) != 1
                or additions[0].reloaded
                or additions[0].use_slot != len(prior.entries)
            ):
                raise CapabilityConsumptionStoreError(
                    "R5D3 returned an invalid durable transition"
                )
            state = _StoredConsumptionState(
                state_key=_state_key(contract.capability_id, additions[0].use_slot),
                capability_ref=contract.capability_id,
                use_slot=additions[0].use_slot,
                ledger=evaluated.ledger,
            )
            root = self._prepare_root()
            try:
                self._publish_state(root, state)
            except FileExistsError:
                continue
            except CapabilityConsumptionStoreError:
                raise
            except (OSError, ReceiptStoreError) as exc:
                raise CapabilityConsumptionStoreError(
                    "durable capability consumption state cannot be published safely"
                ) from exc
            return DurableConsumptionResult(
                decision=evaluated.decision,
                ledger=evaluated.ledger,
                store_key=store_key,
                durable_state_written=True,
            )
        raise CapabilityConsumptionStoreError(
            "durable capability consumption update contention exceeded the retry bound"
        )


def record_consumption(
    contract: IssuedCapabilityContract,
    capability_decision: CapabilityDecision,
    confinement_decision: ConfinementDecision,
    *,
    store_root: Optional[Path] = None,
) -> DurableConsumptionResult:
    """Record one durable consumption without wiring the store into production."""

    return CapabilityConsumptionStore(store_root).record_consumption(
        contract,
        capability_decision,
        confinement_decision,
    )


__all__ = [
    "CAPABILITY_CONSUMPTION_STORE_ENV",
    "CAPABILITY_CONSUMPTION_STORE_MODE",
    "CapabilityConsumptionStore",
    "CapabilityConsumptionStoreError",
    "DurableConsumptionResult",
    "record_consumption",
]
