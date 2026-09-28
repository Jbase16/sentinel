"""R5E4: append-only, exclusive-create local workflow sequence persistence.

One immutable full-ledger snapshot per applied slot is published with the existing
receipt-store hard-link/fsync primitives. Concurrent writers reload and re-evaluate
the one E3 transition definition after collision. Fixture identity, rather than
capture identity, keys the stream: a new capture cannot reset application history.

Passive/unwired with respect to targets; only bounded local filesystem I/O occurs.
No origin, identity, action, budget, transport, finding or execution authority is
added. Disposable fixtures create no target residue/cleanup obligation/orphan risk.
Local retained files are intentional evidence, not target cleanup claims.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .normalize import stable_hash
from .receipts import BehavioralReceiptStore, ReceiptStoreError, _MAX_RECEIPT_BYTES
from .workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
    validate_current_capture,
)
from .workflow_invariant_contract import WorkflowOperation, _fields
from .workflow_invariant_ledger import (
    WorkflowTransitionLedger,
    WorkflowTransitionOutcome,
    WorkflowTransitionResult,
    evaluate_operation,
)

WORKFLOW_INVARIANT_STORE_ENV = "SENTINELFORGE_WORKFLOW_INVARIANT_SEQUENCES"
WORKFLOW_INVARIANT_STORE_MODE = "behavioral_workflow_invariant_store_v1"
_MAX_PUBLISH_ATTEMPTS = 64


class WorkflowInvariantStoreError(RuntimeError):
    """A sequence cannot be read/published with safe durable semantics."""


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _fixture_key(binding: WorkflowInvariantBinding) -> str:
    return stable_hash(
        "workflow_sequence_store_key", {"fixture_ref": binding.fixture.fixture_id}
    ).split(":", 1)[1]


def _slot_key(binding: WorkflowInvariantBinding, slot: int) -> str:
    return stable_hash(
        "workflow_sequence_slot",
        {"fixture_ref": binding.fixture.fixture_id, "slot": slot},
    ).split(":", 1)[1]


@dataclass(frozen=True)
class DurableWorkflowTransition:
    result: WorkflowTransitionResult
    durable_state_written: bool

    def __post_init__(self) -> None:
        if type(self.result) is not WorkflowTransitionResult:
            raise ValueError("invalid durable workflow transition")
        self.result.__post_init__()
        if type(
            self.durable_state_written
        ) is not bool or self.durable_state_written != (
            self.result.outcome is WorkflowTransitionOutcome.FIRST_APPLICATION
        ):
            raise ValueError("inconsistent durable workflow transition")


class WorkflowInvariantSequenceStore:
    """Local-only atomic sequence store, default-off because it has no caller."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root

    def _root(self) -> Path:
        if self.root is not None:
            return self.root
        override = os.environ.get(WORKFLOW_INVARIANT_STORE_ENV)
        if override:
            return Path(override)
        data = os.environ.get("SENTINEL_DATA_DIR")
        return (
            Path(data) / "workflow_invariant_sequences"
            if data
            else Path.home() / ".sentinelforge" / "workflow_invariant_sequences"
        )

    def _prepare_root(self) -> Path:
        try:
            return BehavioralReceiptStore(self._root())._prepare_root()
        except (OSError, ReceiptStoreError) as exc:
            raise WorkflowInvariantStoreError("workflow_sequence_root_unsafe") from exc

    def _existing_root(self) -> Path | None:
        try:
            self._root().lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise WorkflowInvariantStoreError(
                "workflow_sequence_root_unreadable"
            ) from exc
        return self._prepare_root()

    @staticmethod
    def _file_name(binding: WorkflowInvariantBinding, slot: int) -> str:
        return (
            f"workflow-{_fixture_key(binding)}-{slot}-{_slot_key(binding, slot)}.json"
        )

    def _state_paths(
        self, root: Path, binding: WorkflowInvariantBinding
    ) -> list[tuple[int, Path]]:
        prefix = f"workflow-{_fixture_key(binding)}-"
        paths: dict[int, Path] = {}
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if not entry.name.startswith(prefix):
                        continue
                    slot_text = entry.name[len(prefix) :].partition("-")[0]
                    try:
                        slot = int(slot_text)
                    except ValueError as exc:
                        raise WorkflowInvariantStoreError(
                            "workflow_sequence_filename_invalid"
                        ) from exc
                    if (
                        not 0
                        <= slot
                        < min(
                            binding.fixture.contract.max_operations,
                            len(binding.fixture.contract.operations),
                        )
                        or entry.name != self._file_name(binding, slot)
                        or slot in paths
                    ):
                        raise WorkflowInvariantStoreError(
                            "workflow_sequence_filename_invalid"
                        )
                    paths[slot] = root / entry.name
        except OSError as exc:
            raise WorkflowInvariantStoreError(
                "workflow_sequence_directory_unreadable"
            ) from exc
        ordered = sorted(paths.items())
        if [slot for slot, _ in ordered] != list(range(len(ordered))):
            raise WorkflowInvariantStoreError("workflow_sequence_slot_gap")
        return ordered

    @staticmethod
    def _read_state(
        path: Path, binding: WorkflowInvariantBinding, slot: int
    ) -> WorkflowTransitionLedger:
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
            value = _fields(
                json.loads(payload),
                {"mode", "fixture_ref", "slot", "slot_key", "ledger"},
            )
            if (
                payload != _canonical_json(value)
                or value["mode"] != WORKFLOW_INVARIANT_STORE_MODE
                or value["fixture_ref"] != binding.fixture.fixture_id
                or type(value["slot"]) is not int
                or value["slot"] != slot
                or value["slot_key"] != _slot_key(binding, slot)
            ):
                raise WorkflowInvariantStoreError("workflow_sequence_state_invalid")
            ledger = WorkflowTransitionLedger.from_dict(value["ledger"])
            if (
                ledger.binding.binding_id != binding.binding_id
                or len(ledger.entries) != slot + 1
            ):
                raise WorkflowInvariantStoreError(
                    "workflow_sequence_binding_or_slot_mismatch"
                )
            return ledger
        except WorkflowInvariantStoreError:
            raise
        except (
            OSError,
            ReceiptStoreError,
            UnicodeError,
            ValueError,
            TypeError,
            KeyError,
        ) as exc:
            raise WorkflowInvariantStoreError(
                "workflow_sequence_state_unreadable"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def load(self, binding: WorkflowInvariantBinding) -> WorkflowTransitionLedger:
        """Read and recompute the exact complete chain; never create an empty root."""
        genesis = WorkflowTransitionLedger(binding)
        root = self._existing_root()
        if root is None:
            return genesis
        previous = genesis
        for slot, path in self._state_paths(root, binding):
            ledger = self._read_state(path, binding, slot)
            if ledger.entries[:-1] != previous.entries:
                raise WorkflowInvariantStoreError("workflow_sequence_chain_mismatch")
            previous = ledger
        return previous

    def _publish_state(
        self,
        root: Path,
        binding: WorkflowInvariantBinding,
        ledger: WorkflowTransitionLedger,
    ) -> None:
        slot = len(ledger.entries) - 1
        payload = _canonical_json(
            {
                "schema_version": 1,
                "mode": WORKFLOW_INVARIANT_STORE_MODE,
                "fixture_ref": binding.fixture.fixture_id,
                "slot": slot,
                "slot_key": _slot_key(binding, slot),
                "ledger": ledger.to_dict(),
            }
        )
        if len(payload.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise WorkflowInvariantStoreError("workflow_sequence_size_cap_exceeded")
        BehavioralReceiptStore._link_exclusive(
            root / self._file_name(binding, slot), payload
        )
        BehavioralReceiptStore._fsync_directory(root)

    def record_operation(
        self,
        binding: WorkflowInvariantBinding,
        current_capture: WorkflowCaptureProvenance,
        operation: WorkflowOperation,
        *,
        at_index: int,
    ) -> DurableWorkflowTransition:
        """Publish only first application; refusals never write or alter snapshots."""
        validate_current_capture(binding, current_capture, at_index)
        for _ in range(_MAX_PUBLISH_ATTEMPTS):
            prior = self.load(binding)
            result = evaluate_operation(
                binding, current_capture, operation, prior, at_index=at_index
            )
            if result.outcome is not WorkflowTransitionOutcome.FIRST_APPLICATION:
                return DurableWorkflowTransition(result, False)
            root = self._prepare_root()
            try:
                self._publish_state(root, binding, result.ledger)
            except FileExistsError:
                continue
            except WorkflowInvariantStoreError:
                raise
            except (OSError, ReceiptStoreError) as exc:
                raise WorkflowInvariantStoreError(
                    "workflow_sequence_publication_failed"
                ) from exc
            return DurableWorkflowTransition(result, True)
        raise WorkflowInvariantStoreError("workflow_sequence_contention_bound_exceeded")
