"""Passive R5D3 capability-consumption ledger and replay refusal.

R5D1 classifies a capability's logical bounds and R5D2 classifies the orthogonal
confinement/freshness evidence axis.  This module adds only deterministic transition
semantics over an explicit immutable ledger supplied by the caller.  A use is eligible
for recording only when its R5D1 decision is ``VALID`` and its R5D2 decision is
``CONFINED_FRESH``.

For admissible inputs the evaluator uses the fixed precedence
``replayed_presentation -> capability_already_consumed -> first_consumption``.  The
R5D2 confinement-decision ID is the replay key, while the number of prior entries for
the capability is the authoritative use count.  R5D1's caller-supplied ``use_index``
is deliberately not consulted here.

The module is passive and unwired.  It performs no filesystem, database, environment,
clock, target, or receipt I/O; sends no request; reserves no budget; dispatches no
backend; provisions no callback; and grants no finding, promotion, retry, or execution
authority.  Durable persistence, cross-process compare-and-swap, running-target
expiry, receipt completion/abort, cleanup, effect evaluation, and OCB-S17 remain later
active work.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Mapping, Sequence, Tuple

from .capability_confinement_freshness import (
    ConfinementDecision,
    ConfinementOutcome,
)
from .capability_contract import (
    CapabilityDecision,
    CapabilityOutcome,
    IssuedCapabilityContract,
    _hash_ref,
)
from .normalize import stable_hash


CAPABILITY_CONSUMPTION_LEDGER_MODE = "behavioral_capability_consumption_ledger_v1"


class ConsumptionLedgerDenied(RuntimeError):
    """A presentation is inadmissible for consumption-ledger evaluation."""


class ConsumptionOutcome(str, Enum):
    FIRST_CONSUMPTION = "first_consumption"
    REPLAYED_PRESENTATION = "replayed_presentation"
    CAPABILITY_ALREADY_CONSUMED = "capability_already_consumed"


def _axis_context_is_admissible(
    contract: object,
    capability_decision: object,
    confinement_decision: object,
) -> bool:
    if (
        not isinstance(contract, IssuedCapabilityContract)
        or not isinstance(capability_decision, CapabilityDecision)
        or not isinstance(confinement_decision, ConfinementDecision)
    ):
        return False
    try:
        replace(capability_decision)
        replace(confinement_decision)
    except (TypeError, ValueError):
        return False
    return (
        contract.capability_id
        == capability_decision.capability_id
        == confinement_decision.capability_ref
        and capability_decision.outcome is CapabilityOutcome.VALID
        and confinement_decision.outcome is ConfinementOutcome.CONFINED_FRESH
    )


def _entry_payload(entry: "ConsumptionEntry") -> Dict[str, Any]:
    return {
        "capability_ref": entry.capability_ref,
        "presentation_ref": entry.presentation_ref,
        "capability_decision_ref": entry.capability_decision_ref,
        "confinement_decision_ref": entry.confinement_decision_ref,
        "use_slot": entry.use_slot,
    }


@dataclass(frozen=True)
class ConsumptionEntry:
    """One admissible use recorded without retaining bearer or capture material."""

    entry_id: str
    capability_ref: str
    presentation_ref: str
    capability_decision_ref: str
    confinement_decision_ref: str
    use_slot: int
    _contract: IssuedCapabilityContract = field(repr=False, compare=False)
    _capability_decision: CapabilityDecision = field(repr=False, compare=False)
    _confinement_decision: ConfinementDecision = field(
        repr=False,
        compare=False,
    )

    @classmethod
    def build(
        cls,
        *,
        contract: IssuedCapabilityContract,
        capability_decision: CapabilityDecision,
        confinement_decision: ConfinementDecision,
        use_slot: int,
    ) -> "ConsumptionEntry":
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not isinstance(capability_decision, CapabilityDecision):
            raise TypeError("capability_decision must be a CapabilityDecision")
        if not isinstance(confinement_decision, ConfinementDecision):
            raise TypeError("confinement_decision must be a ConfinementDecision")
        if not _axis_context_is_admissible(
            contract,
            capability_decision,
            confinement_decision,
        ):
            raise ConsumptionLedgerDenied("capability_use_is_not_admissible")
        if type(use_slot) is not int or not 0 <= use_slot < contract.max_uses:
            raise ValueError("capability consumption use slot is invalid")

        values = {
            "entry_id": "",
            "capability_ref": contract.capability_id,
            "presentation_ref": confinement_decision.decision_id,
            "capability_decision_ref": capability_decision.decision_id,
            "confinement_decision_ref": confinement_decision.decision_id,
            "use_slot": use_slot,
            "_contract": contract,
            "_capability_decision": capability_decision,
            "_confinement_decision": confinement_decision,
        }
        payload = {
            key: value
            for key, value in values.items()
            if key != "entry_id" and not key.startswith("_")
        }
        return cls(
            **{
                **values,
                "entry_id": stable_hash(
                    "capability_consumption_entry",
                    payload,
                ),
            }
        )

    def __post_init__(self) -> None:
        refs = (
            (self.entry_id, "capability_consumption_entry"),
            (self.capability_ref, "issued_capability_contract"),
            (
                self.presentation_ref,
                "capability_confinement_decision",
            ),
            (self.capability_decision_ref, "capability_decision"),
            (
                self.confinement_decision_ref,
                "capability_confinement_decision",
            ),
        )
        if (
            not _axis_context_is_admissible(
                self._contract,
                self._capability_decision,
                self._confinement_decision,
            )
            or self.entry_id
            != stable_hash(
                "capability_consumption_entry",
                _entry_payload(self),
            )
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or self.capability_ref != self._contract.capability_id
            or self.capability_decision_ref != self._capability_decision.decision_id
            or self.presentation_ref != self._confinement_decision.decision_id
            or self.confinement_decision_ref != self._confinement_decision.decision_id
            or self.presentation_ref != self.confinement_decision_ref
            or type(self.use_slot) is not int
            or not 0 <= self.use_slot < self._contract.max_uses
        ):
            raise ValueError("capability consumption entry is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "entry_id": self.entry_id,
            **_entry_payload(self),
        }

    @property
    def reloaded(self) -> bool:
        """Whether this entry was integrity-checked without live decision context."""

        return False

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConsumptionEntry":
        """Reload an inert entry after re-verifying its public content address."""

        expected_fields = {
            "schema_version",
            "entry_id",
            "capability_ref",
            "presentation_ref",
            "capability_decision_ref",
            "confinement_decision_ref",
            "use_slot",
        }
        if not isinstance(value, Mapping) or set(value) != expected_fields:
            raise ConsumptionLedgerDenied(
                "capability_consumption_serialization_invalid"
            )
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise ConsumptionLedgerDenied(
                "capability_consumption_serialization_invalid"
            )
        try:
            return _ReloadedConsumptionEntry(
                entry_id=value["entry_id"],
                capability_ref=value["capability_ref"],
                presentation_ref=value["presentation_ref"],
                capability_decision_ref=value["capability_decision_ref"],
                confinement_decision_ref=value["confinement_decision_ref"],
                use_slot=value["use_slot"],
            )
        except (TypeError, ValueError) as exc:
            raise ConsumptionLedgerDenied(
                "capability_consumption_serialization_invalid"
            ) from exc


class _ReloadedConsumptionEntry(ConsumptionEntry):
    """Hash-verified persisted entry with no live construction authority."""

    __slots__ = ()

    def __init__(
        self,
        *,
        entry_id: str,
        capability_ref: str,
        presentation_ref: str,
        capability_decision_ref: str,
        confinement_decision_ref: str,
        use_slot: int,
        _contract: object = None,
        _capability_decision: object = None,
        _confinement_decision: object = None,
    ) -> None:
        if any(
            context is not None
            for context in (
                _contract,
                _capability_decision,
                _confinement_decision,
            )
        ):
            raise ConsumptionLedgerDenied(
                "reloaded_capability_consumption_entry_is_inert"
            )
        values = {
            "entry_id": entry_id,
            "capability_ref": capability_ref,
            "presentation_ref": presentation_ref,
            "capability_decision_ref": capability_decision_ref,
            "confinement_decision_ref": confinement_decision_ref,
            "use_slot": use_slot,
        }
        refs = (
            (entry_id, "capability_consumption_entry"),
            (capability_ref, "issued_capability_contract"),
            (presentation_ref, "capability_confinement_decision"),
            (capability_decision_ref, "capability_decision"),
            (confinement_decision_ref, "capability_confinement_decision"),
        )
        if (
            any(
                not isinstance(item, str)
                for item in (
                    entry_id,
                    capability_ref,
                    presentation_ref,
                    capability_decision_ref,
                    confinement_decision_ref,
                )
            )
            or any(not _hash_ref(item, prefix) for item, prefix in refs)
            or entry_id
            != stable_hash(
                "capability_consumption_entry",
                {key: item for key, item in values.items() if key != "entry_id"},
            )
            or presentation_ref != confinement_decision_ref
            or type(use_slot) is not int
            or use_slot < 0
        ):
            raise ValueError("reloaded capability consumption entry is invalid")
        for name, item in values.items():
            object.__setattr__(self, name, item)
        object.__setattr__(self, "_contract", None)
        object.__setattr__(self, "_capability_decision", None)
        object.__setattr__(self, "_confinement_decision", None)

    @property
    def reloaded(self) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConsumptionEntry):
            return NotImplemented
        return self.entry_id == other.entry_id and _entry_payload(self) == (
            _entry_payload(other)
        )

    __hash__ = ConsumptionEntry.__hash__


def _ledger_identity_payload(
    entries: Tuple[ConsumptionEntry, ...],
) -> Dict[str, Any]:
    return {"entry_ids": [entry.entry_id for entry in entries]}


def _ledger_passive_boundary_is_valid(
    ledger: "CapabilityConsumptionLedger",
) -> bool:
    return (
        ledger.durable_persistence_authority is False
        and ledger.target_io_authority is False
        and ledger.backend_dispatch_authority is False
        and ledger.receipt_authority is False
        and ledger.finding_authority is False
        and ledger.executable is False
    )


@dataclass(frozen=True)
class CapabilityConsumptionLedger:
    """An immutable, order-independent collection of consumption entries."""

    ledger_id: str
    entries: Tuple[ConsumptionEntry, ...]
    durable_persistence_authority: bool = False
    target_io_authority: bool = False
    backend_dispatch_authority: bool = False
    receipt_authority: bool = False
    finding_authority: bool = False
    executable: bool = False
    mode: str = CAPABILITY_CONSUMPTION_LEDGER_MODE

    @classmethod
    def build(
        cls,
        *,
        entries: Sequence[ConsumptionEntry] = (),
        durable_persistence_authority: bool = False,
        target_io_authority: bool = False,
        backend_dispatch_authority: bool = False,
        receipt_authority: bool = False,
        finding_authority: bool = False,
        executable: bool = False,
    ) -> "CapabilityConsumptionLedger":
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            raise TypeError("entries must be a sequence of ConsumptionEntry values")
        normalized = tuple(entries)
        if any(not isinstance(entry, ConsumptionEntry) for entry in normalized):
            raise TypeError("entries must contain only ConsumptionEntry values")
        if any(
            flag is not False
            for flag in (
                durable_persistence_authority,
                target_io_authority,
                backend_dispatch_authority,
                receipt_authority,
                finding_authority,
                executable,
            )
        ):
            raise ConsumptionLedgerDenied(
                "capability_consumption_passive_boundary_violation"
            )
        try:
            for entry in normalized:
                replace(entry)
        except (TypeError, ValueError) as exc:
            raise ValueError("capability consumption ledger entry is invalid") from exc
        entry_ids = tuple(entry.entry_id for entry in normalized)
        if len(entry_ids) != len(set(entry_ids)):
            raise ValueError("capability consumption ledger has duplicate entries")

        canonical_entries = tuple(sorted(normalized, key=lambda entry: entry.entry_id))
        return cls(
            ledger_id=stable_hash(
                "capability_consumption_ledger",
                _ledger_identity_payload(canonical_entries),
            ),
            entries=canonical_entries,
            durable_persistence_authority=durable_persistence_authority,
            target_io_authority=target_io_authority,
            backend_dispatch_authority=backend_dispatch_authority,
            receipt_authority=receipt_authority,
            finding_authority=finding_authority,
            executable=executable,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(entry, ConsumptionEntry) for entry in self.entries
        ):
            raise TypeError("entries must be a tuple of ConsumptionEntry values")
        try:
            for entry in self.entries:
                replace(entry)
        except (TypeError, ValueError) as exc:
            raise ValueError("capability consumption ledger is invalid") from exc
        entry_ids = tuple(entry.entry_id for entry in self.entries)
        if (
            self.mode != CAPABILITY_CONSUMPTION_LEDGER_MODE
            or self.ledger_id
            != stable_hash(
                "capability_consumption_ledger",
                _ledger_identity_payload(self.entries),
            )
            or not _hash_ref(
                self.ledger_id,
                "capability_consumption_ledger",
            )
            or self.entries
            != tuple(sorted(self.entries, key=lambda entry: entry.entry_id))
            or len(entry_ids) != len(set(entry_ids))
            or not _ledger_passive_boundary_is_valid(self)
        ):
            raise ValueError("capability consumption ledger is invalid")

    def with_entry(
        self,
        entry: ConsumptionEntry,
    ) -> "CapabilityConsumptionLedger":
        if not isinstance(entry, ConsumptionEntry):
            raise TypeError("entry must be a ConsumptionEntry")
        if entry.reloaded:
            raise ConsumptionLedgerDenied(
                "reloaded_capability_consumption_entry_is_inert"
            )
        replace(self)
        return type(self).build(entries=(*self.entries, entry))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "ledger_id": self.ledger_id,
            "entries": [entry.to_dict() for entry in self.entries],
            "durable_persistence_authority": (self.durable_persistence_authority),
            "target_io_authority": self.target_io_authority,
            "backend_dispatch_authority": self.backend_dispatch_authority,
            "receipt_authority": self.receipt_authority,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityConsumptionLedger":
        """Reload a ledger after verifying all public entry and ledger identities."""

        expected_fields = {
            "schema_version",
            "mode",
            "ledger_id",
            "entries",
            "durable_persistence_authority",
            "target_io_authority",
            "backend_dispatch_authority",
            "receipt_authority",
            "finding_authority",
            "executable",
        }
        passive_fields = (
            "durable_persistence_authority",
            "target_io_authority",
            "backend_dispatch_authority",
            "receipt_authority",
            "finding_authority",
            "executable",
        )
        if (
            not isinstance(value, Mapping)
            or set(value) != expected_fields
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("mode") != CAPABILITY_CONSUMPTION_LEDGER_MODE
            or not isinstance(value.get("ledger_id"), str)
            or not _hash_ref(value["ledger_id"], "capability_consumption_ledger")
            or not isinstance(value.get("entries"), list)
            or any(value.get(field_name) is not False for field_name in passive_fields)
        ):
            raise ConsumptionLedgerDenied(
                "capability_consumption_serialization_invalid"
            )
        try:
            entries = tuple(
                ConsumptionEntry.from_dict(item) for item in value["entries"]
            )
            if entries != tuple(sorted(entries, key=lambda entry: entry.entry_id)):
                raise ValueError("serialized entries are not canonical")
            ledger = cls.build(entries=entries)
        except (ConsumptionLedgerDenied, TypeError, ValueError) as exc:
            raise ConsumptionLedgerDenied(
                "capability_consumption_serialization_invalid"
            ) from exc
        if ledger.ledger_id != value["ledger_id"]:
            raise ConsumptionLedgerDenied(
                "capability_consumption_serialization_invalid"
            )
        return ledger


def _decision_payload(decision: "ConsumptionDecision") -> Dict[str, Any]:
    return {
        "capability_ref": decision.capability_ref,
        "prior_ledger_ref": decision.prior_ledger_ref,
        "next_ledger_ref": decision.next_ledger_ref,
        "presentation_ref": decision.presentation_ref,
        "outcome": decision.outcome.value,
        "reason_ref": decision.reason_ref,
    }


def _consumed_entries(
    contract: IssuedCapabilityContract,
    ledger: CapabilityConsumptionLedger,
) -> Tuple[ConsumptionEntry, ...]:
    return tuple(
        entry
        for entry in ledger.entries
        if entry.capability_ref == contract.capability_id
    )


def _guarded_expected_transition(
    *,
    contract: IssuedCapabilityContract,
    capability_decision: CapabilityDecision,
    confinement_decision: ConfinementDecision,
    prior_ledger: CapabilityConsumptionLedger,
) -> Tuple[ConsumptionOutcome, CapabilityConsumptionLedger]:
    """Independently re-derive the ordered verdict for decision construction."""

    consumed = _consumed_entries(contract, prior_ledger)
    if any(
        entry.presentation_ref == confinement_decision.decision_id for entry in consumed
    ):
        return ConsumptionOutcome.REPLAYED_PRESENTATION, prior_ledger
    if len(consumed) >= contract.max_uses:
        return ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED, prior_ledger

    entry = ConsumptionEntry.build(
        contract=contract,
        capability_decision=capability_decision,
        confinement_decision=confinement_decision,
        use_slot=len(consumed),
    )
    return ConsumptionOutcome.FIRST_CONSUMPTION, prior_ledger.with_entry(entry)


@dataclass(frozen=True)
class ConsumptionDecision:
    """Content-addressed consumption verdict with a guarded ledger transition."""

    decision_id: str
    capability_ref: str
    prior_ledger_ref: str
    next_ledger_ref: str
    presentation_ref: str
    outcome: ConsumptionOutcome
    reason_ref: str
    _contract: IssuedCapabilityContract = field(repr=False, compare=False)
    _capability_decision: CapabilityDecision = field(repr=False, compare=False)
    _confinement_decision: ConfinementDecision = field(
        repr=False,
        compare=False,
    )
    _prior_ledger: CapabilityConsumptionLedger = field(
        repr=False,
        compare=False,
    )
    _next_ledger: CapabilityConsumptionLedger = field(
        repr=False,
        compare=False,
    )

    @classmethod
    def build(
        cls,
        *,
        contract: IssuedCapabilityContract,
        capability_decision: CapabilityDecision,
        confinement_decision: ConfinementDecision,
        prior_ledger: CapabilityConsumptionLedger,
        next_ledger: CapabilityConsumptionLedger,
        outcome: ConsumptionOutcome,
    ) -> "ConsumptionDecision":
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not isinstance(capability_decision, CapabilityDecision):
            raise TypeError("capability_decision must be a CapabilityDecision")
        if not isinstance(confinement_decision, ConfinementDecision):
            raise TypeError("confinement_decision must be a ConfinementDecision")
        if not isinstance(prior_ledger, CapabilityConsumptionLedger):
            raise TypeError("prior_ledger must be a CapabilityConsumptionLedger")
        if not isinstance(next_ledger, CapabilityConsumptionLedger):
            raise TypeError("next_ledger must be a CapabilityConsumptionLedger")
        if not isinstance(outcome, ConsumptionOutcome):
            raise TypeError("outcome must be a ConsumptionOutcome")
        if not _axis_context_is_admissible(
            contract,
            capability_decision,
            confinement_decision,
        ):
            raise ConsumptionLedgerDenied("capability_use_is_not_admissible")
        try:
            replace(prior_ledger)
            replace(next_ledger)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "capability consumption decision ledger is invalid"
            ) from exc

        expected_outcome, expected_ledger = _guarded_expected_transition(
            contract=contract,
            capability_decision=capability_decision,
            confinement_decision=confinement_decision,
            prior_ledger=prior_ledger,
        )
        ledger_changed = next_ledger.ledger_id != prior_ledger.ledger_id
        if (
            ledger_changed != (outcome is ConsumptionOutcome.FIRST_CONSUMPTION)
            or outcome is not expected_outcome
            or next_ledger.ledger_id != expected_ledger.ledger_id
        ):
            raise ValueError("capability consumption decision is inconsistent")

        reason_ref = stable_hash(
            "capability_consumption_reason",
            {"outcome": outcome.value},
        )
        values = {
            "decision_id": "",
            "capability_ref": contract.capability_id,
            "prior_ledger_ref": prior_ledger.ledger_id,
            "next_ledger_ref": next_ledger.ledger_id,
            "presentation_ref": confinement_decision.decision_id,
            "outcome": outcome,
            "reason_ref": reason_ref,
            "_contract": contract,
            "_capability_decision": capability_decision,
            "_confinement_decision": confinement_decision,
            "_prior_ledger": prior_ledger,
            "_next_ledger": next_ledger,
        }
        payload = {
            "capability_ref": values["capability_ref"],
            "prior_ledger_ref": values["prior_ledger_ref"],
            "next_ledger_ref": values["next_ledger_ref"],
            "presentation_ref": values["presentation_ref"],
            "outcome": outcome.value,
            "reason_ref": reason_ref,
        }
        return cls(
            **{
                **values,
                "decision_id": stable_hash(
                    "capability_consumption_decision",
                    payload,
                ),
            }
        )

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, ConsumptionOutcome):
            raise TypeError("outcome must be a ConsumptionOutcome")
        refs = (
            (self.decision_id, "capability_consumption_decision"),
            (self.capability_ref, "issued_capability_contract"),
            (self.prior_ledger_ref, "capability_consumption_ledger"),
            (self.next_ledger_ref, "capability_consumption_ledger"),
            (
                self.presentation_ref,
                "capability_confinement_decision",
            ),
            (self.reason_ref, "capability_consumption_reason"),
        )
        if not _axis_context_is_admissible(
            self._contract,
            self._capability_decision,
            self._confinement_decision,
        ):
            raise ValueError("capability consumption decision is invalid")
        try:
            replace(self._prior_ledger)
            replace(self._next_ledger)
        except (TypeError, ValueError) as exc:
            raise ValueError("capability consumption decision is invalid") from exc
        expected_outcome, expected_ledger = _guarded_expected_transition(
            contract=self._contract,
            capability_decision=self._capability_decision,
            confinement_decision=self._confinement_decision,
            prior_ledger=self._prior_ledger,
        )
        ledger_changed = self.next_ledger_ref != self.prior_ledger_ref
        if (
            self.decision_id
            != stable_hash(
                "capability_consumption_decision",
                _decision_payload(self),
            )
            or any(not _hash_ref(value, prefix) for value, prefix in refs)
            or self.capability_ref != self._contract.capability_id
            or self.prior_ledger_ref != self._prior_ledger.ledger_id
            or self.next_ledger_ref != self._next_ledger.ledger_id
            or self.presentation_ref != self._confinement_decision.decision_id
            or self.reason_ref
            != stable_hash(
                "capability_consumption_reason",
                {"outcome": self.outcome.value},
            )
            or ledger_changed != (self.outcome is ConsumptionOutcome.FIRST_CONSUMPTION)
            or self.outcome is not expected_outcome
            or self.next_ledger_ref != expected_ledger.ledger_id
        ):
            raise ValueError("capability consumption decision is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "decision_id": self.decision_id,
            **_decision_payload(self),
        }


@dataclass(frozen=True)
class ConsumptionResult:
    """The guarded decision and exact next-ledger object returned together."""

    decision: ConsumptionDecision
    ledger: CapabilityConsumptionLedger

    def __post_init__(self) -> None:
        if not isinstance(self.decision, ConsumptionDecision):
            raise TypeError("decision must be a ConsumptionDecision")
        if not isinstance(self.ledger, CapabilityConsumptionLedger):
            raise TypeError("ledger must be a CapabilityConsumptionLedger")
        try:
            replace(self.decision)
            replace(self.ledger)
        except (TypeError, ValueError) as exc:
            raise ValueError("capability consumption result is invalid") from exc
        if (
            self.decision.next_ledger_ref != self.ledger.ledger_id
            or self.decision._next_ledger is not self.ledger
        ):
            raise ValueError("capability consumption result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "decision": self.decision.to_dict(),
            "ledger": self.ledger.to_dict(),
        }


def evaluate_consumption(
    contract: IssuedCapabilityContract,
    capability_decision: CapabilityDecision,
    confinement_decision: ConfinementDecision,
    ledger: CapabilityConsumptionLedger,
) -> ConsumptionResult:
    """Apply one pure consumption transition to an explicit immutable ledger."""

    if not isinstance(contract, IssuedCapabilityContract):
        raise TypeError("contract must be an IssuedCapabilityContract")
    if not isinstance(capability_decision, CapabilityDecision):
        raise TypeError("capability_decision must be a CapabilityDecision")
    if not isinstance(confinement_decision, ConfinementDecision):
        raise TypeError("confinement_decision must be a ConfinementDecision")
    if not isinstance(ledger, CapabilityConsumptionLedger):
        raise TypeError("ledger must be a CapabilityConsumptionLedger")
    if not _axis_context_is_admissible(
        contract,
        capability_decision,
        confinement_decision,
    ):
        raise ConsumptionLedgerDenied("capability_use_is_not_admissible")
    try:
        replace(ledger)
    except (TypeError, ValueError) as exc:
        raise ConsumptionLedgerDenied("capability_use_is_not_admissible") from exc

    consumed = _consumed_entries(contract, ledger)
    key = confinement_decision.decision_id
    if any(entry.presentation_ref == key for entry in consumed):
        outcome = ConsumptionOutcome.REPLAYED_PRESENTATION
        next_ledger = ledger
    elif len(consumed) >= contract.max_uses:
        outcome = ConsumptionOutcome.CAPABILITY_ALREADY_CONSUMED
        next_ledger = ledger
    else:
        outcome = ConsumptionOutcome.FIRST_CONSUMPTION
        entry = ConsumptionEntry.build(
            contract=contract,
            capability_decision=capability_decision,
            confinement_decision=confinement_decision,
            use_slot=len(consumed),
        )
        next_ledger = ledger.with_entry(entry)

    decision = ConsumptionDecision.build(
        contract=contract,
        capability_decision=capability_decision,
        confinement_decision=confinement_decision,
        prior_ledger=ledger,
        next_ledger=next_ledger,
        outcome=outcome,
    )
    return ConsumptionResult(decision=decision, ledger=next_ledger)


__all__ = [
    "CAPABILITY_CONSUMPTION_LEDGER_MODE",
    "CapabilityConsumptionLedger",
    "ConsumptionDecision",
    "ConsumptionEntry",
    "ConsumptionLedgerDenied",
    "ConsumptionOutcome",
    "ConsumptionResult",
    "evaluate_consumption",
]
