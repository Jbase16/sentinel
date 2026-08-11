"""Passive, evidence-backed prerequisite constraint learning.

This module consumes response material that has already been acquired.  It never
performs target I/O and it deliberately separates machine-readable facts from
untrusted textual hints.  The resulting ledger is content-addressed so a later
replanner can prove exactly which evidence changed a plan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .compiler import Capability, CapabilityKind, value_capability_for_field_path
from .normalize import stable_hash


CONSTRAINT_LEDGER_MODE = "constraint_learning_analysis_only"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_.:-]{0,191}$")
_PYDANTIC_MISSING_TYPES = frozenset({"missing", "value_error.missing"})


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _semantic(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a bounded semantic value")
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    normalized = re.sub(r"[^a-z0-9_.:-]+", "_", separated.lower()).strip("_")
    if not normalized or _SEMANTIC.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a bounded semantic value")
    return normalized


def _capability_payload(value: Capability) -> Dict[str, str]:
    if not isinstance(value, Capability):
        raise TypeError("required_capability must be a Capability")
    return value.to_dict()


class ConstraintKind(str, Enum):
    REQUIRED_FIELD = "required_field"
    PARENT_RESOURCE = "parent_resource"
    MEMBERSHIP = "membership"
    ROLE = "role"
    LIFECYCLE_STATE = "lifecycle_state"
    CSRF_CONTEXT = "csrf_context"
    SESSION_CONTEXT = "session_context"
    SERVER_CAPABILITY = "server_capability"


class ConstraintSignalSource(str, Enum):
    STRUCTURED_RESPONSE = "structured_response"
    UNTRUSTED_TEXT_HINT = "untrusted_text_hint"
    INDEPENDENT_CONTROL = "independent_control"


class ConstraintTruth(str, Enum):
    HYPOTHESIS = "hypothesis"
    FACT = "fact"


class ConstraintBasis(str, Enum):
    STRUCTURED_RESPONSE = "structured_response"
    CORROBORATED_CONTROL = "corroborated_control"
    UNTRUSTED_TEXT_HINT = "untrusted_text_hint"


def _signal_payload(
    *,
    operation_id: str,
    kind: ConstraintKind,
    key: str,
    required_capability: Capability,
    source: ConstraintSignalSource,
    evidence_ref: str,
    response_status: int,
    schema_ref: Optional[str],
    control_of_signal_id: Optional[str],
) -> Dict[str, Any]:
    return {
        "operation_id": operation_id,
        "kind": kind.value,
        "key": key,
        "required_capability": _capability_payload(required_capability),
        "source": source.value,
        "evidence_ref": evidence_ref,
        "response_status": response_status,
        "schema_ref": schema_ref,
        "control_of_signal_id": control_of_signal_id,
    }


@dataclass(frozen=True)
class ConstraintSignal:
    """One redacted observation about a possible operation prerequisite."""

    signal_id: str
    operation_id: str
    kind: ConstraintKind
    key: str
    required_capability: Capability
    source: ConstraintSignalSource
    evidence_ref: str
    response_status: int
    schema_ref: Optional[str] = None
    control_of_signal_id: Optional[str] = None

    @classmethod
    def structured_failure(
        cls,
        *,
        operation_id: str,
        kind: ConstraintKind,
        key: str,
        required_capability: Capability,
        evidence_ref: str,
        response_status: int,
        schema_ref: str,
    ) -> "ConstraintSignal":
        return cls._build(
            operation_id=operation_id,
            kind=kind,
            key=key,
            required_capability=required_capability,
            source=ConstraintSignalSource.STRUCTURED_RESPONSE,
            evidence_ref=evidence_ref,
            response_status=response_status,
            schema_ref=schema_ref,
            control_of_signal_id=None,
        )

    @classmethod
    def free_text_hint(
        cls,
        *,
        operation_id: str,
        kind: ConstraintKind,
        key: str,
        required_capability: Capability,
        evidence_ref: str,
        response_status: int,
    ) -> "ConstraintSignal":
        """Record an inferred hint without retaining or trusting the raw text."""

        return cls._build(
            operation_id=operation_id,
            kind=kind,
            key=key,
            required_capability=required_capability,
            source=ConstraintSignalSource.UNTRUSTED_TEXT_HINT,
            evidence_ref=evidence_ref,
            response_status=response_status,
            schema_ref=None,
            control_of_signal_id=None,
        )

    @classmethod
    def successful_control(
        cls,
        *,
        failure: "ConstraintSignal",
        evidence_ref: str,
        response_status: int,
    ) -> "ConstraintSignal":
        if not isinstance(failure, ConstraintSignal):
            raise TypeError("failure must be a ConstraintSignal")
        if failure.source is ConstraintSignalSource.INDEPENDENT_CONTROL:
            raise ValueError("a control cannot corroborate another control")
        if evidence_ref == failure.evidence_ref:
            raise ValueError("an independent control requires distinct evidence")
        return cls._build(
            operation_id=failure.operation_id,
            kind=failure.kind,
            key=failure.key,
            required_capability=failure.required_capability,
            source=ConstraintSignalSource.INDEPENDENT_CONTROL,
            evidence_ref=evidence_ref,
            response_status=response_status,
            schema_ref=None,
            control_of_signal_id=failure.signal_id,
        )

    @classmethod
    def _build(
        cls,
        *,
        operation_id: str,
        kind: ConstraintKind,
        key: str,
        required_capability: Capability,
        source: ConstraintSignalSource,
        evidence_ref: str,
        response_status: int,
        schema_ref: Optional[str],
        control_of_signal_id: Optional[str],
    ) -> "ConstraintSignal":
        normalized_operation = _semantic(operation_id, field_name="operation_id")
        normalized_key = _semantic(key, field_name="constraint key")
        payload = _signal_payload(
            operation_id=normalized_operation,
            kind=kind,
            key=normalized_key,
            required_capability=required_capability,
            source=source,
            evidence_ref=evidence_ref,
            response_status=response_status,
            schema_ref=schema_ref,
            control_of_signal_id=control_of_signal_id,
        )
        return cls(
            signal_id=stable_hash("constraint_signal", payload),
            operation_id=normalized_operation,
            kind=kind,
            key=normalized_key,
            required_capability=required_capability,
            source=source,
            evidence_ref=evidence_ref,
            response_status=response_status,
            schema_ref=schema_ref,
            control_of_signal_id=control_of_signal_id,
        )

    def __post_init__(self) -> None:
        payload = _signal_payload(
            operation_id=self.operation_id,
            kind=self.kind,
            key=self.key,
            required_capability=self.required_capability,
            source=self.source,
            evidence_ref=self.evidence_ref,
            response_status=self.response_status,
            schema_ref=self.schema_ref,
            control_of_signal_id=self.control_of_signal_id,
        )
        structured = self.source is ConstraintSignalSource.STRUCTURED_RESPONSE
        control = self.source is ConstraintSignalSource.INDEPENDENT_CONTROL
        hint = self.source is ConstraintSignalSource.UNTRUSTED_TEXT_HINT
        if (
            self.signal_id != stable_hash("constraint_signal", payload)
            or _SEMANTIC.fullmatch(self.operation_id) is None
            or _SEMANTIC.fullmatch(self.key) is None
            or not isinstance(self.kind, ConstraintKind)
            or not isinstance(self.source, ConstraintSignalSource)
            or not _hash_ref(self.evidence_ref)
            or isinstance(self.response_status, bool)
            or not isinstance(self.response_status, int)
            or not 100 <= self.response_status <= 599
            or (structured and not 400 <= self.response_status <= 499)
            or (hint and not 400 <= self.response_status <= 599)
            or (structured != (self.schema_ref is not None))
            or (self.schema_ref is not None and not _hash_ref(self.schema_ref, "constraint_schema"))
            or (control and not 200 <= self.response_status <= 399)
            or (control != (self.control_of_signal_id is not None))
            or (
                self.control_of_signal_id is not None
                and not _hash_ref(self.control_of_signal_id, "constraint_signal")
            )
        ):
            raise ValueError("constraint signal contract is invalid")

    @property
    def assertion_id(self) -> str:
        return stable_hash(
            "constraint_assertion",
            {
                "operation_id": self.operation_id,
                "kind": self.kind.value,
                "key": self.key,
                "required_capability": self.required_capability.to_dict(),
            },
        )

    @property
    def dimension_id(self) -> str:
        return stable_hash(
            "constraint_dimension",
            {
                "operation_id": self.operation_id,
                "kind": self.kind.value,
                "key": self.key,
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "assertion_id": self.assertion_id,
            "dimension_id": self.dimension_id,
            **_signal_payload(
                operation_id=self.operation_id,
                kind=self.kind,
                key=self.key,
                required_capability=self.required_capability,
                source=self.source,
                evidence_ref=self.evidence_ref,
                response_status=self.response_status,
                schema_ref=self.schema_ref,
                control_of_signal_id=self.control_of_signal_id,
            ),
        }


def _constraint_payload(
    *,
    assertion_id: str,
    dimension_id: str,
    operation_id: str,
    kind: ConstraintKind,
    key: str,
    required_capability: Capability,
    truth: ConstraintTruth,
    basis: ConstraintBasis,
    signal_ids: Sequence[str],
    evidence_refs: Sequence[str],
) -> Dict[str, Any]:
    return {
        "assertion_id": assertion_id,
        "dimension_id": dimension_id,
        "operation_id": operation_id,
        "kind": kind.value,
        "key": key,
        "required_capability": required_capability.to_dict(),
        "truth": truth.value,
        "basis": basis.value,
        "signal_ids": list(signal_ids),
        "evidence_refs": list(evidence_refs),
    }


@dataclass(frozen=True)
class PrerequisiteConstraint:
    """A content-addressed hypothesis or fact derived from one assertion."""

    constraint_id: str
    assertion_id: str
    dimension_id: str
    operation_id: str
    kind: ConstraintKind
    key: str
    required_capability: Capability
    truth: ConstraintTruth
    basis: ConstraintBasis
    signal_ids: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        signals: Sequence[ConstraintSignal],
        truth: ConstraintTruth,
        basis: ConstraintBasis,
    ) -> "PrerequisiteConstraint":
        values = tuple(sorted(set(signals), key=lambda item: item.signal_id))
        if not values:
            raise ValueError("a prerequisite constraint requires evidence")
        first = values[0]
        if any(item.assertion_id != first.assertion_id for item in values):
            raise ValueError("constraint signals must describe one assertion")
        signal_ids = tuple(item.signal_id for item in values)
        evidence_refs = tuple(sorted({item.evidence_ref for item in values}))
        payload = _constraint_payload(
            assertion_id=first.assertion_id,
            dimension_id=first.dimension_id,
            operation_id=first.operation_id,
            kind=first.kind,
            key=first.key,
            required_capability=first.required_capability,
            truth=truth,
            basis=basis,
            signal_ids=signal_ids,
            evidence_refs=evidence_refs,
        )
        return cls(
            constraint_id=stable_hash("prerequisite_constraint", payload),
            assertion_id=first.assertion_id,
            dimension_id=first.dimension_id,
            operation_id=first.operation_id,
            kind=first.kind,
            key=first.key,
            required_capability=first.required_capability,
            truth=truth,
            basis=basis,
            signal_ids=signal_ids,
            evidence_refs=evidence_refs,
        )

    def __post_init__(self) -> None:
        payload = _constraint_payload(
            assertion_id=self.assertion_id,
            dimension_id=self.dimension_id,
            operation_id=self.operation_id,
            kind=self.kind,
            key=self.key,
            required_capability=self.required_capability,
            truth=self.truth,
            basis=self.basis,
            signal_ids=self.signal_ids,
            evidence_refs=self.evidence_refs,
        )
        expected_truth = (
            ConstraintTruth.HYPOTHESIS
            if self.basis is ConstraintBasis.UNTRUSTED_TEXT_HINT
            else ConstraintTruth.FACT
        )
        if (
            self.constraint_id != stable_hash("prerequisite_constraint", payload)
            or not _hash_ref(self.assertion_id, "constraint_assertion")
            or not _hash_ref(self.dimension_id, "constraint_dimension")
            or _SEMANTIC.fullmatch(self.operation_id) is None
            or _SEMANTIC.fullmatch(self.key) is None
            or not isinstance(self.kind, ConstraintKind)
            or not isinstance(self.truth, ConstraintTruth)
            or not isinstance(self.basis, ConstraintBasis)
            or self.truth is not expected_truth
            or not self.signal_ids
            or self.signal_ids != tuple(sorted(set(self.signal_ids)))
            or any(not _hash_ref(item, "constraint_signal") for item in self.signal_ids)
            or not self.evidence_refs
            or self.evidence_refs != tuple(sorted(set(self.evidence_refs)))
            or any(not _hash_ref(item) for item in self.evidence_refs)
        ):
            raise ValueError("prerequisite constraint contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            **_constraint_payload(
                assertion_id=self.assertion_id,
                dimension_id=self.dimension_id,
                operation_id=self.operation_id,
                kind=self.kind,
                key=self.key,
                required_capability=self.required_capability,
                truth=self.truth,
                basis=self.basis,
                signal_ids=self.signal_ids,
                evidence_refs=self.evidence_refs,
            ),
        }


@dataclass(frozen=True)
class ConstraintExtractionLimits:
    max_body_bytes: int = 262_144
    max_issues: int = 64
    max_path_segments: int = 16

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ConstraintExtractionResult:
    extraction_id: str
    operation_id: str
    response_ref: str
    response_status: int
    signals: Tuple[ConstraintSignal, ...]
    blockers: Tuple[str, ...]

    @classmethod
    def build(
        cls,
        *,
        operation_id: str,
        response_ref: str,
        response_status: int,
        signals: Sequence[ConstraintSignal],
        blockers: Sequence[str],
    ) -> "ConstraintExtractionResult":
        signal_values = tuple(sorted(set(signals), key=lambda item: item.signal_id))
        blocker_values = tuple(sorted(set(blockers)))
        payload = {
            "mode": CONSTRAINT_LEDGER_MODE,
            "operation_id": operation_id,
            "response_ref": response_ref,
            "response_status": response_status,
            "signals": [item.to_dict() for item in signal_values],
            "blockers": list(blocker_values),
        }
        return cls(
            extraction_id=stable_hash("constraint_extraction", payload),
            operation_id=operation_id,
            response_ref=response_ref,
            response_status=response_status,
            signals=signal_values,
            blockers=blocker_values,
        )

    def __post_init__(self) -> None:
        payload = {
            "mode": CONSTRAINT_LEDGER_MODE,
            "operation_id": self.operation_id,
            "response_ref": self.response_ref,
            "response_status": self.response_status,
            "signals": [item.to_dict() for item in self.signals],
            "blockers": list(self.blockers),
        }
        if (
            self.extraction_id != stable_hash("constraint_extraction", payload)
            or _SEMANTIC.fullmatch(self.operation_id) is None
            or not _hash_ref(self.response_ref)
            or isinstance(self.response_status, bool)
            or not isinstance(self.response_status, int)
            or not 100 <= self.response_status <= 599
            or self.signals != tuple(sorted(set(self.signals), key=lambda item: item.signal_id))
            or any(item.operation_id != self.operation_id for item in self.signals)
            or any(
                item.source is not ConstraintSignalSource.STRUCTURED_RESPONSE
                or item.evidence_ref != self.response_ref
                or item.response_status != self.response_status
                for item in self.signals
            )
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.blockers)
        ):
            raise ValueError("constraint extraction result contract is invalid")

    @property
    def status(self) -> str:
        if self.blockers:
            return "blocked"
        return "observed" if self.signals else "unconfirmed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": CONSTRAINT_LEDGER_MODE,
            "status": self.status,
            "extraction_id": self.extraction_id,
            "operation_id": self.operation_id,
            "response_ref": self.response_ref,
            "response_status": self.response_status,
            "signals": [item.to_dict() for item in self.signals],
            "blockers": list(self.blockers),
        }


class StructuredConstraintExtractor:
    """Extract only explicitly structured prerequisite failures from acquired JSON."""

    def __init__(
        self,
        limits: ConstraintExtractionLimits = ConstraintExtractionLimits(),
    ) -> None:
        if not isinstance(limits, ConstraintExtractionLimits):
            raise TypeError("limits must be ConstraintExtractionLimits")
        self.limits = limits

    def extract(
        self,
        *,
        operation_id: str,
        response_status: int,
        response_body: Any,
        response_ref: str,
    ) -> ConstraintExtractionResult:
        normalized_operation = _semantic(operation_id, field_name="operation_id")
        if not _hash_ref(response_ref):
            raise ValueError("response_ref must be a content-addressed reference")
        if (
            isinstance(response_status, bool)
            or not isinstance(response_status, int)
            or not 100 <= response_status <= 599
        ):
            raise ValueError("response_status must be an HTTP status")

        parsed, blocker = self._parse_body(response_body)
        if blocker is not None:
            return ConstraintExtractionResult.build(
                operation_id=normalized_operation,
                response_ref=response_ref,
                response_status=response_status,
                signals=(),
                blockers=(blocker,),
            )
        if not 400 <= response_status <= 499:
            return ConstraintExtractionResult.build(
                operation_id=normalized_operation,
                response_ref=response_ref,
                response_status=response_status,
                signals=(),
                blockers=("structured_failure_status_invalid",),
            )

        signals = []
        issues_seen = 0
        truncated = False
        detail = parsed.get("detail") if isinstance(parsed, Mapping) else None
        if isinstance(detail, Sequence) and not isinstance(detail, (str, bytes, bytearray)):
            schema_ref = stable_hash(
                "constraint_schema",
                {"adapter": "pydantic_missing", "version": 1},
            )
            for issue in detail:
                issues_seen += 1
                if issues_seen > self.limits.max_issues:
                    truncated = True
                    break
                signal = self._pydantic_signal(
                    operation_id=normalized_operation,
                    response_status=response_status,
                    response_ref=response_ref,
                    schema_ref=schema_ref,
                    issue=issue,
                )
                if signal is not None:
                    signals.append(signal)

        blockers = []
        if truncated:
            blockers.append("constraint_issue_limit_exceeded")
        if not signals and not blockers:
            blockers.append("no_structured_constraint_evidence")
        return ConstraintExtractionResult.build(
            operation_id=normalized_operation,
            response_ref=response_ref,
            response_status=response_status,
            signals=signals,
            blockers=blockers,
        )

    def _parse_body(self, body: Any) -> Tuple[Mapping[str, Any], Optional[str]]:
        if isinstance(body, Mapping):
            try:
                encoded = json.dumps(
                    body,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            except (TypeError, ValueError, RecursionError):
                return {}, "structured_response_invalid"
            if len(encoded) > self.limits.max_body_bytes:
                return {}, "constraint_body_limit_exceeded"
            return body, None
        if isinstance(body, (bytes, bytearray)):
            if len(body) > self.limits.max_body_bytes:
                return {}, "constraint_body_limit_exceeded"
            try:
                text = bytes(body).decode("utf-8")
            except UnicodeDecodeError:
                return {}, "structured_response_invalid"
        elif isinstance(body, str):
            if len(body.encode("utf-8", errors="replace")) > self.limits.max_body_bytes:
                return {}, "constraint_body_limit_exceeded"
            text = body
        else:
            return {}, "structured_response_invalid"
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError, RecursionError):
            return {}, "untrusted_free_text_only"
        if not isinstance(parsed, Mapping):
            return {}, "structured_response_invalid"
        return parsed, None

    def _pydantic_signal(
        self,
        *,
        operation_id: str,
        response_status: int,
        response_ref: str,
        schema_ref: str,
        issue: Any,
    ) -> Optional[ConstraintSignal]:
        if not isinstance(issue, Mapping) or issue.get("type") not in _PYDANTIC_MISSING_TYPES:
            return None
        path = self._path(issue.get("loc"))
        if path is None:
            return None
        capability = value_capability_for_field_path(path) or Capability(
            CapabilityKind.VALUE,
            path[-1],
        )
        return ConstraintSignal.structured_failure(
            operation_id=operation_id,
            kind=ConstraintKind.REQUIRED_FIELD,
            key=".".join(path),
            required_capability=capability,
            evidence_ref=response_ref,
            response_status=response_status,
            schema_ref=schema_ref,
        )

    def _path(self, value: Any) -> Optional[Tuple[str, ...]]:
        if (
            not isinstance(value, Sequence)
            or isinstance(value, (str, bytes, bytearray))
            or not value
            or len(value) > self.limits.max_path_segments
            or any(not isinstance(item, str) or not item.strip() for item in value)
        ):
            return None
        try:
            return tuple(_semantic(item, field_name="constraint path") for item in value)
        except ValueError:
            return None


@dataclass(frozen=True)
class ConstraintLedgerLimits:
    max_signals: int = 4_096
    max_constraints: int = 2_048

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ConstraintLedgerDiagnostics:
    input_signals: int
    unique_signals: int
    retained_signals: int
    fact_constraints: int
    hypothesis_constraints: int
    structured_facts: int
    corroborated_facts: int
    dropped_signals: int
    duplicate_signals: int
    dropped_constraints: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("constraint ledger diagnostics must be non-negative integers")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _ledger_payload(
    *,
    signals: Sequence[ConstraintSignal],
    constraints: Sequence[PrerequisiteConstraint],
    blockers: Sequence[str],
    diagnostics: ConstraintLedgerDiagnostics,
) -> Dict[str, Any]:
    return {
        "mode": CONSTRAINT_LEDGER_MODE,
        "signals": [item.to_dict() for item in signals],
        "constraints": [item.to_dict() for item in constraints],
        "blockers": list(blockers),
        "diagnostics": diagnostics.to_dict(),
    }


@dataclass(frozen=True)
class ConstraintLedger:
    ledger_id: str
    signals: Tuple[ConstraintSignal, ...]
    constraints: Tuple[PrerequisiteConstraint, ...]
    blockers: Tuple[str, ...]
    diagnostics: ConstraintLedgerDiagnostics
    mode: str = CONSTRAINT_LEDGER_MODE

    def __post_init__(self) -> None:
        payload = _ledger_payload(
            signals=self.signals,
            constraints=self.constraints,
            blockers=self.blockers,
            diagnostics=self.diagnostics,
        )
        facts = sum(item.truth is ConstraintTruth.FACT for item in self.constraints)
        hypotheses = len(self.constraints) - facts
        if (
            self.mode != CONSTRAINT_LEDGER_MODE
            or self.ledger_id != stable_hash("constraint_ledger", payload)
            or self.signals != tuple(sorted(set(self.signals), key=lambda item: item.signal_id))
            or self.constraints
            != tuple(sorted(set(self.constraints), key=lambda item: item.constraint_id))
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_SEMANTIC.fullmatch(item) is None for item in self.blockers)
            or self.diagnostics.retained_signals != len(self.signals)
            or self.diagnostics.unique_signals < self.diagnostics.retained_signals
            or self.diagnostics.input_signals < self.diagnostics.unique_signals
            or self.diagnostics.dropped_signals
            != self.diagnostics.unique_signals - self.diagnostics.retained_signals
            or self.diagnostics.duplicate_signals
            != self.diagnostics.input_signals - self.diagnostics.unique_signals
            or self.diagnostics.fact_constraints != facts
            or self.diagnostics.hypothesis_constraints != hypotheses
            or self.diagnostics.structured_facts
            != sum(
                item.basis is ConstraintBasis.STRUCTURED_RESPONSE
                for item in self.constraints
            )
            or self.diagnostics.corroborated_facts
            != sum(
                item.basis is ConstraintBasis.CORROBORATED_CONTROL
                for item in self.constraints
            )
        ):
            raise ValueError("constraint ledger contract is invalid")

    @property
    def status(self) -> str:
        if self.blockers:
            return "blocked"
        if self.facts:
            return "ready"
        return "hypotheses_only" if self.hypotheses else "empty"

    @property
    def facts(self) -> Tuple[PrerequisiteConstraint, ...]:
        return tuple(item for item in self.constraints if item.truth is ConstraintTruth.FACT)

    @property
    def hypotheses(self) -> Tuple[PrerequisiteConstraint, ...]:
        return tuple(
            item for item in self.constraints if item.truth is ConstraintTruth.HYPOTHESIS
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "ledger_id": self.ledger_id,
            **_ledger_payload(
                signals=self.signals,
                constraints=self.constraints,
                blockers=self.blockers,
                diagnostics=self.diagnostics,
            ),
        }


class ConstraintLedgerBuilder:
    """Promote only structured or independently corroborated signals to facts."""

    def __init__(self, limits: ConstraintLedgerLimits = ConstraintLedgerLimits()) -> None:
        if not isinstance(limits, ConstraintLedgerLimits):
            raise TypeError("limits must be ConstraintLedgerLimits")
        self.limits = limits

    def build(
        self,
        signals: Sequence[ConstraintSignal] = (),
        *,
        extractions: Sequence[ConstraintExtractionResult] = (),
    ) -> ConstraintLedger:
        values = list(signals)
        blockers = set()
        for extraction in extractions:
            if not isinstance(extraction, ConstraintExtractionResult):
                raise TypeError("extractions must contain ConstraintExtractionResult values")
            values.extend(extraction.signals)
            blockers.update(extraction.blockers)
        if any(not isinstance(item, ConstraintSignal) for item in values):
            raise TypeError("signals must contain ConstraintSignal values")

        input_signals = len(values)
        unique = tuple(sorted(set(values), key=lambda item: item.signal_id))
        dropped_signals = max(0, len(unique) - self.limits.max_signals)
        retained = unique[: self.limits.max_signals]
        if dropped_signals:
            blockers.add("constraint_signal_limit_exceeded")

        by_id = {item.signal_id: item for item in retained}
        controls = tuple(
            item
            for item in retained
            if item.source is ConstraintSignalSource.INDEPENDENT_CONTROL
        )
        failures = tuple(
            item
            for item in retained
            if item.source is not ConstraintSignalSource.INDEPENDENT_CONTROL
        )
        valid_controls: Dict[str, list[ConstraintSignal]] = {}
        for control in controls:
            failure = by_id.get(control.control_of_signal_id or "")
            if failure is None:
                blockers.add("orphaned_control_evidence")
                continue
            if (
                failure.source is ConstraintSignalSource.INDEPENDENT_CONTROL
                or failure.assertion_id != control.assertion_id
                or failure.evidence_ref == control.evidence_ref
            ):
                blockers.add("mismatched_control_evidence")
                continue
            valid_controls.setdefault(failure.signal_id, []).append(control)

        grouped: Dict[str, list[ConstraintSignal]] = {}
        for failure in failures:
            grouped.setdefault(failure.assertion_id, []).append(failure)

        constraints = []
        for assertion_id in sorted(grouped):
            group = tuple(sorted(grouped[assertion_id], key=lambda item: item.signal_id))
            corroborating = tuple(
                sorted(
                    (
                        control
                        for failure in group
                        for control in valid_controls.get(failure.signal_id, ())
                    ),
                    key=lambda item: item.signal_id,
                )
            )
            evidence = (*group, *corroborating)
            if any(
                item.source is ConstraintSignalSource.STRUCTURED_RESPONSE for item in group
            ):
                truth = ConstraintTruth.FACT
                basis = ConstraintBasis.STRUCTURED_RESPONSE
            elif corroborating:
                truth = ConstraintTruth.FACT
                basis = ConstraintBasis.CORROBORATED_CONTROL
            else:
                truth = ConstraintTruth.HYPOTHESIS
                basis = ConstraintBasis.UNTRUSTED_TEXT_HINT
            constraints.append(
                PrerequisiteConstraint.build(
                    signals=evidence,
                    truth=truth,
                    basis=basis,
                )
            )

        constraints.sort(key=lambda item: item.constraint_id)
        dropped_constraints = max(0, len(constraints) - self.limits.max_constraints)
        constraints = constraints[: self.limits.max_constraints]
        if dropped_constraints:
            blockers.add("constraint_count_limit_exceeded")

        fact_dimensions: Dict[str, set[str]] = {}
        for constraint in constraints:
            if constraint.truth is ConstraintTruth.FACT:
                fact_dimensions.setdefault(constraint.dimension_id, set()).add(
                    constraint.required_capability.key
                )
        if any(len(values) > 1 for values in fact_dimensions.values()):
            blockers.add("contradictory_constraints")

        structured_facts = sum(
            item.basis is ConstraintBasis.STRUCTURED_RESPONSE for item in constraints
        )
        corroborated_facts = sum(
            item.basis is ConstraintBasis.CORROBORATED_CONTROL for item in constraints
        )
        fact_constraints = sum(
            item.truth is ConstraintTruth.FACT for item in constraints
        )
        diagnostics = ConstraintLedgerDiagnostics(
            input_signals=input_signals,
            unique_signals=len(unique),
            retained_signals=len(retained),
            fact_constraints=fact_constraints,
            hypothesis_constraints=len(constraints) - fact_constraints,
            structured_facts=structured_facts,
            corroborated_facts=corroborated_facts,
            dropped_signals=dropped_signals,
            duplicate_signals=input_signals - len(unique),
            dropped_constraints=dropped_constraints,
        )
        signal_values = tuple(retained)
        constraint_values = tuple(constraints)
        blocker_values = tuple(sorted(blockers))
        payload = _ledger_payload(
            signals=signal_values,
            constraints=constraint_values,
            blockers=blocker_values,
            diagnostics=diagnostics,
        )
        return ConstraintLedger(
            ledger_id=stable_hash("constraint_ledger", payload),
            signals=signal_values,
            constraints=constraint_values,
            blockers=blocker_values,
            diagnostics=diagnostics,
        )


__all__ = [
    "CONSTRAINT_LEDGER_MODE",
    "ConstraintBasis",
    "ConstraintExtractionLimits",
    "ConstraintExtractionResult",
    "ConstraintKind",
    "ConstraintLedger",
    "ConstraintLedgerBuilder",
    "ConstraintLedgerDiagnostics",
    "ConstraintLedgerLimits",
    "ConstraintSignal",
    "ConstraintSignalSource",
    "ConstraintTruth",
    "PrerequisiteConstraint",
    "StructuredConstraintExtractor",
]
