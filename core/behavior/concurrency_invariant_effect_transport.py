"""R5F7: default-off, bounded concurrency-effect transport over an injected client.

Phase 2 exercises a production-shaped, admission-gated (default-off),
origin-confined transport with verified compensating cleanup, through an
injected client against a controlled owned target. It is not evidence of an
effect against a live running target, it is not wired into any production
caller, and it carries no finding-promotion or durable-receipt authority and
no OCB-S22/native claim.

Origin confinement is self-referential to the declared authorized origin; proving that origin belongs to the owned target this binding represents is deferred to F8 (the real client + Foundry composition against the real owned target), exactly as E's real target binding was established only at E8.

The client is supplied by the caller. This module opens no connection and
grants no target scope, receipt, finding, or promotion authority. A target's
cleanup report is checked against the original resource state; it is not
independent live proof.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from .concurrency_invariant_binding import (
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
    validate_current_capture,
)
from .concurrency_invariant_contract import (
    MAX_CONCURRENCY_OPERATIONS,
    MAX_SCHEDULE_STEPS,
    ConcurrencyOperation,
    MicroStep,
    StepKind,
    WorkflowSchedule,
    _fields,
    _hash_ref,
    _integer,
    _passive_flags,
    _revalidate,
)
from .concurrency_invariant_effect import (
    ConcurrencyEffectEvidence,
    ConcurrencyEffectResult,
    ConcurrencyObservedResponse,
    ConcurrencyObservedState,
    ConcurrencyObservedStatus,
    run_concurrency_effect,
)
from .concurrency_invariant_ledger import ConcurrencyScheduleLedger, evaluate_schedule
from .normalize import stable_hash

CONCURRENCY_EFFECT_EXECUTION_ENV = "SENTINELFORGE_BEHAVIOR_CONCURRENCY_EFFECT_EXECUTION"
CONCURRENCY_EFFECT_EXECUTION_MODE = "behavioral_concurrency_effect_execution_v1"
_TRUE = frozenset({"1", "true", "yes", "on"})


def _canonical_origin(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(character.isspace() or character == "\\" for character in value)
    ):
        raise ValueError("concurrency effect target origin is invalid")
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("concurrency effect target origin is invalid")
        parsed.port  # Reject an invalid port before any dispatch.
    except ValueError as exc:
        raise ValueError("concurrency effect target origin is invalid") from exc
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _endpoint(value: object, origin: str) -> tuple[str, str, str]:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(character.isspace() or character == "\\" for character in value)
    ):
        raise ValueError("concurrency effect target url is invalid")
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or _canonical_origin(f"{parsed.scheme}://{parsed.netloc}") != origin
        ):
            raise ValueError(
                "concurrency effect url leaves the authorized target origin"
            )
        parsed.port
    except ValueError as exc:
        raise ValueError(
            "concurrency effect url leaves the authorized target origin"
        ) from exc
    return origin, parsed.path or "/", parsed.query


@dataclass(frozen=True)
class ConcurrencyEffectExecutionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("concurrency effect execution gate is invalid")

    @classmethod
    def from_environment(cls) -> ConcurrencyEffectExecutionConfig:
        return cls(
            os.environ.get(CONCURRENCY_EFFECT_EXECUTION_ENV, "").strip().lower()
            in _TRUE
        )

    @property
    def config_id(self) -> str:
        return stable_hash(
            "concurrency_effect_execution_config", {"enabled": self.enabled}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "config_id": self.config_id,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEffectExecutionConfig:
        value = _fields(value, {"config_id", "enabled"})
        result = cls(value["enabled"])
        if value["config_id"] != result.config_id:
            raise ValueError("concurrency_effect_execution_config_address_mismatch")
        return result


@dataclass(frozen=True)
class ConcurrencyEffectTransportSpec:
    binding_ref: str
    target_origin: str
    operation_urls: tuple[str, ...]
    cleanup_url: str

    def __post_init__(self) -> None:
        origin = _canonical_origin(self.target_origin)
        if (
            origin != self.target_origin
            or not _hash_ref(self.binding_ref, "concurrency_invariant_binding")
            or type(self.operation_urls) is not tuple
            or not 2 <= len(self.operation_urls) <= MAX_CONCURRENCY_OPERATIONS
        ):
            raise ValueError("concurrency effect transport specification is invalid")
        operations = tuple(_endpoint(url, origin) for url in self.operation_urls)
        if _endpoint(self.cleanup_url, origin) in operations:
            raise ValueError("concurrency effect cleanup endpoint must be distinct")

    def _payload(self) -> dict[str, Any]:
        return {
            "binding_ref": self.binding_ref,
            "target_origin": self.target_origin,
            "operation_urls": list(self.operation_urls),
            "cleanup_url": self.cleanup_url,
        }

    @property
    def specification_id(self) -> str:
        return stable_hash(
            "concurrency_effect_transport_specification", self._payload()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "specification_id": self.specification_id,
            **self._payload(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEffectTransportSpec:
        value = _fields(
            value,
            {
                "specification_id",
                "binding_ref",
                "target_origin",
                "operation_urls",
                "cleanup_url",
            },
        )
        if type(value["operation_urls"]) is not list:
            raise ValueError("concurrency effect transport specification is invalid")
        result = cls(
            value["binding_ref"],
            value["target_origin"],
            tuple(value["operation_urls"]),
            value["cleanup_url"],
        )
        if value["specification_id"] != result.specification_id:
            raise ValueError(
                "concurrency_effect_transport_specification_address_mismatch"
            )
        return result


class ConcurrencyEffectClient(Protocol):
    """Injected request/response seam; a real client is a separately gated slice."""

    def issue(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ConcurrencyEffectTransport:
    """F6 ConcurrencyTransport; one confined request per logical micro-step.

    The injected owned target records an OBSERVE snapshot and enforces its own
    guard/CAS rule on COMMIT. OBSERVE acknowledgments never enter the F6 model.
    """

    def __init__(
        self, spec: ConcurrencyEffectTransportSpec, client: ConcurrencyEffectClient
    ):
        if type(spec) is not ConcurrencyEffectTransportSpec:
            raise ValueError("concurrency effect transport specification is invalid")
        _revalidate(spec)
        if not callable(getattr(client, "issue", None)):
            raise ValueError("concurrency effect client is invalid")
        self.spec = spec
        self.client = client
        self.steps_walked = 0
        self.commit_requests_attempted = 0
        self.cleanup_attempts = 0
        self.url_by_ref: dict[str, str] | None = None
        self._operations_by_ref: dict[str, ConcurrencyOperation] | None = None
        self._observed_refs: set[str] = set()
        self._committed_refs: set[str] = set()

    def _bind(self, binding: ConcurrencyInvariantBinding) -> None:
        if (
            type(binding) is not ConcurrencyInvariantBinding
            or binding.binding_id != self.spec.binding_ref
        ):
            raise ValueError("concurrency effect transport binding is invalid")
        operations = binding.fixture.contract.operations
        if len(self.spec.operation_urls) != len(
            operations
        ) or binding.capture.operation_ids != tuple(
            operation.operation_id for operation in operations
        ):
            raise ValueError("concurrency effect transport operations are invalid")
        if self.url_by_ref is None:
            url_by_ref = dict(
                zip(
                    (operation.operation_ref for operation in operations),
                    self.spec.operation_urls,
                )
            )
            if len(url_by_ref) != len(operations):
                raise ValueError("concurrency effect transport operations are invalid")
            self.url_by_ref = url_by_ref
            self._operations_by_ref = {
                operation.operation_ref: operation for operation in operations
            }
        elif self._operations_by_ref != {
            operation.operation_ref: operation for operation in operations
        }:
            raise ValueError("concurrency effect transport binding changed")

    def step(
        self,
        binding: ConcurrencyInvariantBinding,
        micro_step: MicroStep,
        operation: ConcurrencyOperation,
    ) -> ConcurrencyObservedResponse | None:
        _revalidate(self.spec)
        if self.steps_walked >= MAX_SCHEDULE_STEPS:
            raise ValueError("concurrency effect step budget is exhausted")
        index = self.steps_walked
        self.steps_walked += 1
        self._bind(binding)
        if (
            type(micro_step) is not MicroStep
            or type(operation) is not ConcurrencyOperation
            or self.url_by_ref is None
            or self._operations_by_ref is None
            or self.steps_walked > 2 * len(self.url_by_ref)
            or micro_step.operation_ref != operation.operation_ref
            or micro_step.actor_ref != operation.actor_ref
            or self._operations_by_ref.get(operation.operation_ref) != operation
            or operation.operation_ref not in self.url_by_ref
        ):
            raise ValueError("concurrency effect step is not admitted")
        _revalidate(micro_step)
        _revalidate(operation)
        url = self.url_by_ref[operation.operation_ref]
        _endpoint(url, self.spec.target_origin)
        request = {
            "mode": CONCURRENCY_EFFECT_EXECUTION_MODE,
            "kind": micro_step.step_kind.value,
            "method": "POST",
            "url": url,
            "specification_id": self.spec.specification_id,
            "binding_ref": binding.binding_id,
            "operation_ref": operation.operation_ref,
            "operation_id": operation.operation_id,
            "index": index,
            "amount": operation.amount,
        }
        if micro_step.step_kind is StepKind.OBSERVE:
            if operation.operation_ref in self._observed_refs:
                raise ValueError("concurrency effect observe is not admitted")
            self.client.issue(request)
            self._observed_refs.add(operation.operation_ref)
            return None
        if (
            micro_step.step_kind is not StepKind.COMMIT
            or operation.operation_ref not in self._observed_refs
            or operation.operation_ref in self._committed_refs
            or self.commit_requests_attempted >= len(self.url_by_ref)
        ):
            raise ValueError("concurrency effect commit is not admitted")
        self._committed_refs.add(operation.operation_ref)
        self.commit_requests_attempted += 1
        raw = self.client.issue(request)
        expected = {
            "binding_ref",
            "operation_ref",
            "operation_id",
            "index",
            "status",
            "consumed",
            "declared_limit",
        }
        if (
            not isinstance(raw, Mapping)
            or set(raw) != expected
            or raw["index"] != index
        ):
            raise ValueError("concurrency effect commit response is invalid")
        return ConcurrencyObservedResponse(
            binding_ref=raw["binding_ref"],
            operation_ref=raw["operation_ref"],
            operation_id=raw["operation_id"],
            index=index,
            status=ConcurrencyObservedStatus(raw["status"]),
            state=ConcurrencyObservedState(raw["consumed"], raw["declared_limit"]),
        )

    def cleanup(self, binding: ConcurrencyInvariantBinding) -> bool:
        if self.commit_requests_attempted == 0 or self.cleanup_attempts != 0:
            raise ValueError("concurrency effect cleanup is not admitted")
        self.cleanup_attempts += 1
        _revalidate(self.spec)
        if (
            type(binding) is not ConcurrencyInvariantBinding
            or binding.binding_id != self.spec.binding_ref
        ):
            raise ValueError("concurrency effect cleanup binding is invalid")
        _endpoint(self.spec.cleanup_url, self.spec.target_origin)
        initial = binding.fixture.contract.initial_state
        raw = self.client.issue(
            {
                "mode": CONCURRENCY_EFFECT_EXECUTION_MODE,
                "kind": "cleanup",
                "method": "POST",
                "url": self.spec.cleanup_url,
                "specification_id": self.spec.specification_id,
                "binding_ref": binding.binding_id,
                "restore_consumed": initial.consumed,
                "declared_limit": initial.declared_limit,
            }
        )
        expected = {
            "specification_id",
            "binding_ref",
            "cleanup_verified",
            "orphaned_owned_state_possible",
            "consumed",
            "declared_limit",
        }
        return bool(
            isinstance(raw, Mapping)
            and set(raw) == expected
            and raw["specification_id"] == self.spec.specification_id
            and raw["binding_ref"] == binding.binding_id
            and raw["cleanup_verified"] is True
            and raw["orphaned_owned_state_possible"] is False
            and type(raw["consumed"]) is int
            and raw["consumed"] == initial.consumed
            and type(raw["declared_limit"]) is int
            and raw["declared_limit"] == initial.declared_limit
        )


def _rehydrate_effect(value: object, attempts: int) -> ConcurrencyEffectResult:
    if value is None:
        return ConcurrencyEffectResult(attempts)
    evidence_value = _fields(
        value,
        {
            "evidence_id",
            "mode",
            "model",
            "responses",
            "transport_attempts",
            "observed_terminal_state",
            "oracle_outcome",
            "correspondence",
            "race_confirmed",
            "hermetic_fake_target_only",
            "real_concurrency_effect_observed",
            "target_requests_sent",
            "finding_authority",
            "promotion_authority",
            "executable",
        },
    )
    model_value = _fields(
        evidence_value["model"],
        {"result_id", "ledger", "at_index", "decision", *_passive_flags()},
    )
    ledger = ConcurrencyScheduleLedger.from_dict(model_value["ledger"])
    binding = ledger.binding
    schedule = WorkflowSchedule(binding.fixture.contract, ledger.steps)
    model = evaluate_schedule(
        binding, binding.capture, schedule, at_index=model_value["at_index"]
    )
    if model.to_dict() != model_value or type(evidence_value["responses"]) is not list:
        raise ValueError("concurrency effect transport evidence is invalid")
    evidence = ConcurrencyEffectEvidence(
        model,
        tuple(
            ConcurrencyObservedResponse.from_dict(item)
            for item in evidence_value["responses"]
        ),
        attempts,
    )
    if evidence.to_dict() != evidence_value:
        raise ValueError("concurrency_effect_evidence_address_mismatch")
    return ConcurrencyEffectResult(attempts, evidence)


@dataclass(frozen=True)
class ConcurrencyEffectTransportResult:
    admission_gate_enabled: bool
    admitted: bool
    specification_id: str | None
    step_attempts: int
    cleanup_attempts: int
    compensating_cleanup_verified: bool
    effect: ConcurrencyEffectResult

    def __post_init__(self) -> None:
        if (
            type(self.admission_gate_enabled) is not bool
            or type(self.admitted) is not bool
            or type(self.compensating_cleanup_verified) is not bool
            or type(self.effect) is not ConcurrencyEffectResult
            or not _integer(self.step_attempts, 0, MAX_SCHEDULE_STEPS)
            or not _integer(self.cleanup_attempts, 0, 1)
        ):
            raise ValueError("concurrency effect transport result is invalid")
        _revalidate(self.effect)
        if (
            self.effect.transport_attempts != self.step_attempts
            or (self.admitted and not self.admission_gate_enabled)
            or (
                self.admitted
                and not _hash_ref(
                    self.specification_id, "concurrency_effect_transport_specification"
                )
            )
            or (not self.admitted and self.specification_id is not None)
            or (not self.admitted and (self.step_attempts or self.cleanup_attempts))
            or (not self.admitted and self.compensating_cleanup_verified)
            or (self.compensating_cleanup_verified and self.cleanup_attempts != 1)
            or (
                self.effect.evidence is not None
                and not self.compensating_cleanup_verified
            )
        ):
            raise ValueError("concurrency effect transport result is invalid")

    @property
    def evidence(self) -> ConcurrencyEffectEvidence | None:
        return self.effect.evidence

    @property
    def correspondence(self):
        return self.effect.correspondence

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": CONCURRENCY_EFFECT_EXECUTION_MODE,
            "admission_gate_enabled": self.admission_gate_enabled,
            "admitted": self.admitted,
            "specification_id": self.specification_id,
            "target_origin_confined": True,
            "owned_target_origin_bound": False,
            "step_attempts": self.step_attempts,
            "cleanup_attempts": self.cleanup_attempts,
            "compensating_cleanup_verified": self.compensating_cleanup_verified,
            "correspondence": self.correspondence.value,
            "effect_evidence": self.evidence.to_dict() if self.evidence else None,
            "real_concurrency_effect_observed": False,
            "wired_into_production": False,
            "finding_authority": False,
            "promotion_authority": False,
        }

    @property
    def result_id(self) -> str:
        return stable_hash("concurrency_effect_transport_result", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "result_id": self.result_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEffectTransportResult:
        value = _fields(
            value,
            {
                "result_id",
                "mode",
                "admission_gate_enabled",
                "admitted",
                "specification_id",
                "target_origin_confined",
                "owned_target_origin_bound",
                "step_attempts",
                "cleanup_attempts",
                "compensating_cleanup_verified",
                "correspondence",
                "effect_evidence",
                "real_concurrency_effect_observed",
                "wired_into_production",
                "finding_authority",
                "promotion_authority",
            },
        )
        result = cls(
            value["admission_gate_enabled"],
            value["admitted"],
            value["specification_id"],
            value["step_attempts"],
            value["cleanup_attempts"],
            value["compensating_cleanup_verified"],
            _rehydrate_effect(value["effect_evidence"], value["step_attempts"]),
        )
        if value["result_id"] != result.result_id:
            raise ValueError("concurrency_effect_transport_result_address_mismatch")
        if value != result.to_dict():
            raise ValueError("concurrency effect transport result is invalid")
        return result


def run_concurrency_effect_transport(
    spec: ConcurrencyEffectTransportSpec,
    binding: ConcurrencyInvariantBinding,
    current_capture: ConcurrencyCaptureProvenance,
    schedule: WorkflowSchedule,
    client: ConcurrencyEffectClient,
    *,
    config: ConcurrencyEffectExecutionConfig | None = None,
    at_index: int,
) -> ConcurrencyEffectTransportResult:
    """Gate first, confine URLs, run F6 once, then check one cleanup report."""
    try:
        selected = (
            ConcurrencyEffectExecutionConfig.from_environment()
            if config is None
            else config
        )
        if type(selected) is not ConcurrencyEffectExecutionConfig:
            raise ValueError("concurrency effect execution gate is invalid")
        _revalidate(selected)
    except (TypeError, ValueError, AttributeError):
        return ConcurrencyEffectTransportResult(
            False, False, None, 0, 0, False, ConcurrencyEffectResult(0)
        )
    if not selected.enabled:
        return ConcurrencyEffectTransportResult(
            False, False, None, 0, 0, False, ConcurrencyEffectResult(0)
        )
    try:
        if type(spec) is not ConcurrencyEffectTransportSpec:
            raise ValueError("concurrency effect transport specification is invalid")
        _revalidate(spec)
        validate_current_capture(binding, current_capture, at_index)
        if spec.binding_ref != binding.binding_id or len(spec.operation_urls) != len(
            binding.fixture.contract.operations
        ):
            raise ValueError("concurrency effect transport binding is invalid")
        spec = ConcurrencyEffectTransportSpec.from_dict(spec.to_dict())
        transport = ConcurrencyEffectTransport(spec, client)
        transport._bind(binding)
    except Exception:
        return ConcurrencyEffectTransportResult(
            True, False, None, 0, 0, False, ConcurrencyEffectResult(0)
        )
    effect = run_concurrency_effect(
        binding, current_capture, schedule, transport, at_index=at_index
    )
    cleanup_verified = False
    if transport.commit_requests_attempted:
        try:
            cleanup_verified = transport.cleanup(binding)
        except Exception:
            cleanup_verified = False
    if not cleanup_verified:
        effect = ConcurrencyEffectResult(effect.transport_attempts)
    return ConcurrencyEffectTransportResult(
        True,
        True,
        spec.specification_id,
        effect.transport_attempts,
        transport.cleanup_attempts,
        cleanup_verified,
        effect,
    )
