"""R5E7: default-off, bounded workflow-effect transport over an injected client.

Phase 2 exercises a production-shaped, admission-gated (default-off), origin-confined transport with verified compensating cleanup, through an injected client against a controlled owned target. It is not evidence of an effect against a live running workflow, it is not wired into any production caller, and it carries no finding-promotion or durable-receipt authority and no OCB-S21/native claim.

The client is supplied by the caller. This module opens no connection and grants no
target scope, receipt, finding, or promotion authority. A target's cleanup report
is checked against the original resource state; it is not independent live proof.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit

from .normalize import stable_hash
from .workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
    validate_current_capture,
)
from .workflow_invariant_contract import (
    MAX_WORKFLOW_OPERATIONS,
    WorkflowOperation,
    _fields,
    _hash_ref,
    _integer,
    _revalidate,
    classify_sequence,
)
from .workflow_invariant_effect import (
    WorkflowEffectEvidence,
    WorkflowEffectResult,
    WorkflowObservedResponse,
    WorkflowObservedState,
    WorkflowObservedStatus,
    run_workflow_effect,
)
from .workflow_invariant_ledger import WorkflowSequenceResult, WorkflowTransitionLedger

WORKFLOW_EFFECT_EXECUTION_ENV = "SENTINELFORGE_BEHAVIOR_WORKFLOW_EFFECT_EXECUTION"
WORKFLOW_EFFECT_EXECUTION_MODE = "behavioral_workflow_effect_execution_v1"
_TRUE = frozenset({"1", "true", "yes", "on"})


def _canonical_origin(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(character.isspace() or character == "\\" for character in value)
    ):
        raise ValueError("workflow effect target origin is invalid")
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
            raise ValueError("workflow effect target origin is invalid")
        parsed.port  # Reject an invalid port before any dispatch.
    except ValueError as exc:
        raise ValueError("workflow effect target origin is invalid") from exc
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _endpoint(value: object, origin: str) -> tuple[str, str, str]:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(character.isspace() or character == "\\" for character in value)
    ):
        raise ValueError("workflow effect target url is invalid")
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
            raise ValueError("workflow effect url leaves the authorized target origin")
        parsed.port
    except ValueError as exc:
        raise ValueError(
            "workflow effect url leaves the authorized target origin"
        ) from exc
    return origin, parsed.path or "/", parsed.query


@dataclass(frozen=True)
class WorkflowEffectExecutionConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("workflow effect execution gate is invalid")

    @classmethod
    def from_environment(cls) -> WorkflowEffectExecutionConfig:
        return cls(
            os.environ.get(WORKFLOW_EFFECT_EXECUTION_ENV, "").strip().lower() in _TRUE
        )

    @property
    def config_id(self) -> str:
        return stable_hash(
            "workflow_effect_execution_config", {"enabled": self.enabled}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "config_id": self.config_id,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowEffectExecutionConfig:
        value = _fields(value, {"config_id", "enabled"})
        result = cls(value["enabled"])
        if value["config_id"] != result.config_id:
            raise ValueError("workflow_effect_execution_config_address_mismatch")
        return result


@dataclass(frozen=True)
class WorkflowEffectTransportSpec:
    binding_ref: str
    target_origin: str
    operation_urls: tuple[str, ...]
    cleanup_url: str

    def __post_init__(self) -> None:
        origin = _canonical_origin(self.target_origin)
        if (
            origin != self.target_origin
            or not _hash_ref(self.binding_ref, "workflow_invariant_binding")
            or type(self.operation_urls) is not tuple
            or not 1 <= len(self.operation_urls) <= MAX_WORKFLOW_OPERATIONS
        ):
            raise ValueError("workflow effect transport specification is invalid")
        operations = tuple(_endpoint(url, origin) for url in self.operation_urls)
        if _endpoint(self.cleanup_url, origin) in operations:
            raise ValueError("workflow effect cleanup endpoint must be distinct")

    def _payload(self) -> dict[str, Any]:
        return {
            "binding_ref": self.binding_ref,
            "target_origin": self.target_origin,
            "operation_urls": list(self.operation_urls),
            "cleanup_url": self.cleanup_url,
        }

    @property
    def specification_id(self) -> str:
        return stable_hash("workflow_effect_transport_specification", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "specification_id": self.specification_id,
            **self._payload(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowEffectTransportSpec:
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
            raise ValueError("workflow effect transport specification is invalid")
        result = cls(
            value["binding_ref"],
            value["target_origin"],
            tuple(value["operation_urls"]),
            value["cleanup_url"],
        )
        if value["specification_id"] != result.specification_id:
            raise ValueError("workflow_effect_transport_specification_address_mismatch")
        return result


class WorkflowEffectClient(Protocol):
    """Injected request/response seam; a real client is a separately gated slice."""

    def issue(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


class WorkflowEffectTransport:
    """E6 ExecutionTransport; one confined client request per admitted operation."""

    def __init__(self, spec: WorkflowEffectTransportSpec, client: WorkflowEffectClient):
        if type(spec) is not WorkflowEffectTransportSpec:
            raise ValueError("workflow effect transport specification is invalid")
        _revalidate(spec)
        if not callable(getattr(client, "issue", None)):
            raise ValueError("workflow effect client is invalid")
        self.spec = spec
        self.client = client
        self.operation_requests_attempted = 0
        self.cleanup_attempts = 0

    def attempt_operation(
        self, binding: WorkflowInvariantBinding, operation: WorkflowOperation
    ) -> WorkflowObservedResponse:
        _revalidate(self.spec)
        if (
            type(binding) is not WorkflowInvariantBinding
            or type(operation) is not WorkflowOperation
            or binding.binding_id != self.spec.binding_ref
            or not _integer(operation.index, 0, len(self.spec.operation_urls) - 1)
            or operation.index != self.operation_requests_attempted
            or operation.operation_id != binding.capture.operation_ids[operation.index]
            or self.operation_requests_attempted
            >= binding.fixture.contract.max_operations
        ):
            raise ValueError("workflow effect operation is not admitted")
        _revalidate(operation)
        url = self.spec.operation_urls[operation.index]
        _endpoint(url, self.spec.target_origin)
        request = {
            "mode": WORKFLOW_EFFECT_EXECUTION_MODE,
            "kind": "operation",
            "method": "POST",
            "url": url,
            "specification_id": self.spec.specification_id,
            "binding_ref": binding.binding_id,
            "operation_ref": operation.operation_ref,
            "operation_id": operation.operation_id,
            "index": operation.index,
            "amount": operation.amount,
        }
        self.operation_requests_attempted += 1
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
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise ValueError("workflow effect operation response is invalid")
        return WorkflowObservedResponse(
            binding_ref=raw["binding_ref"],
            operation_ref=raw["operation_ref"],
            operation_id=raw["operation_id"],
            index=raw["index"],
            status=WorkflowObservedStatus(raw["status"]),
            state=WorkflowObservedState(raw["consumed"], raw["declared_limit"]),
        )

    def cleanup(self, binding: WorkflowInvariantBinding) -> bool:
        if self.operation_requests_attempted == 0 or self.cleanup_attempts != 0:
            raise ValueError("workflow effect cleanup is not admitted")
        self.cleanup_attempts += 1
        _revalidate(self.spec)
        if (
            type(binding) is not WorkflowInvariantBinding
            or binding.binding_id != self.spec.binding_ref
        ):
            raise ValueError("workflow effect cleanup binding is invalid")
        _endpoint(self.spec.cleanup_url, self.spec.target_origin)
        initial = binding.fixture.contract.initial_state
        raw = self.client.issue(
            {
                "mode": WORKFLOW_EFFECT_EXECUTION_MODE,
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


def _rehydrate_effect(value: object, attempts: int) -> WorkflowEffectResult:
    if value is None:
        return WorkflowEffectResult(attempts)
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
            "hermetic_fake_target_only",
            "real_workflow_effect_observed",
            "target_requests_sent",
            "finding_authority",
            "promotion_authority",
            "executable",
        },
    )
    model_value = _fields(
        evidence_value["model"], {"result_id", "ledger", "at_index", "decision"}
    )
    ledger = WorkflowTransitionLedger.from_dict(model_value["ledger"])
    contract = ledger.binding.fixture.contract
    model = WorkflowSequenceResult(
        ledger,
        model_value["at_index"],
        classify_sequence(contract, contract.initial_state, contract.operations),
    )
    if model.to_dict() != model_value or type(evidence_value["responses"]) is not list:
        raise ValueError("workflow effect transport evidence is invalid")
    evidence = WorkflowEffectEvidence(
        model,
        tuple(
            WorkflowObservedResponse.from_dict(item)
            for item in evidence_value["responses"]
        ),
        attempts,
    )
    if evidence.to_dict() != evidence_value:
        raise ValueError("workflow_effect_evidence_address_mismatch")
    return WorkflowEffectResult(attempts, evidence)


@dataclass(frozen=True)
class WorkflowEffectTransportResult:
    admission_gate_enabled: bool
    admitted: bool
    specification_id: str | None
    operation_attempts: int
    cleanup_attempts: int
    compensating_cleanup_verified: bool
    effect: WorkflowEffectResult

    def __post_init__(self) -> None:
        if (
            type(self.admission_gate_enabled) is not bool
            or type(self.admitted) is not bool
            or type(self.compensating_cleanup_verified) is not bool
            or type(self.effect) is not WorkflowEffectResult
            or not _integer(self.operation_attempts, 0, MAX_WORKFLOW_OPERATIONS)
            or not _integer(self.cleanup_attempts, 0, 1)
        ):
            raise ValueError("workflow effect transport result is invalid")
        _revalidate(self.effect)
        if (
            self.effect.transport_attempts != self.operation_attempts
            or (self.admitted and not self.admission_gate_enabled)
            or (
                self.admitted
                and not _hash_ref(
                    self.specification_id, "workflow_effect_transport_specification"
                )
            )
            or (not self.admitted and self.specification_id is not None)
            or (
                not self.admitted and (self.operation_attempts or self.cleanup_attempts)
            )
            or (not self.admitted and self.compensating_cleanup_verified)
            or (self.compensating_cleanup_verified and self.cleanup_attempts != 1)
            or (
                self.effect.evidence is not None
                and not self.compensating_cleanup_verified
            )
        ):
            raise ValueError("workflow effect transport result is invalid")

    @property
    def evidence(self) -> WorkflowEffectEvidence | None:
        return self.effect.evidence

    @property
    def correspondence(self):
        return self.effect.correspondence

    def _payload(self) -> dict[str, Any]:
        return {
            "mode": WORKFLOW_EFFECT_EXECUTION_MODE,
            "admission_gate_enabled": self.admission_gate_enabled,
            "admitted": self.admitted,
            "specification_id": self.specification_id,
            "target_origin_confined": True,
            "operation_attempts": self.operation_attempts,
            "cleanup_attempts": self.cleanup_attempts,
            "compensating_cleanup_verified": self.compensating_cleanup_verified,
            "correspondence": self.correspondence.value,
            "effect_evidence": self.evidence.to_dict() if self.evidence else None,
            "real_workflow_effect_observed": False,
            "wired_into_production": False,
            "finding_authority": False,
            "promotion_authority": False,
        }

    @property
    def result_id(self) -> str:
        return stable_hash("workflow_effect_transport_result", self._payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "result_id": self.result_id, **self._payload()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowEffectTransportResult:
        value = _fields(
            value,
            {
                "result_id",
                "mode",
                "admission_gate_enabled",
                "admitted",
                "specification_id",
                "target_origin_confined",
                "operation_attempts",
                "cleanup_attempts",
                "compensating_cleanup_verified",
                "correspondence",
                "effect_evidence",
                "real_workflow_effect_observed",
                "wired_into_production",
                "finding_authority",
                "promotion_authority",
            },
        )
        result = cls(
            value["admission_gate_enabled"],
            value["admitted"],
            value["specification_id"],
            value["operation_attempts"],
            value["cleanup_attempts"],
            value["compensating_cleanup_verified"],
            _rehydrate_effect(value["effect_evidence"], value["operation_attempts"]),
        )
        if value["result_id"] != result.result_id:
            raise ValueError("workflow_effect_transport_result_address_mismatch")
        if value != result.to_dict():
            raise ValueError("workflow effect transport result is invalid")
        return result


def run_workflow_effect_transport(
    spec: WorkflowEffectTransportSpec,
    binding: WorkflowInvariantBinding,
    current_capture: WorkflowCaptureProvenance,
    client: WorkflowEffectClient,
    *,
    config: WorkflowEffectExecutionConfig | None = None,
    at_index: int,
) -> WorkflowEffectTransportResult:
    """Gate first, confine all URLs, run E6 once, then check one cleanup report."""
    try:
        selected = (
            WorkflowEffectExecutionConfig.from_environment()
            if config is None
            else config
        )
        if type(selected) is not WorkflowEffectExecutionConfig:
            raise ValueError("workflow effect execution gate is invalid")
        _revalidate(selected)
    except (TypeError, ValueError, AttributeError):
        return WorkflowEffectTransportResult(
            False, False, None, 0, 0, False, WorkflowEffectResult(0)
        )
    if not selected.enabled:
        return WorkflowEffectTransportResult(
            False, False, None, 0, 0, False, WorkflowEffectResult(0)
        )
    try:
        if type(spec) is not WorkflowEffectTransportSpec:
            raise ValueError("workflow effect transport specification is invalid")
        _revalidate(spec)
        validate_current_capture(binding, current_capture, at_index)
        if (
            spec.binding_ref != binding.binding_id
            or stable_hash("behavioral_capture_target", spec.target_origin)
            != binding.target_origin_ref
            or len(spec.operation_urls) != len(binding.fixture.contract.operations)
        ):
            raise ValueError("workflow effect transport binding is invalid")
        spec = WorkflowEffectTransportSpec.from_dict(spec.to_dict())
        transport = WorkflowEffectTransport(spec, client)
    except Exception:
        return WorkflowEffectTransportResult(
            True, False, None, 0, 0, False, WorkflowEffectResult(0)
        )
    effect = run_workflow_effect(binding, current_capture, transport, at_index=at_index)
    cleanup_verified = False
    if transport.operation_requests_attempted:
        try:
            cleanup_verified = transport.cleanup(binding)
        except Exception:
            cleanup_verified = False
    if not cleanup_verified:
        effect = WorkflowEffectResult(effect.transport_attempts)
    return WorkflowEffectTransportResult(
        True,
        True,
        spec.specification_id,
        effect.transport_attempts,
        transport.cleanup_attempts,
        cleanup_verified,
        effect,
    )
