"""R5E8 default-off workflow-effect operator and Foundry composition.

The real client dispatches only through PolicyExecutor and is wired into exactly
one production consumer. Confirmed outcomes are triage candidates with no
finding-promotion authority. No live/native execution is performed by this
slice. The async dispatcher runs frozen E7 synchronously in a worker thread;
each synchronous client call completes PolicyExecutor's async send on a fresh
event loop in that thread, never on the server's running loop.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from core.cortex.execution_policy import CandidateAction, DENIED_STATUS, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.action_classifier import AUTHZ_PROBE, OWNED_UPDATE_LOW_RISK

from .experiment_admission import (
    experiment_authority_context_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind, _hash_ref
from .normalize import stable_hash
from .prerequisite_capture_freshness import graph_bound_capture_artifact_ref
from .workflow_invariant_binding import (
    WorkflowCaptureProvenance,
    WorkflowInvariantBinding,
    validate_current_capture,
)
from .workflow_invariant_effect_transport import (
    WORKFLOW_EFFECT_EXECUTION_ENV,
    WORKFLOW_EFFECT_EXECUTION_MODE,
    WorkflowEffectExecutionConfig,
    WorkflowEffectTransportResult,
    WorkflowEffectTransportSpec,
    run_workflow_effect_transport,
)


WORKFLOW_EFFECT_ONE_CLICK_MODE = "behavioral_workflow_effect_one_click_v1"
_WORKFLOW = "behavioral_workflow_effect"
_MAX_RESPONSE_BYTES = 1_048_576


def _exact(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{label} fields are invalid")
    return value


@dataclass(frozen=True)
class WorkflowEffectOneClickSpecification:
    binding: WorkflowInvariantBinding = field(repr=False)
    current_capture: WorkflowCaptureProvenance = field(repr=False)
    transport_spec: WorkflowEffectTransportSpec = field(repr=False)
    at_index: int

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not WorkflowInvariantBinding
            or type(self.current_capture) is not WorkflowCaptureProvenance
            or type(self.transport_spec) is not WorkflowEffectTransportSpec
        ):
            raise ValueError("workflow effect one-click specification is invalid")
        validate_current_capture(self.binding, self.current_capture, self.at_index)
        WorkflowEffectTransportSpec.from_dict(self.transport_spec.to_dict())
        if (
            self.transport_spec.binding_ref != self.binding.binding_id
            or stable_hash(
                "behavioral_capture_target", self.transport_spec.target_origin
            )
            != self.binding.target_origin_ref
            or len(self.transport_spec.operation_urls)
            != len(self.binding.fixture.contract.operations)
        ):
            raise ValueError("workflow effect one-click binding is invalid")

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], *, target_origin: str
    ) -> WorkflowEffectOneClickSpecification:
        raw = _exact(
            value,
            {
                "schema_version",
                "binding",
                "current_capture",
                "at_index",
                "operation_urls",
                "cleanup_url",
            },
            "workflow effect specification",
        )
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("workflow effect specification version is invalid")
        if type(raw["operation_urls"]) is not list:
            raise ValueError("workflow effect operation urls are invalid")
        binding = WorkflowInvariantBinding.from_dict(raw["binding"])
        capture = WorkflowCaptureProvenance.from_dict(raw["current_capture"])
        return cls(
            binding,
            capture,
            WorkflowEffectTransportSpec(
                binding.binding_id,
                target_origin,
                tuple(raw["operation_urls"]),
                raw["cleanup_url"],
            ),
            raw["at_index"],
        )

    @property
    def specification_id(self) -> str:
        return stable_hash(
            "workflow_effect_one_click_specification",
            {
                "transport_specification_id": self.transport_spec.specification_id,
                "capture_id": self.current_capture.capture_id,
                "at_index": self.at_index,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "specification_id": self.specification_id,
            "binding": self.binding.to_dict(),
            "current_capture": self.current_capture.to_dict(),
            "at_index": self.at_index,
            "transport_spec": self.transport_spec.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowEffectOneClickSpecification:
        raw = _exact(
            value,
            {
                "schema_version",
                "specification_id",
                "binding",
                "current_capture",
                "at_index",
                "transport_spec",
            },
            "workflow effect serialized specification",
        )
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("workflow effect specification version is invalid")
        result = cls(
            WorkflowInvariantBinding.from_dict(raw["binding"]),
            WorkflowCaptureProvenance.from_dict(raw["current_capture"]),
            WorkflowEffectTransportSpec.from_dict(raw["transport_spec"]),
            raw["at_index"],
        )
        if raw != result.to_dict():
            raise ValueError("workflow effect specification address mismatch")
        return result


class WorkflowEffectOneClickDenied(RuntimeError):
    """The selected workflow-effect path lacks a required execution precondition."""


class PolicyExecutorWorkflowEffectClient:
    """Synchronous E7 client; each issue consumes one PolicyExecutor claim."""

    def __init__(
        self,
        *,
        executor: PolicyExecutor,
        specification: WorkflowEffectOneClickSpecification,
        persona_id: str,
    ) -> None:
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("workflow effect policy executor is invalid")
        if type(specification) is not WorkflowEffectOneClickSpecification:
            raise TypeError("workflow effect specification is invalid")
        if type(persona_id) is not str or not persona_id:
            raise ValueError("workflow effect persona is invalid")
        self._executor = executor
        self._specification = specification
        self._persona_id = persona_id

    def issue(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise WorkflowEffectOneClickDenied(
                "workflow_effect_client_requires_worker_thread"
            )
        kind = request.get("kind") if isinstance(request, Mapping) else None
        spec = self._specification.transport_spec
        if kind == "operation":
            expected = {
                "mode",
                "kind",
                "method",
                "url",
                "specification_id",
                "binding_ref",
                "operation_ref",
                "operation_id",
                "index",
                "amount",
            }
            _exact(request, expected, "workflow effect operation request")
            index = request["index"]
            operations = self._specification.binding.fixture.contract.operations
            if type(index) is not int or not 0 <= index < len(operations):
                raise ValueError("workflow effect operation index is invalid")
            operation = operations[index]
            if (
                request["url"] != spec.operation_urls[index]
                or request["operation_ref"] != operation.operation_ref
                or request["operation_id"] != operation.operation_id
                or request["amount"] != operation.amount
            ):
                raise ValueError("workflow effect operation request is invalid")
            hint = AUTHZ_PROBE
        elif kind == "cleanup":
            _exact(
                request,
                {
                    "mode",
                    "kind",
                    "method",
                    "url",
                    "specification_id",
                    "binding_ref",
                    "restore_consumed",
                    "declared_limit",
                },
                "workflow effect cleanup request",
            )
            initial = self._specification.binding.fixture.contract.initial_state
            if (
                request["url"] != spec.cleanup_url
                or type(request["restore_consumed"]) is not int
                or request["restore_consumed"] != initial.consumed
                or type(request["declared_limit"]) is not int
                or request["declared_limit"] != initial.declared_limit
            ):
                raise ValueError("workflow effect cleanup request is invalid")
            hint = OWNED_UPDATE_LOW_RISK
        else:
            raise ValueError("workflow effect request kind is invalid")
        if (
            request["mode"] != WORKFLOW_EFFECT_EXECUTION_MODE
            or request["method"] != "POST"
            or request["specification_id"] != spec.specification_id
            or request["binding_ref"] != self._specification.binding.binding_id
        ):
            raise ValueError("workflow effect request identity is invalid")
        action = CandidateAction(
            method="POST",
            url=request["url"],
            body={
                key: value
                for key, value in request.items()
                if key not in {"method", "url"}
            },
            hint=hint,
            actor_persona_id=self._persona_id,
            target_owner_persona_id=self._persona_id,
            target_is_researcher_owned=True,
            expected_side_effect=kind,
            proof_goal="observe_workflow_invariant_effect",
        )
        claim = self._executor.claim_proposal_action(action)
        if claim is None or claim.max_requests != 1:
            raise WorkflowEffectOneClickDenied("workflow_effect_action_claim_denied")
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            status, response = loop.run_until_complete(
                self._executor.send_claimed_action(
                    action,
                    claim,
                    _redirect_mode="manual",
                    _max_response_chars=_MAX_RESPONSE_BYTES,
                )
            )
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        if (
            status == DENIED_STATUS
            or type(status) is not int
            or not 200 <= status <= 499
        ):
            raise WorkflowEffectOneClickDenied(
                "workflow_effect_policy_or_target_denied"
            )
        if not isinstance(response, Mapping):
            if (
                not isinstance(response, str)
                or getattr(response, "body_truncated", False)
                or len(response.encode("utf-8")) > _MAX_RESPONSE_BYTES
            ):
                raise ValueError("workflow effect target response is invalid")
            response = json.loads(response)
        if not isinstance(response, Mapping):
            raise ValueError("workflow effect target response is invalid")
        if kind == "cleanup" and not 200 <= status <= 299:
            raise ValueError("workflow effect cleanup status is invalid")
        if kind == "operation":
            if response.get("status") == "accepted" and not 200 <= status <= 299:
                raise ValueError("workflow effect accepted status is invalid")
        return dict(response)


def _is_candidate(result: WorkflowEffectTransportResult) -> bool:
    evidence = result.evidence
    return bool(
        result.admitted
        and result.compensating_cleanup_verified
        and evidence is not None
        and evidence.oracle_outcome.value == "effect_observed_violation"
        and result.correspondence.value == "coherent"
    )


@dataclass(frozen=True)
class WorkflowEffectFindingCandidate:
    candidate_id: str
    result_id: str
    evidence_id: str
    _result: WorkflowEffectTransportResult = field(repr=False, compare=False)
    adversarial_triage_required: bool = True
    finding_authority: bool = False
    promotion_authority: bool = False
    real_workflow_effect_observed: bool = False
    wired_into_production: bool = False

    @classmethod
    def from_result(
        cls, result: WorkflowEffectTransportResult
    ) -> WorkflowEffectFindingCandidate:
        if type(result) is not WorkflowEffectTransportResult:
            raise TypeError("workflow effect result is invalid")
        rebuilt = WorkflowEffectTransportResult.from_dict(result.to_dict())
        if not _is_candidate(rebuilt):
            raise ValueError(
                "workflow effect result is not a confirmed triage candidate"
            )
        evidence = rebuilt.evidence
        assert evidence is not None
        return cls(
            stable_hash(
                "workflow_effect_finding_candidate",
                {"result_id": rebuilt.result_id, "evidence_id": evidence.evidence_id},
            ),
            rebuilt.result_id,
            evidence.evidence_id,
            rebuilt,
        )

    def __post_init__(self) -> None:
        if type(self._result) is not WorkflowEffectTransportResult:
            raise ValueError("workflow effect candidate result is invalid")
        rebuilt = WorkflowEffectTransportResult.from_dict(self._result.to_dict())
        evidence = rebuilt.evidence
        if (
            not _is_candidate(rebuilt)
            or evidence is None
            or self.result_id != rebuilt.result_id
            or self.evidence_id != evidence.evidence_id
            or self.candidate_id
            != stable_hash(
                "workflow_effect_finding_candidate",
                {"result_id": rebuilt.result_id, "evidence_id": evidence.evidence_id},
            )
            or self.adversarial_triage_required is not True
            or self.finding_authority is not False
            or self.promotion_authority is not False
            or self.real_workflow_effect_observed is not False
            or self.wired_into_production is not False
        ):
            raise ValueError("workflow effect candidate is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "result_id": self.result_id,
            "evidence_id": self.evidence_id,
            "adversarial_triage_required": True,
            "finding_authority": False,
            "promotion_authority": False,
            "real_workflow_effect_observed": False,
            "wired_into_production": False,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any], result: WorkflowEffectTransportResult
    ) -> WorkflowEffectFindingCandidate:
        _exact(
            value, set(cls.from_result(result).to_dict()), "workflow effect candidate"
        )
        rebuilt = cls.from_result(result)
        if value != rebuilt.to_dict():
            raise ValueError("workflow effect candidate serialization is invalid")
        return rebuilt


@dataclass(frozen=True)
class WorkflowEffectOneClickRun:
    status: str
    specification_id: str
    transport_specification_id: str
    result: WorkflowEffectTransportResult | None = field(default=None, repr=False)
    candidate: WorkflowEffectFindingCandidate | None = None
    disabled_gates: tuple[str, ...] = ()
    mode: str = WORKFLOW_EFFECT_ONE_CLICK_MODE
    finding_authority: bool = False
    promotion_authority: bool = False
    real_workflow_effect_observed: bool = False
    wired_into_production: bool = False

    @classmethod
    def disabled(
        cls, spec: WorkflowEffectOneClickSpecification
    ) -> WorkflowEffectOneClickRun:
        if type(spec) is not WorkflowEffectOneClickSpecification:
            raise TypeError("workflow effect specification is invalid")
        return cls(
            "selected_execution_disabled",
            spec.specification_id,
            spec.transport_spec.specification_id,
            disabled_gates=(WORKFLOW_EFFECT_EXECUTION_ENV,),
        )

    def __post_init__(self) -> None:
        disabled = self.status == "selected_execution_disabled"
        completed = self.status == "completed"
        if not (disabled or completed):
            raise ValueError("workflow effect run status is invalid")
        result = self.result
        if result is not None:
            if type(result) is not WorkflowEffectTransportResult:
                raise ValueError("workflow effect run result is invalid")
            result = WorkflowEffectTransportResult.from_dict(result.to_dict())
        expected_candidate = (
            WorkflowEffectFindingCandidate.from_result(result)
            if result is not None and _is_candidate(result)
            else None
        )
        if (
            self.mode != WORKFLOW_EFFECT_ONE_CLICK_MODE
            or not _hash_ref(
                self.specification_id, "workflow_effect_one_click_specification"
            )
            or not _hash_ref(
                self.transport_specification_id,
                "workflow_effect_transport_specification",
            )
            or completed != (result is not None)
            or (
                completed
                and (
                    not result.admitted
                    or result.specification_id != self.transport_specification_id
                )
            )
            or disabled != (self.disabled_gates == (WORKFLOW_EFFECT_EXECUTION_ENV,))
            or (
                self.candidate is not None
                and type(self.candidate) is not WorkflowEffectFindingCandidate
            )
            or self.candidate != expected_candidate
            or self.finding_authority is not False
            or self.promotion_authority is not False
            or self.real_workflow_effect_observed is not False
            or self.wired_into_production is not False
        ):
            raise ValueError("workflow effect one-click run is invalid")

    @property
    def selected(self) -> bool:
        return True

    @property
    def dispatched(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "specification_id": self.specification_id,
            "transport_specification_id": self.transport_specification_id,
            "disabled_gates": list(self.disabled_gates),
            "dispatched": self.dispatched,
            "result": self.result.to_dict() if self.result is not None else None,
            "candidate": self.candidate.to_dict()
            if self.candidate is not None
            else None,
            "adversarial_triage_required": True,
            "finding_authority": False,
            "promotion_authority": False,
            "real_workflow_effect_observed": False,
            "wired_into_production": False,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkflowEffectOneClickRun:
        raw = _exact(
            value,
            {
                "schema_version",
                "mode",
                "status",
                "specification_id",
                "transport_specification_id",
                "disabled_gates",
                "dispatched",
                "result",
                "candidate",
                "adversarial_triage_required",
                "finding_authority",
                "promotion_authority",
                "real_workflow_effect_observed",
                "wired_into_production",
            },
            "workflow effect run",
        )
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("workflow effect run version is invalid")
        if type(raw["disabled_gates"]) is not list:
            raise ValueError("workflow effect disabled gates are invalid")
        result = (
            WorkflowEffectTransportResult.from_dict(raw["result"])
            if raw["result"] is not None
            else None
        )
        candidate = (
            WorkflowEffectFindingCandidate.from_dict(raw["candidate"], result)
            if raw["candidate"] is not None and result is not None
            else None
        )
        run = cls(
            raw["status"],
            raw["specification_id"],
            raw["transport_specification_id"],
            result,
            candidate,
            tuple(raw["disabled_gates"]),
            raw["mode"],
            raw["finding_authority"],
            raw["promotion_authority"],
            raw["real_workflow_effect_observed"],
            raw["wired_into_production"],
        )
        if raw != run.to_dict():
            raise ValueError("workflow effect run serialization is invalid")
        return run

    def execution_response(self) -> dict[str, Any]:
        if self.result is None:
            raise WorkflowEffectOneClickDenied("workflow_effect_execution_is_missing")
        return {
            "kind": "workflow_invariant_effect_one_click",
            "status": self.result.correspondence.value,
            "execution": self.to_dict(),
            "finding": None,
            "finding_confirmed": False,
            "finding_candidate": self.candidate.to_dict()
            if self.candidate is not None
            else None,
            "adversarial_triage_required": True,
            "finding_authority": False,
            "promotion_authority": False,
            "workflow_invariant_effect_one_click": self.to_dict(),
        }


class WorkflowEffectOneClickDispatcher:
    """Authorize the owned context, then compose the frozen E7 entry point."""

    def __init__(
        self,
        *,
        target_origin: str,
        persona_id: str,
        specification: WorkflowEffectOneClickSpecification,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor | None,
        persona_vault: PersonaVault,
        evidence_records: Sequence[Mapping[str, Any]],
        config: WorkflowEffectExecutionConfig | None = None,
    ) -> None:
        if type(specification) is not WorkflowEffectOneClickSpecification:
            raise TypeError("workflow effect specification is invalid")
        self.specification = specification
        self.config = (
            config
            if config is not None
            else WorkflowEffectExecutionConfig.from_environment()
        )
        if type(self.config) is not WorkflowEffectExecutionConfig:
            raise TypeError("workflow effect execution config is invalid")
        self.executor = executor
        self.persona_id = persona_id
        if not self.config.enabled:
            return
        if (
            not isinstance(authorization, AuthorizationEnvelope)
            or not isinstance(persona_vault, PersonaVault)
            or not isinstance(executor, PolicyExecutor)
            or specification.transport_spec.target_origin != target_origin
        ):
            raise WorkflowEffectOneClickDenied(
                "workflow_effect_authority_context_invalid"
            )
        try:
            authorization.authorize_action(
                target_origin=target_origin, workflow=_WORKFLOW
            )
            persona = persona_vault.get_persona(persona_id)
            if persona is None or persona.persona_id != persona_id:
                raise ValueError("owned persona unavailable")
            world = ExperimentWorldBinding.build(
                slot="actor",
                kind=ExperimentWorldKind.OWNED_ACCOUNT,
                world_ref=stable_hash("world", persona_id),
                persona_ref=experiment_persona_ref(persona_id),
                ownership_ref=experiment_ownership_ref(authorization, persona_id),
            )
            authority_ref = experiment_authority_context_ref(
                authorization, target_origin, (_WORKFLOW,)
            )
            tenant_ref = stable_hash(
                "owned_tenant",
                {"authority_ref": authority_ref, "persona_ref": world.persona_ref},
            )
            tenant_ownership_ref = stable_hash(
                "ownership_proof",
                {
                    "attestation_signature": authorization.attestation_signature,
                    "tenant_ref": tenant_ref,
                },
            )
            source_ref = graph_bound_capture_artifact_ref(
                evidence_records, target_origin=target_origin, world_id=world.binding_id
            )
            binding = specification.binding
            if (
                binding.fixture.world != world
                or binding.fixture.contract.tenant_ref != tenant_ref
                or binding.fixture.contract.tenant_ownership_ref != tenant_ownership_ref
                or binding.capture.source_evidence_refs
                != (source_ref,) * len(binding.fixture.contract.operations)
            ):
                raise ValueError("workflow effect owned capture mismatch")
            validate_current_capture(
                binding, specification.current_capture, specification.at_index
            )
        except Exception as exc:
            raise WorkflowEffectOneClickDenied(
                "workflow_effect_context_invalid"
            ) from exc

    async def run(self) -> WorkflowEffectOneClickRun:
        if not self.config.enabled:
            return WorkflowEffectOneClickRun.disabled(self.specification)
        if self.executor is None:
            raise WorkflowEffectOneClickDenied("workflow_effect_executor_unavailable")
        client = PolicyExecutorWorkflowEffectClient(
            executor=self.executor,
            specification=self.specification,
            persona_id=self.persona_id,
        )
        worker = asyncio.create_task(
            asyncio.to_thread(
                run_workflow_effect_transport,
                self.specification.transport_spec,
                self.specification.binding,
                self.specification.current_capture,
                client,
                config=self.config,
                at_index=self.specification.at_index,
            )
        )
        try:
            result = await asyncio.shield(worker)
        except asyncio.CancelledError:
            # E7 still owns a possible compensating cleanup in the worker.
            # Finish it before the server aborts its root reservation.
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not worker.cancelled():
                worker.exception()
            raise
        if not result.admitted:
            raise WorkflowEffectOneClickDenied("workflow_effect_transport_not_admitted")
        candidate = (
            WorkflowEffectFindingCandidate.from_result(result)
            if _is_candidate(result)
            else None
        )
        return WorkflowEffectOneClickRun(
            "completed",
            self.specification.specification_id,
            self.specification.transport_spec.specification_id,
            result,
            candidate,
        )


__all__ = [
    "WORKFLOW_EFFECT_ONE_CLICK_MODE",
    "PolicyExecutorWorkflowEffectClient",
    "WorkflowEffectOneClickSpecification",
    "WorkflowEffectOneClickDispatcher",
    "WorkflowEffectOneClickRun",
    "WorkflowEffectFindingCandidate",
    "WorkflowEffectOneClickDenied",
]
