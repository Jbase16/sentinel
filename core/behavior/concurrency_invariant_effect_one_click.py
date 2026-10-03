"""R5F8 default-off concurrency-effect operator and Foundry composition.

The real client dispatches only through PolicyExecutor and is wired into exactly
one production consumer. Confirmed outcomes are triage candidates with no
finding-promotion authority. Operator authorization covers target_origin, and
frozen F7 confines every transport URL to that origin. The F binding has no
origin anchor, so this cannot prove that the confined origin is the owned
world's origin. That binding is deferred to OCB-S22 native;
owned_target_origin_bound remains False. No live/native execution is performed
by this slice. The async dispatcher runs frozen F7 in a worker thread;
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

from .experiment_admission import experiment_persona_ref
from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind, _hash_ref
from .normalize import stable_hash
from .concurrency_invariant_binding import (
    ConcurrencyCaptureProvenance,
    ConcurrencyInvariantBinding,
    validate_current_capture,
)
from .concurrency_invariant_contract import WorkflowSchedule
from .concurrency_invariant_effect_transport import (
    CONCURRENCY_EFFECT_EXECUTION_ENV,
    CONCURRENCY_EFFECT_EXECUTION_MODE,
    ConcurrencyEffectExecutionConfig,
    ConcurrencyEffectTransportResult,
    ConcurrencyEffectTransportSpec,
    run_concurrency_effect_transport,
)


CONCURRENCY_EFFECT_ONE_CLICK_MODE = "behavioral_concurrency_effect_one_click_v1"
_CONCURRENCY = "behavioral_concurrency_effect"
_MAX_RESPONSE_BYTES = 1_048_576


def _exact(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{label} fields are invalid")
    return value


@dataclass(frozen=True)
class ConcurrencyEffectOneClickSpecification:
    binding: ConcurrencyInvariantBinding = field(repr=False)
    current_capture: ConcurrencyCaptureProvenance = field(repr=False)
    transport_spec: ConcurrencyEffectTransportSpec = field(repr=False)
    schedule: WorkflowSchedule = field(repr=False)
    at_index: int

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not ConcurrencyInvariantBinding
            or type(self.current_capture) is not ConcurrencyCaptureProvenance
            or type(self.transport_spec) is not ConcurrencyEffectTransportSpec
            or type(self.schedule) is not WorkflowSchedule
        ):
            raise ValueError("concurrency effect one-click specification is invalid")
        validate_current_capture(self.binding, self.current_capture, self.at_index)
        ConcurrencyEffectTransportSpec.from_dict(self.transport_spec.to_dict())
        WorkflowSchedule.from_dict(self.schedule.to_dict())
        if (
            self.transport_spec.binding_ref != self.binding.binding_id
            or self.schedule.contract != self.binding.fixture.contract
            or len(self.transport_spec.operation_urls)
            != len(self.binding.fixture.contract.operations)
        ):
            raise ValueError("concurrency effect one-click binding is invalid")

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], *, target_origin: str
    ) -> ConcurrencyEffectOneClickSpecification:
        raw = _exact(
            value,
            {
                "schema_version",
                "binding",
                "current_capture",
                "schedule",
                "at_index",
                "operation_urls",
                "cleanup_url",
            },
            "concurrency effect specification",
        )
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("concurrency effect specification version is invalid")
        if type(raw["operation_urls"]) is not list:
            raise ValueError("concurrency effect operation urls are invalid")
        binding = ConcurrencyInvariantBinding.from_dict(raw["binding"])
        capture = ConcurrencyCaptureProvenance.from_dict(raw["current_capture"])
        schedule = WorkflowSchedule.from_dict(raw["schedule"])
        return cls(
            binding,
            capture,
            ConcurrencyEffectTransportSpec(
                binding.binding_id,
                target_origin,
                tuple(raw["operation_urls"]),
                raw["cleanup_url"],
            ),
            schedule,
            raw["at_index"],
        )

    @property
    def specification_id(self) -> str:
        return stable_hash(
            "concurrency_effect_one_click_specification",
            {
                "transport_specification_id": self.transport_spec.specification_id,
                "capture_id": self.current_capture.capture_id,
                "schedule_id": self.schedule.schedule_id,
                "at_index": self.at_index,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "specification_id": self.specification_id,
            "binding": self.binding.to_dict(),
            "current_capture": self.current_capture.to_dict(),
            "schedule": self.schedule.to_dict(),
            "at_index": self.at_index,
            "transport_spec": self.transport_spec.to_dict(),
            "owned_target_origin_bound": False,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEffectOneClickSpecification:
        raw = _exact(
            value,
            {
                "schema_version",
                "specification_id",
                "binding",
                "current_capture",
                "schedule",
                "at_index",
                "transport_spec",
                "owned_target_origin_bound",
            },
            "concurrency effect serialized specification",
        )
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("concurrency effect specification version is invalid")
        result = cls(
            ConcurrencyInvariantBinding.from_dict(raw["binding"]),
            ConcurrencyCaptureProvenance.from_dict(raw["current_capture"]),
            ConcurrencyEffectTransportSpec.from_dict(raw["transport_spec"]),
            WorkflowSchedule.from_dict(raw["schedule"]),
            raw["at_index"],
        )
        if raw != result.to_dict():
            raise ValueError("concurrency effect specification address mismatch")
        return result


class ConcurrencyEffectOneClickDenied(RuntimeError):
    """The selected concurrency-effect path lacks a required execution precondition."""


class PolicyExecutorConcurrencyEffectClient:
    """Synchronous F7 client; each issue consumes one PolicyExecutor claim."""

    def __init__(
        self,
        *,
        executor: PolicyExecutor,
        specification: ConcurrencyEffectOneClickSpecification,
        persona_id: str,
    ) -> None:
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("concurrency effect policy executor is invalid")
        if type(specification) is not ConcurrencyEffectOneClickSpecification:
            raise TypeError("concurrency effect specification is invalid")
        if type(persona_id) is not str or not persona_id:
            raise ValueError("concurrency effect persona is invalid")
        self._executor = executor
        self._specification = specification
        self._persona_id = persona_id

    def issue(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise ConcurrencyEffectOneClickDenied(
                "concurrency_effect_client_requires_worker_thread"
            )
        kind = request.get("kind") if isinstance(request, Mapping) else None
        spec = self._specification.transport_spec
        if kind in {"observe", "commit"}:
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
            _exact(request, expected, "concurrency effect operation request")
            index = request["index"]
            steps = self._specification.schedule.steps
            if type(index) is not int or not 0 <= index < len(steps):
                raise ValueError("concurrency effect operation index is invalid")
            step = steps[index]
            operations = self._specification.binding.fixture.contract.operations
            operation_by_ref = {op.operation_ref: op for op in operations}
            operation = operation_by_ref[step.operation_ref]
            url_by_ref = dict(
                zip((op.operation_ref for op in operations), spec.operation_urls)
            )
            if (
                kind != step.step_kind.value
                or request["url"] != url_by_ref[operation.operation_ref]
                or request["operation_ref"] != operation.operation_ref
                or request["operation_id"] != operation.operation_id
                or request["amount"] != operation.amount
            ):
                raise ValueError("concurrency effect operation request is invalid")
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
                "concurrency effect cleanup request",
            )
            initial = self._specification.binding.fixture.contract.initial_state
            if (
                request["url"] != spec.cleanup_url
                or type(request["restore_consumed"]) is not int
                or request["restore_consumed"] != initial.consumed
                or type(request["declared_limit"]) is not int
                or request["declared_limit"] != initial.declared_limit
            ):
                raise ValueError("concurrency effect cleanup request is invalid")
            hint = OWNED_UPDATE_LOW_RISK
        else:
            raise ValueError("concurrency effect request kind is invalid")
        if (
            request["mode"] != CONCURRENCY_EFFECT_EXECUTION_MODE
            or request["method"] != "POST"
            or request["specification_id"] != spec.specification_id
            or request["binding_ref"] != self._specification.binding.binding_id
        ):
            raise ValueError("concurrency effect request identity is invalid")
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
            proof_goal="observe_concurrency_invariant_effect",
        )
        claim = self._executor.claim_proposal_action(action)
        if claim is None or claim.max_requests != 1:
            raise ConcurrencyEffectOneClickDenied("concurrency_effect_action_claim_denied")
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
            raise ConcurrencyEffectOneClickDenied(
                "concurrency_effect_policy_or_target_denied"
            )
        if not isinstance(response, Mapping):
            if (
                not isinstance(response, str)
                or getattr(response, "body_truncated", False)
                or len(response.encode("utf-8")) > _MAX_RESPONSE_BYTES
            ):
                raise ValueError("concurrency effect target response is invalid")
            response = json.loads(response)
        if not isinstance(response, Mapping):
            raise ValueError("concurrency effect target response is invalid")
        if kind == "cleanup" and not 200 <= status <= 299:
            raise ValueError("concurrency effect cleanup status is invalid")
        if kind == "commit":
            if response.get("status") == "accepted" and not 200 <= status <= 299:
                raise ValueError("concurrency effect accepted status is invalid")
            _exact(
                response,
                {
                    "binding_ref",
                    "operation_ref",
                    "operation_id",
                    "index",
                    "status",
                    "consumed",
                    "declared_limit",
                },
                "concurrency effect commit response",
            )
            if response["index"] != request["index"]:
                raise ValueError("concurrency effect commit index is invalid")
        elif kind == "cleanup":
            _exact(
                response,
                {
                    "specification_id",
                    "binding_ref",
                    "cleanup_verified",
                    "orphaned_owned_state_possible",
                    "consumed",
                    "declared_limit",
                },
                "concurrency effect cleanup response",
            )
        return dict(response)


def _is_candidate(result: ConcurrencyEffectTransportResult) -> bool:
    evidence = result.evidence
    return bool(
        result.admitted
        and result.compensating_cleanup_verified
        and evidence is not None
        and evidence.oracle_outcome.value == "effect_observed_violation"
        and evidence.model.decision.race_confirmed is True
        and result.correspondence.value == "coherent"
    )


@dataclass(frozen=True)
class ConcurrencyEffectFindingCandidate:
    candidate_id: str
    result_id: str
    evidence_id: str
    _result: ConcurrencyEffectTransportResult = field(repr=False, compare=False)
    adversarial_triage_required: bool = True
    finding_authority: bool = False
    promotion_authority: bool = False
    real_concurrency_effect_observed: bool = False
    wired_into_production: bool = False
    owned_target_origin_bound: bool = False

    @classmethod
    def from_result(
        cls, result: ConcurrencyEffectTransportResult
    ) -> ConcurrencyEffectFindingCandidate:
        if type(result) is not ConcurrencyEffectTransportResult:
            raise TypeError("concurrency effect result is invalid")
        rebuilt = ConcurrencyEffectTransportResult.from_dict(result.to_dict())
        if not _is_candidate(rebuilt):
            raise ValueError(
                "concurrency effect result is not a confirmed triage candidate"
            )
        evidence = rebuilt.evidence
        assert evidence is not None
        return cls(
            stable_hash(
                "concurrency_effect_finding_candidate",
                {"result_id": rebuilt.result_id, "evidence_id": evidence.evidence_id},
            ),
            rebuilt.result_id,
            evidence.evidence_id,
            rebuilt,
        )

    def __post_init__(self) -> None:
        if type(self._result) is not ConcurrencyEffectTransportResult:
            raise ValueError("concurrency effect candidate result is invalid")
        rebuilt = ConcurrencyEffectTransportResult.from_dict(self._result.to_dict())
        evidence = rebuilt.evidence
        if (
            not _is_candidate(rebuilt)
            or evidence is None
            or self.result_id != rebuilt.result_id
            or self.evidence_id != evidence.evidence_id
            or self.candidate_id
            != stable_hash(
                "concurrency_effect_finding_candidate",
                {"result_id": rebuilt.result_id, "evidence_id": evidence.evidence_id},
            )
            or self.adversarial_triage_required is not True
            or self.finding_authority is not False
            or self.promotion_authority is not False
            or self.real_concurrency_effect_observed is not False
            or self.wired_into_production is not False
            or self.owned_target_origin_bound is not False
        ):
            raise ValueError("concurrency effect candidate is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "result_id": self.result_id,
            "evidence_id": self.evidence_id,
            "adversarial_triage_required": True,
            "finding_authority": False,
            "promotion_authority": False,
            "real_concurrency_effect_observed": False,
            "wired_into_production": False,
            "owned_target_origin_bound": False,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any], result: ConcurrencyEffectTransportResult
    ) -> ConcurrencyEffectFindingCandidate:
        _exact(
            value, set(cls.from_result(result).to_dict()), "concurrency effect candidate"
        )
        rebuilt = cls.from_result(result)
        if value != rebuilt.to_dict():
            raise ValueError("concurrency effect candidate serialization is invalid")
        return rebuilt


@dataclass(frozen=True)
class ConcurrencyEffectOneClickRun:
    status: str
    specification_id: str
    transport_specification_id: str
    result: ConcurrencyEffectTransportResult | None = field(default=None, repr=False)
    candidate: ConcurrencyEffectFindingCandidate | None = None
    disabled_gates: tuple[str, ...] = ()
    mode: str = CONCURRENCY_EFFECT_ONE_CLICK_MODE
    finding_authority: bool = False
    promotion_authority: bool = False
    real_concurrency_effect_observed: bool = False
    wired_into_production: bool = False
    owned_target_origin_bound: bool = False

    @classmethod
    def disabled(
        cls, spec: ConcurrencyEffectOneClickSpecification
    ) -> ConcurrencyEffectOneClickRun:
        if type(spec) is not ConcurrencyEffectOneClickSpecification:
            raise TypeError("concurrency effect specification is invalid")
        return cls(
            "selected_execution_disabled",
            spec.specification_id,
            spec.transport_spec.specification_id,
            disabled_gates=(CONCURRENCY_EFFECT_EXECUTION_ENV,),
        )

    def __post_init__(self) -> None:
        disabled = self.status == "selected_execution_disabled"
        completed = self.status == "completed"
        if not (disabled or completed):
            raise ValueError("concurrency effect run status is invalid")
        result = self.result
        if result is not None:
            if type(result) is not ConcurrencyEffectTransportResult:
                raise ValueError("concurrency effect run result is invalid")
            result = ConcurrencyEffectTransportResult.from_dict(result.to_dict())
        expected_candidate = (
            ConcurrencyEffectFindingCandidate.from_result(result)
            if result is not None and _is_candidate(result)
            else None
        )
        if (
            self.mode != CONCURRENCY_EFFECT_ONE_CLICK_MODE
            or not _hash_ref(
                self.specification_id, "concurrency_effect_one_click_specification"
            )
            or not _hash_ref(
                self.transport_specification_id,
                "concurrency_effect_transport_specification",
            )
            or completed != (result is not None)
            or (
                completed
                and (
                    not result.admitted
                    or result.specification_id != self.transport_specification_id
                )
            )
            or disabled != (self.disabled_gates == (CONCURRENCY_EFFECT_EXECUTION_ENV,))
            or (
                self.candidate is not None
                and type(self.candidate) is not ConcurrencyEffectFindingCandidate
            )
            or self.candidate != expected_candidate
            or self.finding_authority is not False
            or self.promotion_authority is not False
            or self.real_concurrency_effect_observed is not False
            or self.wired_into_production is not False
            or self.owned_target_origin_bound is not False
        ):
            raise ValueError("concurrency effect one-click run is invalid")

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
            "real_concurrency_effect_observed": False,
            "wired_into_production": False,
            "owned_target_origin_bound": False,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ConcurrencyEffectOneClickRun:
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
                "real_concurrency_effect_observed",
                "wired_into_production",
                "owned_target_origin_bound",
            },
            "concurrency effect run",
        )
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError("concurrency effect run version is invalid")
        if type(raw["disabled_gates"]) is not list:
            raise ValueError("concurrency effect disabled gates are invalid")
        result = (
            ConcurrencyEffectTransportResult.from_dict(raw["result"])
            if raw["result"] is not None
            else None
        )
        candidate = (
            ConcurrencyEffectFindingCandidate.from_dict(raw["candidate"], result)
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
            raw["real_concurrency_effect_observed"],
            raw["wired_into_production"],
            raw["owned_target_origin_bound"],
        )
        if raw != run.to_dict():
            raise ValueError("concurrency effect run serialization is invalid")
        return run

    def execution_response(self) -> dict[str, Any]:
        if self.result is None:
            raise ConcurrencyEffectOneClickDenied("concurrency_effect_execution_is_missing")
        return {
            "kind": "concurrency_invariant_effect_one_click",
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
            "real_concurrency_effect_observed": False,
            "wired_into_production": False,
            "owned_target_origin_bound": False,
            "concurrency_invariant_effect_one_click": self.to_dict(),
        }


class ConcurrencyEffectOneClickDispatcher:
    """Authorize paired personas, then compose the frozen F7 entry point."""

    def __init__(
        self,
        *,
        target_origin: str,
        persona_id: str,
        specification: ConcurrencyEffectOneClickSpecification,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor | None,
        persona_vault: PersonaVault,
        evidence_records: Sequence[Mapping[str, Any]],
        config: ConcurrencyEffectExecutionConfig | None = None,
    ) -> None:
        if type(specification) is not ConcurrencyEffectOneClickSpecification:
            raise TypeError("concurrency effect specification is invalid")
        self.specification = specification
        self.config = (
            config
            if config is not None
            else ConcurrencyEffectExecutionConfig.from_environment()
        )
        if type(self.config) is not ConcurrencyEffectExecutionConfig:
            raise TypeError("concurrency effect execution config is invalid")
        self.executor = executor
        self.persona_id = persona_id
        if not self.config.enabled:
            return
        if (
            not isinstance(authorization, AuthorizationEnvelope)
            or not isinstance(persona_vault, PersonaVault)
            or not isinstance(executor, PolicyExecutor)
            or specification.transport_spec.target_origin != target_origin
            or not evidence_records
            or any(not isinstance(record, Mapping) for record in evidence_records)
        ):
            raise ConcurrencyEffectOneClickDenied(
                "concurrency_effect_authority_context_invalid"
            )
        try:
            authorization.authorize_action(target_origin=target_origin, workflow=_CONCURRENCY)
            persona = persona_vault.get_persona(persona_id)
            peer_candidates = [
                selected
                for selected in persona_vault.list_personas()
                if selected.persona_id != persona_id
                and experiment_persona_ref(selected.persona_id)
                == specification.binding.fixture.worlds[1].persona_ref
            ]
            if (
                persona is None
                or persona.persona_id != persona_id
                or len(peer_candidates) != 1
            ):
                raise ValueError("paired owned personas unavailable")
            peer = peer_candidates[0]
            binding = specification.binding
            contract = binding.fixture.contract
            worlds = tuple(
                ExperimentWorldBinding.build(
                    slot=fixture_world.slot,
                    kind=ExperimentWorldKind.OWNED_ACCOUNT,
                    world_ref=stable_hash("world", selected.persona_id),
                    persona_ref=experiment_persona_ref(selected.persona_id),
                    ownership_ref=contract.tenant_ownership_ref,
                )
                for fixture_world, selected in zip(
                    binding.fixture.worlds, (persona, peer)
                )
            )
            if (
                binding.fixture.worlds != worlds
                or contract.tenant_ref != stable_hash("owned_tenant", "concurrency")
                or contract.tenant_ownership_ref
                != stable_hash("ownership_proof", "concurrency")
                or contract.resource_ref
                != stable_hash("owned_resource", "shared-cap")
                or binding.capture.world_binding_refs
                != tuple(world.binding_id for world in worlds)
                or binding.capture.actor_refs
                != tuple(world.persona_ref for world in worlds)
                or binding.capture.tenant_ref != contract.tenant_ref
                or binding.capture.tenant_ownership_ref
                != contract.tenant_ownership_ref
                or binding.capture.resource_ref != contract.resource_ref
                or binding.capture.operation_ids
                != tuple(op.operation_id for op in contract.operations)
            ):
                raise ValueError("concurrency effect owned capture mismatch")
            validate_current_capture(
                binding, specification.current_capture, specification.at_index
            )
        except Exception as exc:
            raise ConcurrencyEffectOneClickDenied(
                "concurrency_effect_context_invalid"
            ) from exc

    async def run(self) -> ConcurrencyEffectOneClickRun:
        if not self.config.enabled:
            return ConcurrencyEffectOneClickRun.disabled(self.specification)
        if self.executor is None:
            raise ConcurrencyEffectOneClickDenied("concurrency_effect_executor_unavailable")
        client = PolicyExecutorConcurrencyEffectClient(
            executor=self.executor,
            specification=self.specification,
            persona_id=self.persona_id,
        )
        worker = asyncio.create_task(
            asyncio.to_thread(
                run_concurrency_effect_transport,
                self.specification.transport_spec,
                self.specification.binding,
                self.specification.current_capture,
                self.specification.schedule,
                client,
                config=self.config,
                at_index=self.specification.at_index,
            )
        )
        try:
            result = await asyncio.shield(worker)
        except asyncio.CancelledError:
            # F7 still owns a possible compensating cleanup in the worker.
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
            raise ConcurrencyEffectOneClickDenied("concurrency_effect_transport_not_admitted")
        candidate = (
            ConcurrencyEffectFindingCandidate.from_result(result)
            if _is_candidate(result)
            else None
        )
        return ConcurrencyEffectOneClickRun(
            "completed",
            self.specification.specification_id,
            self.specification.transport_spec.specification_id,
            result,
            candidate,
        )


__all__ = [
    "CONCURRENCY_EFFECT_ONE_CLICK_MODE",
    "PolicyExecutorConcurrencyEffectClient",
    "ConcurrencyEffectOneClickSpecification",
    "ConcurrencyEffectOneClickDispatcher",
    "ConcurrencyEffectOneClickRun",
    "ConcurrencyEffectFindingCandidate",
    "ConcurrencyEffectOneClickDenied",
]
