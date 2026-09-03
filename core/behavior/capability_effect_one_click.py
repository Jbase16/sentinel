"""Default-off R5D9 operator transport and Foundry composition for Family D.

The concrete transport sends the fixed R5D8 matrix through ``PolicyExecutor``.
It derives every terminal receipt through the existing R5D1-R5D6 evaluators,
immediately content-addresses protected target effects, and verifies a real
compensating cleanup request.  Public values contain typed hashes only; the
confirmed outcome remains a triage candidate with no finding-promotion authority.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import (
    DENIED_STATUS,
    CandidateAction,
    PolicyExecutor,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault
from core.safety.action_classifier import AUTHZ_PROBE, OWNED_UPDATE_LOW_RISK

from .capability_confinement_freshness import (
    ConfinedPresentationBinding,
    ConfinementPresentation,
    evaluate_confinement,
)
from .capability_consumption_ledger import (
    CapabilityConsumptionLedger,
    ConsumptionDecision,
    evaluate_consumption,
)
from .capability_contract import (
    CapabilityDecision,
    CapabilityOutcome,
    CapabilityPresentation,
    CapabilityRevocationState,
    IssuedCapabilityContract,
    _hash_ref,
    classify_presentation,
)
from .capability_effect_evaluation import (
    CAPABILITY_EFFECT_EXECUTION_ENV,
    CAPABILITY_EFFECT_EXECUTION_MODE,
    CapabilityCleanupResult,
    CapabilityEffectExecutionConfig,
    CapabilityEffectExecutionDenied,
    CapabilityEffectExecutionResult,
    CapabilityEffectExperimentExecutor,
    CapabilityEffectOracleVerdict,
)
from .capability_execution_receipt import (
    CapabilityExecutionOutcome,
    CapabilityExecutionReceipt,
    evaluate_capability_execution,
)
from .capability_runtime_expiry import AdmittedRuntimeContract
from .experiment_admission import (
    experiment_authority_context_ref,
    experiment_endpoint_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from .normalize import stable_hash
from .prerequisite_capture_freshness import graph_bound_capture_artifact_ref


CAPABILITY_EFFECT_ONE_CLICK_MODE = "behavioral_capability_effect_one_click_v1"
CAPABILITY_EFFECT_WORKFLOW = "behavioral_capability_effect"

_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_OBSERVATION_KINDS = (
    "no_capability_baseline",
    "valid_capability_effect_witness",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)
_EXPECTED_OUTCOMES = {
    "no_capability_baseline": CapabilityExecutionOutcome.EXECUTION_REFUSED_NOT_LIVE,
    "valid_capability_effect_witness": CapabilityExecutionOutcome.EXECUTION_COMPLETED,
    "replayed_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_ALREADY_CONSUMED
    ),
    "expired_capability_probe": CapabilityExecutionOutcome.EXECUTION_REFUSED_EXPIRED,
    "inadmissible_capability_probe": (
        CapabilityExecutionOutcome.EXECUTION_REFUSED_INADMISSIBLE
    ),
}
_RESPONSE_FIELDS = {
    "access_decision",
    "effect",
    "target_projection_observed",
}
_CLEANUP_RESPONSE_FIELDS = {
    "cleanup_verified",
    "orphaned_owned_state_possible",
    "target_projection_observed",
}
_MAX_RESPONSE_BYTES = 1_048_576


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("capability effect target origin is invalid")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _validated_url(value: object, *, target_origin: str, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 4096
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{field_name} is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or _canonical_origin(f"{parsed.scheme}://{parsed.netloc}") != target_origin
    ):
        raise ValueError(f"{field_name} leaves the authorized target origin")
    return value


def _request_ref(kind: str, url: str) -> str:
    return stable_hash(kind, {"method": "POST", "url": url})


@dataclass(frozen=True)
class CapabilityEffectOneClickSpecification:
    specification_id: str
    run_ref: str
    target_request_ref: str
    cleanup_request_ref: str
    target_endpoint_ref: str
    cleanup_endpoint_ref: str
    target_url: str = field(repr=False, compare=False)
    cleanup_url: str = field(repr=False, compare=False)

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        target_origin: str,
    ) -> "CapabilityEffectOneClickSpecification":
        expected = {"schema_version", "run_id", "target_url", "cleanup_url"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("capability effect specification fields are invalid")
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
            raise ValueError("capability effect specification version is invalid")
        run_id = value.get("run_id")
        if (
            not isinstance(run_id, str)
            or not run_id
            or run_id != run_id.strip()
            or len(run_id) > 256
            or any(ord(character) < 32 for character in run_id)
        ):
            raise ValueError("capability effect run id is invalid")
        origin = _canonical_origin(target_origin)
        target_url = _validated_url(
            value.get("target_url"),
            target_origin=origin,
            field_name="capability effect target url",
        )
        cleanup_url = _validated_url(
            value.get("cleanup_url"),
            target_origin=origin,
            field_name="capability effect cleanup url",
        )
        target_endpoint_ref = experiment_endpoint_ref("POST", target_url)
        cleanup_endpoint_ref = experiment_endpoint_ref("POST", cleanup_url)
        if target_endpoint_ref == cleanup_endpoint_ref:
            raise ValueError("capability effect cleanup endpoint must be distinct")
        values = {
            "run_ref": stable_hash("capability_effect_run", run_id),
            "target_request_ref": _request_ref(
                "capability_effect_target_request",
                target_url,
            ),
            "cleanup_request_ref": _request_ref(
                "capability_effect_cleanup_request",
                cleanup_url,
            ),
            "target_endpoint_ref": target_endpoint_ref,
            "cleanup_endpoint_ref": cleanup_endpoint_ref,
        }
        return cls(
            specification_id=stable_hash(
                "capability_effect_one_click_specification",
                values,
            ),
            target_url=target_url,
            cleanup_url=cleanup_url,
            **values,
        )

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.target_url)
            origin = _canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
            target_url = _validated_url(
                self.target_url,
                target_origin=origin,
                field_name="capability effect target url",
            )
            cleanup_url = _validated_url(
                self.cleanup_url,
                target_origin=origin,
                field_name="capability effect cleanup url",
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capability effect specification is invalid") from exc
        values = {
            "run_ref": self.run_ref,
            "target_request_ref": self.target_request_ref,
            "cleanup_request_ref": self.cleanup_request_ref,
            "target_endpoint_ref": self.target_endpoint_ref,
            "cleanup_endpoint_ref": self.cleanup_endpoint_ref,
        }
        if (
            self.specification_id
            != stable_hash("capability_effect_one_click_specification", values)
            or not _hash_ref(
                self.specification_id,
                "capability_effect_one_click_specification",
            )
            or not _hash_ref(self.run_ref, "capability_effect_run")
            or self.target_request_ref
            != _request_ref("capability_effect_target_request", target_url)
            or self.cleanup_request_ref
            != _request_ref("capability_effect_cleanup_request", cleanup_url)
            or self.target_endpoint_ref != experiment_endpoint_ref("POST", target_url)
            or self.cleanup_endpoint_ref != experiment_endpoint_ref("POST", cleanup_url)
            or self.target_endpoint_ref == self.cleanup_endpoint_ref
        ):
            raise ValueError("capability effect specification is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "specification_id": self.specification_id,
            "run_ref": self.run_ref,
            "target_request_ref": self.target_request_ref,
            "cleanup_request_ref": self.cleanup_request_ref,
            "target_endpoint_ref": self.target_endpoint_ref,
            "cleanup_endpoint_ref": self.cleanup_endpoint_ref,
        }


@dataclass(frozen=True)
class _CapabilityReceiptContext:
    world: ExperimentWorldBinding
    contract: IssuedCapabilityContract
    admission: AdmittedRuntimeContract
    valid_decision: CapabilityDecision
    inadmissible_decision: CapabilityDecision
    first_consumption: ConsumptionDecision
    replay_consumption: ConsumptionDecision
    valid_presentation: CapabilityPresentation
    inadmissible_presentation: CapabilityPresentation
    baseline_epoch: float
    live_epoch: float
    expired_epoch: float

    def phase_receipt(self, observation_kind: str) -> CapabilityExecutionReceipt:
        logical = (
            self.inadmissible_decision
            if observation_kind == "inadmissible_capability_probe"
            else self.valid_decision
        )
        consumption = (
            self.replay_consumption
            if observation_kind == "replayed_capability_probe"
            else self.first_consumption
        )
        if observation_kind == "no_capability_baseline":
            observed = self.baseline_epoch
        elif observation_kind == "expired_capability_probe":
            observed = self.expired_epoch
        else:
            observed = self.live_epoch
        return evaluate_capability_execution(
            logical,
            self.admission,
            consumption,
            clock=lambda: observed,
        )

    def phase_body(self, observation_kind: str) -> Dict[str, Any]:
        presented = observation_kind != "no_capability_baseline"
        presentation = (
            self.inadmissible_presentation
            if observation_kind == "inadmissible_capability_probe"
            else self.valid_presentation
        )
        observed = (
            self.baseline_epoch
            if observation_kind == "no_capability_baseline"
            else (
                self.expired_epoch
                if observation_kind == "expired_capability_probe"
                else self.live_epoch
            )
        )
        return {
            "schema_version": 1,
            "mode": CAPABILITY_EFFECT_EXECUTION_MODE,
            "observation_kind": observation_kind,
            "capability_ref": self.contract.capability_id if presented else None,
            "presentation": presentation.to_dict() if presented else None,
            "runtime": {
                "admitted_at_epoch": repr(self.admission.admitted_at_epoch),
                "expires_at_epoch": repr(self.admission.expires_at_epoch),
                "observed_epoch": repr(observed),
            },
        }


def _build_receipt_context(
    *,
    specification: CapabilityEffectOneClickSpecification,
    target_origin: str,
    persona_id: str,
    authorization: AuthorizationEnvelope,
    evidence_records: Sequence[Mapping[str, Any]],
    clock: Callable[[], object],
) -> _CapabilityReceiptContext:
    observed = clock()
    if type(observed) is not float or not math.isfinite(observed):
        raise ValueError("capability effect clock reading is invalid")
    world = ExperimentWorldBinding.build(
        slot="actor",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", persona_id),
        persona_ref=experiment_persona_ref(persona_id),
        ownership_ref=experiment_ownership_ref(authorization, persona_id),
    )
    authority_ref = experiment_authority_context_ref(
        authorization,
        target_origin,
        (CAPABILITY_EFFECT_WORKFLOW,),
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
    source_evidence_ref = graph_bound_capture_artifact_ref(
        evidence_records,
        target_origin=target_origin,
        world_id=world.binding_id,
    )
    contract = IssuedCapabilityContract.build(
        world=world,
        world_tenant_ref=tenant_ref,
        world_tenant_ownership_ref=tenant_ownership_ref,
        subject_ref=world.persona_ref,
        resource_ref=stable_hash(
            "capability_resource",
            specification.target_request_ref,
        ),
        operation_ref=stable_hash(
            "capability_operation",
            specification.target_endpoint_ref,
        ),
        audience_ref=world.persona_ref,
        issuer_ref=stable_hash("capability_issuer", authority_ref),
        tenant_ref=tenant_ref,
        tenant_ownership_ref=tenant_ownership_ref,
        source_evidence_ref=source_evidence_ref,
        secret_digest=stable_hash(
            "capability_secret_digest",
            {
                "specification_id": specification.specification_id,
                "attestation_signature": authorization.attestation_signature,
            },
        ),
        issued_at_index=0,
        expires_at_index=2,
        max_uses=1,
        revocation_state=CapabilityRevocationState.ACTIVE,
    )
    valid_presentation = CapabilityPresentation.build(
        resource_ref=contract.resource_ref,
        account_ref=contract.subject_ref,
        audience_ref=contract.audience_ref,
        operation_ref=contract.operation_ref,
        at_index=contract.issued_at_index,
        use_index=0,
    )
    inadmissible_presentation = CapabilityPresentation.build(
        resource_ref=stable_hash(
            "capability_resource",
            specification.cleanup_request_ref,
        ),
        account_ref=contract.subject_ref,
        audience_ref=contract.audience_ref,
        operation_ref=contract.operation_ref,
        at_index=contract.issued_at_index,
        use_index=0,
    )
    valid_decision = classify_presentation(contract, valid_presentation)
    inadmissible_decision = classify_presentation(
        contract,
        inadmissible_presentation,
    )
    if (
        valid_decision.outcome is not CapabilityOutcome.VALID
        or inadmissible_decision.outcome is not CapabilityOutcome.WRONG_BINDING
    ):
        raise ValueError("capability effect logical state is invalid")
    binding = ConfinedPresentationBinding.build(
        contract=contract,
        capability_ref=contract.capability_id,
        confined_world=world,
        confined_tenant_ref=tenant_ref,
        confined_tenant_ownership_ref=tenant_ownership_ref,
        target_origin=target_origin,
        prior_presentation_records=evidence_records,
        current_presentation_records=evidence_records,
    )
    confinement_presentation = ConfinementPresentation.build(
        presented_world_ref=world.binding_id,
        presented_tenant_ref=tenant_ref,
        presented_tenant_ownership_ref=tenant_ownership_ref,
        presented_target_origin=target_origin,
        current_capture_records=evidence_records,
    )
    confinement = evaluate_confinement(
        contract,
        binding,
        confinement_presentation,
    )
    first = evaluate_consumption(
        contract,
        valid_decision,
        confinement,
        CapabilityConsumptionLedger.build(),
    )
    replay = evaluate_consumption(
        contract,
        valid_decision,
        confinement,
        first.ledger,
    )
    admitted_at = observed - 1.0
    expires_at = observed + 60.0
    admission = AdmittedRuntimeContract.build(
        contract=contract,
        capability_ref=contract.capability_id,
        runtime_ref=stable_hash(
            "admitted_runtime",
            specification.specification_id,
        ),
        admitted_at_epoch=admitted_at,
        expires_at_epoch=expires_at,
    )
    return _CapabilityReceiptContext(
        world=world,
        contract=contract,
        admission=admission,
        valid_decision=valid_decision,
        inadmissible_decision=inadmissible_decision,
        first_consumption=first.decision,
        replay_consumption=replay.decision,
        valid_presentation=valid_presentation,
        inadmissible_presentation=inadmissible_presentation,
        baseline_epoch=admitted_at - 1.0,
        live_epoch=observed,
        expired_epoch=expires_at,
    )


def _response_mapping(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_RESPONSE_BYTES:
        raise ValueError("capability effect target response is invalid")
    if getattr(value, "body_truncated", False):
        raise ValueError("capability effect target response is truncated")
    parsed = json.loads(value)
    if not isinstance(parsed, Mapping):
        raise ValueError("capability effect target response is invalid")
    return parsed


def _target_response(
    *,
    status: object,
    response: object,
    terminal_receipt: CapabilityExecutionReceipt,
) -> Tuple[int, Mapping[str, Any]]:
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 100 <= status <= 599
    ):
        raise ValueError("capability effect target status is invalid")
    value = _response_mapping(response)
    if not _RESPONSE_FIELDS <= set(value):
        raise ValueError("capability effect target response fields are invalid")
    access_decision = value["access_decision"]
    target_projection_observed = value["target_projection_observed"]
    if (
        not isinstance(access_decision, str)
        or type(target_projection_observed) is not bool
    ):
        raise ValueError("capability effect target projection is invalid")
    raw_effect = value["effect"]
    effect_ref = (
        stable_hash("capability_protected_effect", raw_effect)
        if raw_effect is not None
        else None
    )
    return status, {
        "terminal_receipt": terminal_receipt,
        "access_decision": access_decision,
        "effect": effect_ref,
        "target_projection_observed": target_projection_observed,
    }


class PolicyExecutorCapabilityEffectTransport:
    """One concrete, ordered, single-use adapter over ``PolicyExecutor``."""

    def __init__(
        self,
        *,
        executor: PolicyExecutor,
        specification: CapabilityEffectOneClickSpecification,
        context: _CapabilityReceiptContext,
        persona_id: str,
    ) -> None:
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("capability effect policy executor is invalid")
        if not isinstance(specification, CapabilityEffectOneClickSpecification):
            raise TypeError("capability effect specification is invalid")
        if type(context) is not _CapabilityReceiptContext:
            raise TypeError("capability effect receipt context is invalid")
        if not isinstance(persona_id, str) or not persona_id:
            raise ValueError("capability effect persona is invalid")
        self._executor = executor
        self._specification = specification
        self._context = context
        self._persona_id = persona_id
        self._lock = asyncio.Lock()
        self._prepared: Dict[
            str,
            Tuple[int, Mapping[str, Any]],
        ] = {}
        self._next_index = 0
        self._preparation_started = False
        self._cleanup_called = False
        self._witness_receipt: Optional[CapabilityExecutionReceipt] = None

    def _candidate(self, observation_kind: str) -> CandidateAction:
        return CandidateAction(
            method="POST",
            url=self._specification.target_url,
            body=self._context.phase_body(observation_kind),
            hint=AUTHZ_PROBE,
            actor_persona_id=self._persona_id,
            target_owner_persona_id=self._persona_id,
            target_is_researcher_owned=True,
            expected_side_effect=observation_kind,
            proof_goal="observe_one_time_capability_effect",
        )

    async def _send_phase(
        self,
        observation_kind: str,
    ) -> Tuple[int, Mapping[str, Any]]:
        action = self._candidate(observation_kind)
        if observation_kind == "valid_capability_effect_witness":
            claim = self._executor.claim_proposal_action(action)
            if claim is None or claim.max_requests != 1:
                raise RuntimeError("capability_effect_witness_claim_denied")
            status, response = await self._executor.send_claimed_action(action, claim)
        else:
            status, response = await self._executor.send_action(action)
        if status == DENIED_STATUS:
            raise RuntimeError("capability_effect_policy_denied")
        receipt = self._context.phase_receipt(observation_kind)
        if receipt.outcome is not _EXPECTED_OUTCOMES[observation_kind]:
            raise RuntimeError("capability_effect_receipt_outcome_invalid")
        return _target_response(
            status=status,
            response=response,
            terminal_receipt=receipt,
        )

    async def prepare(self) -> CapabilityExecutionReceipt:
        """Send baseline then witness once and return the real-outcome witness receipt."""

        async with self._lock:
            if self._preparation_started:
                raise RuntimeError("capability_effect_transport_already_prepared")
            self._preparation_started = True
            for kind in _OBSERVATION_KINDS[:2]:
                self._prepared[kind] = await self._send_phase(kind)
            witness = self._prepared["valid_capability_effect_witness"][1][
                "terminal_receipt"
            ]
            if type(witness) is not CapabilityExecutionReceipt:
                raise RuntimeError("capability_effect_witness_receipt_invalid")
            self._witness_receipt = replace(witness)
            return replace(self._witness_receipt)

    def _validate_dispatch_request(
        self,
        request: Mapping[str, Any],
        observation_kind: str,
    ) -> None:
        expected_fields = {
            "schema_version",
            "mode",
            "observation_kind",
            "expected_receipt_outcome",
            "witness_receipt_ref",
            "capability_ref",
            "observation_binding_id",
            "owned_world_ref",
            "owned_persona_ref",
            "ownership_ref",
        }
        witness_receipt = self._witness_receipt
        if (
            not isinstance(request, Mapping)
            or set(request) != expected_fields
            or type(request.get("schema_version")) is not int
            or request.get("schema_version") != 1
            or request.get("mode") != CAPABILITY_EFFECT_EXECUTION_MODE
            or request.get("observation_kind") != observation_kind
            or request.get("expected_receipt_outcome")
            != _EXPECTED_OUTCOMES[observation_kind].value
            or type(witness_receipt) is not CapabilityExecutionReceipt
            or request.get("witness_receipt_ref") != witness_receipt.receipt_id
            or request.get("capability_ref") != self._context.contract.capability_id
            or request.get("observation_binding_id") != self._context.world.binding_id
            or request.get("owned_world_ref") != self._context.world.world_ref
            or request.get("owned_persona_ref") != self._context.world.persona_ref
            or request.get("ownership_ref") != self._context.world.ownership_ref
        ):
            raise RuntimeError("capability_effect_dispatch_request_invalid")

    async def dispatch(
        self,
        request: Mapping[str, Any],
    ) -> Tuple[int, Mapping[str, Any]]:
        async with self._lock:
            if not self._preparation_started or self._next_index >= len(
                _OBSERVATION_KINDS
            ):
                raise RuntimeError("capability_effect_transport_not_available")
            observation_kind = _OBSERVATION_KINDS[self._next_index]
            self._validate_dispatch_request(request, observation_kind)
            self._next_index += 1
            if observation_kind in self._prepared:
                return self._prepared.pop(observation_kind)
            return await self._send_phase(observation_kind)

    def _requests_sent(self) -> int:
        value = self._executor.restraint_summary().get("requests_sent")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("capability effect request count is invalid")
        return value

    def _uncertain_cleanup(
        self, *, request_may_have_been_sent: bool
    ) -> CapabilityCleanupResult:
        try:
            target_requests_sent = self._requests_sent()
        except (AttributeError, TypeError, ValueError):
            target_requests_sent = 0
        return CapabilityCleanupResult(
            status="uncertain",
            target_requests_sent=target_requests_sent,
            target_request_may_have_been_sent=request_may_have_been_sent,
            orphaned_owned_state_possible=True,
        )

    async def cleanup(
        self,
        request: Mapping[str, Any],
    ) -> CapabilityCleanupResult:
        async with self._lock:
            if self._cleanup_called:
                return self._uncertain_cleanup(
                    request_may_have_been_sent=False,
                )
            self._cleanup_called = True
            expected_fields = {
                "schema_version",
                "mode",
                "capability_ref",
                "witness_receipt_ref",
                "observation_binding_id",
                "owned_world_ref",
                "observation_refs",
            }
            witness = self._context.phase_receipt("valid_capability_effect_witness")
            request_valid = bool(
                isinstance(request, Mapping)
                and set(request) == expected_fields
                and type(request.get("schema_version")) is int
                and request.get("schema_version") == 1
                and request.get("mode") == CAPABILITY_EFFECT_EXECUTION_MODE
                and request.get("capability_ref")
                == self._context.contract.capability_id
                and request.get("witness_receipt_ref") == witness.receipt_id
                and request.get("observation_binding_id")
                == self._context.world.binding_id
                and request.get("owned_world_ref") == self._context.world.world_ref
                and isinstance(request.get("observation_refs"), list)
                and all(
                    _hash_ref(item, "capability_effect_observation")
                    for item in request.get("observation_refs", [])
                )
            )
            body = {
                "schema_version": 1,
                "mode": CAPABILITY_EFFECT_ONE_CLICK_MODE,
                "capability_ref": self._context.contract.capability_id,
                "witness_receipt_ref": witness.receipt_id,
                "observation_binding_id": self._context.world.binding_id,
                "observation_refs": (
                    list(request.get("observation_refs", [])) if request_valid else []
                ),
            }
            action = CandidateAction(
                method="POST",
                url=self._specification.cleanup_url,
                body=body,
                hint=OWNED_UPDATE_LOW_RISK,
                actor_persona_id=self._persona_id,
                target_owner_persona_id=self._persona_id,
                target_is_researcher_owned=True,
                expected_side_effect="compensate_capability_effect",
                proof_goal="verify_no_orphaned_owned_state",
            )
            request_may_have_been_sent = True
            try:
                status, response = await self._executor.send_action(action)
                request_may_have_been_sent = False
                count = self._requests_sent()
                if status == DENIED_STATUS:
                    raise RuntimeError("capability_effect_cleanup_policy_denied")
                value = _response_mapping(response)
                verified = bool(
                    request_valid
                    and 200 <= status < 300
                    and _CLEANUP_RESPONSE_FIELDS <= set(value)
                    and value.get("cleanup_verified") is True
                    and value.get("orphaned_owned_state_possible") is False
                    and value.get("target_projection_observed") is True
                )
                if verified:
                    return CapabilityCleanupResult(
                        status="verified",
                        target_requests_sent=count,
                        target_request_may_have_been_sent=False,
                        orphaned_owned_state_possible=False,
                    )
                return CapabilityCleanupResult(
                    status="uncertain",
                    target_requests_sent=count,
                    target_request_may_have_been_sent=False,
                    orphaned_owned_state_possible=True,
                )
            except BaseException:
                return self._uncertain_cleanup(
                    request_may_have_been_sent=request_may_have_been_sent,
                )


class CapabilityEffectOneClickDenied(RuntimeError):
    """R5D9 failed before R5D8 could own the terminal denial."""

    def __init__(
        self,
        reason: str,
        *,
        cleanup: Optional[CapabilityCleanupResult] = None,
    ) -> None:
        if not isinstance(reason, str) or _SEMANTIC.fullmatch(reason) is None:
            raise ValueError("capability effect one-click denial reason is invalid")
        if cleanup is not None and type(cleanup) is not CapabilityCleanupResult:
            raise TypeError("cleanup must be a CapabilityCleanupResult")
        super().__init__(reason)
        self.cleanup = cleanup


@dataclass(frozen=True)
class CapabilityEffectFindingCandidate:
    candidate_id: str
    result_id: str
    oracle_evaluation_id: str
    observation_binding_id: str
    observation_refs: Tuple[str, ...]
    authorized_effect_ref: str
    _result: CapabilityEffectExecutionResult = field(repr=False, compare=False)
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    @classmethod
    def from_result(
        cls,
        result: CapabilityEffectExecutionResult,
    ) -> "CapabilityEffectFindingCandidate":
        if type(result) is not CapabilityEffectExecutionResult:
            raise TypeError("capability effect result is invalid")
        rebuilt = replace(result)
        oracle = rebuilt.oracle
        if (
            oracle.verdict
            is not CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
            or oracle.finding_candidate_ref is None
            or oracle.authorized_effect_ref is None
        ):
            raise ValueError("capability effect result is not a confirmed candidate")
        return cls(
            candidate_id=oracle.finding_candidate_ref,
            result_id=rebuilt.result_id,
            oracle_evaluation_id=oracle.evaluation_id,
            observation_binding_id=rebuilt.observation_binding_id,
            observation_refs=oracle.observation_refs,
            authorized_effect_ref=oracle.authorized_effect_ref,
            _result=rebuilt,
        )

    def __post_init__(self) -> None:
        try:
            if type(self._result) is not CapabilityEffectExecutionResult:
                raise TypeError("result must be a CapabilityEffectExecutionResult")
            result = replace(self._result)
        except (TypeError, ValueError) as exc:
            raise ValueError("capability effect finding candidate is invalid") from exc
        oracle = result.oracle
        if (
            self.candidate_id != oracle.finding_candidate_ref
            or self.result_id != result.result_id
            or self.oracle_evaluation_id != oracle.evaluation_id
            or self.observation_binding_id != result.observation_binding_id
            or self.observation_refs != oracle.observation_refs
            or self.authorized_effect_ref != oracle.authorized_effect_ref
            or oracle.verdict
            is not CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("capability effect finding candidate is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "candidate_id": self.candidate_id,
            "result_id": self.result_id,
            "oracle_evaluation_id": self.oracle_evaluation_id,
            "observation_binding_id": self.observation_binding_id,
            "observation_refs": list(self.observation_refs),
            "authorized_effect_ref": self.authorized_effect_ref,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        }


@dataclass(frozen=True)
class CapabilityEffectOneClickRun:
    status: str
    specification_id: str
    target_request_ref: str
    cleanup_request_ref: str
    disabled_gates: Tuple[str, ...] = ()
    execution: Optional[CapabilityEffectExecutionResult] = field(
        default=None,
        repr=False,
        compare=False,
    )
    candidate: Optional[CapabilityEffectFindingCandidate] = None
    mode: str = CAPABILITY_EFFECT_ONE_CLICK_MODE
    promotion_authority: bool = False
    finding_authority: bool = False

    @classmethod
    def disabled(
        cls,
        specification: CapabilityEffectOneClickSpecification,
    ) -> "CapabilityEffectOneClickRun":
        return cls(
            status="selected_execution_disabled",
            specification_id=specification.specification_id,
            target_request_ref=specification.target_request_ref,
            cleanup_request_ref=specification.cleanup_request_ref,
            disabled_gates=(CAPABILITY_EFFECT_EXECUTION_ENV,),
        )

    def __post_init__(self) -> None:
        try:
            execution = (
                replace(self.execution)
                if type(self.execution) is CapabilityEffectExecutionResult
                else None
            )
            candidate = (
                replace(self.candidate)
                if type(self.candidate) is CapabilityEffectFindingCandidate
                else None
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capability effect one-click run is invalid") from exc
        completed = self.status == "completed"
        disabled = self.status == "selected_execution_disabled"
        confirmed = bool(
            execution is not None
            and execution.oracle.verdict
            is CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
        )
        expected_candidate = (
            CapabilityEffectFindingCandidate.from_result(execution)
            if confirmed and execution is not None
            else None
        )
        if (
            self.mode != CAPABILITY_EFFECT_ONE_CLICK_MODE
            or not (completed or disabled)
            or not _hash_ref(
                self.specification_id,
                "capability_effect_one_click_specification",
            )
            or not _hash_ref(
                self.target_request_ref,
                "capability_effect_target_request",
            )
            or not _hash_ref(
                self.cleanup_request_ref,
                "capability_effect_cleanup_request",
            )
            or completed != (execution is not None)
            or (self.execution is not None and execution is None)
            or disabled != bool(self.disabled_gates)
            or (disabled and self.disabled_gates != (CAPABILITY_EFFECT_EXECUTION_ENV,))
            or (self.candidate is not None and candidate is None)
            or candidate != expected_candidate
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError("capability effect one-click run is invalid")

    @property
    def selected(self) -> bool:
        return True

    @property
    def dispatched(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> Dict[str, Any]:
        execution = self.execution
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "specification_id": self.specification_id,
            "target_request_ref": self.target_request_ref,
            "cleanup_request_ref": self.cleanup_request_ref,
            "disabled_gates": list(self.disabled_gates),
            "dispatched": self.dispatched,
            "result_id": execution.result_id if execution is not None else None,
            "receipt_id": execution.receipt_id if execution is not None else None,
            "capability_ref": (
                execution.capability_ref if execution is not None else None
            ),
            "observation_binding_id": (
                execution.observation_binding_id if execution is not None else None
            ),
            "observation_refs": (
                list(execution.oracle.observation_refs) if execution is not None else []
            ),
            "oracle_evaluation_id": (
                execution.oracle.evaluation_id if execution is not None else None
            ),
            "oracle_verdict": (
                execution.oracle.verdict.value if execution is not None else None
            ),
            "cleanup": (execution.cleanup.to_dict() if execution is not None else None),
            "candidate": self.candidate.to_dict() if self.candidate else None,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        }

    def execution_response(self) -> Dict[str, Any]:
        if self.execution is None:
            raise CapabilityEffectOneClickDenied(
                "capability_effect_one_click_execution_is_missing"
            )
        return {
            "kind": "capability_effect_one_click",
            "status": self.execution.oracle.verdict.value,
            "execution": self.to_dict(),
            "finding": None,
            "finding_confirmed": False,
            "finding_candidate": (
                self.candidate.to_dict() if self.candidate is not None else None
            ),
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
            "capability_effect_one_click": self.to_dict(),
        }


class CapabilityEffectOneClickDispatcher:
    """Compose Foundry authority, concrete transport, and the frozen R5D8 executor."""

    def __init__(
        self,
        *,
        target_origin: str,
        persona_id: str,
        specification: CapabilityEffectOneClickSpecification,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        persona_vault: PersonaVault,
        evidence_records: Sequence[Mapping[str, Any]],
        config: Optional[CapabilityEffectExecutionConfig] = None,
        clock: Callable[[], object] = time.time,
    ) -> None:
        if not isinstance(specification, CapabilityEffectOneClickSpecification):
            raise TypeError("capability effect specification is required")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("capability effect authorization is invalid")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("capability effect executor is invalid")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("capability effect persona vault is invalid")
        if config is not None and type(config) is not CapabilityEffectExecutionConfig:
            raise TypeError("capability effect execution config is invalid")
        if not callable(clock):
            raise TypeError("capability effect clock is invalid")
        self.target_origin = _canonical_origin(target_origin)
        self.persona_id = persona_id
        self.specification = specification
        self.executor = executor
        self.config = config or CapabilityEffectExecutionConfig.from_environment()
        self._context: Optional[_CapabilityReceiptContext] = None
        if self.config.enabled:
            try:
                authorization.authorize_action(
                    target_origin=self.target_origin,
                    workflow=CAPABILITY_EFFECT_WORKFLOW,
                )
            except Exception as exc:
                raise CapabilityEffectOneClickDenied(
                    "capability_effect_authorization_denied"
                ) from exc
            persona = persona_vault.get_persona(persona_id)
            if persona is None or persona.persona_id != persona_id:
                raise CapabilityEffectOneClickDenied(
                    "capability_effect_owned_persona_unavailable"
                )
            try:
                self._context = _build_receipt_context(
                    specification=specification,
                    target_origin=self.target_origin,
                    persona_id=persona_id,
                    authorization=authorization,
                    evidence_records=evidence_records,
                    clock=clock,
                )
            except (RuntimeError, TypeError, ValueError) as exc:
                raise CapabilityEffectOneClickDenied(
                    "capability_effect_context_invalid"
                ) from exc

    async def run(self) -> CapabilityEffectOneClickRun:
        if not self.config.enabled:
            return CapabilityEffectOneClickRun.disabled(self.specification)
        context = self._context
        if context is None:
            raise CapabilityEffectOneClickDenied(
                "capability_effect_context_unavailable"
            )
        transport = PolicyExecutorCapabilityEffectTransport(
            executor=self.executor,
            specification=self.specification,
            context=context,
            persona_id=self.persona_id,
        )
        try:
            witness = await transport.prepare()
        except BaseException as exc:
            cleanup = await transport.cleanup(
                {
                    "schema_version": 1,
                    "mode": CAPABILITY_EFFECT_EXECUTION_MODE,
                    "capability_ref": context.contract.capability_id,
                    "witness_receipt_ref": context.phase_receipt(
                        "valid_capability_effect_witness"
                    ).receipt_id,
                    "observation_binding_id": context.world.binding_id,
                    "owned_world_ref": context.world.world_ref,
                    "observation_refs": [],
                }
            )
            reason = (
                "capability_effect_preparation_failed"
                if cleanup.status == "verified"
                else "capability_effect_cleanup_unverified"
            )
            raise CapabilityEffectOneClickDenied(
                reason,
                cleanup=cleanup,
            ) from exc
        try:
            execution = await CapabilityEffectExperimentExecutor(
                witness,
                transport=transport,
                config=self.config,
            ).execute()
        except CapabilityEffectExecutionDenied:
            raise
        candidate = (
            CapabilityEffectFindingCandidate.from_result(execution)
            if execution.oracle.verdict
            is CapabilityEffectOracleVerdict.CONFIRMED_ONE_TIME_AUTHORIZED_EFFECT
            else None
        )
        return CapabilityEffectOneClickRun(
            status="completed",
            specification_id=self.specification.specification_id,
            target_request_ref=self.specification.target_request_ref,
            cleanup_request_ref=self.specification.cleanup_request_ref,
            execution=execution,
            candidate=candidate,
        )


__all__ = [
    "CAPABILITY_EFFECT_ONE_CLICK_MODE",
    "CAPABILITY_EFFECT_WORKFLOW",
    "CapabilityEffectFindingCandidate",
    "CapabilityEffectOneClickDenied",
    "CapabilityEffectOneClickDispatcher",
    "CapabilityEffectOneClickRun",
    "CapabilityEffectOneClickSpecification",
    "PolicyExecutorCapabilityEffectTransport",
]
