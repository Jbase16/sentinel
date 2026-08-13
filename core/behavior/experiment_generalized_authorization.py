"""R5A3b single-use execution for locator-bound object authorization proofs.

This module is explicit-only.  Preparation revalidates one R5A2 admission,
rehydrates four bounded read actions, and asks the current ownership registry to
seal the exact treatment request.  Execution additionally requires an active R4B
claim and a separately enabled R5A3b gate.  No ordinary scan path imports it.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import (
    DENIED_STATUS,
    CandidateAction,
    LocatorRuntimePermit,
)
from core.foundry.vault import PersonaVault
from core.safety.action_classifier import CROSS_OBJECT_READ, SAFE_READ
from core.safety.ownership_locator import (
    LocatorOwnershipDenied,
    LocatorOwnershipProof,
    OwnedRequestLocatorKind,
    extract_locator_native_value,
    extract_locator_value,
    replace_locator_value,
)
from core.wraith import bola_replay

from .active import ControlledAuthorizationExecutor, ControlledExecutionResult
from .experiment_admission import (
    ExperimentRuntimeActionBinding,
    ProofExperimentAdmissionClaim,
    experiment_endpoint_ref,
)
from .experiment_authorization import (
    AdmittedAuthorizationExperimentConfig,
    AdmittedAuthorizationExperimentExecutor,
    AdmittedAuthorizationExperimentResult,
    _AuthorizationPreflight,
)
from .experiment_sdk import ExistingBackendKind, ProofExperimentManifest
from .lineage import RehydrationDenied
from .normalize import stable_hash
from .ownership_experiment import (
    GeneralizedOwnershipExperimentAdmission,
    GeneralizedOwnershipExperimentDenied,
    GeneralizedOwnershipExperimentProof,
    OwnershipExperimentAdmissionContract,
    OwnershipExperimentRoleBinding,
)
from .ownership_locators import (
    GeneralizedOwnershipLocatorCompiler,
    OwnershipProtocol,
)


GENERALIZED_AUTHORIZATION_EXECUTION_ENV = (
    "SENTINELFORGE_BEHAVIOR_GENERALIZED_AUTHORIZATION_EXECUTION"
)
GENERALIZED_AUTHORIZATION_EXECUTION_MODE = (
    "behavioral_generalized_authorization_execution_v1"
)

_TRUE = frozenset({"1", "true", "yes", "on"})
class GeneralizedAuthorizationExecutionDenied(RuntimeError):
    """The generalized plan or its single-use execution authority is invalid."""


@dataclass(frozen=True)
class GeneralizedAuthorizationExecutionConfig:
    enabled: bool = False

    @classmethod
    def from_environment(cls) -> "GeneralizedAuthorizationExecutionConfig":
        return cls(
            enabled=(
                os.environ.get(
                    GENERALIZED_AUTHORIZATION_EXECUTION_ENV,
                    "",
                ).strip().lower()
                in _TRUE
            )
        )


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise GeneralizedAuthorizationExecutionDenied(
            "generalized_authorization_target_origin_is_invalid"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _validate_read_semantics(
    *,
    method: str,
    body: Any,
    kind: OwnedRequestLocatorKind,
    pointer: str,
    protocol: OwnershipProtocol,
) -> None:
    normalized = str(method or "").upper()
    if normalized in {"GET", "HEAD"}:
        return
    if (
        normalized != "POST"
        or kind is not OwnedRequestLocatorKind.GRAPHQL_VARIABLE
        or protocol is not OwnershipProtocol.GRAPHQL
    ):
        raise GeneralizedAuthorizationExecutionDenied(
            "generalized_authorization_request_is_not_proven_read_only"
        )
    try:
        parsed = copy.deepcopy(body) if isinstance(body, (Mapping, list)) else json.loads(body)
    except (TypeError, ValueError) as exc:
        raise GeneralizedAuthorizationExecutionDenied(
            "generalized_authorization_graphql_item_is_invalid"
        ) from exc
    item: Any = parsed
    if isinstance(item, list):
        raw_index = pointer.split("/", 2)[1] if pointer.startswith("/") else ""
        try:
            index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_graphql_item_is_invalid"
            ) from exc
        if index < 0 or str(index) != raw_index or index >= len(item):
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_graphql_item_is_invalid"
            )
        item = item[index]
    query = item.get("query") if isinstance(item, Mapping) else None
    if (
        not isinstance(query, str)
        or not query.strip()
        or re.search(r"\b(?:mutation|subscription)\b", query, re.IGNORECASE)
        or re.match(r"^\s*(?:query\b|\{)", query, re.IGNORECASE) is None
    ):
        raise GeneralizedAuthorizationExecutionDenied(
            "generalized_authorization_graphql_read_is_unproven"
        )
def _headers(
    raw: Mapping[str, Any],
    *,
    kind: OwnedRequestLocatorKind,
) -> Tuple[Tuple[str, str], ...]:
    values = {str(key): str(value) for key, value in raw.items()}
    default = None
    if kind in {
        OwnedRequestLocatorKind.JSON,
        OwnedRequestLocatorKind.GRAPHQL_VARIABLE,
    }:
        default = "application/json"
    elif kind is OwnedRequestLocatorKind.FORM:
        default = "application/x-www-form-urlencoded"
    sanitized = bola_replay.sanitize_replay_headers(
        values,
        default_content_type=default,
    )
    lowered = [key.lower() for key in sanitized]
    if len(lowered) != len(set(lowered)):
        raise GeneralizedAuthorizationExecutionDenied(
            "generalized_authorization_headers_are_ambiguous"
        )
    return tuple(
        sorted(
            sanitized.items(),
            key=lambda item: (item[0].lower(), item[0]),
        )
    )


@dataclass(frozen=True, repr=False)
class _BoundRequest:
    method: str
    url: str
    body: Any = field(repr=False, compare=False)
    headers: Tuple[Tuple[str, str], ...] = field(repr=False, compare=False)
    value: str = field(repr=False, compare=False)
    typed_value: Any = field(repr=False, compare=False)


def _action_material(action: CandidateAction) -> Mapping[str, Any]:
    return {
        "method": str(action.method).upper(),
        "url": action.url,
        "body": action.body,
        "hint": action.hint,
        "actor_persona_id": action.actor_persona_id,
        "target_owner_persona_id": action.target_owner_persona_id,
        "target_is_researcher_owned": action.target_is_researcher_owned,
        "expected_side_effect": action.expected_side_effect,
        "proof_goal": action.proof_goal,
    }


def _candidate(
    *,
    request: _BoundRequest,
    actor: str,
    owner: str,
    hint: str,
) -> CandidateAction:
    return CandidateAction(
        method=request.method,
        url=request.url,
        body=copy.deepcopy(request.body),
        hint=hint,
        actor_persona_id=actor,
        target_owner_persona_id=owner,
        target_is_researcher_owned=True,
        expected_side_effect="none",
        proof_goal="single_generalized_authorization_counterexample",
    )


def _plan_payload(
    *,
    manifest_id: str,
    ownership_proof_id: str,
    ownership_admission_id: str,
    locator_proof_ref: str,
    action_ids: Sequence[str],
    actions: Sequence[CandidateAction],
    transport_context_refs: Sequence[str],
) -> Mapping[str, Any]:
    return {
        "mode": GENERALIZED_AUTHORIZATION_EXECUTION_MODE,
        "manifest_id": manifest_id,
        "ownership_proof_id": ownership_proof_id,
        "ownership_admission_id": ownership_admission_id,
        "locator_proof_ref": locator_proof_ref,
        "action_ids": list(action_ids),
        "action_refs": [
            stable_hash("generalized_runtime_action", _action_material(item))
            for item in actions
        ],
        "transport_context_refs": list(transport_context_refs),
        "target_requests_sent": 0,
        "budget_reserved": False,
        "execution_authority": False,
    }


@dataclass(frozen=True, repr=False)
class PreparedGeneralizedAuthorizationExperiment:
    plan_ref: str
    manifest_id: str
    ownership_proof_id: str
    ownership_admission_id: str
    locator_proof: LocatorOwnershipProof = field(repr=False, compare=False)
    action_ids: Tuple[str, ...]
    _actions: Tuple[CandidateAction, ...] = field(repr=False, compare=False)
    _headers: Tuple[Tuple[Tuple[str, str], ...], ...] = field(
        repr=False,
        compare=False,
    )
    _transport_context_refs: Tuple[str, ...] = field(
        repr=False,
        compare=False,
    )
    _actor_value: str = field(repr=False, compare=False)
    _owner_value: str = field(repr=False, compare=False)
    mode: str = GENERALIZED_AUTHORIZATION_EXECUTION_MODE
    target_requests_sent: int = 0
    budget_reserved: bool = False
    execution_authority: bool = False

    def __post_init__(self) -> None:
        payload = _plan_payload(
            manifest_id=self.manifest_id,
            ownership_proof_id=self.ownership_proof_id,
            ownership_admission_id=self.ownership_admission_id,
            locator_proof_ref=self.locator_proof.proof_ref,
            action_ids=self.action_ids,
            actions=self._actions,
            transport_context_refs=self._transport_context_refs,
        )
        if (
            self.plan_ref
            != stable_hash("generalized_authorization_plan", payload)
            or self.mode != GENERALIZED_AUTHORIZATION_EXECUTION_MODE
            or not self.manifest_id.startswith("proof_experiment_manifest:")
            or not self.ownership_proof_id.startswith(
                "ownership_experiment_proof:"
            )
            or not self.ownership_admission_id.startswith(
                "ownership_experiment_admission:"
            )
            or not isinstance(self.locator_proof, LocatorOwnershipProof)
            or len(self.action_ids) != 4
            or len(set(self.action_ids)) != 4
            or len(self._actions) != 4
            or len(self._headers) != 4
            or len(self._transport_context_refs) != 4
            or any(
                not item.startswith("locator_transport_context:")
                for item in self._transport_context_refs
            )
            or any(item.budget_reservation_id is not None for item in self._actions)
            or not self._actor_value
            or not self._owner_value
            or self._actor_value == self._owner_value
            or self.target_requests_sent != 0
            or self.budget_reserved
            or self.execution_authority
        ):
            raise ValueError(
                "prepared generalized authorization contract is invalid"
            )

    @property
    def actions(self) -> Tuple[CandidateAction, ...]:
        return copy.deepcopy(self._actions)

    @property
    def runtime_actions(self) -> Mapping[str, CandidateAction]:
        return {
            action_id: copy.deepcopy(action)
            for action_id, action in zip(
                self.action_ids,
                self._actions,
                strict=True,
            )
        }

    @property
    def locator_ownership_proofs(self) -> Mapping[str, LocatorOwnershipProof]:
        return {self.action_ids[2]: copy.deepcopy(self.locator_proof)}

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "schema_version": 1,
            "plan_ref": self.plan_ref,
            **_plan_payload(
                manifest_id=self.manifest_id,
                ownership_proof_id=self.ownership_proof_id,
                ownership_admission_id=self.ownership_admission_id,
                locator_proof_ref=self.locator_proof.proof_ref,
                action_ids=self.action_ids,
                actions=self._actions,
                transport_context_refs=self._transport_context_refs,
            ),
        }


class GeneralizedAuthorizationExecutionPlanner:
    """Prepare an exact R5A3b runtime plan without traffic or budget authority."""

    def __init__(
        self,
        *,
        manifest: ProofExperimentManifest,
        ownership_proof: GeneralizedOwnershipExperimentProof,
        ownership_admission: OwnershipExperimentAdmissionContract,
        backend: ControlledAuthorizationExecutor,
    ) -> None:
        if not isinstance(manifest, ProofExperimentManifest):
            raise TypeError("manifest must be a ProofExperimentManifest")
        if not isinstance(
            ownership_proof,
            GeneralizedOwnershipExperimentProof,
        ):
            raise TypeError(
                "ownership_proof must be a GeneralizedOwnershipExperimentProof"
            )
        if not isinstance(
            ownership_admission,
            OwnershipExperimentAdmissionContract,
        ):
            raise TypeError(
                "ownership_admission must be an OwnershipExperimentAdmissionContract"
            )
        if not isinstance(backend, ControlledAuthorizationExecutor):
            raise TypeError("backend must be a ControlledAuthorizationExecutor")
        self.manifest = manifest
        self.ownership_proof = ownership_proof
        self.ownership_admission = ownership_admission
        self.backend = backend
        self.locator_compiler = GeneralizedOwnershipLocatorCompiler()

    def _request(
        self,
        records: Sequence[Mapping[str, Any]],
        role: OwnershipExperimentRoleBinding,
    ) -> _BoundRequest:
        index = self.locator_compiler.compile(copy.deepcopy(tuple(records)))
        if index.capture_digest != role.capture_digest:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_capture_digest_changed"
            )
        try:
            request = index.rehydrate_use(
                evidence_id=role.ownership_evidence_id,
                use_id=role.ownership_use_id,
            )
        except RehydrationDenied as exc:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_request_rehydration_failed"
            ) from exc
        if (
            request.source_ref != role.source_ref
            or request.request_digest != role.request_digest
            or request.operation_id != role.operation_id
            or _canonical_origin(request.url) != self.backend.target_origin
            or experiment_endpoint_ref(request.method, request.url)
            != role.endpoint_ref
        ):
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_bound_request_changed"
            )
        kind = OwnedRequestLocatorKind(role.locator_kind.value)
        try:
            value = extract_locator_value(
                kind=kind,
                pointer=role.locator_pointer,
                url=request.url,
                body=request.body,
            )
        except LocatorOwnershipDenied as exc:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_locator_rehydration_failed"
            ) from exc
        if stable_hash(
            "lineage_value",
            {
                "capture_digest": role.capture_digest,
                "value": value,
            },
        ) != role.value_hash:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_owned_value_changed"
            )
        _validate_read_semantics(
            method=request.method,
            body=request.body,
            kind=kind,
            pointer=role.locator_pointer,
            protocol=role.protocol,
        )
        typed_value = extract_locator_native_value(
            kind=kind,
            pointer=role.locator_pointer,
            url=request.url,
            body=request.body,
        )
        return _BoundRequest(
            method=request.method,
            url=request.url,
            body=copy.deepcopy(request.body),
            headers=_headers(request.headers, kind=kind),
            value=value,
            typed_value=typed_value,
        )

    def prepare(
        self,
        *,
        actor_records: Sequence[Mapping[str, Any]],
        target_owner_records: Sequence[Mapping[str, Any]],
    ) -> PreparedGeneralizedAuthorizationExperiment:
        self.backend.validate_preflight()
        if (
            self.ownership_proof.manifest_id != self.manifest.manifest_id
            or self.ownership_admission.manifest_id != self.manifest.manifest_id
            or self.ownership_admission.proof_id
            != self.ownership_proof.proof_id
        ):
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_manifest_or_admission_mismatch"
            )
        try:
            fresh_admission = GeneralizedOwnershipExperimentAdmission(
                proof=self.ownership_proof,
                manifest=self.manifest,
                target_origin=self.backend.target_origin,
                authorization=self.backend.authorization,
                actor_records=actor_records,
                target_owner_records=target_owner_records,
            ).admit()
        except GeneralizedOwnershipExperimentDenied as exc:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_r5a2_revalidation_failed"
            ) from exc
        if fresh_admission.to_dict() != self.ownership_admission.to_dict():
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_r5a2_admission_changed"
            )

        actor = self._request(actor_records, self.ownership_proof.actor)
        owner = self._request(
            target_owner_records,
            self.ownership_proof.target_owner,
        )
        kind = OwnedRequestLocatorKind(
            self.ownership_proof.actor.locator_kind.value
        )
        try:
            treatment_url, treatment_body = replace_locator_value(
                kind=kind,
                pointer=self.ownership_proof.actor.locator_pointer,
                url=actor.url,
                body=actor.body,
                expected_value=actor.value,
                replacement_value=owner.typed_value,
            )
        except LocatorOwnershipDenied as exc:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_locator_replacement_failed"
            ) from exc
        treatment = _BoundRequest(
            method=actor.method,
            url=treatment_url,
            body=treatment_body,
            headers=actor.headers,
            value=owner.value,
            typed_value=owner.typed_value,
        )
        actor_id = self.backend.source_persona.persona_id
        owner_id = self.backend.peer_persona.persona_id
        actions = (
            _candidate(
                request=owner,
                actor=owner_id,
                owner=owner_id,
                hint=SAFE_READ,
            ),
            _candidate(
                request=actor,
                actor=actor_id,
                owner=actor_id,
                hint=SAFE_READ,
            ),
            _candidate(
                request=treatment,
                actor=actor_id,
                owner=owner_id,
                hint=CROSS_OBJECT_READ,
            ),
            _candidate(
                request=owner,
                actor=owner_id,
                owner=owner_id,
                hint=SAFE_READ,
            ),
        )
        action_ids = tuple(item.action_id for item in self.manifest.actions)
        if (
            len(action_ids) != 4
            or self.manifest.actions[2].action_id
            != self.ownership_proof.treatment_action_id
            or self.manifest.actions[3].action_id
            != self.ownership_proof.witness_action_id
        ):
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_manifest_action_shape_changed"
            )
        source_executor = self.backend.executors[actor_id]
        registry = source_executor.policy.ownership_registry
        if registry is None:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_ownership_registry_is_unavailable"
            )
        try:
            locator_proof = registry.issue_locator_proof(
                source_proof_ref=self.ownership_proof.proof_id,
                source_role_binding_ref=(
                    self.ownership_proof.target_owner.role_binding_id
                ),
                actor_persona_id=actor_id,
                target_owner_persona_id=owner_id,
                method=actions[2].method,
                url=actions[2].url,
                body=actions[2].body,
                locator_kind=kind,
                locator_pointer=self.ownership_proof.actor.locator_pointer,
            )
        except LocatorOwnershipDenied as exc:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_locator_proof_denied"
            ) from exc
        verification = source_executor.policy.verify_locator_ownership(
            actions[2],
            locator_proof,
        )
        if not verification.verified:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_locator_proof_did_not_verify"
            )
        headers = (owner.headers, actor.headers, actor.headers, owner.headers)
        transport_context_refs = tuple(
            registry.transport_context_ref(dict(item)) for item in headers
        )
        payload = _plan_payload(
            manifest_id=self.manifest.manifest_id,
            ownership_proof_id=self.ownership_proof.proof_id,
            ownership_admission_id=self.ownership_admission.admission_id,
            locator_proof_ref=locator_proof.proof_ref,
            action_ids=action_ids,
            actions=actions,
            transport_context_refs=transport_context_refs,
        )
        return PreparedGeneralizedAuthorizationExperiment(
            plan_ref=stable_hash("generalized_authorization_plan", payload),
            manifest_id=self.manifest.manifest_id,
            ownership_proof_id=self.ownership_proof.proof_id,
            ownership_admission_id=self.ownership_admission.admission_id,
            locator_proof=locator_proof,
            action_ids=action_ids,
            _actions=copy.deepcopy(actions),
            _headers=copy.deepcopy(headers),
            _transport_context_refs=transport_context_refs,
            _actor_value=actor.value,
            _owner_value=owner.value,
        )


@dataclass(frozen=True)
class _GeneralizedPreflight:
    authorization: _AuthorizationPreflight
    plan: PreparedGeneralizedAuthorizationExperiment
    runtime_permit: LocatorRuntimePermit = field(repr=False, compare=False)


@dataclass(frozen=True)
class GeneralizedAuthorizationExperimentResult:
    authorization_result: AdmittedAuthorizationExperimentResult
    ownership_proof_id: str
    ownership_admission_id: str
    locator_proof_ref: str
    runtime_authority_ref: str
    execution_plan_ref: str
    transport_context_ref: str
    mode: str = GENERALIZED_AUTHORIZATION_EXECUTION_MODE
    adversarial_triage_required: bool = True
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(
                self.authorization_result,
                AdmittedAuthorizationExperimentResult,
            )
            or self.mode != GENERALIZED_AUTHORIZATION_EXECUTION_MODE
            or not self.ownership_proof_id.startswith(
                "ownership_experiment_proof:"
            )
            or not self.ownership_admission_id.startswith(
                "ownership_experiment_admission:"
            )
            or not self.locator_proof_ref.startswith(
                "locator_ownership_proof:"
            )
            or not self.runtime_authority_ref.startswith(
                "locator_runtime_authority:"
            )
            or not self.execution_plan_ref.startswith(
                "generalized_authorization_plan:"
            )
            or not self.transport_context_ref.startswith(
                "locator_transport_context:"
            )
            or not self.adversarial_triage_required
            or self.promotion_authority
            or self.finding_authority
        ):
            raise ValueError(
                "generalized authorization result contract is invalid"
            )

    def __getattr__(self, name: str) -> Any:
        return getattr(self.authorization_result, name)

    def to_dict(self) -> Mapping[str, Any]:
        payload = dict(self.authorization_result.to_dict())
        payload["authorization_result_mode"] = payload["mode"]
        payload.update({
            "mode": self.mode,
            "ownership_proof_id": self.ownership_proof_id,
            "ownership_admission_id": self.ownership_admission_id,
            "locator_proof_ref": self.locator_proof_ref,
            "runtime_authority_ref": self.runtime_authority_ref,
            "execution_plan_ref": self.execution_plan_ref,
            "transport_context_ref": self.transport_context_ref,
            "adversarial_triage_required": True,
            "promotion_authority": False,
            "finding_authority": False,
        })
        return payload


def _response(status: int, body: Any) -> bola_replay.ReplayResponse:
    if isinstance(body, str):
        value = body
    else:
        try:
            value = json.dumps(body, sort_keys=True)
        except (TypeError, ValueError):
            value = str(body)
    return bola_replay.ReplayResponse(
        status=int(status),
        body=value,
        body_truncated=bool(getattr(body, "body_truncated", False)),
    )


class GeneralizedAuthorizationExperimentExecutor(
    AdmittedAuthorizationExperimentExecutor
):
    """Consume one R4B claim through the R5A locator-bound read sequence."""

    def __init__(
        self,
        *,
        manifest: ProofExperimentManifest,
        claim: ProofExperimentAdmissionClaim,
        prepared: PreparedGeneralizedAuthorizationExperiment,
        ownership_proof: GeneralizedOwnershipExperimentProof,
        ownership_admission: OwnershipExperimentAdmissionContract,
        backend: ControlledAuthorizationExecutor,
        persona_vault: PersonaVault,
        config: Optional[GeneralizedAuthorizationExecutionConfig] = None,
    ) -> None:
        super().__init__(
            manifest=manifest,
            claim=claim,
            backend=backend,
            persona_vault=persona_vault,
            config=AdmittedAuthorizationExperimentConfig(enabled=False),
        )
        if not isinstance(
            prepared,
            PreparedGeneralizedAuthorizationExperiment,
        ):
            raise TypeError(
                "prepared must be a PreparedGeneralizedAuthorizationExperiment"
            )
        self.prepared = prepared
        self.ownership_proof = ownership_proof
        self.ownership_admission = ownership_admission
        self.generalized_config = (
            config or GeneralizedAuthorizationExecutionConfig.from_environment()
        )
        self._active_locator_proof_ref: Optional[str] = None
        self._active_runtime_authority_ref: Optional[str] = None
        self._active_source_admission_ref: Optional[str] = None
        self._active_source_plan_ref: Optional[str] = None
        self._active_transport_context_ref: Optional[str] = None

    def _generalized_preflight(
        self,
        *,
        actor_records: Sequence[Mapping[str, Any]],
        target_owner_records: Sequence[Mapping[str, Any]],
    ) -> _GeneralizedPreflight:
        if not self.generalized_config.enabled:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_execution_is_disabled"
            )
        if self.claim.state != "claimed":
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_claim_is_not_active"
            )
        contract = self.claim.contract
        if (
            contract.manifest_id != self.manifest.manifest_id
            or contract.backend is not ExistingBackendKind.OBJECT_AUTHORIZATION
            or contract.required_workflows
            != ("behavioral_object_authorization",)
            or contract.authority_context_ref
            != self.manifest.authority_context_ref
            or contract.budget_id != self.manifest.budget.budget_id
            or contract.total_request_units != 4
            or self.prepared.manifest_id != self.manifest.manifest_id
            or self.prepared.ownership_proof_id
            != self.ownership_proof.proof_id
            or self.prepared.ownership_admission_id
            != self.ownership_admission.admission_id
        ):
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_claim_identity_mismatch"
            )
        self.backend.validate_preflight()
        source_executor = self.backend.executors[
            self.backend.source_persona.persona_id
        ]
        sink = source_executor.provenance
        if sink is None or not sink.verify():
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_provenance_is_invalid"
            )
        execution_policy_digest = source_executor.policy.digest()
        if execution_policy_digest != contract.execution_policy_digest:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_policy_changed"
            )
        runtime_worlds = self._bind_worlds()
        fresh = GeneralizedAuthorizationExecutionPlanner(
            manifest=self.manifest,
            ownership_proof=self.ownership_proof,
            ownership_admission=self.ownership_admission,
            backend=self.backend,
        ).prepare(
            actor_records=actor_records,
            target_owner_records=target_owner_records,
        )
        if fresh.plan_ref != self.prepared.plan_ref:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_prepared_plan_changed"
            )
        actions = fresh.actions
        bindings = tuple(
            ExperimentRuntimeActionBinding.bind(
                action=manifest_action,
                candidate=runtime_action,
                target_origin=self.backend.target_origin,
                runtime_worlds=runtime_worlds,
            )
            for manifest_action, runtime_action in zip(
                self.manifest.actions,
                actions,
                strict=True,
            )
        )
        if tuple(
            item.runtime_action_binding_id for item in bindings
        ) != contract.action_binding_ids:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_runtime_action_identity_changed"
            )
        verification = source_executor.policy.verify_locator_ownership(
            actions[2],
            fresh.locator_proof,
        )
        if not verification.verified:
            raise GeneralizedAuthorizationExecutionDenied(
                "generalized_authorization_locator_proof_changed"
            )
        runtime_claim_token: Optional[str] = None
        try:
            (
                budget_reservation_id,
                _,
                runtime_claim_token,
            ) = self.claim._runtime_credentials(
                manifest_id=self.manifest.manifest_id,
                execution_policy_digest=execution_policy_digest,
            )
            treatment = replace(
                actions[2],
                budget_reservation_id=budget_reservation_id,
            )
            permit = self.claim._issue_locator_runtime_permit(
                runtime_claim_token=runtime_claim_token,
                action_binding=bindings[2],
                action=treatment,
                locator_proof_ref=fresh.locator_proof.proof_ref,
                source_admission_ref=self.ownership_admission.admission_id,
                source_plan_ref=fresh.plan_ref,
                transport_context_ref=fresh._transport_context_refs[2],
            )
        except Exception:
            if runtime_claim_token is not None and self.claim.state == "executing":
                self.claim._abort_runtime(
                    runtime_claim_token=runtime_claim_token,
                    reason="generalized_authorization_runtime_permit_denied",
                )
            raise
        authorization = _AuthorizationPreflight(
            actions=actions,
            action_bindings=bindings,
            execution_policy_digest=execution_policy_digest,
            budget_reservation_id=budget_reservation_id,
            runtime_claim_token=runtime_claim_token,
        )
        self._active_locator_proof_ref = fresh.locator_proof.proof_ref
        self._active_runtime_authority_ref = permit.authority_ref
        self._active_source_admission_ref = (
            self.ownership_admission.admission_id
        )
        self._active_source_plan_ref = fresh.plan_ref
        self._active_transport_context_ref = permit.transport_context_ref
        return _GeneralizedPreflight(
            authorization=authorization,
            plan=fresh,
            runtime_permit=permit,
        )

    def _block_matches_action(
        self,
        block: Any,
        action: CandidateAction,
        action_class: str,
    ) -> bool:
        if not super()._block_matches_action(block, action, action_class):
            return False
        if action_class != CROSS_OBJECT_READ:
            return True
        payload = getattr(block, "payload", None)
        return bool(
            isinstance(payload, Mapping)
            and payload.get("ownership_proof_ref")
            == self._active_locator_proof_ref
            and payload.get("runtime_authority_ref")
            == self._active_runtime_authority_ref
            and payload.get("source_admission_ref")
            == self._active_source_admission_ref
            and payload.get("source_plan_ref")
            == self._active_source_plan_ref
            and payload.get("transport_context_ref")
            == self._active_transport_context_ref
        )

    async def _run_sequence(
        self,
        preflight: _GeneralizedPreflight,
    ) -> ControlledExecutionResult:
        actions = tuple(
            replace(
                item,
                budget_reservation_id=(
                    preflight.authorization.budget_reservation_id
                ),
            )
            for item in preflight.authorization.actions
        )
        headers = preflight.plan._headers
        actor_id = self.backend.source_persona.persona_id
        owner_id = self.backend.peer_persona.persona_id
        source_executor = self.backend.executors[actor_id]
        owner_executor = self.backend.executors[owner_id]
        attempted = 0
        sent = 0
        witness_attempted = False
        witness_sent = False
        witness_valid = False
        status = "completed"
        verdict = bola_replay.OpVerdict(
            self.ownership_proof.actor.operation_id,
            "ERROR",
            "generalized authorization sequence did not start",
        )
        responses = []
        try:
            for index in (0, 1):
                attempted += 1
                executor = owner_executor if index == 0 else source_executor
                response_status, response_body = await executor.send_action(
                    actions[index],
                    headers=dict(headers[index]),
                )
                sent += int(response_status != DENIED_STATUS)
                response = _response(response_status, response_body)
                responses.append(response)
                if (
                    response_status == DENIED_STATUS
                    or not 200 <= int(response_status) < 300
                    or bola_replay.is_denied_response(response)
                ):
                    raise GeneralizedAuthorizationExecutionDenied(
                        "generalized_authorization_baseline_is_not_usable"
                    )
            attempted += 1
            treatment_status, treatment_body = (
                await source_executor.send_locator_action(
                    actions[2],
                    preflight.plan.locator_proof,
                    runtime_permit=preflight.runtime_permit,
                    headers=dict(headers[2]),
                )
            )
            sent += int(treatment_status != DENIED_STATUS)
            treatment_response = _response(treatment_status, treatment_body)
            op = bola_replay.ObjectScopedOp(
                kind=(
                    "graphql"
                    if self.ownership_proof.actor.protocol
                    is OwnershipProtocol.GRAPHQL
                    else "rest"
                ),
                label=self.ownership_proof.actor.operation_id,
                method=actions[2].method,
                url=actions[2].url,
                id_where=(
                    f"{self.ownership_proof.actor.locator_kind.value}:"
                    f"{self.ownership_proof.actor.locator_pointer}"
                ),
            )
            verdict = bola_replay.classify_responses(
                op,
                actor_id,
                preflight.plan._owner_value,
                preflight.plan._actor_value,
                responses[0],
                responses[1],
                treatment_response,
            )
        except Exception as exc:
            status = "aborted"
            verdict = bola_replay.OpVerdict(
                self.ownership_proof.actor.operation_id,
                "ERROR",
                f"transport_{type(exc).__name__}",
            )

        if status == "completed" and attempted == sent == 3:
            witness_attempted = True
            attempted += 1
            try:
                witness_status, witness_body = await owner_executor.send_action(
                    actions[3],
                    headers=dict(headers[3]),
                )
                witness_sent = witness_status != DENIED_STATUS
                sent += int(witness_sent)
                witness_response = _response(witness_status, witness_body)
                markers = (
                    tuple(verdict.finding.leaked)
                    if verdict.finding is not None
                    else ()
                )
                witness_valid = bool(
                    witness_sent
                    and 200 <= witness_response.status < 300
                    and not witness_response.body_truncated
                    and not bola_replay.is_denied_response(witness_response)
                    and all(
                        marker in witness_response.body for marker in markers
                    )
                )
            except Exception:
                witness_valid = False
            if not witness_valid:
                status = "aborted"
        else:
            status = "aborted"

        sink = source_executor.provenance
        restraint = source_executor.restraint_summary()
        restraint.update({
            "policy_denials": (
                len(source_executor.skipped) + len(owner_executor.skipped)
            ),
            "stopped_after_first_proof": verdict.finding is not None,
            "stopped_after_terminal_verdict": True,
            "independent_witness_required": True,
            "independent_witness_valid": witness_valid,
            "generalized_locator_kind": (
                self.ownership_proof.actor.locator_kind.value
            ),
            "generalized_locator_bound": True,
        })
        return ControlledExecutionResult(
            proposal_id=self.ownership_proof.source_contract_ref,
            legacy_verdict=verdict,
            requests_attempted=attempted,
            requests_sent=sent,
            policy_denials=(
                len(source_executor.skipped) + len(owner_executor.skipped)
            ),
            provenance_root=(sink.root() if sink is not None else "") or "",
            restraint=restraint,
            provenance=(sink.summary() if sink is not None else {}),
            independent_witness_attempted=witness_attempted,
            independent_witness_sent=witness_sent,
            independent_witness_valid=witness_valid,
            status=status,
        )

    async def execute(
        self,
        *,
        actor_records: Sequence[Mapping[str, Any]],
        target_owner_records: Sequence[Mapping[str, Any]],
    ) -> GeneralizedAuthorizationExperimentResult:
        async with self._lock:
            if self._consumed:
                raise GeneralizedAuthorizationExecutionDenied(
                    "generalized_authorization_executor_already_consumed"
                )
            self._consumed = True
            try:
                preflight = self._generalized_preflight(
                    actor_records=actor_records,
                    target_owner_records=target_owner_records,
                )
            except Exception as exc:
                self._abort_claim(
                    "generalized_authorization_preflight_denied"
                )
                if isinstance(exc, GeneralizedAuthorizationExecutionDenied):
                    raise
                raise GeneralizedAuthorizationExecutionDenied(
                    "generalized_authorization_preflight_failed"
                ) from exc

            source_executor = self.backend.executors[
                self.backend.source_persona.persona_id
            ]
            peer_executor = self.backend.executors[
                self.backend.peer_persona.persona_id
            ]
            sink = source_executor.provenance
            assert sink is not None
            block_start = len(sink.action_blocks)
            denial_start = len(source_executor.skipped) + len(peer_executor.skipped)
            try:
                execution = await self._run_sequence(preflight)
            except Exception as exc:
                self._abort_claim(
                    "generalized_authorization_backend_failed",
                    runtime_claim_token=(
                        preflight.authorization.runtime_claim_token
                    ),
                )
                raise GeneralizedAuthorizationExecutionDenied(
                    "generalized_authorization_backend_failed"
                ) from exc
            try:
                new_blocks = tuple(sink.action_blocks[block_start:])
                policy_denials = max(
                    0,
                    len(source_executor.skipped)
                    + len(peer_executor.skipped)
                    - denial_start,
                )
                evaluation, candidate_ref, status = self._evaluate(
                    preflight=preflight.authorization,
                    execution=execution,
                    new_blocks=new_blocks,
                    policy_denials=policy_denials,
                )
                released_units = self.claim.reserved_units
                outcome = {
                    "kind": "proof_experiment_generalized_authorization",
                    "status": status,
                    "manifest_id": self.manifest.manifest_id,
                    "admission_id": self.claim.contract.admission_id,
                    "ownership_proof_id": self.ownership_proof.proof_id,
                    "ownership_admission_id": (
                        self.ownership_admission.admission_id
                    ),
                    "locator_proof_ref": (
                        preflight.plan.locator_proof.proof_ref
                    ),
                    "runtime_authority_ref": (
                        preflight.runtime_permit.authority_ref
                    ),
                    "execution_plan_ref": preflight.plan.plan_ref,
                    "transport_context_ref": (
                        preflight.runtime_permit.transport_context_ref
                    ),
                    "evaluation_id": evaluation.evaluation_id,
                    "oracle_id": evaluation.oracle_id,
                    "oracle_verdict": evaluation.verdict.value,
                    "backend_receipt_ref": evaluation.backend_receipt_ref,
                    "legacy_verdict": execution.legacy_verdict.verdict,
                    "control_evidence_refs": list(
                        evaluation.control_evidence_refs
                    ),
                    "treatment_evidence_refs": list(
                        evaluation.treatment_evidence_refs
                    ),
                    "witness_evidence_refs": list(
                        evaluation.witness_evidence_refs
                    ),
                    "provenance_root": evaluation.provenance_root,
                    "uncertainty_reasons": list(
                        evaluation.uncertainty_reasons
                    ),
                    "requests_attempted": execution.requests_attempted,
                    "requests_sent": execution.requests_sent,
                    "policy_denials": policy_denials,
                    "reserved_units_released": released_units,
                    "finding_candidate_ref": candidate_ref,
                    "adversarial_triage_required": True,
                    "promotion_authority": False,
                    "finding_authority": False,
                }
            except Exception as exc:
                self._abort_claim(
                    "generalized_authorization_evaluation_failed",
                    runtime_claim_token=(
                        preflight.authorization.runtime_claim_token
                    ),
                )
                raise GeneralizedAuthorizationExecutionDenied(
                    "generalized_authorization_evaluation_failed"
                ) from exc
            try:
                receipt = self.claim._complete_runtime(
                    manifest_id=self.manifest.manifest_id,
                    execution_policy_digest=(
                        preflight.authorization.execution_policy_digest
                    ),
                    outcome=outcome,
                    expected_released_units=released_units,
                    runtime_claim_token=(
                        preflight.authorization.runtime_claim_token
                    ),
                )
            except Exception as exc:
                self._abort_claim(
                    "generalized_authorization_receipt_failed",
                    runtime_claim_token=(
                        preflight.authorization.runtime_claim_token
                    ),
                )
                raise GeneralizedAuthorizationExecutionDenied(
                    "generalized_authorization_receipt_failed"
                ) from exc
            base = AdmittedAuthorizationExperimentResult(
                manifest_id=self.manifest.manifest_id,
                admission_id=self.claim.contract.admission_id,
                receipt_id=receipt.receipt_id,
                status=status,
                legacy_verdict=execution.legacy_verdict.verdict,
                oracle_evaluation=evaluation,
                requests_attempted=execution.requests_attempted,
                requests_sent=execution.requests_sent,
                policy_denials=policy_denials,
                reserved_units_released=released_units,
                finding_candidate_ref=candidate_ref,
                provenance_root=evaluation.provenance_root,
            )
            return GeneralizedAuthorizationExperimentResult(
                authorization_result=base,
                ownership_proof_id=self.ownership_proof.proof_id,
                ownership_admission_id=self.ownership_admission.admission_id,
                locator_proof_ref=preflight.plan.locator_proof.proof_ref,
                runtime_authority_ref=preflight.runtime_permit.authority_ref,
                execution_plan_ref=preflight.plan.plan_ref,
                transport_context_ref=(
                    preflight.runtime_permit.transport_context_ref
                ),
            )


__all__ = [
    "GENERALIZED_AUTHORIZATION_EXECUTION_ENV",
    "GENERALIZED_AUTHORIZATION_EXECUTION_MODE",
    "GeneralizedAuthorizationExecutionConfig",
    "GeneralizedAuthorizationExecutionDenied",
    "GeneralizedAuthorizationExecutionPlanner",
    "GeneralizedAuthorizationExperimentExecutor",
    "GeneralizedAuthorizationExperimentResult",
    "PreparedGeneralizedAuthorizationExperiment",
]
