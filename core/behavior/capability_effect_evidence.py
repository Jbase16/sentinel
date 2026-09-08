"""Strict durable evidence and replay-leak classification for R5D10.

This module consumes only public projections from the R5D8 execution producer.
It has no transport, persistence, promotion-policy, or canonical-ledger authority.
The retained value is immutable, canonically serialized, and independently
revalidates every accessible content-addressed commitment.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from core.base.scope import canonical_origin
from core.identity.context import AssessmentIdentityContext

from .normalize import stable_hash


CAPABILITY_EFFECT_EVIDENCE_SCHEMA_VERSION = 1
CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION = "capability_effect_target_projection_v1"
CAPABILITY_REPLAY_LEAK_CLASS_VERSION = "capability_replay_leak_v1"
CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES = 256 * 1024
CAPABILITY_EFFECT_EVIDENCE_ROOT_DOMAIN = (
    b"sentinelforge:capability-effect-evidence:v1\x00"
)

_SOURCE_EXECUTION_MODE = "behavioral_capability_effect_execution_v1"
_TERMINAL_RECEIPT_MODE = "behavioral_capability_execution_receipt_v1"
_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BUILD_SHA = re.compile(r"^[0-9a-f]{40}$")
_TYPED_SHA256 = re.compile(r"^([a-z][a-z0-9_]{0,127}):([0-9a-f]{64})$")
_BEHAVIORAL_RECEIPT = re.compile(r"^behavioral-[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

_OBSERVATION_KINDS = (
    "no_capability_baseline",
    "valid_capability_effect_witness",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)
_EXPECTED_OUTCOMES = (
    "execution_refused_not_live",
    "execution_completed",
    "execution_refused_already_consumed",
    "execution_refused_expired",
    "execution_refused_inadmissible",
)
_REFUTED = "refuted"
_CONFIRMED = "confirmed_one_time_authorized_effect"
_RUNTIME_EVIDENCE_CLASSIFICATIONS = frozenset(
    {
        "controlled_in_memory_twin",
        "controlled_owned_lab",
        "unknown",
    }
)

_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "session_id",
        "authorization_envelope_id",
        "authorization_envelope_ref",
        "target_origin",
        "target_reset_epoch",
        "world_id",
        "persona_id",
        "target_actor_id",
        "tenant_id",
        "credential_source_ref",
        "credential_epoch",
        "credential_freshness",
        "resource_id",
        "representation_id",
        "display_name",
        "digest",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "observation_id",
        "receipt_ref",
        "capability_ref",
        "observation_binding_id",
        "response_ref",
        "observation_kind",
        "receipt_outcome",
        "access_decision",
        "response_status",
        "effect_ref",
        "protected_effect_observed",
        "target_projection_observed",
    }
)
_TERMINAL_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "capability_ref",
        "liveness_ref",
        "consumption_ref",
        "observed_epoch",
        "outcome",
        "mode",
        "target_dispatch_authority",
        "execution_effect_authority",
        "finding_promotion_authority",
        "target_cleanup_authority",
    }
)
_ORACLE_FIELDS = frozenset(
    {
        "schema_version",
        "evaluation_id",
        "oracle_id",
        "observation_binding_id",
        "verdict",
        "observation_refs",
        "uncertainty_reasons",
        "no_capability_effect_absent",
        "authorized_effect_observed_once",
        "replay_effect_absent",
        "expired_effect_absent",
        "inadmissible_effect_absent",
        "authorized_effect_ref",
        "finding_candidate_ref",
        "adversarial_triage_required",
        "promotion_authority",
        "finding_authority",
    }
)
_CLEANUP_FIELDS = frozenset(
    {
        "status",
        "target_requests_sent",
        "target_request_may_have_been_sent",
        "orphaned_owned_state_possible",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "snapshot_id",
        "policy_ref",
        "primary_execution_gate_enabled",
        "capability_effect_execution_gate_enabled",
        "authorization_admitted",
        "persona_admitted",
        "ownership_admitted",
        "origin_admitted",
        "policy_admitted",
        "budget_admitted",
        "receipt_admitted",
        "cleanup_required",
    }
)
_PRODUCER_FIELDS = frozenset(
    {
        "schema_version",
        "producer_id",
        "producer_name",
        "build_id",
        "build_sha",
        "source_state",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "adapter_contract_version",
        "evidence_root",
        "source_execution_id",
        "source_receipt_id",
        "execution_admission_ref",
        "assessment_session_id",
        "identity_binding",
        "target_origin",
        "specification_ref",
        "operation_ref",
        "capability_ref",
        "experiment_world_ref",
        "observations",
        "terminal_receipts",
        "oracle",
        "oracle_evaluation_ref",
        "cleanup",
        "execution_policy",
        "conduct_provenance_root",
        "producer_identity",
        "observed_at_epoch",
        "runtime_evidence_classification",
    }
)
_EXECUTION_EXPORT_FIELDS = frozenset(
    {
        "schema_version",
        "result_id",
        "receipt_id",
        "capability_ref",
        "observation_binding_id",
        "effect_observations",
        "observation_refs",
        "oracle",
        "oracle_verdict",
        "finding_candidate_ref",
        "cleanup",
        "execution_enabled",
        "execution_effect_authority",
        "adversarial_triage_required",
        "promotion_authority",
        "finding_authority",
        "mode",
        "experiment_world_ref",
        "terminal_receipts",
    }
)
_POLICY_BOOLEAN_FIELDS = (
    "primary_execution_gate_enabled",
    "capability_effect_execution_gate_enabled",
    "authorization_admitted",
    "persona_admitted",
    "ownership_admitted",
    "origin_admitted",
    "policy_admitted",
    "budget_admitted",
    "receipt_admitted",
    "cleanup_required",
)


def _exact_mapping(
    value: object,
    fields: frozenset[str],
    *,
    field_name: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value.keys()) != fields:
        raise ValueError(f"{field_name} fields are invalid")
    if any(type(key) is not str for key in value.keys()):
        raise ValueError(f"{field_name} fields are invalid")
    return value


def _version(value: object, *, field_name: str) -> int:
    if type(value) is not int or value != 1:
        raise ValueError(f"{field_name} version is invalid")
    return value


def _bounded_string(
    value: object,
    *,
    field_name: str,
    maximum: int = 512,
    allow_empty: bool = False,
) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or value != value.strip()
        or (not value and not allow_empty)
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{field_name} is invalid")
    return value


def _semantic(value: object, *, field_name: str) -> str:
    text = _bounded_string(value, field_name=field_name, maximum=128)
    if _SEMANTIC.fullmatch(text) is None:
        raise ValueError(f"{field_name} is invalid")
    return text


def _typed_ref(value: object, prefix: str, *, field_name: str) -> str:
    if type(value) is not str or value != f"{prefix}:{value.rsplit(':', 1)[-1]}":
        raise ValueError(f"{field_name} is invalid")
    match = _TYPED_SHA256.fullmatch(value)
    if match is None or match.group(1) != prefix:
        raise ValueError(f"{field_name} is invalid")
    return value


def _optional_typed_ref(
    value: object,
    prefix: str,
    *,
    field_name: str,
) -> Optional[str]:
    if value is None:
        return None
    return _typed_ref(value, prefix, field_name=field_name)


def _exact_bool(value: object, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be boolean")
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("capability effect evidence is not JSON-safe") from exc


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _frozen_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


def _evidence_root(preimage: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        CAPABILITY_EFFECT_EVIDENCE_ROOT_DOMAIN + _canonical_json_bytes(dict(preimage))
    ).hexdigest()


def _observation_hash_payload(value: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "receipt_ref",
            "capability_ref",
            "observation_binding_id",
            "response_ref",
            "observation_kind",
            "receipt_outcome",
            "access_decision",
            "response_status",
            "effect_ref",
            "protected_effect_observed",
            "target_projection_observed",
        )
    }


def _validate_observation(value: object) -> Mapping[str, Any]:
    source = _exact_mapping(
        value,
        _OBSERVATION_FIELDS,
        field_name="capability effect observation",
    )
    _version(source["schema_version"], field_name="capability effect observation")
    observation_id = _typed_ref(
        source["observation_id"],
        "capability_effect_observation",
        field_name="capability effect observation id",
    )
    receipt_ref = _typed_ref(
        source["receipt_ref"],
        "capability_execution_receipt",
        field_name="capability effect receipt ref",
    )
    capability_ref = _typed_ref(
        source["capability_ref"],
        "issued_capability_contract",
        field_name="capability effect capability ref",
    )
    binding_ref = _typed_ref(
        source["observation_binding_id"],
        "experiment_world_binding",
        field_name="capability effect observation binding",
    )
    response_ref = _typed_ref(
        source["response_ref"],
        "capability_effect_target_response",
        field_name="capability effect response ref",
    )
    kind = _semantic(
        source["observation_kind"],
        field_name="capability effect observation kind",
    )
    if kind not in _OBSERVATION_KINDS:
        raise ValueError("capability effect observation kind is invalid")
    outcome = _semantic(
        source["receipt_outcome"],
        field_name="capability effect receipt outcome",
    )
    access_decision = _semantic(
        source["access_decision"],
        field_name="capability effect access decision",
    )
    if access_decision not in {"allowed", "denied", "unknown"}:
        raise ValueError("capability effect access decision is invalid")
    response_status = source["response_status"]
    if type(response_status) is not int or not 100 <= response_status <= 599:
        raise ValueError("capability effect response status is invalid")
    effect_ref = _optional_typed_ref(
        source["effect_ref"],
        "capability_protected_effect",
        field_name="capability effect protected effect ref",
    )
    effect_observed = _exact_bool(
        source["protected_effect_observed"],
        field_name="capability effect protected effect flag",
    )
    projection_observed = _exact_bool(
        source["target_projection_observed"],
        field_name="capability effect target projection flag",
    )
    if (
        effect_observed != (effect_ref is not None)
        or (effect_observed and not projection_observed)
        or (effect_observed and access_decision != "allowed")
    ):
        raise ValueError("capability effect observation flags are inconsistent")
    normalized = {
        "schema_version": 1,
        "observation_id": observation_id,
        "receipt_ref": receipt_ref,
        "capability_ref": capability_ref,
        "observation_binding_id": binding_ref,
        "response_ref": response_ref,
        "observation_kind": kind,
        "receipt_outcome": outcome,
        "access_decision": access_decision,
        "response_status": response_status,
        "effect_ref": effect_ref,
        "protected_effect_observed": effect_observed,
        "target_projection_observed": projection_observed,
    }
    if observation_id != stable_hash(
        "capability_effect_observation",
        _observation_hash_payload(normalized),
    ):
        raise ValueError("capability effect observation commitment is invalid")
    return _frozen_mapping(normalized)


def _validate_terminal_receipt(value: object) -> Mapping[str, Any]:
    source = _exact_mapping(
        value,
        _TERMINAL_RECEIPT_FIELDS,
        field_name="capability effect terminal receipt",
    )
    _version(source["schema_version"], field_name="capability effect terminal receipt")
    receipt_id = _typed_ref(
        source["receipt_id"],
        "capability_execution_receipt",
        field_name="capability effect terminal receipt id",
    )
    capability_ref = _typed_ref(
        source["capability_ref"],
        "issued_capability_contract",
        field_name="capability effect terminal capability ref",
    )
    liveness_ref = _typed_ref(
        source["liveness_ref"],
        "runtime_liveness_decision",
        field_name="capability effect liveness ref",
    )
    consumption_ref = _typed_ref(
        source["consumption_ref"],
        "capability_consumption_decision",
        field_name="capability effect consumption ref",
    )
    observed_epoch = _bounded_string(
        source["observed_epoch"],
        field_name="capability effect terminal observed epoch",
        maximum=64,
    )
    try:
        parsed_epoch = float(observed_epoch)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "capability effect terminal observed epoch is invalid"
        ) from exc
    if not math.isfinite(parsed_epoch) or repr(parsed_epoch) != observed_epoch:
        raise ValueError("capability effect terminal observed epoch is invalid")
    outcome = _semantic(
        source["outcome"],
        field_name="capability effect terminal outcome",
    )
    if outcome not in _EXPECTED_OUTCOMES:
        raise ValueError("capability effect terminal outcome is invalid")
    mode = _bounded_string(
        source["mode"],
        field_name="capability effect terminal receipt mode",
    )
    if mode != _TERMINAL_RECEIPT_MODE:
        raise ValueError("capability effect terminal receipt mode is invalid")
    authority = {
        key: _exact_bool(source[key], field_name=f"capability effect {key}")
        for key in (
            "target_dispatch_authority",
            "execution_effect_authority",
            "finding_promotion_authority",
            "target_cleanup_authority",
        )
    }
    if any(authority.values()):
        raise ValueError("capability effect terminal receipt grants authority")
    normalized = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "capability_ref": capability_ref,
        "liveness_ref": liveness_ref,
        "consumption_ref": consumption_ref,
        "observed_epoch": observed_epoch,
        "outcome": outcome,
        "mode": mode,
        **authority,
    }
    receipt_payload = {
        key: normalized[key]
        for key in (
            "capability_ref",
            "liveness_ref",
            "consumption_ref",
            "observed_epoch",
            "outcome",
            "mode",
        )
    }
    if receipt_id != stable_hash("capability_execution_receipt", receipt_payload):
        raise ValueError("capability effect terminal receipt commitment is invalid")
    return _frozen_mapping(normalized)


def _validate_cleanup(value: object) -> Mapping[str, Any]:
    source = _exact_mapping(
        value,
        _CLEANUP_FIELDS,
        field_name="capability effect cleanup",
    )
    status = _semantic(source["status"], field_name="capability effect cleanup status")
    requests = source["target_requests_sent"]
    may_have_sent = _exact_bool(
        source["target_request_may_have_been_sent"],
        field_name="capability effect cleanup request uncertainty",
    )
    orphaned = _exact_bool(
        source["orphaned_owned_state_possible"],
        field_name="capability effect orphaned-state flag",
    )
    if (
        status != "verified"
        or type(requests) is not int
        or requests != len(_OBSERVATION_KINDS) + 1
        or may_have_sent
        or orphaned
    ):
        raise ValueError("completed capability effect cleanup is invalid")
    return _frozen_mapping(
        {
            "status": status,
            "target_requests_sent": requests,
            "target_request_may_have_been_sent": may_have_sent,
            "orphaned_owned_state_possible": orphaned,
        }
    )


def _validate_identity(value: object) -> Mapping[str, Any]:
    source = _exact_mapping(
        value,
        _IDENTITY_FIELDS,
        field_name="capability effect identity binding",
    )
    if (
        type(source["target_reset_epoch"]) is not int
        or type(source["credential_epoch"]) is not int
    ):
        raise ValueError("capability effect identity numeric fields are invalid")
    try:
        identity = AssessmentIdentityContext.from_dict(source)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("capability effect identity binding is invalid") from exc
    normalized = identity.to_dict()
    if normalized != dict(source) or normalized["display_name"] != "":
        raise ValueError("capability effect identity binding is not canonical")
    return _frozen_mapping(normalized)


def _oracle_hash_payload(value: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: _thaw(value[key])
        for key in (
            "oracle_id",
            "observation_binding_id",
            "verdict",
            "observation_refs",
            "uncertainty_reasons",
            "no_capability_effect_absent",
            "authorized_effect_observed_once",
            "replay_effect_absent",
            "expired_effect_absent",
            "inadmissible_effect_absent",
            "authorized_effect_ref",
            "finding_candidate_ref",
            "adversarial_triage_required",
            "promotion_authority",
            "finding_authority",
        )
    }


def _validate_oracle(value: object) -> Mapping[str, Any]:
    source = _exact_mapping(
        value,
        _ORACLE_FIELDS,
        field_name="capability effect oracle",
    )
    _version(source["schema_version"], field_name="capability effect oracle")
    evaluation_id = _typed_ref(
        source["evaluation_id"],
        "capability_effect_oracle_evaluation",
        field_name="capability effect oracle evaluation id",
    )
    oracle_id = _typed_ref(
        source["oracle_id"],
        "capability_effect_oracle",
        field_name="capability effect oracle id",
    )
    binding_id = _typed_ref(
        source["observation_binding_id"],
        "experiment_world_binding",
        field_name="capability effect oracle binding id",
    )
    verdict = _semantic(source["verdict"], field_name="capability effect verdict")
    if verdict not in {_CONFIRMED, _REFUTED}:
        raise ValueError("completed capability effect verdict is invalid")
    refs_value = source["observation_refs"]
    if type(refs_value) is not list or len(refs_value) != len(_OBSERVATION_KINDS):
        raise ValueError("capability effect oracle observation refs are invalid")
    observation_refs = tuple(
        _typed_ref(
            item,
            "capability_effect_observation",
            field_name="capability effect oracle observation ref",
        )
        for item in refs_value
    )
    if len(set(observation_refs)) != len(observation_refs):
        raise ValueError("capability effect oracle observation refs are invalid")
    uncertainty_value = source["uncertainty_reasons"]
    if type(uncertainty_value) is not list:
        raise ValueError("capability effect oracle uncertainty is invalid")
    uncertainty = tuple(
        _semantic(item, field_name="capability effect oracle uncertainty")
        for item in uncertainty_value
    )
    if uncertainty != tuple(sorted(set(uncertainty))):
        raise ValueError("capability effect oracle uncertainty is invalid")
    boolean_names = (
        "no_capability_effect_absent",
        "authorized_effect_observed_once",
        "replay_effect_absent",
        "expired_effect_absent",
        "inadmissible_effect_absent",
        "adversarial_triage_required",
        "promotion_authority",
        "finding_authority",
    )
    booleans = {
        name: _exact_bool(source[name], field_name=f"capability effect oracle {name}")
        for name in boolean_names
    }
    if (
        not booleans["adversarial_triage_required"]
        or booleans["promotion_authority"]
        or booleans["finding_authority"]
    ):
        raise ValueError("capability effect oracle authority is invalid")
    authorized_effect_ref = _optional_typed_ref(
        source["authorized_effect_ref"],
        "capability_protected_effect",
        field_name="capability effect oracle authorized effect ref",
    )
    finding_candidate_ref = _optional_typed_ref(
        source["finding_candidate_ref"],
        "capability_effect_finding_candidate",
        field_name="capability effect oracle finding candidate ref",
    )
    if (verdict == _CONFIRMED) != (finding_candidate_ref is not None):
        raise ValueError("capability effect oracle candidate is inconsistent")
    normalized = {
        "schema_version": 1,
        "evaluation_id": evaluation_id,
        "oracle_id": oracle_id,
        "observation_binding_id": binding_id,
        "verdict": verdict,
        "observation_refs": observation_refs,
        "uncertainty_reasons": uncertainty,
        **{name: booleans[name] for name in boolean_names[:5]},
        "authorized_effect_ref": authorized_effect_ref,
        "finding_candidate_ref": finding_candidate_ref,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }
    if evaluation_id != stable_hash(
        "capability_effect_oracle_evaluation",
        _oracle_hash_payload(normalized),
    ):
        raise ValueError("capability effect oracle commitment is invalid")
    return _frozen_mapping(normalized)


def _recomputed_oracle(
    oracle_id: str,
    observation_binding_id: str,
    observations: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    baseline, witness, replay, expired, inadmissible = observations

    def refusal_observed(item: Mapping[str, Any]) -> bool:
        return bool(
            item["target_projection_observed"]
            and item["access_decision"] == "denied"
            and not item["protected_effect_observed"]
        )

    baseline_absent = refusal_observed(baseline)
    replay_absent = refusal_observed(replay)
    expired_absent = refusal_observed(expired)
    inadmissible_absent = refusal_observed(inadmissible)
    refusal_items = (baseline, replay, expired, inadmissible)
    refusal_absence = (
        baseline_absent,
        replay_absent,
        expired_absent,
        inadmissible_absent,
    )
    witness_effect = bool(
        witness["target_projection_observed"]
        and witness["access_decision"] == "allowed"
        and witness["protected_effect_observed"]
    )
    observed_effects = tuple(
        item for item in observations if item["protected_effect_observed"]
    )
    unauthorized_effect = any(
        item["protected_effect_observed"] for item in refusal_items
    )
    unauthorized_access = any(
        item["target_projection_observed"]
        and item["access_decision"] == "allowed"
        and not item["protected_effect_observed"]
        for item in refusal_items
    )
    witness_absent = bool(
        witness["target_projection_observed"]
        and witness["access_decision"] in {"allowed", "denied"}
        and not witness["protected_effect_observed"]
    )
    duplicated_effect = len(observed_effects) > 1
    uncertainty = set()
    for kind, item in zip(_OBSERVATION_KINDS, observations):
        if not item["target_projection_observed"]:
            uncertainty.add(f"{kind}_evidence_unavailable")
        elif item["access_decision"] == "unknown":
            uncertainty.add(f"{kind}_projected_access_decision_unavailable")
    if not witness_effect and not witness_absent:
        uncertainty.add("authorized_effect_witness_unavailable")
    for kind, absent, item in zip(
        (
            "no_capability_baseline",
            "replayed_capability_probe",
            "expired_capability_probe",
            "inadmissible_capability_probe",
        ),
        refusal_absence,
        refusal_items,
    ):
        if (
            not absent
            and not item["protected_effect_observed"]
            and item["access_decision"] != "allowed"
        ):
            uncertainty.add(f"{kind}_refusal_unavailable")

    if (
        unauthorized_effect
        or unauthorized_access
        or witness_absent
        or duplicated_effect
    ):
        verdict = _REFUTED
    elif witness_effect and all(refusal_absence):
        verdict = _CONFIRMED
        uncertainty.clear()
    else:
        verdict = "inconclusive"
    finding_candidate_ref = (
        stable_hash(
            "capability_effect_finding_candidate",
            {
                "oracle_id": oracle_id,
                "observation_binding_id": observation_binding_id,
                "verdict": verdict,
                "observation_refs": [item["observation_id"] for item in observations],
                "authorized_effect_ref": witness["effect_ref"],
            },
        )
        if verdict == _CONFIRMED
        else None
    )
    return {
        "oracle_id": oracle_id,
        "observation_binding_id": observation_binding_id,
        "verdict": verdict,
        "observation_refs": tuple(item["observation_id"] for item in observations),
        "uncertainty_reasons": tuple(sorted(uncertainty)),
        "no_capability_effect_absent": baseline_absent,
        "authorized_effect_observed_once": witness_effect
        and len(observed_effects) == 1,
        "replay_effect_absent": replay_absent,
        "expired_effect_absent": expired_absent,
        "inadmissible_effect_absent": inadmissible_absent,
        "authorized_effect_ref": witness["effect_ref"] if witness_effect else None,
        "finding_candidate_ref": finding_candidate_ref,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


@dataclass(frozen=True)
class CapabilityEffectExecutionPolicySnapshot:
    snapshot_id: str
    policy_ref: str
    primary_execution_gate_enabled: bool
    capability_effect_execution_gate_enabled: bool
    authorization_admitted: bool
    persona_admitted: bool
    ownership_admitted: bool
    origin_admitted: bool
    policy_admitted: bool
    budget_admitted: bool
    receipt_admitted: bool
    cleanup_required: bool

    @classmethod
    def build(
        cls,
        *,
        policy_ref: str,
        primary_execution_gate_enabled: bool,
        capability_effect_execution_gate_enabled: bool,
        authorization_admitted: bool,
        persona_admitted: bool,
        ownership_admitted: bool,
        origin_admitted: bool,
        policy_admitted: bool,
        budget_admitted: bool,
        receipt_admitted: bool,
        cleanup_required: bool,
    ) -> "CapabilityEffectExecutionPolicySnapshot":
        values = {
            "policy_ref": policy_ref,
            "primary_execution_gate_enabled": primary_execution_gate_enabled,
            "capability_effect_execution_gate_enabled": (
                capability_effect_execution_gate_enabled
            ),
            "authorization_admitted": authorization_admitted,
            "persona_admitted": persona_admitted,
            "ownership_admitted": ownership_admitted,
            "origin_admitted": origin_admitted,
            "policy_admitted": policy_admitted,
            "budget_admitted": budget_admitted,
            "receipt_admitted": receipt_admitted,
            "cleanup_required": cleanup_required,
        }
        return cls(
            snapshot_id=stable_hash(
                "capability_effect_execution_policy_snapshot",
                values,
            ),
            **values,
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "CapabilityEffectExecutionPolicySnapshot":
        source = _exact_mapping(
            value,
            _POLICY_FIELDS,
            field_name="capability effect execution policy",
        )
        _version(
            source["schema_version"], field_name="capability effect execution policy"
        )
        return cls(
            snapshot_id=source["snapshot_id"],
            policy_ref=source["policy_ref"],
            **{name: source[name] for name in _POLICY_BOOLEAN_FIELDS},
        )

    def __post_init__(self) -> None:
        _typed_ref(
            self.snapshot_id,
            "capability_effect_execution_policy_snapshot",
            field_name="capability effect policy snapshot id",
        )
        _typed_ref(
            self.policy_ref,
            "capability_effect_execution_policy",
            field_name="capability effect execution policy ref",
        )
        values = {
            "policy_ref": self.policy_ref,
            **{
                name: _exact_bool(
                    getattr(self, name),
                    field_name=f"capability effect policy {name}",
                )
                for name in _POLICY_BOOLEAN_FIELDS
            },
        }
        if self.snapshot_id != stable_hash(
            "capability_effect_execution_policy_snapshot",
            values,
        ):
            raise ValueError("capability effect execution policy commitment is invalid")

    @property
    def all_required_gates_admitted(self) -> bool:
        return all(getattr(self, name) is True for name in _POLICY_BOOLEAN_FIELDS)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "policy_ref": self.policy_ref,
            **{name: getattr(self, name) for name in _POLICY_BOOLEAN_FIELDS},
        }


@dataclass(frozen=True)
class CapabilityEffectProducerIdentity:
    producer_id: str
    producer_name: str
    build_id: str
    build_sha: str
    source_state: str

    @classmethod
    def build(
        cls,
        *,
        producer_name: str,
        build_id: str,
        build_sha: str,
        source_state: str,
    ) -> "CapabilityEffectProducerIdentity":
        values = {
            "producer_name": producer_name,
            "build_id": build_id,
            "build_sha": build_sha,
            "source_state": source_state,
        }
        return cls(
            producer_id=stable_hash("capability_effect_producer_identity", values),
            **values,
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
    ) -> "CapabilityEffectProducerIdentity":
        source = _exact_mapping(
            value,
            _PRODUCER_FIELDS,
            field_name="capability effect producer identity",
        )
        _version(
            source["schema_version"], field_name="capability effect producer identity"
        )
        return cls(
            producer_id=source["producer_id"],
            producer_name=source["producer_name"],
            build_id=source["build_id"],
            build_sha=source["build_sha"],
            source_state=source["source_state"],
        )

    def __post_init__(self) -> None:
        _typed_ref(
            self.producer_id,
            "capability_effect_producer_identity",
            field_name="capability effect producer id",
        )
        producer_name = _bounded_string(
            self.producer_name,
            field_name="capability effect producer name",
            maximum=128,
        )
        build_id = _bounded_string(
            self.build_id,
            field_name="capability effect producer build id",
            maximum=256,
        )
        source_state = _semantic(
            self.source_state,
            field_name="capability effect producer source state",
        )
        if source_state not in {"clean", "dirty", "unknown"}:
            raise ValueError("capability effect producer source state is invalid")
        if (
            source_state in {"clean", "dirty"}
            and (
                type(self.build_sha) is not str
                or _BUILD_SHA.fullmatch(self.build_sha) is None
            )
        ) or (source_state == "unknown" and self.build_sha != "unknown"):
            raise ValueError("capability effect producer build sha is invalid")
        values = {
            "producer_name": producer_name,
            "build_id": build_id,
            "build_sha": self.build_sha,
            "source_state": source_state,
        }
        if self.producer_id != stable_hash(
            "capability_effect_producer_identity",
            values,
        ):
            raise ValueError("capability effect producer commitment is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "producer_id": self.producer_id,
            "producer_name": self.producer_name,
            "build_id": self.build_id,
            "build_sha": self.build_sha,
            "source_state": self.source_state,
        }


def _source_execution_payload(
    *,
    capability_ref: str,
    observations: Sequence[Mapping[str, Any]],
    oracle: Mapping[str, Any],
    cleanup: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "receipt_id": observations[1]["receipt_ref"],
        "capability_ref": capability_ref,
        "observation_binding_id": observations[0]["observation_binding_id"],
        "effect_observations": [_thaw(item) for item in observations],
        "observation_refs": [item["observation_id"] for item in observations],
        "oracle": _thaw(oracle),
        "oracle_verdict": oracle["verdict"],
        "finding_candidate_ref": oracle["finding_candidate_ref"],
        "cleanup": _thaw(cleanup),
        "execution_enabled": True,
        "execution_effect_authority": oracle["verdict"] == _CONFIRMED,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
        "mode": _SOURCE_EXECUTION_MODE,
    }


@dataclass(frozen=True)
class CapabilityEffectEvidence:
    schema_version: int
    adapter_contract_version: str
    evidence_root: str
    source_execution_id: str
    source_receipt_id: str
    execution_admission_ref: str
    assessment_session_id: str
    identity_binding: Mapping[str, Any]
    target_origin: str
    specification_ref: str
    operation_ref: str
    capability_ref: str
    experiment_world_ref: str
    observations: Tuple[Mapping[str, Any], ...]
    terminal_receipts: Tuple[Mapping[str, Any], ...]
    oracle: Mapping[str, Any]
    oracle_evaluation_ref: str
    cleanup: Mapping[str, Any]
    execution_policy: Mapping[str, Any]
    conduct_provenance_root: str
    producer_identity: Mapping[str, Any]
    observed_at_epoch: float
    runtime_evidence_classification: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CapabilityEffectEvidence":
        source = _exact_mapping(
            value,
            _EVIDENCE_FIELDS,
            field_name="capability effect evidence",
        )
        return cls(**{name: source[name] for name in _EVIDENCE_FIELDS})

    @classmethod
    def from_json_bytes(cls, value: bytes) -> "CapabilityEffectEvidence":
        if type(value) is not bytes:
            raise TypeError("capability effect evidence JSON must be bytes")
        if len(value) > CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES:
            raise ValueError("capability effect evidence exceeds 256 KiB")

        def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
            result: Dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise ValueError("capability effect evidence has duplicate keys")
                result[key] = child
            return result

        def reject_constant(value: str) -> None:
            raise ValueError(f"invalid JSON constant: {value}")

        try:
            decoded = value.decode("utf-8", errors="strict")
            parsed = json.loads(
                decoded,
                object_pairs_hook=reject_duplicate_pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("capability effect evidence JSON is invalid") from exc
        evidence = cls.from_mapping(parsed)
        if value != evidence.to_json_bytes():
            raise ValueError("capability effect evidence JSON is not canonical")
        return evidence

    def __post_init__(self) -> None:
        _version(self.schema_version, field_name="capability effect evidence")
        if self.adapter_contract_version != CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION:
            raise ValueError("capability effect adapter contract is unsupported")
        if (
            type(self.evidence_root) is not str
            or _BARE_SHA256.fullmatch(self.evidence_root) is None
        ):
            raise ValueError("capability effect evidence root is invalid")
        _typed_ref(
            self.source_execution_id,
            "capability_effect_execution_result",
            field_name="capability effect source execution id",
        )
        if (
            type(self.source_receipt_id) is not str
            or _BEHAVIORAL_RECEIPT.fullmatch(self.source_receipt_id) is None
        ):
            raise ValueError("capability effect source receipt id is invalid")
        _typed_ref(
            self.execution_admission_ref,
            "capability_effect_execution_admission",
            field_name="capability effect execution admission ref",
        )
        assessment_session_id = _bounded_string(
            self.assessment_session_id,
            field_name="capability effect assessment session id",
            maximum=256,
        )
        identity = _validate_identity(self.identity_binding)
        target_origin = _bounded_string(
            self.target_origin,
            field_name="capability effect target origin",
            maximum=2048,
        )
        parsed_origin = canonical_origin(target_origin)
        if parsed_origin is None or parsed_origin.as_url() != target_origin:
            raise ValueError("capability effect target origin is not canonical")
        specification_ref = _typed_ref(
            self.specification_ref,
            "capability_effect_one_click_specification",
            field_name="capability effect specification ref",
        )
        operation_ref = _typed_ref(
            self.operation_ref,
            "capability_operation",
            field_name="capability effect operation ref",
        )
        capability_ref = _typed_ref(
            self.capability_ref,
            "issued_capability_contract",
            field_name="capability effect capability ref",
        )
        world_ref = _typed_ref(
            self.experiment_world_ref,
            "world",
            field_name="capability effect experiment world ref",
        )
        expected_world_ref = stable_hash("world", identity["persona_id"])
        if world_ref != expected_world_ref:
            raise ValueError(
                "capability effect experiment world ref does not match identity"
            )
        if type(self.observations) not in {list, tuple}:
            raise ValueError("capability effect observations are invalid")
        observations = tuple(_validate_observation(item) for item in self.observations)
        if len(observations) != len(_OBSERVATION_KINDS):
            raise ValueError("capability effect observation count is invalid")
        if type(self.terminal_receipts) not in {list, tuple}:
            raise ValueError("capability effect terminal receipts are invalid")
        terminal_receipts = tuple(
            _validate_terminal_receipt(item) for item in self.terminal_receipts
        )
        if len(terminal_receipts) != len(_OBSERVATION_KINDS):
            raise ValueError("capability effect terminal receipt count is invalid")
        oracle = _validate_oracle(self.oracle)
        oracle_evaluation_ref = _typed_ref(
            self.oracle_evaluation_ref,
            "capability_effect_oracle_evaluation",
            field_name="capability effect oracle evaluation ref",
        )
        cleanup = _validate_cleanup(self.cleanup)
        policy = CapabilityEffectExecutionPolicySnapshot.from_mapping(
            self.execution_policy
        )
        producer = CapabilityEffectProducerIdentity.from_mapping(self.producer_identity)
        if (
            type(self.conduct_provenance_root) is not str
            or _BARE_SHA256.fullmatch(self.conduct_provenance_root) is None
        ):
            raise ValueError("capability effect conduct provenance root is invalid")
        if (
            type(self.observed_at_epoch) is not float
            or not math.isfinite(self.observed_at_epoch)
            or self.observed_at_epoch <= 0
        ):
            raise ValueError("capability effect observation time is invalid")
        runtime_classification = _semantic(
            self.runtime_evidence_classification,
            field_name="capability effect runtime evidence classification",
        )
        if runtime_classification not in _RUNTIME_EVIDENCE_CLASSIFICATIONS:
            raise ValueError(
                "capability effect runtime evidence classification is invalid"
            )

        object.__setattr__(self, "assessment_session_id", assessment_session_id)
        object.__setattr__(self, "identity_binding", identity)
        object.__setattr__(self, "target_origin", target_origin)
        object.__setattr__(self, "specification_ref", specification_ref)
        object.__setattr__(self, "operation_ref", operation_ref)
        object.__setattr__(self, "capability_ref", capability_ref)
        object.__setattr__(self, "experiment_world_ref", world_ref)
        object.__setattr__(self, "observations", observations)
        object.__setattr__(self, "terminal_receipts", terminal_receipts)
        object.__setattr__(self, "oracle", oracle)
        object.__setattr__(self, "oracle_evaluation_ref", oracle_evaluation_ref)
        object.__setattr__(self, "cleanup", cleanup)
        object.__setattr__(self, "execution_policy", _frozen_mapping(policy.to_dict()))
        object.__setattr__(
            self, "producer_identity", _frozen_mapping(producer.to_dict())
        )
        object.__setattr__(
            self,
            "runtime_evidence_classification",
            runtime_classification,
        )

        if (
            identity["session_id"] != assessment_session_id
            or identity["target_origin"] != target_origin
            or tuple(item["observation_kind"] for item in observations)
            != _OBSERVATION_KINDS
            or tuple(item["receipt_outcome"] for item in observations)
            != _EXPECTED_OUTCOMES
            or len({item["receipt_ref"] for item in observations}) != len(observations)
            or len({item["capability_ref"] for item in observations}) != 1
            or any(item["capability_ref"] != capability_ref for item in observations)
            or len({item["observation_binding_id"] for item in observations}) != 1
        ):
            raise ValueError("capability effect evidence source bindings are invalid")
        for observation, receipt, expected_outcome in zip(
            observations,
            terminal_receipts,
            _EXPECTED_OUTCOMES,
        ):
            if (
                observation["receipt_ref"] != receipt["receipt_id"]
                or observation["capability_ref"] != receipt["capability_ref"]
                or observation["receipt_outcome"] != receipt["outcome"]
                or receipt["outcome"] != expected_outcome
            ):
                raise ValueError(
                    "capability effect terminal receipt binding is invalid"
                )
        recomputed = _recomputed_oracle(
            oracle["oracle_id"],
            observations[0]["observation_binding_id"],
            observations,
        )
        if (
            oracle_evaluation_ref != oracle["evaluation_id"]
            or oracle["observation_binding_id"]
            != observations[0]["observation_binding_id"]
            or any(
                oracle[key] != recomputed[key]
                for key in (
                    "oracle_id",
                    "observation_binding_id",
                    "verdict",
                    "observation_refs",
                    "uncertainty_reasons",
                    "no_capability_effect_absent",
                    "authorized_effect_observed_once",
                    "replay_effect_absent",
                    "expired_effect_absent",
                    "inadmissible_effect_absent",
                    "authorized_effect_ref",
                    "finding_candidate_ref",
                    "adversarial_triage_required",
                    "promotion_authority",
                    "finding_authority",
                )
            )
        ):
            raise ValueError("capability effect oracle projection is inconsistent")
        source_payload = _source_execution_payload(
            capability_ref=capability_ref,
            observations=observations,
            oracle=oracle,
            cleanup=cleanup,
        )
        if self.source_execution_id != stable_hash(
            "capability_effect_execution_result",
            source_payload,
        ):
            raise ValueError("capability effect source execution commitment is invalid")
        preimage = self.to_dict()
        preimage.pop("evidence_root")
        if self.evidence_root != _evidence_root(preimage):
            raise ValueError("capability effect evidence root does not match")
        if (
            len(_canonical_json_bytes(self.to_dict()))
            > CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES
        ):
            raise ValueError("capability effect evidence exceeds 256 KiB")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "adapter_contract_version": self.adapter_contract_version,
            "evidence_root": self.evidence_root,
            "source_execution_id": self.source_execution_id,
            "source_receipt_id": self.source_receipt_id,
            "execution_admission_ref": self.execution_admission_ref,
            "assessment_session_id": self.assessment_session_id,
            "identity_binding": _thaw(self.identity_binding),
            "target_origin": self.target_origin,
            "specification_ref": self.specification_ref,
            "operation_ref": self.operation_ref,
            "capability_ref": self.capability_ref,
            "experiment_world_ref": self.experiment_world_ref,
            "observations": [_thaw(item) for item in self.observations],
            "terminal_receipts": [_thaw(item) for item in self.terminal_receipts],
            "oracle": _thaw(self.oracle),
            "oracle_evaluation_ref": self.oracle_evaluation_ref,
            "cleanup": _thaw(self.cleanup),
            "execution_policy": _thaw(self.execution_policy),
            "conduct_provenance_root": self.conduct_provenance_root,
            "producer_identity": _thaw(self.producer_identity),
            "observed_at_epoch": self.observed_at_epoch,
            "runtime_evidence_classification": (self.runtime_evidence_classification),
        }

    def to_json_bytes(self) -> bytes:
        encoded = _canonical_json_bytes(self.to_dict())
        if len(encoded) > CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES:
            raise ValueError("capability effect evidence exceeds 256 KiB")
        return encoded


def _validated_execution_export(value: Mapping[str, Any]) -> Dict[str, Any]:
    source = _exact_mapping(
        value,
        _EXECUTION_EXPORT_FIELDS,
        field_name="capability effect execution export",
    )
    _version(source["schema_version"], field_name="capability effect execution export")
    result_id = _typed_ref(
        source["result_id"],
        "capability_effect_execution_result",
        field_name="capability effect execution result id",
    )
    receipt_id = _typed_ref(
        source["receipt_id"],
        "capability_execution_receipt",
        field_name="capability effect execution receipt id",
    )
    capability_ref = _typed_ref(
        source["capability_ref"],
        "issued_capability_contract",
        field_name="capability effect execution capability ref",
    )
    binding_id = _typed_ref(
        source["observation_binding_id"],
        "experiment_world_binding",
        field_name="capability effect execution binding id",
    )
    world_ref = _typed_ref(
        source["experiment_world_ref"],
        "world",
        field_name="capability effect execution world ref",
    )
    if (
        type(source["effect_observations"]) is not list
        or type(source["terminal_receipts"]) is not list
    ):
        raise ValueError("capability effect execution projections are invalid")
    observations = tuple(
        _validate_observation(item) for item in source["effect_observations"]
    )
    receipts = tuple(
        _validate_terminal_receipt(item) for item in source["terminal_receipts"]
    )
    oracle = _validate_oracle(source["oracle"])
    cleanup = _validate_cleanup(source["cleanup"])
    refs = source["observation_refs"]
    if type(refs) is not list:
        raise ValueError("capability effect execution observation refs are invalid")
    if (
        len(observations) != len(_OBSERVATION_KINDS)
        or len(receipts) != len(_OBSERVATION_KINDS)
        or refs != [item["observation_id"] for item in observations]
        or receipt_id != observations[1]["receipt_ref"]
        or capability_ref != observations[0]["capability_ref"]
        or binding_id != observations[0]["observation_binding_id"]
        or source["oracle_verdict"] != oracle["verdict"]
        or source["finding_candidate_ref"] != oracle["finding_candidate_ref"]
        or source["mode"] != _SOURCE_EXECUTION_MODE
        or _exact_bool(
            source["execution_enabled"],
            field_name="capability effect execution enabled",
        )
        is not True
        or _exact_bool(
            source["execution_effect_authority"],
            field_name="capability effect execution effect authority",
        )
        != (oracle["verdict"] == _CONFIRMED)
        or _exact_bool(
            source["adversarial_triage_required"],
            field_name="capability effect execution triage flag",
        )
        is not True
        or _exact_bool(
            source["promotion_authority"],
            field_name="capability effect execution promotion authority",
        )
        is not False
        or _exact_bool(
            source["finding_authority"],
            field_name="capability effect execution finding authority",
        )
        is not False
    ):
        raise ValueError("capability effect execution export is inconsistent")
    payload = _source_execution_payload(
        capability_ref=capability_ref,
        observations=observations,
        oracle=oracle,
        cleanup=cleanup,
    )
    if result_id != stable_hash("capability_effect_execution_result", payload):
        raise ValueError("capability effect execution result commitment is invalid")
    return {
        "result_id": result_id,
        "capability_ref": capability_ref,
        "experiment_world_ref": world_ref,
        "observations": [_thaw(item) for item in observations],
        "terminal_receipts": [_thaw(item) for item in receipts],
        "oracle": _thaw(oracle),
        "cleanup": _thaw(cleanup),
    }


def build_capability_effect_evidence(
    *,
    execution_export: Mapping[str, Any],
    source_receipt_id: str,
    execution_admission_ref: str,
    assessment_session_id: str,
    identity_binding: Mapping[str, Any],
    target_origin: str,
    specification_ref: str,
    operation_ref: str,
    execution_policy: (Mapping[str, Any] | CapabilityEffectExecutionPolicySnapshot),
    conduct_provenance_root: str,
    producer_identity: Mapping[str, Any] | CapabilityEffectProducerIdentity,
    observed_at_epoch: float,
    runtime_evidence_classification: str,
) -> CapabilityEffectEvidence:
    """Build one completed secure or refuted evidence record from public exports."""

    export = _validated_execution_export(execution_export)
    policy_value = (
        execution_policy.to_dict()
        if type(execution_policy) is CapabilityEffectExecutionPolicySnapshot
        else execution_policy
    )
    producer_value = (
        producer_identity.to_dict()
        if type(producer_identity) is CapabilityEffectProducerIdentity
        else producer_identity
    )
    preimage: Dict[str, Any] = {
        "schema_version": CAPABILITY_EFFECT_EVIDENCE_SCHEMA_VERSION,
        "adapter_contract_version": CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION,
        "source_execution_id": export["result_id"],
        "source_receipt_id": source_receipt_id,
        "execution_admission_ref": execution_admission_ref,
        "assessment_session_id": assessment_session_id,
        "identity_binding": dict(identity_binding),
        "target_origin": target_origin,
        "specification_ref": specification_ref,
        "operation_ref": operation_ref,
        "capability_ref": export["capability_ref"],
        "experiment_world_ref": export["experiment_world_ref"],
        "observations": export["observations"],
        "terminal_receipts": export["terminal_receipts"],
        "oracle": export["oracle"],
        "oracle_evaluation_ref": export["oracle"]["evaluation_id"],
        "cleanup": export["cleanup"],
        "execution_policy": dict(policy_value),
        "conduct_provenance_root": conduct_provenance_root,
        "producer_identity": dict(producer_value),
        "observed_at_epoch": observed_at_epoch,
        "runtime_evidence_classification": runtime_evidence_classification,
    }
    value = {"evidence_root": _evidence_root(preimage), **preimage}
    return CapabilityEffectEvidence.from_mapping(value)


@dataclass(frozen=True)
class CapabilityReplayLeakEvaluation:
    eligible: bool
    reason_code: str
    failed_clauses: Tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise TypeError("capability replay eligibility must be boolean")
        _semantic(self.reason_code, field_name="capability replay reason code")
        if any(
            type(item) is not int or not 1 <= item <= 11 for item in self.failed_clauses
        ):
            raise ValueError("capability replay failed clauses are invalid")


def evaluate_replay_leak(
    evidence: CapabilityEffectEvidence,
) -> CapabilityReplayLeakEvaluation:
    """Purely evaluate the frozen eleven-clause replay-leak predicate."""

    if type(evidence) is not CapabilityEffectEvidence:
        raise TypeError("capability replay evaluation requires typed evidence")
    observations = evidence.observations
    receipts = evidence.terminal_receipts
    baseline, witness, replay, expired, inadmissible = observations
    clause_1 = bool(
        len(observations) == 5
        and tuple(item["observation_kind"] for item in observations)
        == _OBSERVATION_KINDS
    )
    clause_2 = bool(
        len(receipts) == 5
        and all(
            observation["receipt_ref"] == receipt["receipt_id"]
            and observation["receipt_outcome"] == expected
            and receipt["outcome"] == expected
            for observation, receipt, expected in zip(
                observations,
                receipts,
                _EXPECTED_OUTCOMES,
            )
        )
    )
    clause_3 = bool(
        len({item["capability_ref"] for item in observations}) == 1
        and observations[0]["capability_ref"] == evidence.capability_ref
        and len({item["observation_binding_id"] for item in observations}) == 1
        and evidence.identity_binding["session_id"] == evidence.assessment_session_id
        and evidence.identity_binding["target_origin"] == evidence.target_origin
        and evidence.experiment_world_ref
        == stable_hash("world", evidence.identity_binding["persona_id"])
        and evidence.oracle["observation_refs"]
        == tuple(item["observation_id"] for item in observations)
    )
    clause_4 = bool(
        witness["target_projection_observed"]
        and witness["access_decision"] == "allowed"
        and witness["protected_effect_observed"]
        and witness["effect_ref"] is not None
    )
    clause_5 = bool(
        replay["target_projection_observed"]
        and replay["access_decision"] == "allowed"
        and replay["protected_effect_observed"]
        and replay["effect_ref"] is not None
        and replay["receipt_outcome"] == "execution_refused_already_consumed"
    )
    clause_6 = bool(
        witness["effect_ref"] is not None
        and replay["effect_ref"] is not None
        and witness["effect_ref"] == replay["effect_ref"]
        and witness["effect_ref"] == evidence.oracle["authorized_effect_ref"]
    )
    clause_7 = tuple(
        index
        for index, item in enumerate(observations)
        if item["protected_effect_observed"]
    ) == (1, 2)
    controls = (baseline, expired, inadmissible)
    clause_8 = all(
        item["target_projection_observed"]
        and item["access_decision"] == "denied"
        and not item["protected_effect_observed"]
        and item["effect_ref"] is None
        for item in controls
    )
    recomputed = _recomputed_oracle(
        evidence.oracle["oracle_id"],
        observations[0]["observation_binding_id"],
        observations,
    )
    clause_9 = bool(
        recomputed["verdict"] == _REFUTED
        and not recomputed["uncertainty_reasons"]
        and evidence.oracle["verdict"] == _REFUTED
        and not evidence.oracle["uncertainty_reasons"]
    )
    clause_10 = bool(
        evidence.cleanup["status"] == "verified"
        and not evidence.cleanup["target_request_may_have_been_sent"]
        and not evidence.cleanup["orphaned_owned_state_possible"]
    )
    policy = CapabilityEffectExecutionPolicySnapshot.from_mapping(
        evidence.execution_policy
    )
    preimage = evidence.to_dict()
    preimage.pop("evidence_root")
    clause_11 = bool(
        _BEHAVIORAL_RECEIPT.fullmatch(evidence.source_receipt_id)
        and _TYPED_SHA256.fullmatch(evidence.execution_admission_ref)
        and evidence.adapter_contract_version
        == CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION
        and evidence.evidence_root == _evidence_root(preimage)
        and policy.all_required_gates_admitted
        and evidence.source_execution_id
        == stable_hash(
            "capability_effect_execution_result",
            _source_execution_payload(
                capability_ref=evidence.capability_ref,
                observations=observations,
                oracle=evidence.oracle,
                cleanup=evidence.cleanup,
            ),
        )
    )
    clauses = (
        clause_1,
        clause_2,
        clause_3,
        clause_4,
        clause_5,
        clause_6,
        clause_7,
        clause_8,
        clause_9,
        clause_10,
        clause_11,
    )
    failed = tuple(index for index, passed in enumerate(clauses, 1) if not passed)
    if not failed:
        return CapabilityReplayLeakEvaluation(
            eligible=True,
            reason_code="eligible_replay_leak",
            failed_clauses=(),
        )
    if evidence.oracle["verdict"] == _CONFIRMED and recomputed["verdict"] == _CONFIRMED:
        reason = "secure_one_time_authorized_effect"
    else:
        reasons = {
            1: "observation_matrix_mismatch",
            2: "terminal_receipt_mismatch",
            3: "source_reference_mismatch",
            4: "authorized_witness_effect_missing",
            5: "replay_protected_effect_missing",
            6: "replay_effect_reference_mismatch",
            7: "unexpected_effect_phase",
            8: "control_phase_not_clean",
            9: "oracle_not_replay_refuted",
            10: "cleanup_not_verified",
            11: "source_validation_failed",
        }
        reason = reasons[failed[0]]
    return CapabilityReplayLeakEvaluation(
        eligible=False,
        reason_code=reason,
        failed_clauses=failed,
    )


def replay_leak_finding_material(
    evidence: CapabilityEffectEvidence,
) -> Dict[str, Any]:
    """Build the frozen bounded finding claim for eligible retained evidence."""

    evaluation = evaluate_replay_leak(evidence)
    if not evaluation.eligible:
        raise ValueError("capability effect evidence is not a replay leak")
    return {
        "title": "Protected effect exposed by replay after capability consumption",
        "confirmation_level": "confirmed",
        "severity": "medium",
        "description": (
            "Retained controlled-execution evidence shows that the valid witness "
            "and consumed-capability replay exposed the same target-reported "
            "protected-effect representation, while the no-capability, expired, "
            "and inadmissible controls exposed no protected effect and cleanup was "
            "verified. This confirms repeated exposure of the same representation "
            "after consumption; it does not independently establish two distinct "
            "backend state mutations."
        ),
        "remediation": (
            "Enforce one-time capability consumption atomically at the protected "
            "operation, and prevent a consumed capability from causing repeated "
            "protected-effect exposure or repeated execution."
        ),
        "metadata": {
            "finding_class": CAPABILITY_REPLAY_LEAK_CLASS_VERSION,
            "evidence_schema_version": evidence.schema_version,
            "leak_class_version": CAPABILITY_REPLAY_LEAK_CLASS_VERSION,
            "evidence_root": evidence.evidence_root,
            "source_execution_id": evidence.source_execution_id,
            "source_receipt_id": evidence.source_receipt_id,
            "execution_admission_ref": evidence.execution_admission_ref,
            "adapter_contract_version": evidence.adapter_contract_version,
            "producer_identity": _thaw(evidence.producer_identity),
            "assessment_session_id": evidence.assessment_session_id,
            "target_origin": evidence.target_origin,
            "specification_ref": evidence.specification_ref,
            "operation_ref": evidence.operation_ref,
            "capability_ref": evidence.capability_ref,
            "experiment_world_ref": evidence.experiment_world_ref,
            "oracle_evaluation_ref": evidence.oracle_evaluation_ref,
            "conduct_provenance_root": evidence.conduct_provenance_root,
            "observed_at_epoch": evidence.observed_at_epoch,
            "runtime_evidence_classification": (
                evidence.runtime_evidence_classification
            ),
            "impact_assessment": "unassessed",
            "severity_basis": ("provisional_class_default_pending_impact_assessment"),
            "evidence_trust_boundary": "authenticated_local_execution_producer",
        },
    }


__all__ = [
    "CAPABILITY_EFFECT_ADAPTER_CONTRACT_VERSION",
    "CAPABILITY_EFFECT_EVIDENCE_MAX_BYTES",
    "CAPABILITY_EFFECT_EVIDENCE_ROOT_DOMAIN",
    "CAPABILITY_EFFECT_EVIDENCE_SCHEMA_VERSION",
    "CAPABILITY_REPLAY_LEAK_CLASS_VERSION",
    "CapabilityEffectEvidence",
    "CapabilityEffectExecutionPolicySnapshot",
    "CapabilityEffectProducerIdentity",
    "CapabilityReplayLeakEvaluation",
    "build_capability_effect_evidence",
    "evaluate_replay_leak",
    "replay_leak_finding_material",
]
