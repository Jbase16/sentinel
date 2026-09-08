#!/usr/bin/env python3
"""Independently verify one retained R5D10 promotion result.

This acceptance verifier intentionally uses only the Python standard library.
It does not import Sentinel's evidence parser, promotion service, canonical
ledger, or any other production module whose answer it is checking.

The verifier treats the authenticated local execution producer as the origin
trust boundary.  Hashes establish integrity and linkage inside that boundary;
they do not authenticate evidence against an attacker controlling every local
store.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote, urlparse


MAX_EVIDENCE_BYTES = 256 * 1024
EVIDENCE_ROOT_DOMAIN = b"sentinelforge:capability-effect-evidence:v1\x00"
ADAPTER_VERSION = "capability_effect_target_projection_v1"
LEAK_CLASS_VERSION = "capability_replay_leak_v1"
SOURCE_MODE = "behavioral_capability_effect_execution_v1"
TERMINAL_MODE = "behavioral_capability_execution_receipt_v1"

OBSERVATION_KINDS = (
    "no_capability_baseline",
    "valid_capability_effect_witness",
    "replayed_capability_probe",
    "expired_capability_probe",
    "inadmissible_capability_probe",
)
EXPECTED_OUTCOMES = (
    "execution_refused_not_live",
    "execution_completed",
    "execution_refused_already_consumed",
    "execution_refused_expired",
    "execution_refused_inadmissible",
)
REFUTED = "refuted"
CONFIRMED = "confirmed_one_time_authorized_effect"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BUILD_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TYPED_REF_RE = re.compile(r"^([a-z][a-z0-9_]{0,127}):([0-9a-f]{64})$")
RECEIPT_RE = re.compile(r"^behavioral-([0-9a-f]{64})$")
SEMANTIC_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")

RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_id",
        "fingerprint",
        "state",
        "context",
        "created_at",
        "updated_at",
        "reservation_hash",
        "outcome",
        "abort_reason",
        "terminal_evidence",
    }
)
RECEIPT_CONTEXT_FIELDS = frozenset(
    {"target_ref", "envelope_ref", "source_persona_ref", "peer_persona_ref"}
)
RECEIPT_OUTCOME_FIELDS = frozenset(
    {
        "kind",
        "status",
        "capability_effect_evidence",
        "finding",
        "finding_confirmed",
        "promotion_authority",
        "finding_authority",
    }
)
EVIDENCE_FIELDS = frozenset(
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
IDENTITY_FIELDS = frozenset(
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
OBSERVATION_FIELDS = frozenset(
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
TERMINAL_FIELDS = frozenset(
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
ORACLE_FIELDS = frozenset(
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
CLEANUP_FIELDS = frozenset(
    {
        "status",
        "target_requests_sent",
        "target_request_may_have_been_sent",
        "orphaned_owned_state_possible",
    }
)
POLICY_BOOLEAN_FIELDS = (
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
POLICY_FIELDS = frozenset(
    {"schema_version", "snapshot_id", "policy_ref", *POLICY_BOOLEAN_FIELDS}
)
PRODUCER_FIELDS = frozenset(
    {
        "schema_version",
        "producer_id",
        "producer_name",
        "build_id",
        "build_sha",
        "source_state",
    }
)

FINDING_TITLE = "Protected effect exposed by replay after capability consumption"
FINDING_DESCRIPTION = (
    "Retained controlled-execution evidence shows that the valid witness "
    "and consumed-capability replay exposed the same target-reported "
    "protected-effect representation, while the no-capability, expired, "
    "and inadmissible controls exposed no protected effect and cleanup was "
    "verified. This confirms repeated exposure of the same representation "
    "after consumption; it does not independently establish two distinct "
    "backend state mutations."
)
FINDING_REMEDIATION = (
    "Enforce one-time capability consumption atomically at the protected "
    "operation, and prevent a consumed capability from causing repeated "
    "protected-effect exposure or repeated execution."
)


class VerificationError(ValueError):
    """One independently checked contract is invalid."""


def _duplicate_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise VerificationError(f"duplicate JSON key: {key}")
        value[key] = child
    return value


def _reject_constant(value: str) -> None:
    raise VerificationError(f"invalid JSON constant: {value}")


def _decode_json_bytes(payload: bytes, *, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_duplicate_rejector,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not strict UTF-8 JSON") from exc


def _decode_json_text(payload: str, *, label: str) -> Any:
    if type(payload) is not str:
        raise VerificationError(f"{label} is not JSON text")
    return _decode_json_bytes(payload.encode("utf-8"), label=label)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise VerificationError("value is not canonical-JSON-safe") from exc


def _stable_hash(kind: str, value: Any) -> str:
    return f"{kind}:{hashlib.sha256(_canonical_bytes(value)).hexdigest()}"


def _merkle_normalize(value: Any) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise VerificationError("event contains a non-finite number")
        return int(value) if value.is_integer() else value
    if type(value) is list:
        return [_merkle_normalize(item) for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise VerificationError("event contains a non-string key")
        return {key: _merkle_normalize(child) for key, child in value.items()}
    raise VerificationError("event contains an unsupported canonical type")


def _event_id(content: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        _canonical_bytes(_merkle_normalize(dict(content)))
    ).hexdigest()
    return f"evt-{digest[:12]}"


def _exact_mapping(value: Any, fields: frozenset[str], *, label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise VerificationError(f"{label} fields are invalid")
    return value


def _exact_list(value: Any, *, label: str) -> list[Any]:
    if type(value) is not list:
        raise VerificationError(f"{label} must be a list")
    return value


def _version(value: Any, *, label: str) -> None:
    if type(value) is not int or value != 1:
        raise VerificationError(f"{label} version is unsupported")


def _bounded_string(
    value: Any,
    *,
    label: str,
    maximum: int = 512,
    allow_empty: bool = False,
) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or len(value) > maximum
        or (not value and not allow_empty)
        or any(ord(character) < 0x20 for character in value)
    ):
        raise VerificationError(f"{label} is invalid")
    return value


def _semantic(value: Any, *, label: str) -> str:
    text = _bounded_string(value, label=label, maximum=128)
    if SEMANTIC_RE.fullmatch(text) is None:
        raise VerificationError(f"{label} is not a bounded semantic name")
    return text


def _typed_ref(value: Any, prefix: str, *, label: str) -> str:
    if type(value) is not str:
        raise VerificationError(f"{label} is not a typed reference")
    match = TYPED_REF_RE.fullmatch(value)
    if match is None or match.group(1) != prefix:
        raise VerificationError(f"{label} has the wrong typed-reference domain")
    return value


def _optional_typed_ref(value: Any, prefix: str, *, label: str) -> str | None:
    if value is None:
        return None
    return _typed_ref(value, prefix, label=label)


def _exact_bool(value: Any, *, label: str) -> bool:
    if type(value) is not bool:
        raise VerificationError(f"{label} must be a boolean")
    return value


def _exact_int(value: Any, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise VerificationError(f"{label} must be an integer >= {minimum}")
    return value


def _positive_finite_float(
    value: Any, *, label: str, exact_float: bool = False
) -> float:
    allowed = type(value) is float if exact_float else type(value) in {int, float}
    if not allowed or not math.isfinite(value) or value <= 0:
        raise VerificationError(f"{label} must be a positive finite number")
    return float(value)


def _canonical_origin(value: Any) -> str:
    text = _bounded_string(value, label="target origin", maximum=2048)
    try:
        parsed = urlparse(text)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise VerificationError("target origin is not an HTTP(S) origin")
        host = parsed.hostname.rstrip(".")
        try:
            host = str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise VerificationError("target origin port is invalid")
        rendered_host = f"[{host}]" if ":" in host else host
        default = 443 if scheme == "https" else 80
        canonical = f"{scheme}://{rendered_host}{'' if port == default else f':{port}'}"
    except (TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, VerificationError):
            raise
        raise VerificationError("target origin is invalid") from exc
    if text != canonical:
        raise VerificationError("target origin is not canonical")
    return canonical


def _identity_digest(identity: Mapping[str, Any]) -> str:
    material = {
        key: identity[key]
        for key in (
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
        )
    }
    return (
        f"assessment_identity:{hashlib.sha256(_canonical_bytes(material)).hexdigest()}"
    )


def _validate_identity(value: Any) -> dict[str, Any]:
    identity = _exact_mapping(value, IDENTITY_FIELDS, label="identity binding")
    if identity["schema"] != "assessment_identity_v1":
        raise VerificationError("identity schema is unsupported")
    for key in (
        "session_id",
        "authorization_envelope_id",
        "authorization_envelope_ref",
        "world_id",
        "persona_id",
        "target_actor_id",
        "tenant_id",
        "credential_source_ref",
        "resource_id",
        "representation_id",
    ):
        _bounded_string(identity[key], label=f"identity {key}")
    _typed_ref(
        identity["authorization_envelope_ref"],
        "authorization_envelope",
        label="identity authorization envelope",
    )
    _exact_int(identity["target_reset_epoch"], label="target reset epoch")
    _exact_int(identity["credential_epoch"], label="credential epoch")
    if identity["credential_freshness"] not in {"fresh", "stale", "unknown"}:
        raise VerificationError("identity credential freshness is invalid")
    if identity["display_name"] != "":
        raise VerificationError("identity display name was not redacted")
    if _canonical_origin(identity["target_origin"]) != identity["target_origin"]:
        raise VerificationError("identity target origin is inconsistent")
    if identity["digest"] != _identity_digest(identity):
        raise VerificationError("identity digest is invalid")
    return identity


def _observation_hash_payload(value: Mapping[str, Any]) -> dict[str, Any]:
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


def _validate_observation(value: Any) -> dict[str, Any]:
    item = _exact_mapping(value, OBSERVATION_FIELDS, label="effect observation")
    _version(item["schema_version"], label="effect observation")
    _typed_ref(
        item["observation_id"], "capability_effect_observation", label="observation id"
    )
    _typed_ref(
        item["receipt_ref"], "capability_execution_receipt", label="observation receipt"
    )
    _typed_ref(
        item["capability_ref"],
        "issued_capability_contract",
        label="observation capability",
    )
    _typed_ref(
        item["observation_binding_id"],
        "experiment_world_binding",
        label="observation binding",
    )
    _typed_ref(
        item["response_ref"],
        "capability_effect_target_response",
        label="observation response",
    )
    if (
        _semantic(item["observation_kind"], label="observation kind")
        not in OBSERVATION_KINDS
    ):
        raise VerificationError("observation kind is unsupported")
    _semantic(item["receipt_outcome"], label="observation receipt outcome")
    if item["access_decision"] not in {"allowed", "denied", "unknown"}:
        raise VerificationError("observation access decision is invalid")
    status = _exact_int(
        item["response_status"], label="observation response status", minimum=100
    )
    if status > 599:
        raise VerificationError("observation response status is invalid")
    _optional_typed_ref(
        item["effect_ref"], "capability_protected_effect", label="effect reference"
    )
    observed = _exact_bool(
        item["protected_effect_observed"], label="protected-effect flag"
    )
    projected = _exact_bool(
        item["target_projection_observed"], label="target-projection flag"
    )
    if (
        observed != (item["effect_ref"] is not None)
        or (observed and not projected)
        or (observed and item["access_decision"] != "allowed")
    ):
        raise VerificationError("observation effect flags are inconsistent")
    expected = _stable_hash(
        "capability_effect_observation", _observation_hash_payload(item)
    )
    if item["observation_id"] != expected:
        raise VerificationError("observation commitment is invalid")
    return item


def _validate_terminal(value: Any) -> dict[str, Any]:
    item = _exact_mapping(value, TERMINAL_FIELDS, label="terminal receipt")
    _version(item["schema_version"], label="terminal receipt")
    _typed_ref(
        item["receipt_id"], "capability_execution_receipt", label="terminal receipt id"
    )
    _typed_ref(
        item["capability_ref"],
        "issued_capability_contract",
        label="terminal capability",
    )
    _typed_ref(
        item["liveness_ref"], "runtime_liveness_decision", label="terminal liveness"
    )
    _typed_ref(
        item["consumption_ref"],
        "capability_consumption_decision",
        label="terminal consumption",
    )
    epoch_text = _bounded_string(
        item["observed_epoch"], label="terminal observed epoch", maximum=64
    )
    try:
        epoch = float(epoch_text)
    except ValueError as exc:
        raise VerificationError("terminal observed epoch is invalid") from exc
    if not math.isfinite(epoch) or repr(epoch) != epoch_text:
        raise VerificationError("terminal observed epoch is not canonical")
    if item["outcome"] not in EXPECTED_OUTCOMES or item["mode"] != TERMINAL_MODE:
        raise VerificationError("terminal receipt outcome or mode is invalid")
    for key in (
        "target_dispatch_authority",
        "execution_effect_authority",
        "finding_promotion_authority",
        "target_cleanup_authority",
    ):
        if _exact_bool(item[key], label=f"terminal {key}"):
            raise VerificationError("terminal receipt grants authority")
    payload = {
        key: item[key]
        for key in (
            "capability_ref",
            "liveness_ref",
            "consumption_ref",
            "observed_epoch",
            "outcome",
            "mode",
        )
    }
    if item["receipt_id"] != _stable_hash("capability_execution_receipt", payload):
        raise VerificationError("terminal receipt commitment is invalid")
    return item


def _recomputed_oracle(
    oracle_id: str,
    binding_id: str,
    observations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    baseline, witness, replay, expired, inadmissible = observations

    def refused(item: Mapping[str, Any]) -> bool:
        return bool(
            item["target_projection_observed"]
            and item["access_decision"] == "denied"
            and not item["protected_effect_observed"]
        )

    baseline_absent = refused(baseline)
    replay_absent = refused(replay)
    expired_absent = refused(expired)
    inadmissible_absent = refused(inadmissible)
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
    uncertainty: set[str] = set()
    for kind, item in zip(OBSERVATION_KINDS, observations):
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
        verdict = REFUTED
    elif witness_effect and all(refusal_absence):
        verdict = CONFIRMED
        uncertainty.clear()
    else:
        verdict = "inconclusive"
    candidate = (
        _stable_hash(
            "capability_effect_finding_candidate",
            {
                "oracle_id": oracle_id,
                "observation_binding_id": binding_id,
                "verdict": verdict,
                "observation_refs": [item["observation_id"] for item in observations],
                "authorized_effect_ref": witness["effect_ref"],
            },
        )
        if verdict == CONFIRMED
        else None
    )
    return {
        "oracle_id": oracle_id,
        "observation_binding_id": binding_id,
        "verdict": verdict,
        "observation_refs": [item["observation_id"] for item in observations],
        "uncertainty_reasons": sorted(uncertainty),
        "no_capability_effect_absent": baseline_absent,
        "authorized_effect_observed_once": witness_effect
        and len(observed_effects) == 1,
        "replay_effect_absent": replay_absent,
        "expired_effect_absent": expired_absent,
        "inadmissible_effect_absent": inadmissible_absent,
        "authorized_effect_ref": witness["effect_ref"] if witness_effect else None,
        "finding_candidate_ref": candidate,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
    }


def _oracle_hash_payload(oracle: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: oracle[key]
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


def _source_execution_payload(evidence: Mapping[str, Any]) -> dict[str, Any]:
    observations = evidence["observations"]
    oracle = evidence["oracle"]
    return {
        "receipt_id": observations[1]["receipt_ref"],
        "capability_ref": evidence["capability_ref"],
        "observation_binding_id": observations[0]["observation_binding_id"],
        "effect_observations": observations,
        "observation_refs": [item["observation_id"] for item in observations],
        "oracle": oracle,
        "oracle_verdict": oracle["verdict"],
        "finding_candidate_ref": oracle["finding_candidate_ref"],
        "cleanup": evidence["cleanup"],
        "execution_enabled": True,
        "execution_effect_authority": oracle["verdict"] == CONFIRMED,
        "adversarial_triage_required": True,
        "promotion_authority": False,
        "finding_authority": False,
        "mode": SOURCE_MODE,
    }


def _validate_evidence(evidence: Any) -> dict[str, Any]:
    value = _exact_mapping(
        evidence, EVIDENCE_FIELDS, label="capability-effect evidence"
    )
    _version(value["schema_version"], label="capability-effect evidence")
    if value["adapter_contract_version"] != ADAPTER_VERSION:
        raise VerificationError("adapter contract is unsupported")
    if (
        type(value["evidence_root"]) is not str
        or SHA256_RE.fullmatch(value["evidence_root"]) is None
    ):
        raise VerificationError("evidence root is invalid")
    _typed_ref(
        value["source_execution_id"],
        "capability_effect_execution_result",
        label="source execution",
    )
    if (
        type(value["source_receipt_id"]) is not str
        or RECEIPT_RE.fullmatch(value["source_receipt_id"]) is None
    ):
        raise VerificationError("source receipt id is invalid")
    _typed_ref(
        value["execution_admission_ref"],
        "capability_effect_execution_admission",
        label="execution admission",
    )
    _bounded_string(
        value["assessment_session_id"], label="assessment session", maximum=256
    )
    identity = _validate_identity(value["identity_binding"])
    origin = _canonical_origin(value["target_origin"])
    _typed_ref(
        value["specification_ref"],
        "capability_effect_one_click_specification",
        label="specification",
    )
    _typed_ref(value["operation_ref"], "capability_operation", label="operation")
    _typed_ref(
        value["capability_ref"], "issued_capability_contract", label="capability"
    )
    _typed_ref(value["experiment_world_ref"], "world", label="experiment world")
    expected_world_ref = _stable_hash("world", identity["persona_id"])
    if value["experiment_world_ref"] != expected_world_ref:
        raise VerificationError("experiment world does not match the retained identity")
    observations = [
        _validate_observation(item)
        for item in _exact_list(value["observations"], label="observations")
    ]
    terminals = [
        _validate_terminal(item)
        for item in _exact_list(value["terminal_receipts"], label="terminal receipts")
    ]
    if len(observations) != 5 or len(terminals) != 5:
        raise VerificationError("evidence does not contain exactly five phases")
    if tuple(item["observation_kind"] for item in observations) != OBSERVATION_KINDS:
        raise VerificationError("observation phases are reordered")
    if tuple(item["receipt_outcome"] for item in observations) != EXPECTED_OUTCOMES:
        raise VerificationError("observation outcomes are reordered")
    if len({item["receipt_ref"] for item in observations}) != 5:
        raise VerificationError("observation receipt references are not unique")
    if any(item["capability_ref"] != value["capability_ref"] for item in observations):
        raise VerificationError("observation capability binding is inconsistent")
    if len({item["observation_binding_id"] for item in observations}) != 1:
        raise VerificationError("observation world binding is inconsistent")
    for item, receipt, outcome in zip(observations, terminals, EXPECTED_OUTCOMES):
        if (
            item["receipt_ref"] != receipt["receipt_id"]
            or item["capability_ref"] != receipt["capability_ref"]
            or item["receipt_outcome"] != receipt["outcome"]
            or receipt["outcome"] != outcome
        ):
            raise VerificationError("terminal receipt is not bound to its observation")

    oracle = _exact_mapping(value["oracle"], ORACLE_FIELDS, label="oracle")
    _version(oracle["schema_version"], label="oracle")
    _typed_ref(
        oracle["evaluation_id"],
        "capability_effect_oracle_evaluation",
        label="oracle evaluation",
    )
    _typed_ref(oracle["oracle_id"], "capability_effect_oracle", label="oracle id")
    _typed_ref(
        oracle["observation_binding_id"],
        "experiment_world_binding",
        label="oracle binding",
    )
    if oracle["verdict"] not in {REFUTED, CONFIRMED}:
        raise VerificationError("oracle verdict is not a completed verdict")
    oracle_refs = _exact_list(
        oracle["observation_refs"], label="oracle observation refs"
    )
    if len(oracle_refs) != 5 or len(set(oracle_refs)) != 5:
        raise VerificationError("oracle observation references are invalid")
    for ref in oracle_refs:
        _typed_ref(
            ref, "capability_effect_observation", label="oracle observation reference"
        )
    uncertainty = _exact_list(oracle["uncertainty_reasons"], label="oracle uncertainty")
    if any(_semantic(item, label="oracle uncertainty") != item for item in uncertainty):
        raise VerificationError("oracle uncertainty is invalid")
    if uncertainty != sorted(set(uncertainty)):
        raise VerificationError("oracle uncertainty is not canonical")
    for key in (
        "no_capability_effect_absent",
        "authorized_effect_observed_once",
        "replay_effect_absent",
        "expired_effect_absent",
        "inadmissible_effect_absent",
        "adversarial_triage_required",
        "promotion_authority",
        "finding_authority",
    ):
        _exact_bool(oracle[key], label=f"oracle {key}")
    if (
        not oracle["adversarial_triage_required"]
        or oracle["promotion_authority"]
        or oracle["finding_authority"]
    ):
        raise VerificationError("oracle authority fields are invalid")
    _optional_typed_ref(
        oracle["authorized_effect_ref"],
        "capability_protected_effect",
        label="oracle authorized effect",
    )
    _optional_typed_ref(
        oracle["finding_candidate_ref"],
        "capability_effect_finding_candidate",
        label="oracle candidate",
    )
    if (oracle["verdict"] == CONFIRMED) != (
        oracle["finding_candidate_ref"] is not None
    ):
        raise VerificationError("oracle candidate binding is inconsistent")
    recomputed = _recomputed_oracle(
        oracle["oracle_id"],
        observations[0]["observation_binding_id"],
        observations,
    )
    if any(oracle[key] != recomputed[key] for key in recomputed):
        raise VerificationError(
            "oracle projection does not match retained observations"
        )
    expected_evaluation = _stable_hash(
        "capability_effect_oracle_evaluation",
        _oracle_hash_payload(oracle),
    )
    if (
        oracle["evaluation_id"] != expected_evaluation
        or value["oracle_evaluation_ref"] != expected_evaluation
    ):
        raise VerificationError("oracle evaluation commitment is invalid")

    cleanup = _exact_mapping(value["cleanup"], CLEANUP_FIELDS, label="cleanup")
    if cleanup["status"] != "verified":
        raise VerificationError("cleanup is not verified")
    if _exact_int(cleanup["target_requests_sent"], label="cleanup request count") != 6:
        raise VerificationError("cleanup request count is not the frozen six requests")
    if _exact_bool(
        cleanup["target_request_may_have_been_sent"],
        label="cleanup request uncertainty",
    ):
        raise VerificationError("cleanup request uncertainty is set")
    if _exact_bool(
        cleanup["orphaned_owned_state_possible"], label="cleanup orphan flag"
    ):
        raise VerificationError("cleanup permits orphaned owned state")

    policy = _exact_mapping(
        value["execution_policy"], POLICY_FIELDS, label="execution policy"
    )
    _version(policy["schema_version"], label="execution policy")
    _typed_ref(
        policy["snapshot_id"],
        "capability_effect_execution_policy_snapshot",
        label="policy snapshot",
    )
    _typed_ref(
        policy["policy_ref"], "capability_effect_execution_policy", label="policy ref"
    )
    for key in POLICY_BOOLEAN_FIELDS:
        _exact_bool(policy[key], label=f"policy {key}")
    policy_payload = {
        "policy_ref": policy["policy_ref"],
        **{key: policy[key] for key in POLICY_BOOLEAN_FIELDS},
    }
    if policy["snapshot_id"] != _stable_hash(
        "capability_effect_execution_policy_snapshot", policy_payload
    ):
        raise VerificationError("execution policy snapshot commitment is invalid")

    producer = _exact_mapping(
        value["producer_identity"], PRODUCER_FIELDS, label="producer identity"
    )
    _version(producer["schema_version"], label="producer identity")
    _typed_ref(
        producer["producer_id"],
        "capability_effect_producer_identity",
        label="producer id",
    )
    _bounded_string(producer["producer_name"], label="producer name", maximum=128)
    _bounded_string(producer["build_id"], label="producer build id", maximum=256)
    if producer["source_state"] not in {"clean", "dirty", "unknown"}:
        raise VerificationError("producer source state is invalid")
    if (
        producer["source_state"] in {"clean", "dirty"}
        and (
            type(producer["build_sha"]) is not str
            or BUILD_SHA_RE.fullmatch(producer["build_sha"]) is None
        )
    ) or (producer["source_state"] == "unknown" and producer["build_sha"] != "unknown"):
        raise VerificationError("producer build sha is invalid")
    producer_payload = {
        key: producer[key]
        for key in ("producer_name", "build_id", "build_sha", "source_state")
    }
    if producer["producer_id"] != _stable_hash(
        "capability_effect_producer_identity", producer_payload
    ):
        raise VerificationError("producer commitment is invalid")

    if (
        type(value["conduct_provenance_root"]) is not str
        or SHA256_RE.fullmatch(value["conduct_provenance_root"]) is None
    ):
        raise VerificationError("conduct provenance root is invalid")
    _positive_finite_float(
        value["observed_at_epoch"], label="observation time", exact_float=True
    )
    if value["runtime_evidence_classification"] not in {
        "controlled_in_memory_twin",
        "controlled_owned_lab",
        "unknown",
    }:
        raise VerificationError("runtime evidence classification is invalid")
    if (
        identity["session_id"] != value["assessment_session_id"]
        or identity["target_origin"] != origin
    ):
        raise VerificationError("identity does not bind the evidence context")
    if oracle_refs != [item["observation_id"] for item in observations]:
        raise VerificationError("oracle observation references are reordered")
    if oracle["observation_binding_id"] != observations[0]["observation_binding_id"]:
        raise VerificationError("oracle observation binding is inconsistent")
    expected_execution = _stable_hash(
        "capability_effect_execution_result", _source_execution_payload(value)
    )
    if value["source_execution_id"] != expected_execution:
        raise VerificationError("source execution commitment is invalid")
    preimage = dict(value)
    preimage.pop("evidence_root")
    expected_root = hashlib.sha256(
        EVIDENCE_ROOT_DOMAIN + _canonical_bytes(preimage)
    ).hexdigest()
    if value["evidence_root"] != expected_root:
        raise VerificationError("evidence root is invalid")
    if len(_canonical_bytes(value)) > MAX_EVIDENCE_BYTES:
        raise VerificationError("evidence exceeds 256 KiB")
    return value


@dataclass
class Context:
    receipt_path: Path
    database_path: Path
    cas_blob_path: Path
    execution_id: str
    receipt_bytes: bytes | None = None
    receipt: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    cas_bytes: bytes | None = None
    journal: dict[str, Any] | None = None
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)


def _require_evidence(context: Context) -> dict[str, Any]:
    if context.evidence is None:
        raise VerificationError("schema-valid evidence is unavailable")
    return context.evidence


def _read_journal_snapshot(context: Context) -> dict[str, Any]:
    if context.journal is not None:
        return context.journal
    if not context.database_path.is_file():
        raise VerificationError("canonical database does not exist")
    identifier = context.execution_id
    if identifier.startswith("capability_effect_execution_admission:"):
        column = "admission_id"
    elif identifier.startswith("capability_effect_intake:"):
        column = "intake_id"
    elif identifier.startswith("behavioral-"):
        column = "source_receipt_id"
    elif SHA256_RE.fullmatch(identifier):
        column = "source_fingerprint"
    else:
        raise VerificationError("execution identifier is not a supported canonical id")
    columns = (
        "admission_id",
        "intake_id",
        "session_id",
        "target_origin",
        "identity_data",
        "operation_data",
        "producer_data",
        "storage_data",
        "source_receipt_id",
        "source_fingerprint",
        "event_timestamp",
        "event_run_id",
        "attempt_count",
        "attempts_data",
        "state",
        "evidence_root",
        "cas_blob_hash",
        "observation_id",
        "finding_id",
        "last_error",
    )
    uri_path = quote(str(context.database_path.resolve()), safe="/")
    try:
        connection = sqlite3.connect(f"file:{uri_path}?mode=ro", uri=True)
        connection.execute("BEGIN")
        row = connection.execute(
            f"SELECT {','.join(columns)} FROM capability_effect_promotion_journal WHERE {column} = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            raise VerificationError("promotion journal entry does not exist")
        journal = dict(zip(columns, row))
        for key in (
            "identity_data",
            "operation_data",
            "producer_data",
            "storage_data",
            "attempts_data",
        ):
            journal[key] = _decode_json_text(journal[key], label=f"journal {key}")
        entity_rows = connection.execute(
            "SELECT id,session_id,kind,commitment,data FROM epistemic_entities WHERE id IN (?,?)",
            (journal["observation_id"], journal["finding_id"]),
        ).fetchall()
        event_rows = connection.execute(
            "SELECT id,session_id,entity_id,event_type,data FROM epistemic_events WHERE entity_id IN (?,?) ORDER BY sequence",
            (journal["observation_id"], journal["finding_id"]),
        ).fetchall()
        connection.commit()
        connection.close()
    except sqlite3.Error as exc:
        raise VerificationError("canonical database could not be read") from exc
    context.journal = journal
    context.entities = {
        row[0]: {
            "id": row[0],
            "session_id": row[1],
            "kind": row[2],
            "commitment": row[3],
            "data_text": row[4],
            "data": _decode_json_text(row[4], label=f"canonical entity {row[0]}"),
        }
        for row in entity_rows
    }
    context.events = [
        {
            "id": row[0],
            "session_id": row[1],
            "entity_id": row[2],
            "event_type": row[3],
            "data_text": row[4],
            "data": _decode_json_text(row[4], label=f"canonical event {row[0]}"),
        }
        for row in event_rows
    ]
    return journal


def _check_schema(context: Context) -> dict[str, Any]:
    if not context.receipt_path.is_file():
        raise VerificationError("retained receipt does not exist")
    receipt_bytes = context.receipt_path.read_bytes()
    receipt = _exact_mapping(
        _decode_json_bytes(receipt_bytes, label="retained receipt"),
        RECEIPT_FIELDS,
        label="retained receipt",
    )
    _version(receipt["schema_version"], label="retained receipt")
    if (
        type(receipt["fingerprint"]) is not str
        or SHA256_RE.fullmatch(receipt["fingerprint"]) is None
    ):
        raise VerificationError("retained receipt fingerprint is invalid")
    if receipt["receipt_id"] != f"behavioral-{receipt['fingerprint']}":
        raise VerificationError("retained receipt identity is invalid")
    if receipt["state"] != "completed":
        raise VerificationError("retained receipt is not completed")
    created = _positive_finite_float(
        receipt["created_at"], label="receipt creation time"
    )
    updated = _positive_finite_float(receipt["updated_at"], label="receipt update time")
    if updated < created:
        raise VerificationError("retained receipt timestamps are inconsistent")
    if any(
        receipt[key] is not None
        for key in ("reservation_hash", "abort_reason", "terminal_evidence")
    ):
        raise VerificationError("completed receipt retains non-completed state")
    context_fields = _exact_mapping(
        receipt["context"], RECEIPT_CONTEXT_FIELDS, label="receipt context"
    )
    for key, prefix in (
        ("target_ref", "behavioral_receipt_target"),
        ("envelope_ref", "behavioral_receipt_envelope"),
        ("source_persona_ref", "behavioral_receipt_persona"),
        ("peer_persona_ref", "behavioral_receipt_persona"),
    ):
        _typed_ref(context_fields[key], prefix, label=f"receipt context {key}")
    outcome = _exact_mapping(
        receipt["outcome"], RECEIPT_OUTCOME_FIELDS, label="receipt outcome"
    )
    if outcome["kind"] != "capability_effect_one_click":
        raise VerificationError("receipt is not an inner capability-effect source")
    if (
        outcome["finding"] is not None
        or outcome["finding_confirmed"] is not False
        or outcome["promotion_authority"] is not False
        or outcome["finding_authority"] is not False
    ):
        raise VerificationError("source receipt improperly claims finding authority")
    evidence = _validate_evidence(outcome["capability_effect_evidence"])
    if outcome["status"] != evidence["oracle"]["verdict"]:
        raise VerificationError("source receipt status is inconsistent with its oracle")
    if evidence["source_receipt_id"] != receipt["receipt_id"]:
        raise VerificationError("evidence does not bind the retained receipt")
    context.receipt_bytes = receipt_bytes
    context.receipt = receipt
    context.evidence = evidence
    return {
        "receipt_id": receipt["receipt_id"],
        "evidence_schema_version": evidence["schema_version"],
        "adapter_contract_version": evidence["adapter_contract_version"],
    }


def _check_integrity(context: Context) -> dict[str, Any]:
    evidence = _require_evidence(context)
    journal = _read_journal_snapshot(context)
    if not context.cas_blob_path.is_file() or context.cas_blob_path.is_symlink():
        raise VerificationError("CAS artifact is missing or unsafe")
    cas_bytes = context.cas_blob_path.read_bytes()
    digest = hashlib.sha256(cas_bytes).hexdigest()
    if context.cas_blob_path.name != digest:
        raise VerificationError("CAS artifact filename does not equal its digest")
    if journal["cas_blob_hash"] != digest:
        raise VerificationError("journal CAS address does not equal artifact digest")
    if journal["evidence_root"] != evidence["evidence_root"]:
        raise VerificationError("journal evidence root is inconsistent")
    parsed = _decode_json_bytes(cas_bytes, label="CAS evidence artifact")
    if cas_bytes != _canonical_bytes(parsed):
        raise VerificationError("CAS evidence artifact is not canonical JSON")
    validated = _validate_evidence(parsed)
    if validated != evidence:
        raise VerificationError(
            "CAS evidence differs from the completed source receipt"
        )
    context.cas_bytes = cas_bytes
    return {
        "evidence_root": evidence["evidence_root"],
        "cas_blob_hash": digest,
        "canonical_bytes": True,
        "receipt_cas_equal": True,
    }


def _check_source_trust_mode(context: Context) -> dict[str, Any]:
    evidence = _require_evidence(context)
    producer = evidence["producer_identity"]
    mode = evidence["runtime_evidence_classification"]
    # Unknown/dirty are valid only as explicit qualifications.  This check
    # reports, rather than upgrades, the producer's actual claim.
    return {
        "trust_boundary": "authenticated_local_execution_producer",
        "runtime_evidence_classification": mode,
        "producer_id": producer["producer_id"],
        "producer_name": producer["producer_name"],
        "build_id": producer["build_id"],
        "build_sha": producer["build_sha"],
        "source_state": producer["source_state"],
        "qualification": (
            "unqualified_clean_build"
            if producer["source_state"] == "clean"
            else f"explicit_{producer['source_state']}_qualification"
        ),
    }


def _replay_clauses(evidence: Mapping[str, Any]) -> tuple[bool, ...]:
    observations = evidence["observations"]
    receipts = evidence["terminal_receipts"]
    baseline, witness, replay, expired, inadmissible = observations
    recomputed = _recomputed_oracle(
        evidence["oracle"]["oracle_id"],
        observations[0]["observation_binding_id"],
        observations,
    )
    preimage = dict(evidence)
    preimage.pop("evidence_root")
    source_payload = _source_execution_payload(evidence)
    return (
        len(observations) == 5
        and tuple(item["observation_kind"] for item in observations)
        == OBSERVATION_KINDS,
        len(receipts) == 5
        and all(
            observation["receipt_ref"] == receipt["receipt_id"]
            and observation["receipt_outcome"] == expected
            and receipt["outcome"] == expected
            for observation, receipt, expected in zip(
                observations, receipts, EXPECTED_OUTCOMES
            )
        ),
        len({item["capability_ref"] for item in observations}) == 1
        and observations[0]["capability_ref"] == evidence["capability_ref"]
        and len({item["observation_binding_id"] for item in observations}) == 1
        and evidence["identity_binding"]["session_id"]
        == evidence["assessment_session_id"]
        and evidence["identity_binding"]["target_origin"] == evidence["target_origin"]
        and evidence["experiment_world_ref"]
        == _stable_hash("world", evidence["identity_binding"]["persona_id"])
        and evidence["oracle"]["observation_refs"]
        == [item["observation_id"] for item in observations],
        witness["target_projection_observed"]
        and witness["access_decision"] == "allowed"
        and witness["protected_effect_observed"]
        and witness["effect_ref"] is not None,
        replay["target_projection_observed"]
        and replay["access_decision"] == "allowed"
        and replay["protected_effect_observed"]
        and replay["effect_ref"] is not None
        and replay["receipt_outcome"] == "execution_refused_already_consumed",
        witness["effect_ref"] is not None
        and replay["effect_ref"] is not None
        and witness["effect_ref"] == replay["effect_ref"]
        and witness["effect_ref"] == evidence["oracle"]["authorized_effect_ref"],
        tuple(
            index
            for index, item in enumerate(observations)
            if item["protected_effect_observed"]
        )
        == (1, 2),
        all(
            item["target_projection_observed"]
            and item["access_decision"] == "denied"
            and not item["protected_effect_observed"]
            and item["effect_ref"] is None
            for item in (baseline, expired, inadmissible)
        ),
        recomputed["verdict"] == REFUTED
        and not recomputed["uncertainty_reasons"]
        and evidence["oracle"]["verdict"] == REFUTED
        and not evidence["oracle"]["uncertainty_reasons"],
        evidence["cleanup"]["status"] == "verified"
        and not evidence["cleanup"]["target_request_may_have_been_sent"]
        and not evidence["cleanup"]["orphaned_owned_state_possible"],
        RECEIPT_RE.fullmatch(evidence["source_receipt_id"]) is not None
        and TYPED_REF_RE.fullmatch(evidence["execution_admission_ref"]) is not None
        and evidence["adapter_contract_version"] == ADAPTER_VERSION
        and evidence["evidence_root"]
        == hashlib.sha256(EVIDENCE_ROOT_DOMAIN + _canonical_bytes(preimage)).hexdigest()
        and all(
            evidence["execution_policy"][key] is True for key in POLICY_BOOLEAN_FIELDS
        )
        and evidence["source_execution_id"]
        == _stable_hash("capability_effect_execution_result", source_payload),
    )


def _check_replay_predicate(context: Context) -> dict[str, Any]:
    evidence = _require_evidence(context)
    clauses = _replay_clauses(evidence)
    failed = [index for index, passed in enumerate(clauses, 1) if not passed]
    if failed:
        raise VerificationError(
            "strict replay-leak predicate failed clauses "
            + ",".join(str(item) for item in failed)
        )
    return {"eligible": True, "predicate_version": LEAK_CLASS_VERSION, "clauses": 11}


def _check_original_identity_linkage(context: Context) -> dict[str, Any]:
    evidence = _require_evidence(context)
    receipt = context.receipt
    if receipt is None:
        raise VerificationError("schema-valid receipt is unavailable")
    journal = _read_journal_snapshot(context)
    operation = journal["operation_data"]
    if type(operation) is not dict:
        raise VerificationError("journal operation context is invalid")
    if (
        journal["source_receipt_id"] != evidence["source_receipt_id"]
        or journal["source_fingerprint"] != receipt["fingerprint"]
        or journal["session_id"] != evidence["assessment_session_id"]
        or journal["target_origin"] != evidence["target_origin"]
        or journal["identity_data"] != evidence["identity_binding"]
        or journal["producer_data"] != evidence["producer_identity"]
        or operation.get("specification_ref") != evidence["specification_ref"]
        or operation.get("operation_ref") != evidence["operation_ref"]
        or operation.get("execution_policy") != evidence["execution_policy"]
        or operation.get("authorization_envelope_ref")
        != evidence["identity_binding"]["authorization_envelope_ref"]
        or evidence["experiment_world_ref"]
        != _stable_hash("world", evidence["identity_binding"]["persona_id"])
    ):
        raise VerificationError(
            "journal context does not equal the original evidence context"
        )
    if journal["admission_id"] != evidence["execution_admission_ref"]:
        raise VerificationError("journal admission does not equal the source admission")
    if type(journal["intake_id"]) is not str:
        raise VerificationError("journal intake id is invalid")
    _typed_ref(journal["intake_id"], "capability_effect_intake", label="journal intake")
    expected_admission = _stable_hash(
        "capability_effect_execution_admission",
        {
            "intake_id": journal["intake_id"],
            "session_id": journal["session_id"],
            "target_origin": journal["target_origin"],
            "identity_digest": evidence["identity_binding"]["digest"],
            "operation": operation,
            "producer": journal["producer_data"],
            "storage": journal["storage_data"],
        },
    )
    if journal["admission_id"] != expected_admission:
        raise VerificationError("execution admission commitment is invalid")
    receipt_context = receipt["context"]
    identity = evidence["identity_binding"]
    if (
        receipt_context["target_ref"]
        != _stable_hash("behavioral_receipt_target", evidence["target_origin"])
        or receipt_context["envelope_ref"]
        != _stable_hash(
            "behavioral_receipt_envelope", identity["authorization_envelope_id"]
        )
        or receipt_context["source_persona_ref"]
        != _stable_hash("behavioral_receipt_persona", identity["persona_id"])
    ):
        raise VerificationError(
            "receipt redacted context does not bind the original identity"
        )
    return {
        "admission_id": journal["admission_id"],
        "assessment_session_id": journal["session_id"],
        "identity_digest": identity["digest"],
        "source_receipt_id": journal["source_receipt_id"],
    }


def _finding_metadata(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "finding_class": LEAK_CLASS_VERSION,
        "evidence_schema_version": evidence["schema_version"],
        "leak_class_version": LEAK_CLASS_VERSION,
        "evidence_root": evidence["evidence_root"],
        "source_execution_id": evidence["source_execution_id"],
        "source_receipt_id": evidence["source_receipt_id"],
        "execution_admission_ref": evidence["execution_admission_ref"],
        "adapter_contract_version": evidence["adapter_contract_version"],
        "producer_identity": evidence["producer_identity"],
        "assessment_session_id": evidence["assessment_session_id"],
        "target_origin": evidence["target_origin"],
        "specification_ref": evidence["specification_ref"],
        "operation_ref": evidence["operation_ref"],
        "capability_ref": evidence["capability_ref"],
        "experiment_world_ref": evidence["experiment_world_ref"],
        "oracle_evaluation_ref": evidence["oracle_evaluation_ref"],
        "conduct_provenance_root": evidence["conduct_provenance_root"],
        "observed_at_epoch": evidence["observed_at_epoch"],
        "runtime_evidence_classification": evidence["runtime_evidence_classification"],
        "impact_assessment": "unassessed",
        "severity_basis": "provisional_class_default_pending_impact_assessment",
        "evidence_trust_boundary": "authenticated_local_execution_producer",
    }


def _check_canonical_correspondence(context: Context) -> dict[str, Any]:
    evidence = _require_evidence(context)
    journal = _read_journal_snapshot(context)
    if context.cas_bytes is None:
        # Re-read and independently bind the bytes even when a prior reported
        # integrity check failed for a journal-only reason.
        if not context.cas_blob_path.is_file():
            raise VerificationError("canonical CAS artifact is unavailable")
        context.cas_bytes = context.cas_blob_path.read_bytes()
    if journal["state"] != "promoted":
        raise VerificationError("journal does not describe a committed promotion")
    observation_id = journal["observation_id"]
    finding_id = journal["finding_id"]
    if type(observation_id) is not str or type(finding_id) is not str:
        raise VerificationError("journal canonical result references are absent")
    observation_row = context.entities.get(observation_id)
    finding_row = context.entities.get(finding_id)
    if observation_row is None or finding_row is None:
        raise VerificationError("canonical observation or finding is absent")
    if (
        observation_row["kind"] != "observation"
        or finding_row["kind"] != "finding"
        or observation_row["session_id"] != journal["session_id"]
        or finding_row["session_id"] != journal["session_id"]
    ):
        raise VerificationError("canonical entity kind or session is inconsistent")
    source_ref = _stable_hash(
        "source_ref",
        {
            "source_receipt_id": evidence["source_receipt_id"],
            "evidence_root": evidence["evidence_root"],
        },
    )
    action_id = _stable_hash(
        "action", {"kind": "capability_replay_leak_evidence_admission"}
    )
    label = "capability replay-leak evidence admission"
    family_id = _stable_hash(
        "operation_family", {"action_id": action_id, "label": label}
    )
    family = {
        "family_id": family_id,
        "action_id": action_id,
        "label": label,
        "method": "LOCAL",
        "requires": [],
        "safety": "read_only",
        "source_refs": [source_ref],
    }
    identity = evidence["identity_binding"]
    world_ref = (
        identity["world_id"]
        if identity["world_id"].startswith("world:")
        else _stable_hash("world", identity["world_id"])
    )
    state_ref = _stable_hash(
        "state",
        {
            "evidence_root": evidence["evidence_root"],
            "source_receipt_id": evidence["source_receipt_id"],
        },
    )
    instance_identity = {
        "family_id": family_id,
        "source_ref": source_ref,
        "world_ref": world_ref,
        "state_ref": state_ref,
    }
    instance = {
        "instance_id": _stable_hash("operation_instance", instance_identity),
        **instance_identity,
        "response_status": 200,
        "outcome": "success",
        "outputs": [],
    }
    tool = {
        "name": "capability_effect_evidence",
        "args": [evidence["source_receipt_id"]],
        "version": evidence["adapter_contract_version"],
        "exit_code": 0,
    }
    observation_material = {
        "schema": "evidence_observation_envelope_v1",
        "tool": tool,
        "target": evidence["target_origin"],
        "blob_hash": journal["cas_blob_hash"],
        "session_id": identity["session_id"],
        "identity_digest": identity["digest"],
        "operation_family_id": family_id,
        "operation_instance_id": instance["instance_id"],
        "operation_outcome": "success",
        "operation_source_ref": source_ref,
    }
    observation_commitment = _stable_hash("observation_envelope", observation_material)
    expected_observation_id = f"obs-{observation_commitment.rsplit(':', 1)[-1]}"
    expected_observation = {
        "id": expected_observation_id,
        "timestamp": evidence["observed_at_epoch"],
        "tool": tool,
        "target": evidence["target_origin"],
        "blob_hash": journal["cas_blob_hash"],
        "commitment": observation_commitment,
        "session_id": identity["session_id"],
        "identity": identity,
        "operation_family": family,
        "operation_instance": instance,
    }
    if (
        observation_id != expected_observation_id
        or observation_row["commitment"] != observation_commitment
        or observation_row["data"] != expected_observation
        or observation_row["data_text"]
        != _canonical_bytes(expected_observation).decode("utf-8")
    ):
        raise VerificationError(
            "canonical observation does not correspond to the evidence"
        )

    citation = {
        "observation_id": observation_id,
        "line_start": None,
        "line_end": None,
        "snippet": None,
    }
    active_proof = {
        "observation_id": observation_id,
        "receipt_id": evidence["source_receipt_id"],
        "provenance_root": evidence["evidence_root"],
    }
    finding_material = {
        "schema": "evidence_finding_v2",
        "session_id": identity["session_id"],
        "title": FINDING_TITLE,
        "severity": "medium",
        "citations": [citation],
        "description": FINDING_DESCRIPTION,
        "remediation": FINDING_REMEDIATION,
        "metadata": _finding_metadata(evidence),
        "confirmation_level": "confirmed",
        "active_proof": [active_proof],
    }
    finding_commitment = _stable_hash("evidence_finding", finding_material)
    expected_finding_id = f"find-{finding_commitment.rsplit(':', 1)[-1]}"
    expected_finding = {
        "id": expected_finding_id,
        "title": FINDING_TITLE,
        "severity": "medium",
        "citations": [citation],
        "description": FINDING_DESCRIPTION,
        "remediation": FINDING_REMEDIATION,
        "metadata": _finding_metadata(evidence),
        "confirmation_level": "confirmed",
        "session_id": identity["session_id"],
        "commitment": finding_commitment,
        "active_proof": [active_proof],
    }
    if (
        finding_id != expected_finding_id
        or finding_row["commitment"] != finding_commitment
        or finding_row["data"] != expected_finding
        or finding_row["data_text"]
        != _canonical_bytes(expected_finding).decode("utf-8")
    ):
        raise VerificationError(
            "canonical finding does not match the frozen claim template"
        )

    timestamp = _positive_finite_float(
        journal["event_timestamp"], label="journal event time"
    )
    expected_events: list[dict[str, Any]] = []
    for event_type, entity in (
        ("observed", expected_observation),
        ("promoted", expected_finding),
    ):
        content = {
            "type": event_type,
            "entity": entity["id"],
            "payload": entity,
            "time": timestamp,
        }
        expected_events.append(
            {
                "id": _event_id(content),
                "event_type": event_type,
                "entity_id": entity["id"],
                "payload": entity,
                "timestamp": timestamp,
                "run_id": journal["event_run_id"],
            }
        )
    for expected in expected_events:
        matches = [
            row
            for row in context.events
            if row["entity_id"] == expected["entity_id"]
            and row["event_type"] == expected["event_type"]
        ]
        if len(matches) != 1:
            raise VerificationError(
                "canonical admission event is missing or duplicated"
            )
        row = matches[0]
        if (
            row["session_id"] != identity["session_id"]
            or row["id"] != expected["id"]
            or row["data"] != expected
            or row["data_text"] != _canonical_bytes(expected).decode("utf-8")
        ):
            raise VerificationError("canonical admission event is inconsistent")
    return {
        "observation_id": observation_id,
        "finding_id": finding_id,
        "session_id": identity["session_id"],
        "events_verified": 2,
        "journal_success_trusted_as_proof": False,
    }


CHECKS: tuple[tuple[str, Callable[[Context], dict[str, Any]]], ...] = (
    ("schema_validity", _check_schema),
    ("integrity", _check_integrity),
    ("source_trust_mode", _check_source_trust_mode),
    ("replay_predicate", _check_replay_predicate),
    ("original_identity_linkage", _check_original_identity_linkage),
    ("canonical_correspondence", _check_canonical_correspondence),
)


def verify(
    *,
    receipt_path: Path,
    database_path: Path,
    cas_blob_path: Path,
    execution_id: str,
) -> dict[str, Any]:
    """Return six separate acceptance checks without trusting journal success."""

    context = Context(
        receipt_path=Path(receipt_path),
        database_path=Path(database_path),
        cas_blob_path=Path(cas_blob_path),
        execution_id=execution_id,
    )
    results: dict[str, Any] = {}
    for name, check in CHECKS:
        try:
            details = check(context)
        except (OSError, VerificationError, KeyError, TypeError, ValueError) as exc:
            results[name] = {"passed": False, "error": str(exc)}
        else:
            results[name] = {"passed": True, "details": details}
    return {
        "schema_version": 1,
        "verifier": "r5d10_independent_acceptance_v1",
        "execution_id": execution_id,
        "overall_passed": all(item["passed"] for item in results.values()),
        "checks": results,
        "trust_boundary": (
            "Local hashes prove integrity and linkage inside the authenticated-local-"
            "producer boundary; they do not authenticate a wholly attacker-controlled "
            "local evidence store."
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt",
        required=True,
        type=Path,
        help="completed inner behavioral receipt JSON",
    )
    parser.add_argument(
        "--database", required=True, type=Path, help="canonical SQLite database"
    )
    parser.add_argument(
        "--cas-blob", required=True, type=Path, help="exact CAS evidence artifact"
    )
    parser.add_argument(
        "--execution-id",
        required=True,
        help="admission, intake, behavioral receipt, or source fingerprint identifier",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = verify(
        receipt_path=args.receipt,
        database_path=args.database,
        cas_blob_path=args.cas_blob,
        execution_id=args.execution_id,
    )
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False))
    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
