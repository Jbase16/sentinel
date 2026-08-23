"""Transport-free request binding for graph-bound prerequisite experiments.

R5B3b1 reconstructs current captured request templates, applies the one declared
counterfactual, classifies every action, evaluates the current policy, and previews
the exact ordered budget reservation. Raw request material remains ephemeral and is
excluded from every public artifact. The reservation order places all fresh-world
prerequisites before the three terminal actions, cleanup suffix, and independent
post-cleanup verification reads. This module cannot reserve budget or send traffic.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.cortex.execution_policy import CandidateAction, PolicyExecutor
from core.safety.action_classifier import (
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    SAFE_READ,
)
from core.safety.proof_budget import endpoint_key

from .compiler import (
    BackwardExploitCompiler,
    CompilerLimits,
    OperationCatalogLimits,
    high_value_goals,
)
from .lifecycle import (
    LifecycleContractMiner,
    LifecycleMiningResult,
    OwnedLifecycleCandidate,
)
from .lineage import (
    EphemeralRehydratedStep,
    LineageBinding,
    LocatorKind,
    PlanRehydrator,
    RehydrationRecipe,
    ValueLineageLedger,
)
from .normalize import stable_hash
from .prerequisite_admission import (
    GRAPH_BOUND_MANIFEST_ADMISSION_MODE,
    GraphBoundExperimentManifest,
    GraphBoundManifestAdmissionResult,
)
from .prerequisite_experiments import (
    GraphBoundExperimentCompilationResult,
    GraphBoundPrerequisiteExperimentCompiler,
    GraphBoundPrerequisiteExperimentSpec,
    PrerequisiteCounterfactualFamily,
)
from .safety_contracts import (
    classification_body,
    is_proven_safe_cleanup_body,
    is_proven_safe_owned_create_body,
)
from .state_machine import (
    MAX_STATE_MACHINE_PLAN_STEPS,
    MAX_STATE_MACHINE_RECORDS,
    MAX_STATE_MACHINE_SEARCH_STATES,
    StateMachineLegalityCandidate,
    StateMachineLegalityMiner,
    StateMachineLegalityResult,
)

GRAPH_BOUND_REQUEST_BINDING_MODE = "behavioral_graph_bound_request_binding_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_SEMANTIC = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_PHASES = ("baseline", "treatment", "control")
_CLEANUP_PHASE = "cleanup"
_CLEANUP_VERIFICATION_PHASE = "cleanup_verification"
_WORLD_ROLE_BY_PHASE = {
    "baseline": "valid_baseline",
    "treatment": "counterfactual_treatment",
    "control": "independent_control",
}
_ACTION_CONTRACTS = {
    OWNED_CREATE: ("POST", "create_owned_test_object"),
    SAFE_READ: (("GET", "HEAD"), "none"),
    OWNED_UPDATE_LOW_RISK: (("PATCH", "PUT"), "cleanup_owned_test_object"),
}
_RESOLVED_MANIFEST_BLOCKERS = frozenset(
    {
        "endpoint_budget_bindings_not_compiled",
        "per_action_policy_preflight_not_completed",
    }
)
_STATUSES = frozenset(
    {
        "admission_not_ready",
        "capture_mismatch",
        "no_bindable_manifests",
        "ready_for_single_use_execution_claim",
    }
)


class GraphBoundRequestBindingDenied(RuntimeError):
    """One manifest cannot be reconstructed or preflighted safely."""

    def __init__(self, reason: str, *, category: str = "reconstruction") -> None:
        super().__init__(reason)
        self.category = category


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    if not isinstance(value, str) or _HASH_REF.fullmatch(value) is None:
        return False
    return prefix is None or value.startswith(f"{prefix}:")


def _canonical_origin(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("graph-bound request origin must be a string")
    parts = urlsplit(value.strip())
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("graph-bound request origin has an invalid port") from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("graph-bound request origin is invalid")
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    authority = host if port is None or default_port else f"{host}:{port}"
    return f"{scheme}://{authority}"


def _request_origin(value: str) -> str:
    parts = urlsplit(value)
    if parts.fragment:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_request_fragment_is_not_allowed"
        )
    return _canonical_origin(
        urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    )


def _decode_pointer(pointer: str) -> Tuple[str, ...]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_pointer_is_invalid"
        )
    return tuple(
        item.replace("~1", "/").replace("~0", "~")
        for item in pointer[1:].split("/")
    )


def _remove_key_occurrence(
    pairs: Sequence[Tuple[str, str]],
    pointer: str,
) -> Tuple[Tuple[str, str], ...]:
    tokens = _decode_pointer(pointer)
    if len(tokens) != 2:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_occurrence_pointer_is_invalid"
        )
    key = tokens[0]
    try:
        desired = int(tokens[1])
    except (TypeError, ValueError) as exc:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_occurrence_index_is_invalid"
        ) from exc
    if desired < 0:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_occurrence_index_is_invalid"
        )
    output = []
    seen = 0
    removed = False
    for current_key, current_value in pairs:
        if current_key == key:
            if seen == desired:
                removed = True
            else:
                output.append((current_key, current_value))
            seen += 1
        else:
            output.append((current_key, current_value))
    if not removed:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_binding_is_missing"
        )
    return tuple(output)


def _remove_json_pointer(value: Any, pointer: str) -> Any:
    tokens = _decode_pointer(pointer)
    if not tokens:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_json_root_cannot_be_removed"
        )
    result = copy.deepcopy(value)
    parent = result
    for token in tokens[:-1]:
        if isinstance(parent, Mapping):
            if token not in parent:
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_omission_json_pointer_is_missing"
                )
            parent = parent[token]
        elif isinstance(parent, list):
            try:
                index = int(token)
            except (TypeError, ValueError) as exc:
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_omission_json_index_is_invalid"
                ) from exc
            if index < 0 or index >= len(parent):
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_omission_json_pointer_is_missing"
                )
            parent = parent[index]
        else:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_omission_json_pointer_is_missing"
            )
    leaf = tokens[-1]
    if isinstance(parent, Mapping):
        if leaf not in parent:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_omission_json_pointer_is_missing"
            )
        del parent[leaf]
    elif isinstance(parent, list):
        try:
            index = int(leaf)
        except (TypeError, ValueError) as exc:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_omission_json_index_is_invalid"
            ) from exc
        if index < 0 or index >= len(parent):
            raise GraphBoundRequestBindingDenied(
                "graph_bound_omission_json_pointer_is_missing"
            )
        parent.pop(index)
    else:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_json_pointer_is_missing"
        )
    return result


def _remove_omission_binding(
    request: EphemeralRehydratedStep,
    binding: LineageBinding,
) -> EphemeralRehydratedStep:
    locator = binding.consumer_locator
    url = request.url
    body = copy.deepcopy(request.body)
    if locator.kind is LocatorKind.REQUEST_QUERY:
        parsed = urlsplit(url)
        query = _remove_key_occurrence(
            parse_qsl(parsed.query, keep_blank_values=True),
            locator.pointer,
        )
        url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(query),
                parsed.fragment,
            )
        )
    elif locator.kind is LocatorKind.REQUEST_FORM:
        if not isinstance(body, str):
            raise GraphBoundRequestBindingDenied(
                "graph_bound_omission_form_body_is_not_text"
            )
        body = urlencode(
            _remove_key_occurrence(
                parse_qsl(body, keep_blank_values=True),
                locator.pointer,
            )
        )
    elif locator.kind is LocatorKind.REQUEST_JSON:
        original_text = isinstance(body, str)
        if original_text:
            try:
                parsed_body = json.loads(body)
            except (TypeError, ValueError) as exc:
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_omission_json_body_is_invalid"
                ) from exc
        else:
            parsed_body = body
        if not isinstance(parsed_body, (Mapping, list)):
            raise GraphBoundRequestBindingDenied(
                "graph_bound_omission_json_body_is_invalid"
            )
        parsed_body = _remove_json_pointer(parsed_body, locator.pointer)
        body = (
            json.dumps(parsed_body, sort_keys=True, separators=(",", ":"))
            if original_text
            else parsed_body
        )
    else:
        raise GraphBoundRequestBindingDenied(
            "graph_bound_omission_locator_is_not_removable"
        )
    return EphemeralRehydratedStep(
        operation_id=request.operation_id,
        source_ref=request.source_ref,
        request_digest=request.request_digest,
        method=request.method,
        url=url,
        headers=copy.deepcopy(dict(request.headers)),
        body=body,
    )


def _request_template_ref(request: EphemeralRehydratedStep) -> str:
    return stable_hash(
        "graph_bound_request_template",
        {
            "source_request_digest": request.request_digest,
            "method": request.method,
            "url": request.url,
            "headers": copy.deepcopy(dict(request.headers)),
            "body": copy.deepcopy(request.body),
        },
    )


def _action_payload(
    *,
    manifest_id: str,
    world_slot_id: str,
    world_role: str,
    phase: str,
    ordinal: int,
    operation_id: str,
    source_ref: str,
    source_request_digest: str,
    request_template_ref: str,
    method: str,
    endpoint_key_ref: str,
    action_class: str,
    expected_side_effect: str,
    input_binding_ids: Sequence[str],
    request_mutation_ref: Optional[str],
    runtime_override_binding_id: Optional[str],
    runtime_override_source_world_slot_id: Optional[str],
    runtime_override_source_create_operation_id: Optional[str],
    conditional_cleanup: bool,
    policy_decision_ref: str,
) -> Dict[str, Any]:
    return {
        "manifest_id": manifest_id,
        "world_slot_id": world_slot_id,
        "world_role": world_role,
        "phase": phase,
        "ordinal": ordinal,
        "operation_id": operation_id,
        "source_ref": source_ref,
        "source_request_digest": source_request_digest,
        "request_template_ref": request_template_ref,
        "method": method,
        "endpoint_key_ref": endpoint_key_ref,
        "action_class": action_class,
        "expected_side_effect": expected_side_effect,
        "input_binding_ids": list(input_binding_ids),
        "request_mutation_ref": request_mutation_ref,
        "runtime_override_binding_id": runtime_override_binding_id,
        "runtime_override_source_world_slot_id": (
            runtime_override_source_world_slot_id
        ),
        "runtime_override_source_create_operation_id": (
            runtime_override_source_create_operation_id
        ),
        "conditional_cleanup": conditional_cleanup,
        "policy_decision_ref": policy_decision_ref,
        "policy_allowed": True,
        "budget_reserved": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundRequestActionBinding:
    binding_id: str
    manifest_id: str
    world_slot_id: str
    world_role: str
    phase: str
    ordinal: int
    operation_id: str
    source_ref: str
    source_request_digest: str
    request_template_ref: str
    method: str
    endpoint_key_ref: str
    action_class: str
    expected_side_effect: str
    input_binding_ids: Tuple[str, ...]
    request_mutation_ref: Optional[str]
    runtime_override_binding_id: Optional[str]
    runtime_override_source_world_slot_id: Optional[str]
    runtime_override_source_create_operation_id: Optional[str]
    conditional_cleanup: bool
    policy_decision_ref: str
    policy_allowed: bool = True
    budget_reserved: bool = False
    target_requests_sent: int = 0
    executable: bool = False

    def __post_init__(self) -> None:
        payload = _action_payload(
            manifest_id=self.manifest_id,
            world_slot_id=self.world_slot_id,
            world_role=self.world_role,
            phase=self.phase,
            ordinal=self.ordinal,
            operation_id=self.operation_id,
            source_ref=self.source_ref,
            source_request_digest=self.source_request_digest,
            request_template_ref=self.request_template_ref,
            method=self.method,
            endpoint_key_ref=self.endpoint_key_ref,
            action_class=self.action_class,
            expected_side_effect=self.expected_side_effect,
            input_binding_ids=self.input_binding_ids,
            request_mutation_ref=self.request_mutation_ref,
            runtime_override_binding_id=self.runtime_override_binding_id,
            runtime_override_source_world_slot_id=(
                self.runtime_override_source_world_slot_id
            ),
            runtime_override_source_create_operation_id=(
                self.runtime_override_source_create_operation_id
            ),
            conditional_cleanup=self.conditional_cleanup,
            policy_decision_ref=self.policy_decision_ref,
        )
        expected_method, expected_effect = _ACTION_CONTRACTS.get(
            self.action_class,
            (None, None),
        )
        method_allowed = (
            self.method == expected_method
            if isinstance(expected_method, str)
            else self.method in (expected_method or ())
        )
        cleanup = self.phase == _CLEANUP_PHASE
        cleanup_verification = self.phase == _CLEANUP_VERIFICATION_PHASE
        conditional_cleanup = cleanup or cleanup_verification
        runtime_override = self.runtime_override_binding_id is not None
        if (
            self.binding_id != stable_hash("graph_bound_request_action", payload)
            or not _hash_ref(self.manifest_id, "graph_bound_experiment_manifest")
            or not _hash_ref(self.world_slot_id, "graph_bound_fresh_world_slot")
            or self.world_role not in _WORLD_ROLE_BY_PHASE.values()
            or self.phase
            not in {*_PHASES, _CLEANUP_PHASE, _CLEANUP_VERIFICATION_PHASE}
            or isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 0
            or not _hash_ref(self.operation_id, "action")
            or not _hash_ref(self.source_ref, "source_ref")
            or not _hash_ref(self.source_request_digest, "request_template")
            or not _hash_ref(
                self.request_template_ref,
                "graph_bound_request_template",
            )
            or not method_allowed
            or not _hash_ref(self.endpoint_key_ref, "graph_bound_endpoint_key")
            or self.expected_side_effect != expected_effect
            or self.input_binding_ids
            != tuple(sorted(set(self.input_binding_ids)))
            or any(
                not _hash_ref(item, "lineage_binding")
                for item in self.input_binding_ids
            )
            or (
                self.request_mutation_ref is not None
                and not _hash_ref(
                    self.request_mutation_ref,
                    "graph_counterfactual_delta",
                )
            )
            or runtime_override
            != (self.runtime_override_source_world_slot_id is not None)
            or runtime_override
            != (self.runtime_override_source_create_operation_id is not None)
            or (
                runtime_override
                and (
                    self.phase != "control"
                    or self.world_role != _WORLD_ROLE_BY_PHASE["control"]
                    or self.runtime_override_binding_id
                    not in self.input_binding_ids
                    or not _hash_ref(
                        self.runtime_override_binding_id,
                        "lineage_binding",
                    )
                    or not _hash_ref(
                        self.runtime_override_source_world_slot_id,
                        "graph_bound_fresh_world_slot",
                    )
                    or self.runtime_override_source_world_slot_id
                    == self.world_slot_id
                    or not _hash_ref(
                        self.runtime_override_source_create_operation_id,
                        "action",
                    )
                    or self.request_mutation_ref is not None
                )
            )
            or (
                self.request_mutation_ref is not None
                and not (
                    self.phase == "treatment"
                    or (
                        cleanup_verification
                        and self.world_role
                        == _WORLD_ROLE_BY_PHASE["treatment"]
                    )
                )
            )
            or self.conditional_cleanup != conditional_cleanup
            or cleanup != (self.action_class == OWNED_UPDATE_LOW_RISK)
            or (
                cleanup_verification
                and (
                    self.action_class != SAFE_READ
                    or self.method not in {"GET", "HEAD"}
                )
            )
            or not _hash_ref(
                self.policy_decision_ref,
                "graph_bound_policy_decision",
            )
            or not self.policy_allowed
            or self.budget_reserved
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("graph-bound request-action binding is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            **_action_payload(
                manifest_id=self.manifest_id,
                world_slot_id=self.world_slot_id,
                world_role=self.world_role,
                phase=self.phase,
                ordinal=self.ordinal,
                operation_id=self.operation_id,
                source_ref=self.source_ref,
                source_request_digest=self.source_request_digest,
                request_template_ref=self.request_template_ref,
                method=self.method,
                endpoint_key_ref=self.endpoint_key_ref,
                action_class=self.action_class,
                expected_side_effect=self.expected_side_effect,
                input_binding_ids=self.input_binding_ids,
                request_mutation_ref=self.request_mutation_ref,
                runtime_override_binding_id=self.runtime_override_binding_id,
                runtime_override_source_world_slot_id=(
                    self.runtime_override_source_world_slot_id
                ),
                runtime_override_source_create_operation_id=(
                    self.runtime_override_source_create_operation_id
                ),
                conditional_cleanup=self.conditional_cleanup,
                policy_decision_ref=self.policy_decision_ref,
            ),
        }


def _budget_entry_payload(
    *,
    request_binding_id: str,
    ordinal: int,
    action_class: str,
    endpoint_key_ref: str,
) -> Dict[str, Any]:
    return {
        "request_binding_id": request_binding_id,
        "ordinal": ordinal,
        "action_class": action_class,
        "endpoint_key_ref": endpoint_key_ref,
        "reservation_required": True,
        "reserved": False,
    }


@dataclass(frozen=True)
class GraphBoundEndpointBudgetBinding:
    entry_id: str
    request_binding_id: str
    ordinal: int
    action_class: str
    endpoint_key_ref: str
    reservation_required: bool = True
    reserved: bool = False

    def __post_init__(self) -> None:
        payload = _budget_entry_payload(
            request_binding_id=self.request_binding_id,
            ordinal=self.ordinal,
            action_class=self.action_class,
            endpoint_key_ref=self.endpoint_key_ref,
        )
        if (
            self.entry_id != stable_hash("graph_bound_endpoint_budget", payload)
            or not _hash_ref(
                self.request_binding_id,
                "graph_bound_request_action",
            )
            or isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 0
            or self.action_class not in _ACTION_CONTRACTS
            or not _hash_ref(self.endpoint_key_ref, "graph_bound_endpoint_key")
            or not self.reservation_required
            or self.reserved
        ):
            raise ValueError("graph-bound endpoint-budget binding is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            **_budget_entry_payload(
                request_binding_id=self.request_binding_id,
                ordinal=self.ordinal,
                action_class=self.action_class,
                endpoint_key_ref=self.endpoint_key_ref,
            ),
        }


@dataclass(frozen=True, repr=False)
class _EphemeralBoundRequest:
    binding_id: str
    request: EphemeralRehydratedStep = field(repr=False, compare=False)
    endpoint_key_value: str = field(repr=False, compare=False)
    action: CandidateAction = field(repr=False, compare=False)
    input_bindings: Tuple[LineageBinding, ...] = field(
        repr=False,
        compare=False,
    )
    output_bindings: Tuple[LineageBinding, ...] = field(
        repr=False,
        compare=False,
    )

    def __repr__(self) -> str:
        return (
            "_EphemeralBoundRequest("
            f"binding_id={self.binding_id!r}, raw_request=REDACTED)"
        )


def _plan_payload(
    *,
    manifest_id: str,
    compilation_result_id: str,
    lifecycle_capture_digest: str,
    specification_id: str,
    delta_id: str,
    family: str,
    baseline_operation_ids: Sequence[str],
    treatment_operation_ids: Sequence[str],
    request_bindings: Sequence[GraphBoundRequestActionBinding],
    budget_bindings: Sequence[GraphBoundEndpointBudgetBinding],
    budget_preview_ref: str,
    remaining_execution_blockers: Sequence[str],
) -> Dict[str, Any]:
    return {
        "manifest_id": manifest_id,
        "compilation_result_id": compilation_result_id,
        "lifecycle_capture_digest": lifecycle_capture_digest,
        "specification_id": specification_id,
        "delta_id": delta_id,
        "family": family,
        "baseline_operation_ids": list(baseline_operation_ids),
        "treatment_operation_ids": list(treatment_operation_ids),
        "request_bindings": [item.to_dict() for item in request_bindings],
        "budget_bindings": [item.to_dict() for item in budget_bindings],
        "budget_preview_ref": budget_preview_ref,
        "request_bindings_complete": True,
        "policy_preflight_complete": True,
        "budget_preview_allowed": True,
        "budget_reserved": False,
        "single_use_claim_acquired": False,
        "remaining_execution_blockers": list(remaining_execution_blockers),
        "dispatch_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundPreparedRequestPlan:
    plan_id: str
    manifest_id: str
    compilation_result_id: str
    lifecycle_capture_digest: str
    specification_id: str
    delta_id: str
    family: str
    baseline_operation_ids: Tuple[str, ...]
    treatment_operation_ids: Tuple[str, ...]
    request_bindings: Tuple[GraphBoundRequestActionBinding, ...]
    budget_bindings: Tuple[GraphBoundEndpointBudgetBinding, ...]
    budget_preview_ref: str
    remaining_execution_blockers: Tuple[str, ...]
    ephemeral_requests: Tuple[_EphemeralBoundRequest, ...] = field(
        repr=False,
        compare=False,
    )
    request_bindings_complete: bool = True
    policy_preflight_complete: bool = True
    budget_preview_allowed: bool = True
    budget_reserved: bool = False
    single_use_claim_acquired: bool = False
    dispatch_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = GRAPH_BOUND_REQUEST_BINDING_MODE

    def __post_init__(self) -> None:
        payload = _plan_payload(
            manifest_id=self.manifest_id,
            compilation_result_id=self.compilation_result_id,
            lifecycle_capture_digest=self.lifecycle_capture_digest,
            specification_id=self.specification_id,
            delta_id=self.delta_id,
            family=self.family,
            baseline_operation_ids=self.baseline_operation_ids,
            treatment_operation_ids=self.treatment_operation_ids,
            request_bindings=self.request_bindings,
            budget_bindings=self.budget_bindings,
            budget_preview_ref=self.budget_preview_ref,
            remaining_execution_blockers=self.remaining_execution_blockers,
        )
        phase_operations = {
            phase: tuple(
                item.operation_id
                for item in self.request_bindings
                if item.phase == phase
            )
            for phase in _PHASES
        }
        raw_by_id = {item.binding_id: item for item in self.ephemeral_requests}
        runtime_overrides = tuple(
            item
            for item in self.request_bindings
            if item.runtime_override_binding_id is not None
        )
        terminal_actions = {
            phase: tuple(
                item
                for item in self.request_bindings
                if item.phase == phase
                and item.operation_id == self.baseline_operation_ids[-1]
            )
            for phase in _PHASES
        }
        omission_witness_shape = bool(
            self.family == "omission"
            and all(len(terminal_actions[phase]) == 1 for phase in _PHASES)
            and len(runtime_overrides) == 1
            and runtime_overrides[0] is terminal_actions["control"][0]
            and set(terminal_actions["baseline"][0].input_binding_ids)
            - set(terminal_actions["treatment"][0].input_binding_ids)
            == {runtime_overrides[0].runtime_override_binding_id}
            and terminal_actions["control"][0].input_binding_ids
            == terminal_actions["baseline"][0].input_binding_ids
        )
        if (
            self.plan_id != stable_hash("graph_bound_prepared_request_plan", payload)
            or self.mode != GRAPH_BOUND_REQUEST_BINDING_MODE
            or not _hash_ref(self.manifest_id, "graph_bound_experiment_manifest")
            or not _hash_ref(
                self.compilation_result_id,
                "graph_bound_experiment_compilation",
            )
            or not _hash_ref(self.lifecycle_capture_digest, "capture_set")
            or not _hash_ref(
                self.specification_id,
                "graph_bound_prerequisite_experiment",
            )
            or not _hash_ref(self.delta_id, "graph_counterfactual_delta")
            or self.family not in {"omission", "reordering"}
            or phase_operations["baseline"] != self.baseline_operation_ids
            or phase_operations["control"] != self.baseline_operation_ids
            or phase_operations["treatment"] != self.treatment_operation_ids
            or any(
                item.phase in _PHASES
                and item.world_role != _WORLD_ROLE_BY_PHASE[item.phase]
                for item in self.request_bindings
            )
            or sum(
                item.request_mutation_ref is not None
                for item in self.request_bindings
            )
            != (2 if self.family == "omission" else 0)
            or any(
                item.request_mutation_ref not in {None, self.delta_id}
                for item in self.request_bindings
            )
            or len(runtime_overrides)
            != (1 if self.family == "omission" else 0)
            or (self.family == "omission" and not omission_witness_shape)
            or (
                self.family == "omission"
                and runtime_overrides[0].runtime_override_source_world_slot_id
                not in {
                    item.world_slot_id
                    for item in self.request_bindings
                    if item.phase == "baseline"
                }
            )
            or not self.request_bindings
            or tuple(item.ordinal for item in self.request_bindings)
            != tuple(range(len(self.request_bindings)))
            or len(self.request_bindings) != len(self.budget_bindings)
            or tuple(item.ordinal for item in self.budget_bindings)
            != tuple(range(len(self.budget_bindings)))
            or any(
                budget.request_binding_id != request.binding_id
                or budget.action_class != request.action_class
                or budget.endpoint_key_ref != request.endpoint_key_ref
                for request, budget in zip(
                    self.request_bindings,
                    self.budget_bindings,
                )
            )
            or set(raw_by_id)
            != {item.binding_id for item in self.request_bindings}
            or any(
                _request_template_ref(raw_by_id[item.binding_id].request)
                != item.request_template_ref
                or stable_hash(
                    "graph_bound_endpoint_key",
                    raw_by_id[item.binding_id].endpoint_key_value,
                )
                != item.endpoint_key_ref
                for item in self.request_bindings
            )
            or any(
                tuple(
                    sorted(binding.binding_id for binding in raw.input_bindings)
                )
                != item.input_binding_ids
                or any(
                    binding.consumer_operation_id != item.operation_id
                    for binding in raw.input_bindings
                )
                or any(
                    binding.producer_operation_id != item.operation_id
                    for binding in raw.output_bindings
                )
                for item, raw in (
                    (item, raw_by_id[item.binding_id])
                    for item in self.request_bindings
                )
            )
            or not _hash_ref(
                self.budget_preview_ref,
                "graph_bound_budget_preview",
            )
            or self.remaining_execution_blockers
            != tuple(sorted(set(self.remaining_execution_blockers)))
            or not self.remaining_execution_blockers
            or any(
                _SEMANTIC.fullmatch(item) is None
                for item in self.remaining_execution_blockers
            )
            or not self.request_bindings_complete
            or not self.policy_preflight_complete
            or not self.budget_preview_allowed
            or self.budget_reserved
            or self.single_use_claim_acquired
            or self.dispatch_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("graph-bound prepared request plan is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "plan_id": self.plan_id,
            **_plan_payload(
                manifest_id=self.manifest_id,
                compilation_result_id=self.compilation_result_id,
                lifecycle_capture_digest=self.lifecycle_capture_digest,
                specification_id=self.specification_id,
                delta_id=self.delta_id,
                family=self.family,
                baseline_operation_ids=self.baseline_operation_ids,
                treatment_operation_ids=self.treatment_operation_ids,
                request_bindings=self.request_bindings,
                budget_bindings=self.budget_bindings,
                budget_preview_ref=self.budget_preview_ref,
                remaining_execution_blockers=self.remaining_execution_blockers,
            ),
        }


@dataclass(frozen=True)
class GraphBoundRequestBindingDiagnostics:
    manifests_examined: int
    plans_bound: int
    reconstruction_denials: int
    policy_denials: int
    budget_denials: int

    def __post_init__(self) -> None:
        values = tuple(vars(self).values())
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in values
        ) or self.plans_bound > self.manifests_examined:
            raise ValueError("graph-bound request diagnostics are invalid")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


def _result_payload(
    *,
    status: str,
    admission_result_id: str,
    compilation_result_id: str,
    target_ref: str,
    world_ref: str,
    policy_ref: Optional[str],
    plans: Sequence[GraphBoundPreparedRequestPlan],
    blocker: Optional[str],
    diagnostics: GraphBoundRequestBindingDiagnostics,
) -> Dict[str, Any]:
    return {
        "status": status,
        "admission_result_id": admission_result_id,
        "compilation_result_id": compilation_result_id,
        "target_ref": target_ref,
        "world_ref": world_ref,
        "policy_ref": policy_ref,
        "plans": [item.to_dict() for item in plans],
        "blocker": blocker,
        "diagnostics": diagnostics.to_dict(),
        "request_bindings_complete": bool(plans),
        "policy_preflight_complete": bool(plans),
        "budget_preview_only": True,
        "budget_reserved": False,
        "dispatch_authority": False,
        "finding_authority": False,
        "target_requests_sent": 0,
        "executable": False,
    }


@dataclass(frozen=True)
class GraphBoundRequestBindingResult:
    result_id: str
    status: str
    admission_result_id: str
    compilation_result_id: str
    target_ref: str
    world_ref: str
    policy_ref: Optional[str]
    plans: Tuple[GraphBoundPreparedRequestPlan, ...]
    blocker: Optional[str]
    diagnostics: GraphBoundRequestBindingDiagnostics
    request_bindings_complete: bool
    policy_preflight_complete: bool
    budget_preview_only: bool = True
    budget_reserved: bool = False
    dispatch_authority: bool = False
    finding_authority: bool = False
    target_requests_sent: int = 0
    executable: bool = False
    mode: str = GRAPH_BOUND_REQUEST_BINDING_MODE

    @classmethod
    def build(
        cls,
        *,
        status: str,
        admission_result_id: str,
        compilation_result_id: str,
        target_ref: str,
        world_ref: str,
        policy_ref: Optional[str],
        plans: Sequence[GraphBoundPreparedRequestPlan],
        blocker: Optional[str],
        diagnostics: GraphBoundRequestBindingDiagnostics,
    ) -> "GraphBoundRequestBindingResult":
        values = tuple(plans)
        payload = _result_payload(
            status=status,
            admission_result_id=admission_result_id,
            compilation_result_id=compilation_result_id,
            target_ref=target_ref,
            world_ref=world_ref,
            policy_ref=policy_ref,
            plans=values,
            blocker=blocker,
            diagnostics=diagnostics,
        )
        return cls(
            result_id=stable_hash("graph_bound_request_binding_result", payload),
            status=status,
            admission_result_id=admission_result_id,
            compilation_result_id=compilation_result_id,
            target_ref=target_ref,
            world_ref=world_ref,
            policy_ref=policy_ref,
            plans=values,
            blocker=blocker,
            diagnostics=diagnostics,
            request_bindings_complete=bool(values),
            policy_preflight_complete=bool(values),
        )

    def __post_init__(self) -> None:
        payload = _result_payload(
            status=self.status,
            admission_result_id=self.admission_result_id,
            compilation_result_id=self.compilation_result_id,
            target_ref=self.target_ref,
            world_ref=self.world_ref,
            policy_ref=self.policy_ref,
            plans=self.plans,
            blocker=self.blocker,
            diagnostics=self.diagnostics,
        )
        ready = self.status == "ready_for_single_use_execution_claim"
        if (
            self.result_id
            != stable_hash("graph_bound_request_binding_result", payload)
            or self.mode != GRAPH_BOUND_REQUEST_BINDING_MODE
            or self.status not in _STATUSES
            or not _hash_ref(
                self.admission_result_id,
                "graph_bound_manifest_admission",
            )
            or not _hash_ref(
                self.compilation_result_id,
                "graph_bound_experiment_compilation",
            )
            or not _hash_ref(self.target_ref, "security_obligation_target")
            or not _hash_ref(self.world_ref, "world")
            or (
                self.policy_ref is not None
                and not _hash_ref(
                    self.policy_ref,
                    "graph_bound_experiment_policy",
                )
            )
            or ready != bool(self.plans)
            or ready != (self.policy_ref is not None)
            or tuple(sorted(self.plans, key=lambda item: item.plan_id))
            != self.plans
            or any(
                item.compilation_result_id != self.compilation_result_id
                for item in self.plans
            )
            or (self.blocker is None) != ready
            or (
                self.blocker is not None
                and _SEMANTIC.fullmatch(self.blocker) is None
            )
            or self.diagnostics.manifests_examined
            < self.diagnostics.plans_bound
            or self.diagnostics.plans_bound != len(self.plans)
            or self.request_bindings_complete != ready
            or self.policy_preflight_complete != ready
            or not self.budget_preview_only
            or self.budget_reserved
            or self.dispatch_authority
            or self.finding_authority
            or self.target_requests_sent != 0
            or self.executable
        ):
            raise ValueError("graph-bound request binding result is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "result_id": self.result_id,
            **_result_payload(
                status=self.status,
                admission_result_id=self.admission_result_id,
                compilation_result_id=self.compilation_result_id,
                target_ref=self.target_ref,
                world_ref=self.world_ref,
                policy_ref=self.policy_ref,
                plans=self.plans,
                blocker=self.blocker,
                diagnostics=self.diagnostics,
            ),
        }


class GraphBoundRequestBinder:
    """Reconstruct and preflight R5B3a manifests without reserving or sending."""

    def __init__(
        self,
        *,
        experiment_compiler: Optional[
            GraphBoundPrerequisiteExperimentCompiler
        ] = None,
        lifecycle_miner: Optional[LifecycleContractMiner] = None,
        state_machine_miner: Optional[StateMachineLegalityMiner] = None,
    ) -> None:
        self.experiment_compiler = (
            experiment_compiler or GraphBoundPrerequisiteExperimentCompiler()
        )
        self.lifecycle_miner = lifecycle_miner or LifecycleContractMiner()
        self.state_machine_miner = (
            state_machine_miner or StateMachineLegalityMiner()
        )

    @staticmethod
    def _result(
        *,
        status: str,
        admission: GraphBoundManifestAdmissionResult,
        plans: Sequence[GraphBoundPreparedRequestPlan] = (),
        blocker: Optional[str],
        reconstruction_denials: int = 0,
        policy_denials: int = 0,
        budget_denials: int = 0,
    ) -> GraphBoundRequestBindingResult:
        return GraphBoundRequestBindingResult.build(
            status=status,
            admission_result_id=admission.result_id,
            compilation_result_id=admission.compilation_result_id,
            target_ref=admission.target_ref,
            world_ref=admission.world_ref,
            policy_ref=admission.policy_ref if plans else None,
            plans=plans,
            blocker=blocker,
            diagnostics=GraphBoundRequestBindingDiagnostics(
                manifests_examined=len(admission.manifests),
                plans_bound=len(plans),
                reconstruction_denials=reconstruction_denials,
                policy_denials=policy_denials,
                budget_denials=budget_denials,
            ),
        )

    @staticmethod
    def _reconstruct_recipe(
        *,
        specification: GraphBoundPrerequisiteExperimentSpec,
        candidate: StateMachineLegalityCandidate,
        ledger: ValueLineageLedger,
        world_id: str,
    ) -> Tuple[PlanRehydrator, RehydrationRecipe]:
        compiler = BackwardExploitCompiler(
            ledger.operations,
            limits=CompilerLimits(
                max_search_states=MAX_STATE_MACHINE_SEARCH_STATES,
                max_plan_steps=MAX_STATE_MACHINE_PLAN_STEPS,
            ),
        )
        goal = {
            item.terminal_operation_id: item
            for item in high_value_goals(ledger.operations)
        }.get(specification.terminal_operation_id)
        if goal is None:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_request_goal_is_not_current"
            )
        plan = compiler.compile(goal)
        if (
            plan.status != "planned"
            or plan.plan_id != candidate.plan_id
            or plan.step_ids != specification.delta.baseline_operation_ids
        ):
            raise GraphBoundRequestBindingDenied(
                "graph_bound_request_plan_is_not_current"
            )
        rehydrator = PlanRehydrator(ledger)
        recipe = rehydrator.build_recipe(plan, world_id=world_id)
        if (
            recipe.status != "ready"
            or recipe.recipe_id != candidate.recipe_id
            or tuple(item.source_ref for item in recipe.steps)
            != candidate.source_refs
            or tuple(sorted(item.binding_id for item in recipe.bindings))
            != candidate.lineage_binding_ids
        ):
            raise GraphBoundRequestBindingDenied(
                "graph_bound_request_recipe_is_not_current"
            )
        return rehydrator, recipe

    @staticmethod
    def _cleanup_requests(
        *,
        specification: GraphBoundPrerequisiteExperimentSpec,
        lifecycle: LifecycleMiningResult,
    ) -> Tuple[Tuple[OwnedLifecycleCandidate, LineageBinding, EphemeralRehydratedStep], ...]:
        candidates = {item.lifecycle_id: item for item in lifecycle.candidates}
        bindings = {
            item.binding_id: item for item in lifecycle.ledger.bindings
        }
        observations = {item.source_ref: item for item in lifecycle.ledger.observations}
        output = []
        for cleanup in specification.cleanup.bindings:
            candidate = candidates.get(cleanup.lifecycle_id)
            binding = bindings.get(cleanup.cleanup_binding_id)
            if (
                candidate is None
                or candidate.create_operation_id != cleanup.create_operation_id
                or candidate.cleanup_operation_id != cleanup.cleanup_operation_id
                or candidate.cleanup_binding_id != cleanup.cleanup_binding_id
                or binding is None
                or binding.producer_operation_id != cleanup.create_operation_id
                or binding.consumer_operation_id != cleanup.cleanup_operation_id
            ):
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_cleanup_binding_is_not_current"
                )
            observation = observations.get(binding.consumer_source_ref)
            if (
                observation is None
                or observation.operation_id != cleanup.cleanup_operation_id
                or not 200 <= observation.response_status < 300
            ):
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_cleanup_observation_is_not_current"
                )
            request = lifecycle.ledger._rehydrate_observation(observation)
            output.append((candidate, binding, request))
        return tuple(output)

    @staticmethod
    def _expected_action(
        *,
        request: EphemeralRehydratedStep,
        create_operation_ids: frozenset[str],
        cleanup: bool,
        cleanup_verification: bool = False,
    ) -> Tuple[str, str, bool]:
        if cleanup and cleanup_verification:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_request_phase_is_ambiguous"
            )
        if cleanup:
            if (
                request.method not in {"PATCH", "PUT"}
                or not is_proven_safe_cleanup_body(request.body)
            ):
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_cleanup_request_is_not_safe"
                )
            return OWNED_UPDATE_LOW_RISK, "cleanup_owned_test_object", True
        if cleanup_verification:
            if request.method not in {"GET", "HEAD"}:
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_cleanup_verification_request_is_not_safe"
                )
            return SAFE_READ, "none", True
        if request.operation_id in create_operation_ids:
            if (
                request.method != "POST"
                or not is_proven_safe_owned_create_body(request.body)
            ):
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_create_request_is_not_safe"
                )
            return OWNED_CREATE, "create_owned_test_object", False
        if request.method not in {"GET", "HEAD"}:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_non_create_request_is_not_read_only"
            )
        return SAFE_READ, "none", False

    @staticmethod
    def _bind_action(
        *,
        manifest: GraphBoundExperimentManifest,
        world_slot_id: str,
        world_role: str,
        phase: str,
        ordinal: int,
        request: EphemeralRehydratedStep,
        input_bindings: Sequence[LineageBinding],
        output_bindings: Sequence[LineageBinding],
        request_mutation_ref: Optional[str],
        runtime_override_binding_id: Optional[str],
        runtime_override_source_world_slot_id: Optional[str],
        runtime_override_source_create_operation_id: Optional[str],
        action_class: str,
        expected_side_effect: str,
        conditional_cleanup: bool,
        executor: PolicyExecutor,
        actor_persona_id: str,
        target_origin: str,
    ) -> Tuple[
        GraphBoundRequestActionBinding,
        GraphBoundEndpointBudgetBinding,
        _EphemeralBoundRequest,
    ]:
        input_binding_values = tuple(
            sorted(input_bindings, key=lambda item: item.binding_id)
        )
        output_binding_values = tuple(
            sorted(output_bindings, key=lambda item: item.binding_id)
        )
        input_binding_ids = tuple(
            item.binding_id for item in input_binding_values
        )
        if _request_origin(request.url) != target_origin:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_request_origin_changed"
            )
        action = CandidateAction(
            method=request.method,
            url=request.url,
            body=classification_body(request.body),
            hint=action_class,
            actor_persona_id=actor_persona_id,
            target_owner_persona_id=(
                actor_persona_id if conditional_cleanup else None
            ),
            target_is_researcher_owned=(True if conditional_cleanup else None),
            expected_side_effect=expected_side_effect,
            proof_goal="graph_bound_prerequisite_counterexample",
        )
        decision = executor.policy.evaluate_action(action)
        if not decision.allowed or decision.action_class != action_class:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_request_policy_preflight_denied",
                category="policy",
            )
        endpoint_value = endpoint_key(request.url)
        endpoint_ref = stable_hash("graph_bound_endpoint_key", endpoint_value)
        template_ref = _request_template_ref(request)
        policy_decision_ref = stable_hash(
            "graph_bound_policy_decision",
            {
                "policy_ref": manifest.policy_ref,
                "request_template_ref": template_ref,
                "endpoint_key_ref": endpoint_ref,
                "action_class": action_class,
                "allowed": True,
                "reason": decision.reason,
            },
        )
        action_payload = _action_payload(
            manifest_id=manifest.manifest_id,
            world_slot_id=world_slot_id,
            world_role=world_role,
            phase=phase,
            ordinal=ordinal,
            operation_id=request.operation_id,
            source_ref=request.source_ref,
            source_request_digest=request.request_digest,
            request_template_ref=template_ref,
            method=request.method,
            endpoint_key_ref=endpoint_ref,
            action_class=action_class,
            expected_side_effect=expected_side_effect,
            input_binding_ids=tuple(sorted(set(input_binding_ids))),
            request_mutation_ref=request_mutation_ref,
            runtime_override_binding_id=runtime_override_binding_id,
            runtime_override_source_world_slot_id=(
                runtime_override_source_world_slot_id
            ),
            runtime_override_source_create_operation_id=(
                runtime_override_source_create_operation_id
            ),
            conditional_cleanup=conditional_cleanup,
            policy_decision_ref=policy_decision_ref,
        )
        request_binding = GraphBoundRequestActionBinding(
            binding_id=stable_hash("graph_bound_request_action", action_payload),
            manifest_id=manifest.manifest_id,
            world_slot_id=world_slot_id,
            world_role=world_role,
            phase=phase,
            ordinal=ordinal,
            operation_id=request.operation_id,
            source_ref=request.source_ref,
            source_request_digest=request.request_digest,
            request_template_ref=template_ref,
            method=request.method,
            endpoint_key_ref=endpoint_ref,
            action_class=action_class,
            expected_side_effect=expected_side_effect,
            input_binding_ids=tuple(sorted(set(input_binding_ids))),
            request_mutation_ref=request_mutation_ref,
            runtime_override_binding_id=runtime_override_binding_id,
            runtime_override_source_world_slot_id=(
                runtime_override_source_world_slot_id
            ),
            runtime_override_source_create_operation_id=(
                runtime_override_source_create_operation_id
            ),
            conditional_cleanup=conditional_cleanup,
            policy_decision_ref=policy_decision_ref,
        )
        budget_payload = _budget_entry_payload(
            request_binding_id=request_binding.binding_id,
            ordinal=ordinal,
            action_class=action_class,
            endpoint_key_ref=endpoint_ref,
        )
        budget_binding = GraphBoundEndpointBudgetBinding(
            entry_id=stable_hash("graph_bound_endpoint_budget", budget_payload),
            request_binding_id=request_binding.binding_id,
            ordinal=ordinal,
            action_class=action_class,
            endpoint_key_ref=endpoint_ref,
        )
        ephemeral = _EphemeralBoundRequest(
            binding_id=request_binding.binding_id,
            request=request,
            endpoint_key_value=endpoint_value,
            action=action,
            input_bindings=input_binding_values,
            output_bindings=output_binding_values,
        )
        return request_binding, budget_binding, ephemeral

    def _bind_manifest(
        self,
        *,
        manifest: GraphBoundExperimentManifest,
        candidate: StateMachineLegalityCandidate,
        lifecycle: LifecycleMiningResult,
        ledger: ValueLineageLedger,
        world_id: str,
        target_origin: str,
        executor: PolicyExecutor,
    ) -> GraphBoundPreparedRequestPlan:
        specification = manifest.specification
        rehydrator, recipe = self._reconstruct_recipe(
            specification=specification,
            candidate=candidate,
            ledger=ledger,
            world_id=world_id,
        )
        requests = {
            operation_id: rehydrator.rehydrate_step(recipe, operation_id)
            for operation_id in specification.delta.baseline_operation_ids
        }
        recipe_bindings = {item.binding_id: item for item in recipe.bindings}
        cleanup_requests = self._cleanup_requests(
            specification=specification,
            lifecycle=lifecycle,
        )
        runtime_bindings = {item.binding_id: item for item in recipe.bindings}
        runtime_bindings.update(
            {
                binding.binding_id: binding
                for _candidate, binding, _request in cleanup_requests
            }
        )
        create_operation_ids = frozenset(
            item.create_operation_id for item, _binding, _request in cleanup_requests
        )
        slots = {item.role: item for item in manifest.world_slots}
        request_bindings = []
        budget_bindings = []
        ephemeral_requests = []

        def append_request(
            *,
            world_role: str,
            phase: str,
            request: EphemeralRehydratedStep,
            input_bindings: Sequence[LineageBinding],
            mutation_ref: Optional[str] = None,
            runtime_override_binding_id: Optional[str] = None,
            runtime_override_source_world_slot_id: Optional[str] = None,
            runtime_override_source_create_operation_id: Optional[str] = None,
            cleanup: bool = False,
            cleanup_verification: bool = False,
        ) -> None:
            action_class, expected_effect, conditional = self._expected_action(
                request=request,
                create_operation_ids=create_operation_ids,
                cleanup=cleanup,
                cleanup_verification=cleanup_verification,
            )
            bound = self._bind_action(
                manifest=manifest,
                world_slot_id=slots[world_role].slot_id,
                world_role=world_role,
                phase=phase,
                ordinal=len(request_bindings),
                request=request,
                input_bindings=input_bindings,
                output_bindings=tuple(
                    item
                    for item in runtime_bindings.values()
                    if item.producer_operation_id == request.operation_id
                ),
                request_mutation_ref=mutation_ref,
                runtime_override_binding_id=runtime_override_binding_id,
                runtime_override_source_world_slot_id=(
                    runtime_override_source_world_slot_id
                ),
                runtime_override_source_create_operation_id=(
                    runtime_override_source_create_operation_id
                ),
                action_class=action_class,
                expected_side_effect=expected_effect,
                conditional_cleanup=conditional,
                executor=executor,
                actor_persona_id=world_id,
                target_origin=target_origin,
            )
            request_bindings.append(bound[0])
            budget_bindings.append(bound[1])
            ephemeral_requests.append(bound[2])

        phase_operation_ids = {
            phase: (
                specification.delta.treatment_operation_ids
                if phase == "treatment"
                else specification.delta.baseline_operation_ids
            )
            for phase in _PHASES
        }
        terminal_requests = {}

        def append_phase_operation(*, phase: str, operation_id: str) -> None:
            world_role = _WORLD_ROLE_BY_PHASE[phase]
            request = requests[operation_id]
            input_bindings = tuple(
                item
                for item in recipe.bindings
                if item.consumer_operation_id == operation_id
            )
            mutation_ref = None
            runtime_override_binding_id = None
            runtime_override_source_world_slot_id = None
            runtime_override_source_create_operation_id = None
            if (
                phase == "treatment"
                and specification.delta.family
                is PrerequisiteCounterfactualFamily.OMISSION
                and operation_id == specification.terminal_operation_id
            ):
                target_binding_id = specification.delta.target_binding_ids[0]
                binding = recipe_bindings.get(target_binding_id)
                if (
                    binding is None
                    or binding.consumer_operation_id != operation_id
                    or binding.consumer_locator.kind.value
                    != specification.delta.consumer_locator_kind
                    or binding.consumer_locator.pointer
                    != specification.delta.consumer_locator_pointer
                ):
                    raise GraphBoundRequestBindingDenied(
                        "graph_bound_omission_binding_is_not_current"
                    )
                request = _remove_omission_binding(request, binding)
                input_bindings = tuple(
                    item
                    for item in input_bindings
                    if item.binding_id != target_binding_id
                )
                mutation_ref = specification.delta.delta_id
            if (
                phase == "control"
                and specification.delta.family
                is PrerequisiteCounterfactualFamily.OMISSION
                and operation_id == specification.terminal_operation_id
            ):
                target_binding_id = specification.delta.target_binding_ids[0]
                binding = recipe_bindings.get(target_binding_id)
                if binding is None or binding not in input_bindings:
                    raise GraphBoundRequestBindingDenied(
                        "graph_bound_effect_witness_binding_is_not_current"
                    )
                producer_create_bindings = tuple(
                    item
                    for item in recipe.bindings
                    if item.consumer_operation_id
                    == binding.producer_operation_id
                    and item.producer_operation_id in create_operation_ids
                )
                if len(producer_create_bindings) != 1:
                    raise GraphBoundRequestBindingDenied(
                        "graph_bound_effect_witness_producer_is_not_directly_owned"
                    )
                runtime_override_binding_id = target_binding_id
                runtime_override_source_world_slot_id = slots[
                    "valid_baseline"
                ].slot_id
                runtime_override_source_create_operation_id = (
                    producer_create_bindings[0].producer_operation_id
                )
            append_request(
                world_role=world_role,
                phase=phase,
                request=request,
                input_bindings=input_bindings,
                mutation_ref=mutation_ref,
                runtime_override_binding_id=runtime_override_binding_id,
                runtime_override_source_world_slot_id=(
                    runtime_override_source_world_slot_id
                ),
                runtime_override_source_create_operation_id=(
                    runtime_override_source_create_operation_id
                ),
            )
            if operation_id == specification.terminal_operation_id:
                terminal_requests[phase] = (
                    request,
                    input_bindings,
                    mutation_ref,
                )

        # Provision all three fresh worlds before any terminal experiment action.
        # The reserved sequence can therefore stop at a hard boundary without
        # dispatching a baseline, treatment, or control observation.
        terminal_phases = (
            ("control", "baseline", "treatment")
            if specification.delta.family
            is PrerequisiteCounterfactualFamily.OMISSION
            else _PHASES
        )
        for phase in _PHASES:
            for operation_id in phase_operation_ids[phase]:
                if operation_id != specification.terminal_operation_id:
                    append_phase_operation(phase=phase, operation_id=operation_id)
        for phase in terminal_phases:
            if specification.terminal_operation_id not in phase_operation_ids[phase]:
                raise GraphBoundRequestBindingDenied(
                    "graph_bound_terminal_operation_is_missing"
                )
            append_phase_operation(
                phase=phase,
                operation_id=specification.terminal_operation_id,
            )
        for phase in _PHASES:
            world_role = _WORLD_ROLE_BY_PHASE[phase]
            for _candidate, cleanup_binding, cleanup_request in cleanup_requests:
                append_request(
                    world_role=world_role,
                    phase="cleanup",
                    request=cleanup_request,
                    input_bindings=(cleanup_binding,),
                    cleanup=True,
                )
        for phase in _PHASES:
            world_role = _WORLD_ROLE_BY_PHASE[phase]
            terminal_request, input_bindings, mutation_ref = terminal_requests[
                phase
            ]
            append_request(
                world_role=world_role,
                phase=_CLEANUP_VERIFICATION_PHASE,
                request=terminal_request,
                input_bindings=input_bindings,
                mutation_ref=mutation_ref,
                cleanup_verification=True,
            )

        public_requests = tuple(request_bindings)
        public_budget = tuple(budget_bindings)
        private_requests = tuple(ephemeral_requests)
        if len(public_requests) != manifest.budget.total_request_units:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_bound_request_count_mismatch"
            )
        phase_counts = {
            phase: sum(item.phase == phase for item in public_requests)
            for phase in (
                *_PHASES,
                _CLEANUP_PHASE,
                _CLEANUP_VERIFICATION_PHASE,
            )
        }
        if phase_counts != {
            "baseline": manifest.budget.baseline_request_units,
            "treatment": manifest.budget.treatment_request_units,
            "control": manifest.budget.control_request_units,
            _CLEANUP_PHASE: manifest.budget.cleanup_request_units,
            _CLEANUP_VERIFICATION_PHASE: (
                manifest.budget.cleanup_verification_request_units
            ),
        }:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_bound_request_phase_count_mismatch"
            )
        reservation_sequence = tuple(
            (item.action_class, raw.endpoint_key_value)
            for item, raw in zip(public_requests, private_requests)
        )
        preview_allowed, preview_reason = executor.policy.budget.preview_reservation(
            reservation_sequence
        )
        if not preview_allowed:
            raise GraphBoundRequestBindingDenied(
                "graph_bound_budget_preview_denied",
                category="budget",
            )
        budget_preview_ref = stable_hash(
            "graph_bound_budget_preview",
            {
                "manifest_budget_id": manifest.budget.budget_id,
                "policy_ref": manifest.policy_ref,
                "budget_binding_ids": [item.entry_id for item in public_budget],
                "allowed": True,
                "reason": preview_reason,
                "reserved": False,
            },
        )
        remaining_blockers = tuple(
            sorted(
                set(manifest.pending_execution_blockers)
                - _RESOLVED_MANIFEST_BLOCKERS
            )
        )
        payload = _plan_payload(
            manifest_id=manifest.manifest_id,
            compilation_result_id=manifest.compilation_result_id,
            lifecycle_capture_digest=manifest.lifecycle_capture_digest,
            specification_id=specification.spec_id,
            delta_id=specification.delta.delta_id,
            family=specification.delta.family.value,
            baseline_operation_ids=specification.delta.baseline_operation_ids,
            treatment_operation_ids=specification.delta.treatment_operation_ids,
            request_bindings=public_requests,
            budget_bindings=public_budget,
            budget_preview_ref=budget_preview_ref,
            remaining_execution_blockers=remaining_blockers,
        )
        return GraphBoundPreparedRequestPlan(
            plan_id=stable_hash("graph_bound_prepared_request_plan", payload),
            manifest_id=manifest.manifest_id,
            compilation_result_id=manifest.compilation_result_id,
            lifecycle_capture_digest=manifest.lifecycle_capture_digest,
            specification_id=specification.spec_id,
            delta_id=specification.delta.delta_id,
            family=specification.delta.family.value,
            baseline_operation_ids=specification.delta.baseline_operation_ids,
            treatment_operation_ids=specification.delta.treatment_operation_ids,
            request_bindings=public_requests,
            budget_bindings=public_budget,
            budget_preview_ref=budget_preview_ref,
            remaining_execution_blockers=remaining_blockers,
            ephemeral_requests=private_requests,
        )

    def bind(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        target_origin: str,
        world_id: str,
        lifecycle: LifecycleMiningResult,
        state_machine: StateMachineLegalityResult,
        compilation: GraphBoundExperimentCompilationResult,
        admission: GraphBoundManifestAdmissionResult,
        executor: Optional[PolicyExecutor] = None,
    ) -> GraphBoundRequestBindingResult:
        if isinstance(records, (str, bytes)) or any(
            not isinstance(item, Mapping) for item in records
        ):
            raise TypeError("graph-bound request records must contain mappings")
        if not isinstance(lifecycle, LifecycleMiningResult):
            raise TypeError("lifecycle must be a LifecycleMiningResult")
        if not isinstance(state_machine, StateMachineLegalityResult):
            raise TypeError("state_machine must be a StateMachineLegalityResult")
        if not isinstance(compilation, GraphBoundExperimentCompilationResult):
            raise TypeError(
                "compilation must be a GraphBoundExperimentCompilationResult"
            )
        if not isinstance(admission, GraphBoundManifestAdmissionResult):
            raise TypeError("admission must be a GraphBoundManifestAdmissionResult")
        origin = _canonical_origin(target_origin)
        if (
            admission.mode != GRAPH_BOUND_MANIFEST_ADMISSION_MODE
            or admission.compilation_result_id != compilation.result_id
            or admission.target_ref
            != stable_hash("security_obligation_target", origin)
            or admission.world_ref != stable_hash("world", world_id)
        ):
            raise ValueError("graph-bound request admission context mismatch")
        if admission.status != "ready_for_explicit_execution_boundary":
            return self._result(
                status="admission_not_ready",
                admission=admission,
                blocker="graph_bound_static_admission_not_ready",
            )
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("ready graph-bound admission requires a PolicyExecutor")
        policy_ref = stable_hash(
            "graph_bound_experiment_policy",
            executor.policy.digest(),
        )
        if admission.policy_ref != policy_ref:
            raise ValueError("graph-bound request policy context mismatch")

        record_values = tuple(records)
        fresh_lifecycle = self.lifecycle_miner.mine(
            record_values,
            world_id=world_id,
        )
        fresh_state_machine = self.state_machine_miner.mine(
            record_values,
            world_id=world_id,
        )
        if (
            fresh_lifecycle.to_dict() != lifecycle.to_dict()
            or fresh_state_machine.to_dict() != state_machine.to_dict()
        ):
            return self._result(
                status="capture_mismatch",
                admission=admission,
                blocker="graph_bound_request_capture_changed",
            )
        fresh_compilation = self.experiment_compiler.compile(
            record_values,
            world_id=world_id,
            lifecycle=fresh_lifecycle,
            state_machine=fresh_state_machine,
        )
        if fresh_compilation.to_dict() != compilation.to_dict():
            return self._result(
                status="capture_mismatch",
                admission=admission,
                blocker="graph_bound_request_capture_changed",
            )
        try:
            ledger = ValueLineageLedger(
                record_values,
                world_id=world_id,
                catalog_limits=OperationCatalogLimits(
                    max_records=MAX_STATE_MACHINE_RECORDS,
                ),
            )
        except ValueError:
            return self._result(
                status="capture_mismatch",
                admission=admission,
                blocker="graph_bound_request_capture_limits_exceeded",
            )
        candidates = {
            item.candidate_id: item for item in fresh_state_machine.candidates
        }
        current_specs = {
            item.spec_id: item for item in fresh_compilation.specifications
        }
        plans = []
        reconstruction_denials = 0
        policy_denials = 0
        budget_denials = 0
        for manifest in admission.manifests:
            specification = current_specs.get(manifest.specification.spec_id)
            candidate = candidates.get(
                manifest.specification.state_machine_candidate_id
            )
            if (
                specification is None
                or specification.to_dict() != manifest.specification.to_dict()
                or candidate is None
            ):
                reconstruction_denials += 1
                continue
            try:
                plans.append(
                    self._bind_manifest(
                        manifest=manifest,
                        candidate=candidate,
                        lifecycle=fresh_lifecycle,
                        ledger=ledger,
                        world_id=world_id,
                        target_origin=origin,
                        executor=executor,
                    )
                )
            except GraphBoundRequestBindingDenied as exc:
                if exc.category == "policy":
                    policy_denials += 1
                elif exc.category == "budget":
                    budget_denials += 1
                else:
                    reconstruction_denials += 1
        ordered = tuple(sorted(plans, key=lambda item: item.plan_id))
        if not ordered:
            return self._result(
                status="no_bindable_manifests",
                admission=admission,
                blocker="graph_bound_no_manifest_passed_request_preflight",
                reconstruction_denials=reconstruction_denials,
                policy_denials=policy_denials,
                budget_denials=budget_denials,
            )
        return self._result(
            status="ready_for_single_use_execution_claim",
            admission=admission,
            plans=ordered,
            blocker=None,
            reconstruction_denials=reconstruction_denials,
            policy_denials=policy_denials,
            budget_denials=budget_denials,
        )


__all__ = [
    "GRAPH_BOUND_REQUEST_BINDING_MODE",
    "GraphBoundEndpointBudgetBinding",
    "GraphBoundPreparedRequestPlan",
    "GraphBoundRequestActionBinding",
    "GraphBoundRequestBinder",
    "GraphBoundRequestBindingDenied",
    "GraphBoundRequestBindingDiagnostics",
    "GraphBoundRequestBindingResult",
]
