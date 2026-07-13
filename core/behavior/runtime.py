"""Controlled runtime substitution for compiler plans, without router wiring.

This is the first active-capable compiler component, but it is deliberately not
reachable from an API or UI.  It accepts only a lineage-ready recipe, one owned
persona, explicit per-operation intent, a signed authorization envelope, and a
shared bounty-safe PolicyExecutor with ownership, provenance, and budget gates.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from core.cortex.execution_policy import (
    DENIED_STATUS,
    CandidateAction,
    PolicyExecutor,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import (
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    SAFE_READ,
    classify,
)
from core.safety.proof_budget import endpoint_key
from core.safety.proof_mode import ProofMode

from .compiler import OperationContract, OperationSafety
from .lineage import (
    EphemeralRehydratedStep,
    LineageBinding,
    LocatorKind,
    PlanRehydrator,
    RehydrationRecipe,
    ValueLineageLedger,
)
from .normalize import stable_hash

CONTROLLED_SEQUENCE_WORKFLOW = "behavioral_compiled_owned_sequence"
_ALLOWED_HINTS = frozenset({SAFE_READ, OWNED_CREATE, OWNED_UPDATE_LOW_RISK})
_CLEANUP_FIELDS = frozenset({"active", "archived", "is_archived", "state", "status"})
_CLEANUP_VALUES = frozenset({"archive", "archived", "inactive", "removed", "test_complete"})


class ControlledSequenceDenied(RuntimeError):
    """Raised before or during a fail-closed compiled sequence."""


@dataclass(frozen=True)
class RuntimeStepIntent:
    operation_id: str
    hint: str
    expected_side_effect: str

    def __post_init__(self) -> None:
        if not self.operation_id:
            raise ValueError("runtime intent operation_id is required")
        if self.hint not in _ALLOWED_HINTS:
            raise ValueError("runtime intent hint is not allowed for compiled execution")
        if self.expected_side_effect not in {
            "none",
            "create_owned_test_object",
            "cleanup_owned_test_object",
        }:
            raise ValueError("runtime intent expected_side_effect is unsupported")


@dataclass(frozen=True)
class ControlledSequenceResult:
    sequence_id: str
    status: str
    main_steps_attempted: int
    main_steps_completed: int
    cleanup_steps_attempted: int
    cleanup_steps_completed: int
    policy_denials: int
    runtime_values_bound: int
    orphaned_owned_state_possible: bool
    provenance_root: str
    budget_snapshot: Dict[str, int]
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "status": self.status,
            "main_steps_attempted": self.main_steps_attempted,
            "main_steps_completed": self.main_steps_completed,
            "cleanup_steps_attempted": self.cleanup_steps_attempted,
            "cleanup_steps_completed": self.cleanup_steps_completed,
            "policy_denials": self.policy_denials,
            "runtime_values_bound": self.runtime_values_bound,
            "orphaned_owned_state_possible": self.orphaned_owned_state_possible,
            "provenance_root": self.provenance_root,
            "budget_snapshot": dict(self.budget_snapshot),
            "error_code": self.error_code,
        }


@dataclass(frozen=True)
class _RuntimeStep:
    operation: OperationContract
    request: EphemeralRehydratedStep
    intent: RuntimeStepIntent
    action_class: str


@dataclass(frozen=True)
class _CleanupStep:
    create_operation_id: str
    step: _RuntimeStep
    binding: LineageBinding


@dataclass(frozen=True)
class _Preflight:
    sequence_id: str
    main_steps: Tuple[_RuntimeStep, ...]
    cleanup_steps: Tuple[_CleanupStep, ...]
    all_bindings: Tuple[LineageBinding, ...]


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ControlledSequenceDenied("target_origin_is_invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ControlledSequenceDenied("target_origin_must_be_absolute_http_url")
    port = parsed.port
    default = (parsed.scheme == "http" and port in {None, 80}) or (
        parsed.scheme == "https" and port in {None, 443}
    )
    return f"{parsed.scheme}://{parsed.hostname}" if default else (
        f"{parsed.scheme}://{parsed.hostname}:{port}"
    )


def _validate_authorization(
    envelope: AuthorizationEnvelope,
    target_origin: str,
) -> None:
    if not envelope.attestation_signature:
        raise ControlledSequenceDenied("authorization_envelope_is_unsigned")
    expected = copy.deepcopy(envelope).sign()
    if not hmac.compare_digest(envelope.attestation_signature, expected):
        raise ControlledSequenceDenied("authorization_envelope_signature_mismatch")
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=CONTROLLED_SEQUENCE_WORKFLOW,
        )
    except Exception as exc:
        raise ControlledSequenceDenied("authorization_envelope_denied_sequence") from exc


def _decode_pointer(pointer: str) -> Tuple[str, ...]:
    if not pointer.startswith("/"):
        raise ControlledSequenceDenied("runtime_locator_is_not_absolute")
    if pointer == "/":
        return ("",)
    return tuple(
        item.replace("~1", "/").replace("~0", "~")
        for item in pointer[1:].split("/")
    )


def _json_body(value: Any) -> tuple[Any, bool]:
    if isinstance(value, (Mapping, list)):
        return copy.deepcopy(value), False
    if not isinstance(value, str):
        raise ControlledSequenceDenied("runtime_body_is_not_structured")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise ControlledSequenceDenied("runtime_body_json_is_invalid") from exc
    if not isinstance(parsed, (Mapping, list)):
        raise ControlledSequenceDenied("runtime_body_json_is_not_container")
    return parsed, True


def _pointer_get(value: Any, pointer: str) -> Any:
    current = value
    for token in _decode_pointer(pointer):
        if isinstance(current, Mapping):
            if token not in current:
                raise ControlledSequenceDenied("runtime_response_locator_missing")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except (TypeError, ValueError) as exc:
                raise ControlledSequenceDenied("runtime_response_array_index_invalid") from exc
            if index < 0 or index >= len(current):
                raise ControlledSequenceDenied("runtime_response_array_index_missing")
            current = current[index]
        else:
            raise ControlledSequenceDenied("runtime_response_locator_crosses_scalar")
    if isinstance(current, bool) or current is None or not isinstance(current, (str, int)):
        raise ControlledSequenceDenied("runtime_response_value_is_not_scalar_identifier")
    text = str(current).strip()
    if not text or len(text) > 4_096 or any(ord(char) < 0x20 for char in text):
        raise ControlledSequenceDenied("runtime_response_value_is_invalid")
    return current


def _pointer_set(value: Any, pointer: str, replacement: Any) -> Any:
    tokens = _decode_pointer(pointer)
    if not tokens:
        raise ControlledSequenceDenied("runtime_request_locator_is_empty")
    current = value
    for token in tokens[:-1]:
        if isinstance(current, Mapping):
            if token not in current:
                raise ControlledSequenceDenied("runtime_request_locator_missing")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except (TypeError, ValueError) as exc:
                raise ControlledSequenceDenied("runtime_request_array_index_invalid") from exc
            if index < 0 or index >= len(current):
                raise ControlledSequenceDenied("runtime_request_array_index_missing")
            current = current[index]
        else:
            raise ControlledSequenceDenied("runtime_request_locator_crosses_scalar")
    leaf = tokens[-1]
    if isinstance(current, dict):
        if leaf not in current:
            raise ControlledSequenceDenied("runtime_request_locator_missing")
        current[leaf] = replacement
    elif isinstance(current, list):
        try:
            index = int(leaf)
        except (TypeError, ValueError) as exc:
            raise ControlledSequenceDenied("runtime_request_array_index_invalid") from exc
        if index < 0 or index >= len(current):
            raise ControlledSequenceDenied("runtime_request_array_index_missing")
        current[index] = replacement
    else:
        raise ControlledSequenceDenied("runtime_request_locator_parent_is_scalar")
    return value


def _replace_key_occurrence(
    pairs: Sequence[Tuple[str, str]],
    pointer: str,
    replacement: Any,
) -> list[Tuple[str, str]]:
    tokens = _decode_pointer(pointer)
    if len(tokens) != 2:
        raise ControlledSequenceDenied("runtime_parameter_locator_is_invalid")
    key = tokens[0]
    try:
        desired = int(tokens[1])
    except (TypeError, ValueError) as exc:
        raise ControlledSequenceDenied("runtime_parameter_occurrence_is_invalid") from exc
    output: list[Tuple[str, str]] = []
    seen = 0
    replaced = False
    for current_key, current_value in pairs:
        if current_key == key:
            if seen == desired:
                output.append((current_key, str(replacement)))
                replaced = True
            else:
                output.append((current_key, current_value))
            seen += 1
        else:
            output.append((current_key, current_value))
    if not replaced:
        raise ControlledSequenceDenied("runtime_parameter_locator_missing")
    return output


def _apply_binding(
    request: EphemeralRehydratedStep,
    binding: LineageBinding,
    replacement: Any,
) -> EphemeralRehydratedStep:
    url = request.url
    body = copy.deepcopy(request.body)
    locator = binding.consumer_locator
    if locator.kind == LocatorKind.REQUEST_PATH:
        tokens = _decode_pointer(locator.pointer)
        if len(tokens) != 2 or tokens[0] != "segments":
            raise ControlledSequenceDenied("runtime_path_locator_is_invalid")
        try:
            target_index = int(tokens[1])
        except (TypeError, ValueError) as exc:
            raise ControlledSequenceDenied("runtime_path_index_is_invalid") from exc
        parsed = urlsplit(url)
        raw_segments = parsed.path.split("/")
        nonempty = [index for index, item in enumerate(raw_segments) if item]
        if target_index < 0 or target_index >= len(nonempty):
            raise ControlledSequenceDenied("runtime_path_locator_missing")
        raw_segments[nonempty[target_index]] = quote(str(replacement), safe="")
        url = urlunsplit(
            (parsed.scheme, parsed.netloc, "/".join(raw_segments), parsed.query, parsed.fragment)
        )
    elif locator.kind == LocatorKind.REQUEST_QUERY:
        parsed = urlsplit(url)
        pairs = _replace_key_occurrence(
            parse_qsl(parsed.query, keep_blank_values=True),
            locator.pointer,
            replacement,
        )
        url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), parsed.fragment)
        )
    elif locator.kind == LocatorKind.REQUEST_JSON:
        parsed_body, was_string = _json_body(body)
        parsed_body = _pointer_set(parsed_body, locator.pointer, replacement)
        body = (
            json.dumps(parsed_body, sort_keys=True, separators=(",", ":"))
            if was_string
            else parsed_body
        )
    elif locator.kind == LocatorKind.REQUEST_FORM:
        if not isinstance(body, str):
            raise ControlledSequenceDenied("runtime_form_body_is_not_text")
        pairs = _replace_key_occurrence(
            parse_qsl(body, keep_blank_values=True),
            locator.pointer,
            replacement,
        )
        body = urlencode(pairs)
    else:
        raise ControlledSequenceDenied("runtime_consumer_locator_is_not_supported")
    return EphemeralRehydratedStep(
        operation_id=request.operation_id,
        source_ref=request.source_ref,
        request_digest=request.request_digest,
        method=request.method,
        url=url,
        headers=copy.deepcopy(dict(request.headers)),
        body=body,
    )


def _extract_runtime_value(response: Any, binding: LineageBinding) -> Any:
    if binding.producer_locator.kind != LocatorKind.RESPONSE_JSON:
        raise ControlledSequenceDenied("runtime_producer_locator_is_not_supported")
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except (TypeError, ValueError) as exc:
            raise ControlledSequenceDenied("runtime_response_json_is_invalid") from exc
    if not isinstance(response, (Mapping, list)):
        raise ControlledSequenceDenied("runtime_response_json_is_not_container")
    return _pointer_get(response, binding.producer_locator.pointer)


def _classification_body(body: Any) -> Any:
    if not isinstance(body, str):
        return body
    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(body)
        except (TypeError, ValueError):
            return body
    return body


def _valid_cleanup_body(body: Any) -> bool:
    parsed = _classification_body(body)
    if not isinstance(parsed, Mapping) or not parsed:
        return False
    keys = {str(key).lower() for key in parsed}
    if not keys <= _CLEANUP_FIELDS:
        return False
    for key, value in parsed.items():
        normalized_key = str(key).lower()
        if normalized_key in {"active", "archived", "is_archived"}:
            if value not in {False, True}:
                return False
            if normalized_key == "active" and value is not False:
                return False
            if normalized_key in {"archived", "is_archived"} and value is not True:
                return False
        elif str(value).strip().lower() not in _CLEANUP_VALUES:
            return False
    return True


class ControlledRuntimeSequenceExecutor:
    """Single-use executor for one owned, reversible compiled sequence."""

    def __init__(
        self,
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        executor: PolicyExecutor,
        ledger: ValueLineageLedger,
        recipe: RehydrationRecipe,
        intents: Mapping[str, RuntimeStepIntent],
    ) -> None:
        self.target_origin = _origin(target_origin)
        self.authorization = authorization
        self.actor_persona_id = str(actor_persona_id)
        self.executor = executor
        self.ledger = ledger
        self.recipe = recipe
        self.intents = dict(intents)
        self._lock = asyncio.Lock()
        self._consumed = False

    def _validate_executor(self) -> None:
        _validate_authorization(self.authorization, self.target_origin)
        if not self.actor_persona_id:
            raise ControlledSequenceDenied("runtime_actor_persona_is_required")
        if self.recipe.world_ref != stable_hash("world", self.actor_persona_id):
            raise ControlledSequenceDenied("runtime_recipe_world_mismatch")
        policy = self.executor.policy
        if policy.mode != ProofMode.BOUNTY_SAFE:
            raise ControlledSequenceDenied("runtime_sequence_requires_bounty_safe_mode")
        if policy.scope_filter is None:
            raise ControlledSequenceDenied("runtime_sequence_requires_scope_filter")
        if policy.ownership_registry is None:
            raise ControlledSequenceDenied("runtime_sequence_requires_ownership_registry")
        if self.executor.provenance is None:
            raise ControlledSequenceDenied("runtime_sequence_requires_provenance")

    def _validate_step(
        self,
        operation: OperationContract,
        request: EphemeralRehydratedStep,
        intent: RuntimeStepIntent,
        *,
        cleanup: bool,
    ) -> _RuntimeStep:
        if intent.operation_id != operation.operation_id:
            raise ControlledSequenceDenied("runtime_intent_operation_mismatch")
        if _origin(request.url) != self.target_origin:
            raise ControlledSequenceDenied("runtime_step_origin_mismatch")
        if cleanup:
            if intent.hint != OWNED_UPDATE_LOW_RISK:
                raise ControlledSequenceDenied("runtime_cleanup_requires_low_risk_update")
            if operation.safety != OperationSafety.OWNED_REVERSIBLE_WRITE:
                raise ControlledSequenceDenied("runtime_cleanup_safety_contract_mismatch")
            if request.method not in {"PUT", "PATCH"}:
                raise ControlledSequenceDenied("runtime_cleanup_method_is_not_reversible_update")
            if intent.expected_side_effect != "cleanup_owned_test_object":
                raise ControlledSequenceDenied("runtime_cleanup_intent_is_invalid")
            if not _valid_cleanup_body(request.body):
                raise ControlledSequenceDenied("runtime_cleanup_body_is_not_proven_safe")
        elif intent.hint == SAFE_READ:
            if request.method != "GET" or operation.safety != OperationSafety.READ_ONLY:
                raise ControlledSequenceDenied("runtime_read_contract_mismatch")
            if intent.expected_side_effect != "none":
                raise ControlledSequenceDenied("runtime_read_side_effect_mismatch")
        elif intent.hint == OWNED_CREATE:
            if request.method != "POST":
                raise ControlledSequenceDenied("runtime_create_requires_post")
            if operation.safety != OperationSafety.OWNED_REVERSIBLE_WRITE:
                raise ControlledSequenceDenied("runtime_create_safety_contract_mismatch")
            if intent.expected_side_effect != "create_owned_test_object":
                raise ControlledSequenceDenied("runtime_create_intent_is_invalid")
            if not operation.cleanup_operation_id:
                raise ControlledSequenceDenied("runtime_create_has_no_cleanup_contract")
        else:
            raise ControlledSequenceDenied("runtime_main_write_is_not_supported")
        classified = classify(
            request.method,
            request.url,
            _classification_body(request.body),
            hint=intent.hint,
        )
        if classified != intent.hint:
            raise ControlledSequenceDenied(
                f"runtime_structural_classification_overruled_intent:{classified}"
            )
        decision = self.executor.policy.evaluate_action(
            CandidateAction(
                method=request.method,
                url=request.url,
                body=_classification_body(request.body),
                hint=intent.hint,
                actor_persona_id=self.actor_persona_id,
                expected_side_effect=intent.expected_side_effect,
                proof_goal="manufacture_owned_compiler_prerequisite",
            )
        )
        if not decision.allowed:
            raise ControlledSequenceDenied(f"runtime_policy_preflight_denied:{decision.reason}")
        return _RuntimeStep(operation, request, intent, classified)

    def _preflight(self) -> _Preflight:
        self._validate_executor()
        if self.recipe.status != "ready" or self.recipe.executable:
            raise ControlledSequenceDenied("runtime_recipe_is_not_analysis_ready")
        allowed_blockers = {
            "analysis_only_no_execution_authority",
        }
        unexpected = [
            blocker
            for blocker in self.recipe.execution_blockers
            if blocker not in allowed_blockers
            and not blocker.startswith("ownership_proof_required:")
            and not blocker.startswith("ownership_rehydration_required:")
        ]
        if unexpected:
            raise ControlledSequenceDenied("runtime_recipe_has_unresolved_execution_blockers")
        rehydrator = PlanRehydrator(self.ledger)
        operations = {item.operation_id: item for item in self.ledger.operations}
        main_steps: list[_RuntimeStep] = []
        cleanup_steps: list[_CleanupStep] = []
        required_intents: set[str] = set(self.recipe_step_ids)
        for operation_id in self.recipe_step_ids:
            operation = operations.get(operation_id)
            intent = self.intents.get(operation_id)
            if operation is None or intent is None:
                raise ControlledSequenceDenied("runtime_main_contract_or_intent_missing")
            request = rehydrator.rehydrate_step(self.recipe, operation_id)
            main_steps.append(
                self._validate_step(operation, request, intent, cleanup=False)
            )
            if intent.hint != OWNED_CREATE:
                continue
            cleanup_id = operation.cleanup_operation_id
            if cleanup_id is None or cleanup_id in self.recipe_step_ids:
                raise ControlledSequenceDenied("runtime_cleanup_contract_is_invalid")
            cleanup_operation = operations.get(cleanup_id)
            cleanup_intent = self.intents.get(cleanup_id)
            if cleanup_operation is None or cleanup_intent is None:
                raise ControlledSequenceDenied("runtime_cleanup_contract_or_intent_missing")
            required_intents.add(cleanup_id)
            observations = self.ledger.observations_for(cleanup_id, self.recipe.world_ref)
            if len(observations) != 1:
                raise ControlledSequenceDenied("runtime_cleanup_capture_is_missing_or_ambiguous")
            cleanup_request = self.ledger._rehydrate_observation(observations[0])
            cleanup_step = self._validate_step(
                cleanup_operation,
                cleanup_request,
                cleanup_intent,
                cleanup=True,
            )
            candidate_bindings = [
                binding
                for capability in cleanup_operation.requires
                for binding in self.ledger.bindings_for(
                    capability=capability,
                    consumer_operation_id=cleanup_id,
                    world_ref=self.recipe.world_ref,
                    producer_operation_ids=(operation_id,),
                )
                if binding.consumer_locator.kind == LocatorKind.REQUEST_PATH
            ]
            unique = {item.binding_id: item for item in candidate_bindings}
            if len(unique) != 1:
                raise ControlledSequenceDenied("runtime_cleanup_lineage_is_missing_or_ambiguous")
            cleanup_steps.append(
                _CleanupStep(operation_id, cleanup_step, next(iter(unique.values())))
            )
        if set(self.intents) != required_intents:
            raise ControlledSequenceDenied("runtime_intent_set_mismatch")
        create_ids = {
            step.operation.operation_id
            for step in main_steps
            if step.intent.hint == OWNED_CREATE
        }
        for binding in self.recipe.bindings:
            if binding.producer_operation_id in create_ids:
                if binding.consumer_locator.kind != LocatorKind.REQUEST_PATH:
                    raise ControlledSequenceDenied(
                        "runtime_owned_state_requires_path_lineage"
                    )
        all_bindings = {
            item.binding_id: item
            for item in (*self.recipe.bindings, *(item.binding for item in cleanup_steps))
        }
        descriptor = {
            "recipe_id": self.recipe.recipe_id,
            "actor_world": self.recipe.world_ref,
            "actor_persona_ref": stable_hash(
                "controlled_runtime_actor",
                self.actor_persona_id,
            ),
            "target_origin_ref": stable_hash(
                "controlled_runtime_target",
                self.target_origin,
            ),
            "authorization_signature": self.authorization.attestation_signature,
            "main": [item.operation.operation_id for item in main_steps],
            "cleanup": [item.step.operation.operation_id for item in cleanup_steps],
            "intents": [
                {
                    "operation_id": item.operation.operation_id,
                    "hint": item.intent.hint,
                    "expected_side_effect": item.intent.expected_side_effect,
                }
                for item in main_steps
            ]
            + [
                {
                    "operation_id": item.step.operation.operation_id,
                    "hint": item.step.intent.hint,
                    "expected_side_effect": item.step.intent.expected_side_effect,
                }
                for item in cleanup_steps
            ],
            "bindings": sorted(all_bindings),
            "policy_digest": self.executor.policy.digest(),
        }
        return _Preflight(
            sequence_id=stable_hash("controlled_runtime_sequence", descriptor),
            main_steps=tuple(main_steps),
            cleanup_steps=tuple(reversed(cleanup_steps)),
            all_bindings=tuple(all_bindings[key] for key in sorted(all_bindings)),
        )

    @property
    def recipe_step_ids(self) -> Tuple[str, ...]:
        return tuple(item.operation_id for item in self.recipe.steps)

    def validate_preflight(self) -> str:
        """Validate every invariant without reserving budget or sending traffic."""

        return self._preflight().sequence_id

    async def execute(
        self,
        *,
        expected_sequence_id: Optional[str] = None,
    ) -> ControlledSequenceResult:
        async with self._lock:
            if self._consumed:
                raise ControlledSequenceDenied("runtime_sequence_executor_already_consumed")
            preflight = self._preflight()
            if (
                expected_sequence_id is not None
                and preflight.sequence_id != expected_sequence_id
            ):
                raise ControlledSequenceDenied("runtime_sequence_identity_changed")
            self._consumed = True
            budget = self.executor.policy.budget
            reserved_actions = tuple(
                (step.action_class, endpoint_key(step.request.url))
                for step in preflight.main_steps
            ) + tuple(
                (item.step.action_class, endpoint_key(item.step.request.url))
                for item in preflight.cleanup_steps
            )
            reservation_id, reason = budget.try_reserve(reserved_actions)
            if reservation_id is None:
                raise ControlledSequenceDenied(f"runtime_budget_reservation_denied:{reason}")

            runtime_values: Dict[str, Any] = {}
            successful_creates: set[str] = set()
            main_attempted = 0
            main_completed = 0
            cleanup_attempted = 0
            cleanup_completed = 0
            orphan_possible = False
            error_code: Optional[str] = None
            main_aborted = False
            bindings_by_producer: Dict[str, list[LineageBinding]] = {}
            bindings_by_consumer: Dict[str, list[LineageBinding]] = {}
            for binding in preflight.all_bindings:
                bindings_by_producer.setdefault(binding.producer_operation_id, []).append(binding)
                bindings_by_consumer.setdefault(binding.consumer_operation_id, []).append(binding)

            try:
                for index, step in enumerate(preflight.main_steps):
                    request = step.request
                    consumed = False
                    send_started = False
                    policy_denied = False
                    try:
                        for binding in bindings_by_consumer.get(
                            step.operation.operation_id,
                            (),
                        ):
                            if binding.binding_id not in runtime_values:
                                raise ControlledSequenceDenied(
                                    "runtime_dependency_value_is_unavailable"
                                )
                            request = _apply_binding(
                                request,
                                binding,
                                runtime_values[binding.binding_id],
                            )
                        if endpoint_key(request.url) != endpoint_key(step.request.url):
                            raise ControlledSequenceDenied(
                                "runtime_substitution_changed_endpoint_budget_key"
                            )
                        requires_owned = step.operation.requires_owned_state
                        registry = self.executor.policy.ownership_registry
                        if requires_owned and (
                            registry is None or not registry.is_owned(request.url)
                        ):
                            raise ControlledSequenceDenied(
                                "runtime_owned_target_is_not_registered"
                            )
                        main_attempted += 1
                        before = budget.snapshot()["total_requests"]
                        send_started = True
                        status, response = await self.executor.send_action(
                            CandidateAction(
                                method=request.method,
                                url=request.url,
                                body=request.body,
                                hint=step.intent.hint,
                                actor_persona_id=self.actor_persona_id,
                                target_owner_persona_id=(
                                    self.actor_persona_id if requires_owned else None
                                ),
                                target_is_researcher_owned=(
                                    True if requires_owned else None
                                ),
                                expected_side_effect=step.intent.expected_side_effect,
                                proof_goal="manufacture_owned_compiler_prerequisite",
                                budget_reservation_id=reservation_id,
                            ),
                            headers=dict(request.headers),
                        )
                        consumed = budget.snapshot()["total_requests"] > before
                        if status == DENIED_STATUS:
                            policy_denied = True
                            raise ControlledSequenceDenied("runtime_step_denied_by_policy")
                        if not 200 <= int(status) < 300:
                            raise ControlledSequenceDenied("runtime_step_returned_non_2xx")
                        produced = bindings_by_producer.get(
                            step.operation.operation_id,
                            (),
                        )
                        for binding in produced:
                            runtime_values[binding.binding_id] = _extract_runtime_value(
                                response,
                                binding,
                            )
                        if step.intent.hint == OWNED_CREATE:
                            path_bindings = [
                                item
                                for item in produced
                                if item.consumer_locator.kind == LocatorKind.REQUEST_PATH
                            ]
                            values = {
                                str(runtime_values[item.binding_id])
                                for item in path_bindings
                            }
                            if len(values) != 1:
                                orphan_possible = True
                                raise ControlledSequenceDenied(
                                    "runtime_create_id_is_missing_or_ambiguous"
                                )
                            registry = self.executor.policy.ownership_registry
                            if registry is None or registry.register_created_value(
                                request.url,
                                next(iter(values)),
                                actor_persona=self.actor_persona_id,
                            ) is None:
                                orphan_possible = True
                                raise ControlledSequenceDenied(
                                    "runtime_create_ownership_registration_failed"
                                )
                            successful_creates.add(step.operation.operation_id)
                        main_completed += 1
                    except Exception as exc:
                        if (
                            step.intent.hint == OWNED_CREATE
                            and send_started
                            and not policy_denied
                            and step.operation.operation_id not in successful_creates
                        ):
                            orphan_possible = True
                        error_code = (
                            str(exc)
                            if isinstance(exc, ControlledSequenceDenied)
                            else "runtime_transport_error"
                        )
                        main_aborted = True
                        remaining_main = len(preflight.main_steps) - index - (
                            1 if consumed else 0
                        )
                        if remaining_main > 0:
                            budget.skip_reservation_entries(
                                reservation_id,
                                remaining_main,
                            )
                        break

                for cleanup in preflight.cleanup_steps:
                    if cleanup.create_operation_id not in successful_creates:
                        budget.skip_reservation_entries(reservation_id, 1)
                        continue
                    cleanup_attempted += 1
                    cleanup_consumed = False
                    try:
                        value = runtime_values.get(cleanup.binding.binding_id)
                        if value is None:
                            raise ControlledSequenceDenied(
                                "runtime_cleanup_value_is_unavailable"
                            )
                        request = _apply_binding(
                            cleanup.step.request,
                            cleanup.binding,
                            value,
                        )
                        if endpoint_key(request.url) != endpoint_key(
                            cleanup.step.request.url
                        ):
                            raise ControlledSequenceDenied(
                                "runtime_cleanup_changed_endpoint_budget_key"
                            )
                        registry = self.executor.policy.ownership_registry
                        if registry is None or not registry.is_owned(request.url):
                            raise ControlledSequenceDenied(
                                "runtime_cleanup_target_is_not_registered"
                            )
                        before = budget.snapshot()["total_requests"]
                        status, _response = await self.executor.send_action(
                            CandidateAction(
                                method=request.method,
                                url=request.url,
                                body=request.body,
                                hint=cleanup.step.intent.hint,
                                actor_persona_id=self.actor_persona_id,
                                target_owner_persona_id=self.actor_persona_id,
                                target_is_researcher_owned=True,
                                expected_side_effect=(
                                    cleanup.step.intent.expected_side_effect
                                ),
                                proof_goal="cleanup_owned_compiler_prerequisite",
                                budget_reservation_id=reservation_id,
                            ),
                            headers=dict(request.headers),
                        )
                        cleanup_consumed = (
                            budget.snapshot()["total_requests"] > before
                        )
                        if status == DENIED_STATUS or not 200 <= int(status) < 300:
                            raise ControlledSequenceDenied("runtime_cleanup_failed")
                        cleanup_completed += 1
                    except Exception as exc:
                        orphan_possible = True
                        if error_code is None:
                            error_code = (
                                str(exc)
                                if isinstance(exc, ControlledSequenceDenied)
                                else "runtime_cleanup_transport_error"
                            )
                        if (
                            not cleanup_consumed
                            and budget.reservation_remaining(reservation_id)
                        ):
                            budget.skip_reservation_entries(reservation_id, 1)
            finally:
                budget.release_reservation(reservation_id)

            final_status = "completed"
            if cleanup_attempted != cleanup_completed:
                final_status = "cleanup_failed"
            elif main_aborted:
                final_status = "aborted"
            sink = self.executor.provenance
            return ControlledSequenceResult(
                sequence_id=preflight.sequence_id,
                status=final_status,
                main_steps_attempted=main_attempted,
                main_steps_completed=main_completed,
                cleanup_steps_attempted=cleanup_attempted,
                cleanup_steps_completed=cleanup_completed,
                policy_denials=len(self.executor.skipped),
                runtime_values_bound=len(runtime_values),
                orphaned_owned_state_possible=orphan_possible,
                provenance_root=(sink.root() if sink is not None else "") or "",
                budget_snapshot=budget.snapshot(),
                error_code=error_code,
            )


__all__ = [
    "CONTROLLED_SEQUENCE_WORKFLOW",
    "ControlledRuntimeSequenceExecutor",
    "ControlledSequenceDenied",
    "ControlledSequenceResult",
    "RuntimeStepIntent",
]
