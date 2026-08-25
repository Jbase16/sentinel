"""Bounded ordinary-click coordination for Family-C role proof.

The request carries an exact, operator-supplied runtime specification because
ordinary capture does not discover role order, membership endpoints, retained
session identities, or target response projections.  The specification grants
no authority by itself: payout selection, the signed workflow, four independent
default-off gates, R5C3 binding, the R5C4 single-use claim, R5C6 target-side
observations, and a completed durable receipt all remain mandatory.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import CandidateAction, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import PersonaVault

from .experiment_admission import (
    experiment_authority_context_ref,
    experiment_endpoint_ref,
    experiment_ownership_ref,
    experiment_persona_ref,
)
from .experiment_sdk import (
    ExperimentAction,
    ExperimentActionClass,
    ExperimentPhase,
    ExperimentWorldBinding,
    ExperimentWorldKind,
    ExperimentWorldManifest,
    MutationExpectation,
)
from .normalize import stable_hash
from .obligations import SecurityObligationGraph
from .payout_goals import (
    PayoutGoalPlan,
    ProofTopology,
    SecurityProperty,
    SecurityWitnessGoal,
    WorldRequirement,
)
from .receipts import (
    BehavioralReceiptStore,
    redacted_role_protected_effect_execution_outcome,
)
from .role_effect_evaluation import (
    ROLE_PROTECTED_EFFECT_EXECUTION_ENV,
    RoleProtectedEffectExecutionConfig,
    RoleProtectedEffectExecutionDenied,
    RoleProtectedEffectExecutionResult,
)
from .role_execution_claim import (
    ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV,
    RoleMonotonicityExecutionClaimConfig,
)
from .role_membership import (
    OwnedMembershipFixture,
    RoleAuthorityLattice,
    owned_membership_ref,
)
from .role_membership_lifecycle import (
    ROLE_MEMBERSHIP_LIFECYCLE_ENV,
    RoleMembershipLifecycleConfig,
)
from .role_monotonicity import (
    ROLE_MONOTONICITY_WORKFLOW,
    RoleMonotonicityExperimentAdmission,
    RoleMonotonicityExperimentCompiler,
)
from .role_request_binding import (
    RoleMembershipObservationBinding,
    RoleMonotonicityRuntimeContext,
    RoleProtectedEffectObservationBinding,
    RoleRuntimeAuthorityValidator,
    role_tenant_ownership_ref,
)


ROLE_MONOTONICITY_ONE_CLICK_ENV = "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK"
ROLE_MONOTONICITY_ONE_CLICK_MODE = "behavioral_role_monotonicity_one_click_v1"
ROLE_MONOTONICITY_BACKEND = "authority_monotonicity"

_TRUE = frozenset({"1", "true", "yes", "on"})
_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_ACTION_NAMES = (
    "setup",
    "higher_baseline",
    "active_lower_probe",
    "active_effect_witness",
    "revocation",
    "revocation_verification",
    "revoked_lower_probe",
    "revoked_effect_witness",
)
_GET_ACTIONS = frozenset(
    {
        "higher_baseline",
        "active_lower_probe",
        "active_effect_witness",
        "revocation_verification",
        "revoked_lower_probe",
        "revoked_effect_witness",
    }
)
_METHODS = {
    "setup": "POST",
    "higher_baseline": "GET",
    "active_lower_probe": "GET",
    "active_effect_witness": "GET",
    "revocation": "PATCH",
    "revocation_verification": "GET",
    "revoked_lower_probe": "GET",
    "revoked_effect_witness": "GET",
}


def _typed_ref(value: Any, prefix: Optional[str] = None) -> bool:
    return bool(
        isinstance(value, str)
        and _HASH_REF.fullmatch(value)
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _bounded_string(
    value: Any,
    *,
    field_name: str,
    max_length: int = 512,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{field_name} is invalid")
    return value


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
        raise ValueError("role one-click target origin is invalid")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _validated_url(value: Any, *, target_origin: str, field_name: str) -> str:
    url = _bounded_string(
        value,
        field_name=field_name,
        max_length=4096,
    )
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or _canonical_origin(f"{parsed.scheme}://{parsed.netloc}") != target_origin
    ):
        raise ValueError(f"{field_name} leaves the signed target origin")
    return url


def _canonical_json(value: Any, *, field_name: str) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON serializable") from exc
    if len(encoded.encode("utf-8")) > 1_048_576:
        raise ValueError(f"{field_name} exceeds the 1 MiB bound")
    return encoded


@dataclass(frozen=True)
class RoleMonotonicityActionSpecification:
    name: str
    method: str
    url: str = field(repr=False)
    body_json: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.url)
            origin = _canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
            _validated_url(
                self.url,
                target_origin=origin,
                field_name=f"role action {self.name} url",
            )
            body = self.body
        except (TypeError, ValueError) as exc:
            raise ValueError("role action specification is invalid") from exc
        if (
            self.name not in _ACTION_NAMES
            or self.method != _METHODS[self.name]
            or (self.name in _GET_ACTIONS and self.body_json is not None)
            or (
                self.name not in _GET_ACTIONS
                and (
                    not isinstance(body, Mapping)
                    or self.body_json
                    != _canonical_json(
                        body,
                        field_name=f"role action {self.name} body",
                    )
                )
            )
        ):
            raise ValueError("role action specification is invalid")

    @classmethod
    def from_mapping(
        cls,
        name: str,
        value: Mapping[str, Any],
        *,
        target_origin: str,
    ) -> "RoleMonotonicityActionSpecification":
        if name not in _ACTION_NAMES or not isinstance(value, Mapping):
            raise ValueError("role action specification is invalid")
        expected_fields = {"url"} if name in _GET_ACTIONS else {"url", "body"}
        if set(value) != expected_fields:
            raise ValueError(f"role action {name} fields are invalid")
        body_json = None
        if name not in _GET_ACTIONS:
            if not isinstance(value.get("body"), Mapping):
                raise ValueError(f"role action {name} body must be an object")
            body_json = _canonical_json(
                value["body"],
                field_name=f"role action {name} body",
            )
        return cls(
            name=name,
            method=_METHODS[name],
            url=_validated_url(
                value.get("url"),
                target_origin=target_origin,
                field_name=f"role action {name} url",
            ),
            body_json=body_json,
        )

    @property
    def body(self) -> Any:
        return json.loads(self.body_json) if self.body_json is not None else None

    def private_payload(self) -> Dict[str, Any]:
        output = {"url": self.url}
        if self.body_json is not None:
            output["body"] = self.body
        return output


@dataclass(frozen=True)
class RoleMonotonicityOneClickSpecification:
    specification_id: str
    run_id: str = field(repr=False)
    tenant_id: str = field(repr=False)
    higher_role_ref: str
    lower_role_ref: str
    higher_session_id: str = field(repr=False)
    active_lower_session_id: str = field(repr=False)
    revoked_lower_session_id: str = field(repr=False)
    active_membership_generation: int
    revoked_membership_generation: int
    actions: Tuple[RoleMonotonicityActionSpecification, ...] = field(
        repr=False,
    )
    membership_pointers: Tuple[Tuple[str, str], ...]
    effect_pointers: Tuple[Tuple[str, str], ...]

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        target_origin: str,
    ) -> "RoleMonotonicityOneClickSpecification":
        required_fields = {
            "schema_version",
            "run_id",
            "tenant_id",
            "higher_role_ref",
            "lower_role_ref",
            "higher_session_id",
            "active_lower_session_id",
            "revoked_lower_session_id",
            "active_membership_generation",
            "revoked_membership_generation",
            "actions",
            "membership_pointers",
            "effect_pointers",
        }
        if not isinstance(value, Mapping) or set(value) != required_fields:
            raise ValueError("role one-click specification fields are invalid")
        if value.get("schema_version") != 1:
            raise ValueError("role one-click specification version is invalid")
        origin = _canonical_origin(target_origin)
        role_refs = (value.get("higher_role_ref"), value.get("lower_role_ref"))
        if (
            any(not _typed_ref(item, "experiment_role") for item in role_refs)
            or role_refs[0] == role_refs[1]
        ):
            raise ValueError("role one-click authority references are invalid")
        sessions = tuple(
            _bounded_string(value.get(key), field_name=key)
            for key in (
                "higher_session_id",
                "active_lower_session_id",
                "revoked_lower_session_id",
            )
        )
        if len(set(sessions)) != 3:
            raise ValueError("role one-click sessions must be distinct")
        active_generation = value.get("active_membership_generation")
        revoked_generation = value.get("revoked_membership_generation")
        if (
            isinstance(active_generation, bool)
            or not isinstance(active_generation, int)
            or active_generation < 0
            or isinstance(revoked_generation, bool)
            or not isinstance(revoked_generation, int)
            or revoked_generation != active_generation + 1
        ):
            raise ValueError("role one-click membership generations are stale")
        action_values = value.get("actions")
        if not isinstance(action_values, Mapping) or set(action_values) != set(
            _ACTION_NAMES
        ):
            raise ValueError("role one-click action set is invalid")
        actions = tuple(
            RoleMonotonicityActionSpecification.from_mapping(
                name,
                action_values[name],
                target_origin=origin,
            )
            for name in _ACTION_NAMES
        )
        by_name = {item.name: item for item in actions}
        probe_refs = {
            experiment_endpoint_ref(_METHODS[name], by_name[name].url)
            for name in (
                "higher_baseline",
                "active_lower_probe",
                "revoked_lower_probe",
            )
        }
        witness_refs = {
            experiment_endpoint_ref(_METHODS[name], by_name[name].url)
            for name in (
                "active_effect_witness",
                "revoked_effect_witness",
            )
        }
        if len(probe_refs) != 1 or len(witness_refs) != 1 or probe_refs == witness_refs:
            raise ValueError("role one-click probe equivalence is invalid")

        pointer_shapes = {
            "membership_pointers": {
                "tenant",
                "subject",
                "role",
                "state",
                "generation",
            },
            "effect_pointers": {
                "probe_authorized",
                "probe_effect",
                "witness_effect",
            },
        }
        normalized_pointers: Dict[str, Tuple[Tuple[str, str], ...]] = {}
        for field_name, expected in pointer_shapes.items():
            raw = value.get(field_name)
            if not isinstance(raw, Mapping) or set(raw) != expected:
                raise ValueError(f"role one-click {field_name} are invalid")
            pairs = []
            for key in sorted(expected):
                pointer = raw.get(key)
                if (
                    not isinstance(pointer, str)
                    or not pointer
                    or len(pointer) > 256
                    or any(ord(character) < 32 for character in pointer)
                ):
                    raise ValueError(f"role one-click {field_name} are invalid")
                pairs.append((key, pointer))
            normalized_pointers[field_name] = tuple(pairs)

        private_payload = {
            "schema_version": 1,
            "run_id": _bounded_string(value.get("run_id"), field_name="run_id"),
            "tenant_id": _bounded_string(
                value.get("tenant_id"),
                field_name="tenant_id",
            ),
            "higher_role_ref": role_refs[0],
            "lower_role_ref": role_refs[1],
            "higher_session_id": sessions[0],
            "active_lower_session_id": sessions[1],
            "revoked_lower_session_id": sessions[2],
            "active_membership_generation": active_generation,
            "revoked_membership_generation": revoked_generation,
            "actions": {item.name: item.private_payload() for item in actions},
            "membership_pointers": dict(normalized_pointers["membership_pointers"]),
            "effect_pointers": dict(normalized_pointers["effect_pointers"]),
        }
        _canonical_json(private_payload, field_name="role one-click specification")
        return cls(
            specification_id=stable_hash(
                "role_monotonicity_one_click_specification",
                private_payload,
            ),
            run_id=private_payload["run_id"],
            tenant_id=private_payload["tenant_id"],
            higher_role_ref=role_refs[0],
            lower_role_ref=role_refs[1],
            higher_session_id=sessions[0],
            active_lower_session_id=sessions[1],
            revoked_lower_session_id=sessions[2],
            active_membership_generation=active_generation,
            revoked_membership_generation=revoked_generation,
            actions=actions,
            membership_pointers=normalized_pointers["membership_pointers"],
            effect_pointers=normalized_pointers["effect_pointers"],
        )

    def private_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "higher_role_ref": self.higher_role_ref,
            "lower_role_ref": self.lower_role_ref,
            "higher_session_id": self.higher_session_id,
            "active_lower_session_id": self.active_lower_session_id,
            "revoked_lower_session_id": self.revoked_lower_session_id,
            "active_membership_generation": self.active_membership_generation,
            "revoked_membership_generation": self.revoked_membership_generation,
            "actions": {item.name: item.private_payload() for item in self.actions},
            "membership_pointers": dict(self.membership_pointers),
            "effect_pointers": dict(self.effect_pointers),
        }

    def __post_init__(self) -> None:
        if (
            not isinstance(self.actions, tuple)
            or len(self.actions) != len(_ACTION_NAMES)
            or any(
                not isinstance(item, RoleMonotonicityActionSpecification)
                for item in self.actions
            )
            or tuple(item.name for item in self.actions) != _ACTION_NAMES
        ):
            raise ValueError("role one-click specification is invalid")
        try:
            sessions = (
                _bounded_string(
                    self.higher_session_id,
                    field_name="higher_session_id",
                ),
                _bounded_string(
                    self.active_lower_session_id,
                    field_name="active_lower_session_id",
                ),
                _bounded_string(
                    self.revoked_lower_session_id,
                    field_name="revoked_lower_session_id",
                ),
            )
            _bounded_string(self.run_id, field_name="run_id")
            _bounded_string(self.tenant_id, field_name="tenant_id")
            membership = dict(self.membership_pointers)
            effects = dict(self.effect_pointers)
            origins = {
                _canonical_origin(
                    f"{urlsplit(item.url).scheme}://{urlsplit(item.url).netloc}"
                )
                for item in self.actions
            }
            probe_refs = {
                experiment_endpoint_ref(item.method, item.url)
                for item in self.actions
                if item.name
                in {
                    "higher_baseline",
                    "active_lower_probe",
                    "revoked_lower_probe",
                }
            }
            witness_refs = {
                experiment_endpoint_ref(item.method, item.url)
                for item in self.actions
                if item.name in {"active_effect_witness", "revoked_effect_witness"}
            }
            payload = self.private_payload()
            _canonical_json(
                payload,
                field_name="role one-click specification",
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("role one-click specification is invalid") from exc
        pointers = (*membership.values(), *effects.values())
        if (
            not _typed_ref(
                self.specification_id,
                "role_monotonicity_one_click_specification",
            )
            or not _typed_ref(self.higher_role_ref, "experiment_role")
            or not _typed_ref(self.lower_role_ref, "experiment_role")
            or self.higher_role_ref == self.lower_role_ref
            or len(set(sessions)) != 3
            or isinstance(self.active_membership_generation, bool)
            or not isinstance(self.active_membership_generation, int)
            or self.active_membership_generation < 0
            or isinstance(self.revoked_membership_generation, bool)
            or not isinstance(self.revoked_membership_generation, int)
            or self.revoked_membership_generation
            != self.active_membership_generation + 1
            or len(origins) != 1
            or len(probe_refs) != 1
            or len(witness_refs) != 1
            or probe_refs == witness_refs
            or len(self.membership_pointers) != 5
            or set(membership) != {"tenant", "subject", "role", "state", "generation"}
            or len(self.effect_pointers) != 3
            or set(effects) != {"probe_authorized", "probe_effect", "witness_effect"}
            or any(
                not isinstance(pointer, str)
                or not pointer
                or len(pointer) > 256
                or any(ord(character) < 32 for character in pointer)
                for pointer in pointers
            )
            or self.specification_id
            != stable_hash(
                "role_monotonicity_one_click_specification",
                payload,
            )
        ):
            raise ValueError("role one-click specification is invalid")

    def action(self, name: str) -> RoleMonotonicityActionSpecification:
        for action in self.actions:
            if action.name == name:
                return action
        raise KeyError(name)


@dataclass(frozen=True)
class RoleMonotonicityOneClickConfig:
    enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("role one-click enabled must be boolean")

    @classmethod
    def from_environment(cls) -> "RoleMonotonicityOneClickConfig":
        return cls(
            enabled=(
                str(os.environ.get(ROLE_MONOTONICITY_ONE_CLICK_ENV, "")).strip().lower()
                in _TRUE
            )
        )


@dataclass(frozen=True)
class _PreparedRoleMonotonicityRun:
    coordinator: RoleMonotonicityExperimentAdmission
    runtime: RoleMonotonicityRuntimeContext = field(repr=False, compare=False)
    authority_validator: RoleRuntimeAuthorityValidator = field(
        repr=False,
        compare=False,
    )


def _experiment_action(
    *,
    ordinal: int,
    phase: ExperimentPhase,
    operation_id: str,
    action_spec: RoleMonotonicityActionSpecification,
    world_binding_id: str,
    action_class: ExperimentActionClass,
    mutation: MutationExpectation,
    evidence_refs: Tuple[str, ...],
) -> ExperimentAction:
    return ExperimentAction.build(
        ordinal=ordinal,
        phase=phase,
        operation_id=operation_id,
        world_binding_id=world_binding_id,
        action_class=action_class,
        endpoint_ref=experiment_endpoint_ref(action_spec.method, action_spec.url),
        mutation=mutation,
        evidence_refs=evidence_refs,
    )


def _candidate(
    action: ExperimentAction,
    action_spec: RoleMonotonicityActionSpecification,
    *,
    actor_persona_id: str,
    target_owner_persona_id: str,
    expected_side_effect: str,
) -> CandidateAction:
    return CandidateAction(
        method=action_spec.method,
        url=action_spec.url,
        body=copy.deepcopy(action_spec.body),
        hint=action.action_class.value,
        actor_persona_id=actor_persona_id,
        target_owner_persona_id=target_owner_persona_id,
        target_is_researcher_owned=True,
        expected_side_effect=expected_side_effect,
        proof_goal=action.operation_id,
    )


def _prepare_role_run(
    *,
    specification: RoleMonotonicityOneClickSpecification,
    goal: SecurityWitnessGoal,
    target_origin: str,
    authorization: AuthorizationEnvelope,
    higher_persona_id: str,
    lower_persona_id: str,
) -> _PreparedRoleMonotonicityRun:
    if goal.security_property is not SecurityProperty.AUTHORITY_MONOTONICITY:
        raise ValueError("role one-click payout goal is not role monotonicity")
    requirement = WorldRequirement(
        ProofTopology.OWNED_ROLE_DIFFERENTIAL,
        2,
        required_role_worlds=2,
        required_workflows=(ROLE_MONOTONICITY_WORKFLOW,),
    )
    higher_world = ExperimentWorldBinding.build(
        slot="high_role",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", higher_persona_id),
        persona_ref=experiment_persona_ref(higher_persona_id),
        ownership_ref=experiment_ownership_ref(
            authorization,
            higher_persona_id,
        ),
        role_ref=specification.higher_role_ref,
    )
    lower_world = ExperimentWorldBinding.build(
        slot="low_role",
        kind=ExperimentWorldKind.OWNED_ACCOUNT,
        world_ref=stable_hash("world", lower_persona_id),
        persona_ref=experiment_persona_ref(lower_persona_id),
        ownership_ref=experiment_ownership_ref(
            authorization,
            lower_persona_id,
        ),
        role_ref=specification.lower_role_ref,
    )
    manifest = ExperimentWorldManifest.build(
        requirement=requirement,
        bindings=(higher_world, lower_world),
    )
    lattice = RoleAuthorityLattice.build(
        world_manifest=manifest,
        tenant_ref=stable_hash("owned_tenant", specification.tenant_id),
        tenant_ownership_ref=role_tenant_ownership_ref(
            authorization,
            specification.tenant_id,
        ),
    )
    membership_ref = owned_membership_ref(lattice)
    fixture_evidence = (
        lattice.lattice_id,
        lattice.tenant_ownership_ref,
        membership_ref,
    )
    setup = _experiment_action(
        ordinal=0,
        phase=ExperimentPhase.SETUP,
        operation_id="provision_owned_membership",
        action_spec=specification.action("setup"),
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.PRIVILEGE_MUTATION,
        mutation=MutationExpectation.PRIVILEGE_REVERSIBLE,
        evidence_refs=fixture_evidence,
    )
    revocation = _experiment_action(
        ordinal=4,
        phase=ExperimentPhase.CLEANUP,
        operation_id="revoke_owned_membership",
        action_spec=specification.action("revocation"),
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.PRIVILEGE_MUTATION,
        mutation=MutationExpectation.CLEANUP,
        evidence_refs=fixture_evidence,
    )
    revocation_verification = _experiment_action(
        ordinal=5,
        phase=ExperimentPhase.CLEANUP_VERIFICATION,
        operation_id="verify_owned_membership_revocation",
        action_spec=specification.action("revocation_verification"),
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        mutation=MutationExpectation.NONE,
        evidence_refs=fixture_evidence,
    )
    fixture = OwnedMembershipFixture.build(
        lattice=lattice,
        setup_action=setup,
        revocation_action=revocation,
        revocation_verification_action=revocation_verification,
    )
    proof_evidence = (
        fixture.fixture_id,
        lattice.lattice_id,
        fixture.membership_ref,
        goal.goal_id,
    )
    higher_baseline = _experiment_action(
        ordinal=1,
        phase=ExperimentPhase.CONTROL,
        operation_id="probe_selected_protected_effect",
        action_spec=specification.action("higher_baseline"),
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    active_lower_probe = _experiment_action(
        ordinal=2,
        phase=ExperimentPhase.TREATMENT,
        operation_id="probe_selected_protected_effect",
        action_spec=specification.action("active_lower_probe"),
        world_binding_id=lattice.lower.world_binding_id,
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    active_witness = _experiment_action(
        ordinal=3,
        phase=ExperimentPhase.WITNESS,
        operation_id="witness_selected_protected_effect",
        action_spec=specification.action("active_effect_witness"),
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    revoked_lower_probe = _experiment_action(
        ordinal=6,
        phase=ExperimentPhase.TREATMENT,
        operation_id="probe_selected_protected_effect",
        action_spec=specification.action("revoked_lower_probe"),
        world_binding_id=lattice.lower.world_binding_id,
        action_class=ExperimentActionClass.AUTHZ_PROBE,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    revoked_witness = _experiment_action(
        ordinal=7,
        phase=ExperimentPhase.WITNESS,
        operation_id="witness_selected_protected_effect",
        action_spec=specification.action("revoked_effect_witness"),
        world_binding_id=lattice.higher.world_binding_id,
        action_class=ExperimentActionClass.SAFE_READ,
        mutation=MutationExpectation.NONE,
        evidence_refs=proof_evidence,
    )
    proof = RoleMonotonicityExperimentCompiler().compile(
        fixture=fixture,
        goal=goal,
        target_ref=stable_hash("security_obligation_target", target_origin),
        authority_context_ref=experiment_authority_context_ref(
            authorization,
            target_origin,
            (ROLE_MONOTONICITY_WORKFLOW,),
        ),
        higher_baseline=higher_baseline,
        active_lower_probe=active_lower_probe,
        active_effect_witness=active_witness,
        revoked_lower_probe=revoked_lower_probe,
        revoked_effect_witness=revoked_witness,
    )
    runtime_actions = {
        setup.action_id: _candidate(
            setup,
            specification.action("setup"),
            actor_persona_id=higher_persona_id,
            target_owner_persona_id=lower_persona_id,
            expected_side_effect="provision_owned_membership",
        ),
        higher_baseline.action_id: _candidate(
            higher_baseline,
            specification.action("higher_baseline"),
            actor_persona_id=higher_persona_id,
            target_owner_persona_id=higher_persona_id,
            expected_side_effect="none",
        ),
        active_lower_probe.action_id: _candidate(
            active_lower_probe,
            specification.action("active_lower_probe"),
            actor_persona_id=lower_persona_id,
            target_owner_persona_id=higher_persona_id,
            expected_side_effect="none",
        ),
        active_witness.action_id: _candidate(
            active_witness,
            specification.action("active_effect_witness"),
            actor_persona_id=higher_persona_id,
            target_owner_persona_id=higher_persona_id,
            expected_side_effect="none",
        ),
        revocation.action_id: _candidate(
            revocation,
            specification.action("revocation"),
            actor_persona_id=higher_persona_id,
            target_owner_persona_id=lower_persona_id,
            expected_side_effect="cleanup_owned_test_object",
        ),
        revocation_verification.action_id: _candidate(
            revocation_verification,
            specification.action("revocation_verification"),
            actor_persona_id=higher_persona_id,
            target_owner_persona_id=lower_persona_id,
            expected_side_effect="none",
        ),
        revoked_lower_probe.action_id: _candidate(
            revoked_lower_probe,
            specification.action("revoked_lower_probe"),
            actor_persona_id=lower_persona_id,
            target_owner_persona_id=higher_persona_id,
            expected_side_effect="none",
        ),
        revoked_witness.action_id: _candidate(
            revoked_witness,
            specification.action("revoked_effect_witness"),
            actor_persona_id=higher_persona_id,
            target_owner_persona_id=higher_persona_id,
            expected_side_effect="none",
        ),
    }
    membership = dict(specification.membership_pointers)
    effects = dict(specification.effect_pointers)
    membership_binding = RoleMembershipObservationBinding.build(
        proof=proof,
        tenant_pointer=membership["tenant"],
        subject_pointer=membership["subject"],
        role_pointer=membership["role"],
        state_pointer=membership["state"],
        generation_pointer=membership["generation"],
    )
    effect_binding = RoleProtectedEffectObservationBinding.build(
        proof=proof,
        probe_authorized_pointer=effects["probe_authorized"],
        probe_effect_pointer=effects["probe_effect"],
        witness_effect_pointer=effects["witness_effect"],
    )
    runtime = RoleMonotonicityRuntimeContext.build(
        proof=proof,
        authorization=authorization,
        run_id=specification.run_id,
        tenant_id=specification.tenant_id,
        higher_persona_id=higher_persona_id,
        lower_persona_id=lower_persona_id,
        higher_session_id=specification.higher_session_id,
        active_lower_session_id=specification.active_lower_session_id,
        revoked_lower_session_id=specification.revoked_lower_session_id,
        active_membership_generation=specification.active_membership_generation,
        revoked_membership_generation=specification.revoked_membership_generation,
        membership_observation_binding=membership_binding,
        effect_observation_binding=effect_binding,
        runtime_actions=runtime_actions,
    )
    expected_runtime_identity = {
        "proof_id": proof.proof_id,
        "run_ref": runtime.run_ref,
        "tenant_ref": runtime.tenant_ref,
        "higher_persona_id": higher_persona_id,
        "lower_persona_id": lower_persona_id,
        "higher_role_ref": specification.higher_role_ref,
        "lower_role_ref": specification.lower_role_ref,
        "higher_session_ref": runtime.higher_session_ref,
        "active_lower_session_ref": runtime.active_lower_session_ref,
        "revoked_lower_session_ref": runtime.revoked_lower_session_ref,
        "active_generation_ref": runtime.active_generation_ref,
        "revoked_generation_ref": runtime.revoked_generation_ref,
        "request_intent_refs": dict(runtime.request_intent_refs),
    }

    def authority_validator(current_proof, admission, current_runtime) -> bool:
        return (
            current_proof.proof_id == expected_runtime_identity["proof_id"]
            and admission.proof_id == current_proof.proof_id
            and current_runtime.run_ref == expected_runtime_identity["run_ref"]
            and current_runtime.tenant_ref == expected_runtime_identity["tenant_ref"]
            and current_runtime.higher_persona_id
            == expected_runtime_identity["higher_persona_id"]
            and current_runtime.lower_persona_id
            == expected_runtime_identity["lower_persona_id"]
            and current_runtime.higher_role_ref
            == expected_runtime_identity["higher_role_ref"]
            and current_runtime.lower_role_ref
            == expected_runtime_identity["lower_role_ref"]
            and current_runtime.higher_session_ref
            == expected_runtime_identity["higher_session_ref"]
            and current_runtime.active_lower_session_ref
            == expected_runtime_identity["active_lower_session_ref"]
            and current_runtime.revoked_lower_session_ref
            == expected_runtime_identity["revoked_lower_session_ref"]
            and current_runtime.active_generation_ref
            == expected_runtime_identity["active_generation_ref"]
            and current_runtime.revoked_generation_ref
            == expected_runtime_identity["revoked_generation_ref"]
            and dict(current_runtime.request_intent_refs)
            == expected_runtime_identity["request_intent_refs"]
        )

    return _PreparedRoleMonotonicityRun(
        coordinator=RoleMonotonicityExperimentAdmission(
            proof=proof,
            target_origin=target_origin,
            authorization=authorization,
        ),
        runtime=runtime,
        authority_validator=authority_validator,
    )


class RoleMonotonicityOneClickDenied(RuntimeError):
    """The selected ordinary-click role proof failed closed."""


class RoleMonotonicityOneClickInternalError(RuntimeError):
    """Role coordination failed after selection and needs operator review."""


@dataclass(frozen=True)
class RoleMonotonicityFindingCandidate:
    finding_id: str
    verdict: str
    claim_contract_id: str
    oracle_id: str
    oracle_evaluation_id: str
    active_membership_observation_ref: str
    revoked_membership_observation_ref: str
    effect_observation_refs: Tuple[str, ...]
    active_effect_witness_ref: str
    revoked_effect_witness_ref: str
    provenance_root: str
    payout_goal_plan_id: str
    payout_candidate_id: str
    payout_goal_id: str
    payout_terminal_operation_id: str
    specification_id: str
    proof_id: str
    request_binding_id: str
    effect_observation_binding_id: str
    graph_target_ref: str
    graph_digest: str
    role_receipt_id: str
    selection_ref: str
    finding_authority: bool = True

    @classmethod
    def from_completed_outcome(
        cls,
        outcome: Mapping[str, Any],
    ) -> "RoleMonotonicityFindingCandidate":
        candidate_outcome = dict(outcome)
        if candidate_outcome.get(
            "status"
        ) == "already_executed" and candidate_outcome.get("oracle_verdict") in {
            "confirmed_active_escalation",
            "confirmed_revocation_survival",
            "refuted",
        }:
            candidate_outcome["status"] = candidate_outcome["oracle_verdict"]
        redacted = redacted_role_protected_effect_execution_outcome(candidate_outcome)
        verdict = redacted["oracle_verdict"]
        if (
            verdict
            not in {
                "confirmed_active_escalation",
                "confirmed_revocation_survival",
            }
            or redacted["finding_confirmed"] is not True
            or redacted["cleanup_status"] != "verified"
            or redacted["orphaned_owned_state_possible"] is not False
        ):
            raise RoleMonotonicityOneClickDenied(
                "role_completed_outcome_is_not_finding_eligible"
            )
        candidate_payload = {
            "oracle_id": redacted["oracle_id"],
            "observation_binding_id": redacted["effect_observation_binding_id"],
            "verdict": verdict,
            "observation_refs": list(redacted["effect_observation_refs"]),
            "active_effect_witness_ref": redacted["active_effect_witness_ref"],
            "revoked_effect_witness_ref": redacted["revoked_effect_witness_ref"],
        }
        if redacted["finding_candidate_ref"] != stable_hash(
            "role_monotonicity_finding_candidate",
            candidate_payload,
        ):
            raise RoleMonotonicityOneClickDenied(
                "role_completed_candidate_identity_mismatch"
            )
        return cls(
            finding_id=redacted["finding_candidate_ref"],
            verdict=verdict,
            claim_contract_id=redacted["claim_contract_id"],
            oracle_id=redacted["oracle_id"],
            oracle_evaluation_id=redacted["oracle_evaluation_id"],
            active_membership_observation_ref=redacted[
                "active_membership_observation_ref"
            ],
            revoked_membership_observation_ref=redacted[
                "revoked_membership_observation_ref"
            ],
            effect_observation_refs=tuple(redacted["effect_observation_refs"]),
            active_effect_witness_ref=redacted["active_effect_witness_ref"],
            revoked_effect_witness_ref=redacted["revoked_effect_witness_ref"],
            provenance_root=redacted["provenance_root"],
            payout_goal_plan_id=redacted["payout_goal_plan_id"],
            payout_candidate_id=redacted["payout_candidate_id"],
            payout_goal_id=redacted["payout_goal_id"],
            payout_terminal_operation_id=redacted["payout_terminal_operation_id"],
            specification_id=redacted["specification_id"],
            proof_id=redacted["proof_id"],
            request_binding_id=redacted["request_binding_id"],
            effect_observation_binding_id=redacted["effect_observation_binding_id"],
            graph_target_ref=redacted["graph_target_ref"],
            graph_digest=redacted["graph_digest"],
            role_receipt_id=redacted["role_receipt_id"],
            selection_ref=redacted["selection_ref"],
        )

    def __post_init__(self) -> None:
        selection = {
            "payout_goal_plan_id": self.payout_goal_plan_id,
            "payout_candidate_id": self.payout_candidate_id,
            "payout_goal_id": self.payout_goal_id,
            "payout_terminal_operation_id": self.payout_terminal_operation_id,
            "specification_id": self.specification_id,
            "proof_id": self.proof_id,
            "request_binding_id": self.request_binding_id,
            "effect_observation_binding_id": self.effect_observation_binding_id,
            "graph_target_ref": self.graph_target_ref,
            "graph_digest": self.graph_digest,
            "role_receipt_id": self.role_receipt_id,
        }
        candidate = {
            "oracle_id": self.oracle_id,
            "observation_binding_id": self.effect_observation_binding_id,
            "verdict": self.verdict,
            "observation_refs": list(self.effect_observation_refs),
            "active_effect_witness_ref": self.active_effect_witness_ref,
            "revoked_effect_witness_ref": self.revoked_effect_witness_ref,
        }
        if (
            self.verdict
            not in {
                "confirmed_active_escalation",
                "confirmed_revocation_survival",
            }
            or self.finding_id
            != stable_hash("role_monotonicity_finding_candidate", candidate)
            or self.selection_ref
            != stable_hash("role_monotonicity_one_click_selection", selection)
            or not self.finding_authority
        ):
            raise ValueError("role monotonicity finding candidate is invalid")

    def to_finding(self) -> Dict[str, Any]:
        revocation = self.verdict == "confirmed_revocation_survival"
        return {
            "id": self.finding_id,
            "type": "Role and membership monotonicity failure",
            "severity": "HIGH",
            "tool": "behavioral_role_monotonicity",
            "target": self.request_binding_id,
            "message": (
                "A revoked lower-role retained session reproduced the protected "
                "effect after target-observed revocation, with an independent "
                "higher-role effect witness."
                if revocation
                else "An active lower-role retained session reproduced the protected "
                "effect established by the higher-role baseline, with an "
                "independent higher-role effect witness."
            ),
            "tags": [
                "verified",
                "business_logic",
                "role_monotonicity",
                ("revocation_survival" if revocation else "active_role_escalation"),
            ],
            "families": ["confirmed_vuln"],
            "metadata": {
                "vuln_class": "business_logic",
                "subtype": self.verdict,
                "finding_candidate_ref": self.finding_id,
                "claim_contract_id": self.claim_contract_id,
                "oracle_id": self.oracle_id,
                "oracle_evaluation_id": self.oracle_evaluation_id,
                "active_membership_observation_ref": (
                    self.active_membership_observation_ref
                ),
                "revoked_membership_observation_ref": (
                    self.revoked_membership_observation_ref
                ),
                "effect_observation_refs": list(self.effect_observation_refs),
                "active_effect_witness_ref": self.active_effect_witness_ref,
                "revoked_effect_witness_ref": self.revoked_effect_witness_ref,
                "provenance_root": self.provenance_root,
                "payout_goal_plan_id": self.payout_goal_plan_id,
                "payout_candidate_id": self.payout_candidate_id,
                "payout_goal_id": self.payout_goal_id,
                "payout_terminal_operation_id": (self.payout_terminal_operation_id),
                "specification_id": self.specification_id,
                "proof_id": self.proof_id,
                "request_binding_id": self.request_binding_id,
                "effect_observation_binding_id": (self.effect_observation_binding_id),
                "graph_target_ref": self.graph_target_ref,
                "graph_digest": self.graph_digest,
                "role_receipt_id": self.role_receipt_id,
                "selection_ref": self.selection_ref,
                "cleanup_status": "verified",
                "orphaned_owned_state_possible": False,
                "adversarial_triage_required": True,
                "promotion_authority": False,
                "submission_authority": False,
            },
        }


@dataclass(frozen=True)
class RoleMonotonicityOneClickRun:
    status: str
    payout_candidate_id: Optional[str] = None
    specification_id: Optional[str] = None
    payout_goal_plan_id: Optional[str] = None
    payout_goal_id: Optional[str] = None
    payout_terminal_operation_id: Optional[str] = None
    proof_id: Optional[str] = None
    request_binding_id: Optional[str] = None
    effect_observation_binding_id: Optional[str] = None
    graph_target_ref: Optional[str] = None
    graph_digest: Optional[str] = None
    role_receipt_id: Optional[str] = None
    selection_ref: Optional[str] = None
    disabled_gates: Tuple[str, ...] = ()
    execution: Optional[RoleProtectedEffectExecutionResult] = field(
        default=None,
        repr=False,
        compare=False,
    )
    finding: Optional[RoleMonotonicityFindingCandidate] = None
    mode: str = ROLE_MONOTONICITY_ONE_CLICK_MODE
    promotion_authority: bool = False
    finding_authority: bool = False

    def __post_init__(self) -> None:
        completed_refs = (
            self.payout_candidate_id,
            self.specification_id,
            self.payout_goal_plan_id,
            self.payout_goal_id,
            self.payout_terminal_operation_id,
            self.proof_id,
            self.request_binding_id,
            self.effect_observation_binding_id,
            self.graph_target_ref,
            self.graph_digest,
            self.role_receipt_id,
            self.selection_ref,
        )
        if (
            self.mode != ROLE_MONOTONICITY_ONE_CLICK_MODE
            or self.status
            not in {
                "no_eligible_candidate",
                "selected_execution_disabled",
                "completed",
            }
            or self.promotion_authority
            or self.finding_authority
            or (self.status == "no_eligible_candidate" and any(completed_refs))
            or (
                self.status == "selected_execution_disabled"
                and (
                    not all(completed_refs[:2])
                    or any(completed_refs[2:])
                    or not self.disabled_gates
                )
            )
            or (self.status == "completed" and not all(completed_refs))
            or (self.status == "selected_execution_disabled")
            != bool(self.disabled_gates)
            or (self.status == "completed") != (self.execution is not None)
            or (self.finding is not None)
            != (
                self.execution is not None
                and self.execution.oracle.finding_candidate_ref is not None
            )
        ):
            raise ValueError("role monotonicity one-click run is invalid")

    @property
    def selected(self) -> bool:
        return self.payout_candidate_id is not None

    @property
    def dispatched(self) -> bool:
        return self.status == "completed" and self.execution is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "status": self.status,
            "payout_candidate_id": self.payout_candidate_id,
            "specification_id": self.specification_id,
            "payout_goal_plan_id": self.payout_goal_plan_id,
            "payout_goal_id": self.payout_goal_id,
            "payout_terminal_operation_id": self.payout_terminal_operation_id,
            "proof_id": self.proof_id,
            "request_binding_id": self.request_binding_id,
            "effect_observation_binding_id": (self.effect_observation_binding_id),
            "graph_target_ref": self.graph_target_ref,
            "graph_digest": self.graph_digest,
            "role_receipt_id": self.role_receipt_id,
            "selection_ref": self.selection_ref,
            "disabled_gates": list(self.disabled_gates),
            "dispatched": self.dispatched,
            "finding_candidate_ref": (
                self.finding.finding_id if self.finding is not None else None
            ),
            "promotion_authority": False,
            "finding_authority": False,
        }

    def execution_response(self) -> Dict[str, Any]:
        if self.execution is None:
            raise RoleMonotonicityOneClickDenied("role_one_click_execution_is_missing")
        response = self.execution.execution_response()
        response.update(
            {
                "payout_goal_plan_id": self.payout_goal_plan_id,
                "payout_candidate_id": self.payout_candidate_id,
                "payout_goal_id": self.payout_goal_id,
                "payout_terminal_operation_id": (self.payout_terminal_operation_id),
                "specification_id": self.specification_id,
                "proof_id": self.proof_id,
                "request_binding_id": self.request_binding_id,
                "effect_observation_binding_id": (self.effect_observation_binding_id),
                "graph_target_ref": self.graph_target_ref,
                "graph_digest": self.graph_digest,
                "role_receipt_id": self.role_receipt_id,
                "selection_ref": self.selection_ref,
            }
        )
        response["role_monotonicity_one_click"] = self.to_dict()
        response["finding"] = (
            self.finding.to_finding() if self.finding is not None else None
        )
        return response


class RoleMonotonicityOneClickDispatcher:
    """Execute one payout-selected Family-C proof without legacy fallback."""

    def __init__(
        self,
        *,
        target_origin: str,
        higher_persona_id: str,
        lower_persona_id: str,
        specification: RoleMonotonicityOneClickSpecification,
        authorization: AuthorizationEnvelope,
        executor: PolicyExecutor,
        persona_vault: PersonaVault,
        receipt_store: BehavioralReceiptStore,
        one_click_config: Optional[RoleMonotonicityOneClickConfig] = None,
        claim_config: Optional[RoleMonotonicityExecutionClaimConfig] = None,
        lifecycle_config: Optional[RoleMembershipLifecycleConfig] = None,
        execution_config: Optional[RoleProtectedEffectExecutionConfig] = None,
    ) -> None:
        if not isinstance(specification, RoleMonotonicityOneClickSpecification):
            raise TypeError("role one-click specification is required")
        if not isinstance(authorization, AuthorizationEnvelope):
            raise TypeError("role one-click authorization is invalid")
        if not isinstance(executor, PolicyExecutor):
            raise TypeError("role one-click executor is invalid")
        if not isinstance(persona_vault, PersonaVault):
            raise TypeError("role one-click persona vault is invalid")
        if not isinstance(receipt_store, BehavioralReceiptStore):
            raise TypeError("role one-click receipt store is invalid")
        self.target_origin = _canonical_origin(target_origin)
        self.higher_persona_id = higher_persona_id
        self.lower_persona_id = lower_persona_id
        self.specification = specification
        self.authorization = authorization
        self.executor = executor
        self.persona_vault = persona_vault
        self.receipt_store = receipt_store
        self.one_click_config = (
            one_click_config or RoleMonotonicityOneClickConfig.from_environment()
        )
        self.claim_config = (
            claim_config or RoleMonotonicityExecutionClaimConfig.from_environment()
        )
        self.lifecycle_config = (
            lifecycle_config or RoleMembershipLifecycleConfig.from_environment()
        )
        self.execution_config = (
            execution_config or RoleProtectedEffectExecutionConfig.from_environment()
        )

    def _disabled_gates(self) -> Tuple[str, ...]:
        gates = (
            (ROLE_MONOTONICITY_ONE_CLICK_ENV, self.one_click_config.enabled),
            (
                ROLE_MONOTONICITY_EXECUTION_CLAIM_ENV,
                self.claim_config.enabled,
            ),
            (ROLE_MEMBERSHIP_LIFECYCLE_ENV, self.lifecycle_config.enabled),
            (
                ROLE_PROTECTED_EFFECT_EXECUTION_ENV,
                self.execution_config.enabled,
            ),
        )
        return tuple(name for name, enabled in gates if not enabled)

    async def run(
        self,
        *,
        payout_goal_plan: PayoutGoalPlan,
        graph: SecurityObligationGraph,
    ) -> RoleMonotonicityOneClickRun:
        if not isinstance(payout_goal_plan, PayoutGoalPlan):
            raise TypeError("payout_goal_plan must be a PayoutGoalPlan")
        if not isinstance(graph, SecurityObligationGraph):
            raise TypeError("graph must be a SecurityObligationGraph")
        context = payout_goal_plan.context
        expected_authorization_ref = stable_hash(
            "payout_goal_authorization",
            {
                "envelope_id": self.authorization.envelope_id,
                "attestation_signature": (self.authorization.attestation_signature),
            },
        )
        expected_role_world_refs = tuple(
            sorted(
                {
                    stable_hash("world", self.higher_persona_id),
                    stable_hash("world", self.lower_persona_id),
                }
            )
        )
        if (
            payout_goal_plan.target_ref != graph.target_ref
            or payout_goal_plan.graph_digest != graph.graph_digest
            or context.target_ref != graph.target_ref
            or graph.target_ref
            != stable_hash("security_obligation_target", self.target_origin)
            or context.selected_world_ref
            != stable_hash("world", self.higher_persona_id)
            or context.authorization_ref != expected_authorization_ref
            or context.authorization_approved is not True
            or context.origin_authorized is not True
            or context.allowed_workflows
            != tuple(sorted(set(self.authorization.allowed_workflows)))
            or context.role_world_refs != expected_role_world_refs
        ):
            raise RoleMonotonicityOneClickDenied(
                "role_one_click_payout_graph_context_mismatch"
            )
        selected = payout_goal_plan.selected
        if (
            payout_goal_plan.status != "ready"
            or selected is None
            or selected.status != "admissible"
            or selected.blockers
            or selected.backend != ROLE_MONOTONICITY_BACKEND
            or selected.goal.security_property
            is not SecurityProperty.AUTHORITY_MONOTONICITY
            or selected.world_requirement.topology
            is not ProofTopology.OWNED_ROLE_DIFFERENTIAL
        ):
            return RoleMonotonicityOneClickRun(status="no_eligible_candidate")
        if (
            ROLE_MONOTONICITY_BACKEND not in context.available_backends
            or selected.world_requirement.required_role_worlds != 2
            or selected.world_requirement.required_workflows
            != (ROLE_MONOTONICITY_WORKFLOW,)
        ):
            raise RoleMonotonicityOneClickDenied(
                "role_one_click_payout_authority_context_mismatch"
            )
        disabled_gates = self._disabled_gates()
        if disabled_gates:
            return RoleMonotonicityOneClickRun(
                status="selected_execution_disabled",
                payout_candidate_id=selected.candidate_id,
                specification_id=self.specification.specification_id,
                disabled_gates=disabled_gates,
            )
        prepared = _prepare_role_run(
            specification=self.specification,
            goal=selected.goal,
            target_origin=self.target_origin,
            authorization=self.authorization,
            higher_persona_id=self.higher_persona_id,
            lower_persona_id=self.lower_persona_id,
        )
        binding = prepared.coordinator.bind_requests(
            executor=self.executor,
            persona_vault=self.persona_vault,
            runtime=prepared.runtime,
            authority_validator=prepared.authority_validator,
        )
        try:
            execution = await prepared.coordinator.run_protected_effect_evaluation(
                request_binding=binding,
                executor=self.executor,
                persona_vault=self.persona_vault,
                runtime=prepared.runtime,
                authority_validator=prepared.authority_validator,
                claim_config=self.claim_config,
                execution_config=self.execution_config,
                receipt_store=self.receipt_store,
            )
        except RoleProtectedEffectExecutionDenied:
            raise
        except Exception as exc:
            raise RoleMonotonicityOneClickInternalError(
                "role_one_click_coordination_failed"
            ) from exc
        selection = {
            "payout_goal_plan_id": payout_goal_plan.plan_id,
            "payout_candidate_id": selected.candidate_id,
            "payout_goal_id": selected.goal.goal_id,
            "payout_terminal_operation_id": selected.goal.terminal_operation_id,
            "specification_id": self.specification.specification_id,
            "proof_id": prepared.coordinator.proof.proof_id,
            "request_binding_id": binding.binding_id,
            "effect_observation_binding_id": (
                binding.effect_observation_binding.binding_id
            ),
            "graph_target_ref": graph.target_ref,
            "graph_digest": graph.graph_digest,
            "role_receipt_id": execution.receipt_id,
        }
        selection_ref = stable_hash(
            "role_monotonicity_one_click_selection",
            selection,
        )
        outcome = execution.execution_response()
        outcome.update({**selection, "selection_ref": selection_ref})
        finding = (
            RoleMonotonicityFindingCandidate.from_completed_outcome(outcome)
            if execution.oracle.finding_candidate_ref is not None
            else None
        )
        return RoleMonotonicityOneClickRun(
            status="completed",
            payout_candidate_id=selected.candidate_id,
            specification_id=self.specification.specification_id,
            payout_goal_plan_id=payout_goal_plan.plan_id,
            payout_goal_id=selected.goal.goal_id,
            payout_terminal_operation_id=selected.goal.terminal_operation_id,
            proof_id=prepared.coordinator.proof.proof_id,
            request_binding_id=binding.binding_id,
            effect_observation_binding_id=(
                binding.effect_observation_binding.binding_id
            ),
            graph_target_ref=graph.target_ref,
            graph_digest=graph.graph_digest,
            role_receipt_id=execution.receipt_id,
            selection_ref=selection_ref,
            execution=execution,
            finding=finding,
        )


__all__ = [
    "ROLE_MONOTONICITY_BACKEND",
    "ROLE_MONOTONICITY_ONE_CLICK_ENV",
    "ROLE_MONOTONICITY_ONE_CLICK_MODE",
    "RoleMonotonicityFindingCandidate",
    "RoleMonotonicityOneClickConfig",
    "RoleMonotonicityOneClickDenied",
    "RoleMonotonicityOneClickDispatcher",
    "RoleMonotonicityOneClickInternalError",
    "RoleMonotonicityOneClickRun",
    "RoleMonotonicityOneClickSpecification",
]
