"""Transport-free compilation of a proven plan into a controlled runtime bundle.

Manifest v1 accepts only one observed owned create, directly bound owned reads,
and one explicit observed reversible cleanup.  It derives the fixed runtime intent
vocabulary from those contracts and never sends target traffic or grants admission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.safety.action_classifier import (
    OWNED_CREATE,
    OWNED_UPDATE_LOW_RISK,
    SAFE_READ,
)

from .admission import (
    ControlledAdmissionConfig,
    ControlledSequenceAdmission,
)
from .compiler import (
    ANALYSIS_ONLY_MODE,
    BackwardPlan,
    OperationContract,
    OperationSafety,
)
from .lineage import (
    LocatorKind,
    PlanRehydrator,
    RehydrationDenied,
    RehydrationRecipe,
    ValueLineageLedger,
)
from .normalize import stable_hash
from .receipts import BehavioralReceiptStore
from .runtime import (
    ControlledRuntimeSequenceExecutor,
    ControlledSequenceDenied,
    RuntimeStepIntent,
)

EXECUTION_MANIFEST_MODE = "behavioral_execution_manifest_v1"


def _is_hash_ref(value: Any, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    digest = value[len(prefix) + 1 :]
    return len(digest) == 64 and all(item in "0123456789abcdef" for item in digest)


class ExecutionManifestDenied(RuntimeError):
    """The evidence cannot be compiled into the controlled runtime contract."""


@dataclass(frozen=True)
class ExecutionManifestStep:
    operation_id: str
    role: str
    hint: str
    expected_side_effect: str

    def __post_init__(self) -> None:
        expected = {
            "owned_create": (OWNED_CREATE, "create_owned_test_object"),
            "owned_read": (SAFE_READ, "none"),
            "owned_cleanup": (
                OWNED_UPDATE_LOW_RISK,
                "cleanup_owned_test_object",
            ),
        }
        if self.role not in expected:
            raise ValueError("execution manifest step role is invalid")
        if (self.hint, self.expected_side_effect) != expected[self.role]:
            raise ValueError("execution manifest step intent is inconsistent")
        if not isinstance(self.operation_id, str) or not self.operation_id:
            raise ValueError("execution manifest operation_id is required")

    def to_dict(self) -> Dict[str, str]:
        return {
            "operation_id": self.operation_id,
            "role": self.role,
            "hint": self.hint,
            "expected_side_effect": self.expected_side_effect,
        }


@dataclass(frozen=True)
class ExecutionManifest:
    manifest_id: str
    plan_id: str
    recipe_id: str
    capture_digest: str
    catalog_digest: str
    world_ref: str
    sequence_id: str
    target_ref: str
    authorization_ref: str
    actor_ref: str
    policy_digest: str
    terminal_operation_id: str
    steps: Tuple[ExecutionManifestStep, ...]
    mode: str = EXECUTION_MANIFEST_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        refs = {
            "manifest_id": (self.manifest_id, "execution_manifest"),
            "plan_id": (self.plan_id, "backward_plan"),
            "recipe_id": (self.recipe_id, "rehydration_recipe"),
            "capture_digest": (self.capture_digest, "capture_set"),
            "catalog_digest": (self.catalog_digest, "operation_catalog"),
            "world_ref": (self.world_ref, "world"),
            "sequence_id": (self.sequence_id, "controlled_runtime_sequence"),
            "target_ref": (self.target_ref, "execution_manifest_target"),
            "authorization_ref": (
                self.authorization_ref,
                "execution_manifest_authorization",
            ),
            "actor_ref": (self.actor_ref, "execution_manifest_actor"),
        }
        if any(not _is_hash_ref(value, prefix) for value, prefix in refs.values()):
            raise ValueError("execution manifest contains an invalid hash reference")
        if (
            self.mode != EXECUTION_MANIFEST_MODE
            or self.executable
            or not self.policy_digest
            or not self.terminal_operation_id
            or not self.steps
            or self.steps[-1].role != "owned_cleanup"
        ):
            raise ValueError("execution manifest contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "manifest_id": self.manifest_id,
            "plan_id": self.plan_id,
            "recipe_id": self.recipe_id,
            "capture_digest": self.capture_digest,
            "catalog_digest": self.catalog_digest,
            "world_ref": self.world_ref,
            "sequence_id": self.sequence_id,
            "target_ref": self.target_ref,
            "authorization_ref": self.authorization_ref,
            "actor_ref": self.actor_ref,
            "policy_digest": self.policy_digest,
            "terminal_operation_id": self.terminal_operation_id,
            "steps": [item.to_dict() for item in self.steps],
        }


@dataclass(frozen=True)
class CompiledExecutionBundle:
    manifest: ExecutionManifest
    runtime: ControlledRuntimeSequenceExecutor = field(repr=False)
    admission: ControlledSequenceAdmission = field(repr=False)


def _expected_plan_id(plan: BackwardPlan) -> str:
    return stable_hash(
        "backward_plan",
        {
            "goal_id": plan.goal_id,
            "terminal_operation_id": plan.terminal_operation_id,
            "step_ids": plan.step_ids,
            "initial_capabilities": sorted(
                item.key for item in plan.initial_capabilities
            ),
            "catalog_digest": plan.catalog_digest,
            "policy_digest": plan.policy_digest,
        },
    )


def _allowed_analysis_blocker(value: str) -> bool:
    return (
        value == "analysis_only_no_execution_authority"
        or value.startswith("ownership_rehydration_required:")
        or value.startswith("ownership_proof_required:")
    )


class ExecutionManifestCompiler:
    """Compile one evidence-complete owned lifecycle without executing it."""

    def compile(
        self,
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        executor: PolicyExecutor,
        ledger: ValueLineageLedger,
        plan: BackwardPlan,
        recipe: RehydrationRecipe,
        admission_config: Optional[ControlledAdmissionConfig] = None,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> CompiledExecutionBundle:
        if not isinstance(plan, BackwardPlan) or not isinstance(
            recipe,
            RehydrationRecipe,
        ):
            raise TypeError("manifest compilation requires plan and recipe contracts")
        if (
            plan.mode != ANALYSIS_ONLY_MODE
            or plan.executable
            or plan.status != "planned"
            or plan.missing_capabilities
            or plan.search_exhausted
            or not plan.step_ids
            or plan.step_ids[-1] != plan.terminal_operation_id
            or len(set(plan.step_ids)) != len(plan.step_ids)
        ):
            raise ExecutionManifestDenied("manifest_plan_is_not_ready")
        if plan.plan_id != _expected_plan_id(plan):
            raise ExecutionManifestDenied("manifest_plan_identity_mismatch")
        if "analysis_only_no_execution_authority" not in plan.execution_blockers:
            raise ExecutionManifestDenied("manifest_plan_authority_blocker_is_missing")
        if any(not _allowed_analysis_blocker(item) for item in plan.execution_blockers):
            raise ExecutionManifestDenied("manifest_plan_has_unsafe_blockers")
        if (
            recipe.mode != ANALYSIS_ONLY_MODE
            or recipe.executable
            or recipe.status != "ready"
            or recipe.validation_errors
            or recipe.plan_id != plan.plan_id
            or tuple(item.operation_id for item in recipe.steps) != plan.step_ids
        ):
            raise ExecutionManifestDenied("manifest_recipe_is_not_ready")
        if "analysis_only_no_execution_authority" not in recipe.execution_blockers:
            raise ExecutionManifestDenied("manifest_recipe_authority_blocker_is_missing")
        if any(not _allowed_analysis_blocker(item) for item in recipe.execution_blockers):
            raise ExecutionManifestDenied("manifest_recipe_has_unsafe_blockers")
        if (
            plan.catalog_digest != ledger.catalog_digest
            or recipe.catalog_digest != ledger.catalog_digest
            or recipe.capture_digest != ledger.capture_digest
        ):
            raise ExecutionManifestDenied("manifest_evidence_digest_mismatch")
        if any(binding.sensitive for binding in recipe.bindings):
            raise ExecutionManifestDenied("manifest_sensitive_lineage_is_unsupported")

        operations = {item.operation_id: item for item in ledger.operations}
        rehydrator = PlanRehydrator(ledger)
        intents: Dict[str, RuntimeStepIntent] = {}
        manifest_steps: list[ExecutionManifestStep] = []
        creates: list[OperationContract] = []
        reads: list[OperationContract] = []
        for operation_id in plan.step_ids:
            operation = operations.get(operation_id)
            if operation is None or not operation.observed_success:
                raise ExecutionManifestDenied("manifest_operation_is_not_observed")
            try:
                request = rehydrator.rehydrate_step(recipe, operation_id)
            except RehydrationDenied as exc:
                raise ExecutionManifestDenied(
                    "manifest_recipe_rehydration_denied"
                ) from exc
            if (
                request.method == "POST"
                and operation.safety == OperationSafety.OWNED_REVERSIBLE_WRITE
                and not operation.requires_owned_state
                and operation.cleanup_operation_id is not None
            ):
                intent = RuntimeStepIntent(
                    operation_id,
                    OWNED_CREATE,
                    "create_owned_test_object",
                )
                role = "owned_create"
                creates.append(operation)
            elif (
                request.method == "GET"
                and operation.safety == OperationSafety.READ_ONLY
                and operation.requires_owned_state
            ):
                intent = RuntimeStepIntent(operation_id, SAFE_READ, "none")
                role = "owned_read"
                reads.append(operation)
            else:
                raise ExecutionManifestDenied("manifest_main_operation_is_unsupported")
            intents[operation_id] = intent
            manifest_steps.append(
                ExecutionManifestStep(
                    operation_id,
                    role,
                    intent.hint,
                    intent.expected_side_effect,
                )
            )

        if len(creates) != 1 or not reads:
            raise ExecutionManifestDenied("manifest_requires_one_create_and_owned_read")
        create = creates[0]
        if reads[-1].operation_id != plan.terminal_operation_id:
            raise ExecutionManifestDenied("manifest_terminal_must_be_owned_read")
        cleanup_id = create.cleanup_operation_id
        if cleanup_id is None or cleanup_id in plan.step_ids:
            raise ExecutionManifestDenied("manifest_cleanup_contract_is_invalid")
        cleanup = operations.get(cleanup_id)
        if (
            cleanup is None
            or not cleanup.observed_success
            or cleanup.safety != OperationSafety.OWNED_REVERSIBLE_WRITE
            or not cleanup.requires_owned_state
            or cleanup.cleanup_operation_id is not None
        ):
            raise ExecutionManifestDenied("manifest_cleanup_contract_is_unsupported")
        cleanup_observations = ledger.observations_for(cleanup_id, recipe.world_ref)
        if len(cleanup_observations) != 1:
            raise ExecutionManifestDenied("manifest_cleanup_capture_is_ambiguous")
        cleanup_request = ledger._rehydrate_observation(cleanup_observations[0])
        if cleanup_request.method not in {"PATCH", "PUT"}:
            raise ExecutionManifestDenied("manifest_cleanup_method_is_unsupported")
        cleanup_intent = RuntimeStepIntent(
            cleanup_id,
            OWNED_UPDATE_LOW_RISK,
            "cleanup_owned_test_object",
        )
        intents[cleanup_id] = cleanup_intent
        manifest_steps.append(
            ExecutionManifestStep(
                cleanup_id,
                "owned_cleanup",
                cleanup_intent.hint,
                cleanup_intent.expected_side_effect,
            )
        )

        for read in reads:
            owned_bindings = {
                item.binding_id: item
                for item in recipe.bindings
                if item.producer_operation_id == create.operation_id
                and item.consumer_operation_id == read.operation_id
                and item.consumer_locator.kind == LocatorKind.REQUEST_PATH
            }
            if len(owned_bindings) != 1:
                raise ExecutionManifestDenied(
                    "manifest_owned_read_lineage_is_missing_or_ambiguous"
                )

        runtime = ControlledRuntimeSequenceExecutor(
            target_origin=target_origin,
            authorization=authorization,
            actor_persona_id=actor_persona_id,
            executor=executor,
            ledger=ledger,
            recipe=recipe,
            intents=intents,
        )
        try:
            sequence_id = runtime.validate_preflight()
        except ControlledSequenceDenied as exc:
            raise ExecutionManifestDenied("manifest_runtime_preflight_denied") from exc

        policy_digest = executor.policy.digest()
        target_ref = stable_hash("execution_manifest_target", runtime.target_origin)
        authorization_ref = stable_hash(
            "execution_manifest_authorization",
            {
                "envelope_id": authorization.envelope_id,
                "attestation_signature": authorization.attestation_signature,
            },
        )
        actor_ref = stable_hash("execution_manifest_actor", actor_persona_id)
        payload = {
            "mode": EXECUTION_MANIFEST_MODE,
            "plan_id": plan.plan_id,
            "recipe_id": recipe.recipe_id,
            "capture_digest": recipe.capture_digest,
            "catalog_digest": recipe.catalog_digest,
            "world_ref": recipe.world_ref,
            "sequence_id": sequence_id,
            "target_ref": target_ref,
            "authorization_ref": authorization_ref,
            "actor_ref": actor_ref,
            "policy_digest": policy_digest,
            "terminal_operation_id": plan.terminal_operation_id,
            "steps": [item.to_dict() for item in manifest_steps],
        }
        manifest = ExecutionManifest(
            manifest_id=stable_hash("execution_manifest", payload),
            plan_id=plan.plan_id,
            recipe_id=recipe.recipe_id,
            capture_digest=recipe.capture_digest,
            catalog_digest=recipe.catalog_digest,
            world_ref=recipe.world_ref,
            sequence_id=sequence_id,
            target_ref=target_ref,
            authorization_ref=authorization_ref,
            actor_ref=actor_ref,
            policy_digest=policy_digest,
            terminal_operation_id=plan.terminal_operation_id,
            steps=tuple(manifest_steps),
        )
        admission = ControlledSequenceAdmission(
            runtime,
            config=admission_config,
            receipt_store=receipt_store,
        )
        return CompiledExecutionBundle(manifest, runtime, admission)


__all__ = [
    "EXECUTION_MANIFEST_MODE",
    "CompiledExecutionBundle",
    "ExecutionManifest",
    "ExecutionManifestCompiler",
    "ExecutionManifestDenied",
    "ExecutionManifestStep",
]
