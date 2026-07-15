"""Deterministic, transport-free assembly of proven owned experiments.

The factory closes the passive handoff between lifecycle mining and execution
manifest compilation.  It inventories every bounded, directly bound owned read
that survives the existing planner, lineage, authorization, policy, and runtime
preflight contracts.  It never admits or executes a compiled sequence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Sequence, Tuple

from core.cortex.execution_policy import PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope

from .admission import ControlledAdmissionConfig
from .compiler import BackwardExploitCompiler, BackwardGoal
from .lifecycle import LifecycleContractMiner
from .lineage import PlanRehydrator
from .manifest import (
    CompiledExecutionBundle,
    ExecutionManifestCompiler,
    ExecutionManifestDenied,
)
from .normalize import stable_hash

OWNED_EXPERIMENT_FACTORY_MODE = "behavioral_owned_experiment_factory_v1"


def _is_hash_ref(value: Any, prefix: str) -> bool:
    if not isinstance(value, str) or not value.startswith(f"{prefix}:"):
        return False
    digest = value[len(prefix) + 1 :]
    return len(digest) == 64 and all(item in "0123456789abcdef" for item in digest)


class OwnedExperimentFactoryDenied(RuntimeError):
    """A global safety preflight prevented experiment inventory construction."""


@dataclass(frozen=True)
class OwnedExperimentFactoryConfig:
    """Hard bound on candidate plans compiled from one capture set."""

    max_experiments: int = 64

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_experiments, bool)
            or not isinstance(self.max_experiments, int)
            or not 1 <= self.max_experiments <= 4_096
        ):
            raise ValueError("max_experiments must be an integer between 1 and 4096")


@dataclass(frozen=True)
class OwnedExperimentFactoryDiagnostics:
    lifecycle_candidates: int
    read_candidates: int
    candidate_attempts: int
    ready_experiments: int
    duplicate_manifests: int
    rejected_worlds: int
    rejected_plans: int
    rejected_recipes: int
    rejected_manifests: int
    dropped_for_bound: int

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in vars(self).values()
        ):
            raise ValueError("factory diagnostics must be non-negative integers")
        classified_attempts = (
            self.ready_experiments
            + self.duplicate_manifests
            + self.rejected_plans
            + self.rejected_recipes
            + self.rejected_manifests
        )
        if (
            classified_attempts != self.candidate_attempts
            or self.candidate_attempts + self.dropped_for_bound != self.read_candidates
        ):
            raise ValueError("factory diagnostics are inconsistent")

    def to_dict(self) -> Dict[str, int]:
        return dict(vars(self))


@dataclass(frozen=True)
class PreparedOwnedExperiment:
    """One passive experiment descriptor plus its default-off runtime bundle."""

    experiment_id: str
    lifecycle_id: str
    terminal_operation_id: str
    bundle: CompiledExecutionBundle = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.bundle, CompiledExecutionBundle):
            raise ValueError("prepared owned experiment bundle is invalid")
        manifest = self.bundle.manifest
        expected_id = stable_hash(
            "owned_experiment",
            {
                "lifecycle_id": self.lifecycle_id,
                "terminal_operation_id": self.terminal_operation_id,
                "manifest_id": manifest.manifest_id,
            },
        )
        if (
            self.experiment_id != expected_id
            or not _is_hash_ref(self.lifecycle_id, "owned_lifecycle")
            or not self.terminal_operation_id
            or manifest.terminal_operation_id != self.terminal_operation_id
            or self.bundle.admission.config.enabled
        ):
            raise ValueError("prepared owned experiment contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "lifecycle_id": self.lifecycle_id,
            "terminal_operation_id": self.terminal_operation_id,
            "manifest": self.bundle.manifest.to_dict(),
        }


@dataclass(frozen=True)
class OwnedExperimentInventory:
    status: str
    capture_digest: str
    catalog_digest: str
    experiments: Tuple[PreparedOwnedExperiment, ...]
    diagnostics: OwnedExperimentFactoryDiagnostics
    mode: str = OWNED_EXPERIMENT_FACTORY_MODE
    executable: bool = False

    def __post_init__(self) -> None:
        expected_status = "ready" if self.experiments else "no_ready_experiments"
        manifest_ids = [item.bundle.manifest.manifest_id for item in self.experiments]
        experiment_ids = [item.experiment_id for item in self.experiments]
        if (
            self.status != expected_status
            or self.mode != OWNED_EXPERIMENT_FACTORY_MODE
            or self.executable
            or not _is_hash_ref(self.capture_digest, "capture_set")
            or not _is_hash_ref(self.catalog_digest, "operation_catalog")
            or len(manifest_ids) != len(set(manifest_ids))
            or len(experiment_ids) != len(set(experiment_ids))
            or manifest_ids != sorted(manifest_ids)
            or any(
                item.bundle.manifest.capture_digest != self.capture_digest
                or item.bundle.manifest.catalog_digest != self.catalog_digest
                for item in self.experiments
            )
            or self.diagnostics.ready_experiments != len(self.experiments)
        ):
            raise ValueError("owned experiment inventory contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": self.mode,
            "executable": self.executable,
            "status": self.status,
            "capture_digest": self.capture_digest,
            "catalog_digest": self.catalog_digest,
            "experiments": [item.to_dict() for item in self.experiments],
            "diagnostics": self.diagnostics.to_dict(),
        }


class OwnedExperimentFactory:
    """Mine and compile all bounded, admissible owned reads without executing."""

    def __init__(
        self,
        *,
        config: OwnedExperimentFactoryConfig = OwnedExperimentFactoryConfig(),
        miner: LifecycleContractMiner | None = None,
    ) -> None:
        if not isinstance(config, OwnedExperimentFactoryConfig):
            raise TypeError("config must be an OwnedExperimentFactoryConfig")
        self.config = config
        self.miner = miner or LifecycleContractMiner()

    def build(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        actor_persona_id: str,
        executor: PolicyExecutor,
    ) -> OwnedExperimentInventory:
        mined = self.miner.mine(records, world_id=actor_persona_id)
        actor_world_ref = stable_hash("world", str(actor_persona_id or "captured"))
        matching = tuple(
            candidate
            for candidate in mined.candidates
            if candidate.world_ref == actor_world_ref
        )
        rejected_worlds = len(mined.candidates) - len(matching)
        read_pairs = tuple(
            sorted(
                (
                    (
                        candidate.lifecycle_id,
                        read_operation_id,
                        read_binding_id,
                        candidate,
                    )
                    for candidate in matching
                    for read_operation_id, read_binding_id in zip(
                        candidate.read_operation_ids,
                        candidate.read_binding_ids,
                    )
                ),
                key=lambda item: item[:3],
            )
        )
        bounded_pairs = read_pairs[: self.config.max_experiments]
        dropped_for_bound = len(read_pairs) - len(bounded_pairs)

        compiler = BackwardExploitCompiler(mined.ledger.operations)
        rehydrator = PlanRehydrator(mined.ledger)
        manifest_compiler = ExecutionManifestCompiler()
        prepared_by_manifest: Dict[str, PreparedOwnedExperiment] = {}
        rejected_plans = 0
        rejected_recipes = 0
        rejected_manifests = 0
        duplicate_manifests = 0

        for (
            lifecycle_id,
            read_operation_id,
            read_binding_id,
            candidate,
        ) in bounded_pairs:
            goal_id = stable_hash(
                "owned_experiment_goal",
                {
                    "lifecycle_id": lifecycle_id,
                    "terminal_operation_id": read_operation_id,
                },
            )
            plan = compiler.compile(BackwardGoal(goal_id, read_operation_id))
            if (
                plan.status != "planned"
                or candidate.create_operation_id not in plan.step_ids
            ):
                rejected_plans += 1
                continue
            recipe = rehydrator.build_recipe(plan, world_id=actor_persona_id)
            if recipe.status != "ready" or read_binding_id not in {
                binding.binding_id for binding in recipe.bindings
            }:
                rejected_recipes += 1
                continue
            try:
                bundle = manifest_compiler.compile(
                    target_origin=target_origin,
                    authorization=authorization,
                    actor_persona_id=actor_persona_id,
                    executor=executor,
                    ledger=mined.ledger,
                    plan=plan,
                    recipe=recipe,
                    admission_config=ControlledAdmissionConfig(enabled=False),
                )
            except ExecutionManifestDenied as exc:
                if str(exc) == "manifest_runtime_preflight_denied":
                    raise OwnedExperimentFactoryDenied(
                        "factory_global_runtime_preflight_denied"
                    ) from exc
                rejected_manifests += 1
                continue

            manifest_roles = {
                (step.operation_id, step.role) for step in bundle.manifest.steps
            }
            if not {
                (candidate.create_operation_id, "owned_create"),
                (read_operation_id, "owned_read"),
                (candidate.cleanup_operation_id, "owned_cleanup"),
            }.issubset(manifest_roles):
                rejected_manifests += 1
                continue

            manifest_id = bundle.manifest.manifest_id
            if manifest_id in prepared_by_manifest:
                duplicate_manifests += 1
                continue
            experiment_id = stable_hash(
                "owned_experiment",
                {
                    "lifecycle_id": lifecycle_id,
                    "terminal_operation_id": read_operation_id,
                    "manifest_id": manifest_id,
                },
            )
            prepared_by_manifest[manifest_id] = PreparedOwnedExperiment(
                experiment_id=experiment_id,
                lifecycle_id=lifecycle_id,
                terminal_operation_id=read_operation_id,
                bundle=bundle,
            )

        experiments = tuple(
            prepared_by_manifest[key] for key in sorted(prepared_by_manifest)
        )
        diagnostics = OwnedExperimentFactoryDiagnostics(
            lifecycle_candidates=len(mined.candidates),
            read_candidates=len(read_pairs),
            candidate_attempts=len(bounded_pairs),
            ready_experiments=len(experiments),
            duplicate_manifests=duplicate_manifests,
            rejected_worlds=rejected_worlds,
            rejected_plans=rejected_plans,
            rejected_recipes=rejected_recipes,
            rejected_manifests=rejected_manifests,
            dropped_for_bound=dropped_for_bound,
        )
        return OwnedExperimentInventory(
            status="ready" if experiments else "no_ready_experiments",
            capture_digest=mined.capture_digest,
            catalog_digest=mined.catalog_digest,
            experiments=experiments,
            diagnostics=diagnostics,
        )


__all__ = [
    "OWNED_EXPERIMENT_FACTORY_MODE",
    "OwnedExperimentFactory",
    "OwnedExperimentFactoryConfig",
    "OwnedExperimentFactoryDenied",
    "OwnedExperimentFactoryDiagnostics",
    "OwnedExperimentInventory",
    "PreparedOwnedExperiment",
]
