from __future__ import annotations

from dataclasses import dataclass

from .base import Differ, ExecutionPolicy, MutationOutcome, Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.models import ParamSpec, WebMission
from ..context import WebContext


@dataclass
class ReflectionMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.REFLECTION

    def attempt(
        self,
        mission: WebMission,
        ctx: WebContext,
        url: str,
        method: WebMethod,
        differ: Differ,
        policy: ExecutionPolicy,
        budget_index: int,
    ) -> MutationOutcome:
        # Agent implements deterministic canary injection + reflection detection.
        # Must:
        # - compute baseline
        # - perform bounded mutation
        # - compute delta
        # - never mark confirmed without EvidenceBundle later
        raise NotImplementedError("ReflectionMutator.attempt is not implemented")
