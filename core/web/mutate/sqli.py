from __future__ import annotations

from dataclasses import dataclass

from .base import Differ, ExecutionPolicy, MutationOutcome
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.models import WebMission
from ..context import WebContext


@dataclass
class SqlInjectionMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQLI

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
        # Agent implements:
        # - error-based signatures first
        # - bounded timing probes second
        # - statistical confirmation gate
        raise NotImplementedError("SqlInjectionMutator.attempt is not implemented")
