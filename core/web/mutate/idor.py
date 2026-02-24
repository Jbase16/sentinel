from __future__ import annotations

from dataclasses import dataclass

from .base import Differ, ExecutionPolicy, MutationOutcome
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.models import WebMission
from ..context import WebContext


@dataclass
class IdorMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.IDOR

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
        # - identifier detection (path/query/json)
        # - alternate principal replay (requires orchestrator to provide ctxB)
        raise NotImplementedError("IdorMutator.attempt is not implemented")
