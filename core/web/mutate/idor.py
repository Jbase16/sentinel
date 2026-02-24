from __future__ import annotations

from dataclasses import dataclass

from typing import List

from .base import Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.models import WebMission
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


@dataclass
class IdorMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.IDOR

    def run(
        self,
        mission: WebMission,
        ctx: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int,
    ) -> List[MutationResult]:
        # Agent implements:
        # - identifier detection (path/query/json)
        # - alternate principal replay (requires orchestrator to provide ctxB)
        raise NotImplementedError("IdorMutator.run is not implemented")
