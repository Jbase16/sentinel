from __future__ import annotations

from dataclasses import dataclass

from typing import List

from .base import Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.models import WebMission
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


@dataclass
class SqlInjectionMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.SQLI

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
        # - error-based signatures first
        # - bounded timing probes second
        # - statistical confirmation gate
        raise NotImplementedError("SqlInjectionMutator.run is not implemented")
