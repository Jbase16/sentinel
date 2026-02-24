from __future__ import annotations

from dataclasses import dataclass

from typing import List

from .base import Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.errors import PolicyViolation
from ..contracts.models import WebMission
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


@dataclass
class SsrfMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.SSRF

    def run(
        self,
        mission: WebMission,
        ctx: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int,
    ) -> List[MutationResult]:
        if not mission.oob_allowed:
            raise PolicyViolation("SSRF mutator requires oob_allowed=true")
        raise NotImplementedError("SsrfMutator.run is not implemented")
