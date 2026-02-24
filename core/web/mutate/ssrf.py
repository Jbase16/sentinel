from __future__ import annotations

from dataclasses import dataclass

from .base import Differ, ExecutionPolicy, MutationOutcome
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.errors import PolicyViolation
from ..contracts.models import WebMission
from ..context import WebContext


@dataclass
class SsrfMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.SSRF

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
        if not mission.oob_allowed:
            raise PolicyViolation("SSRF mutator requires oob_allowed=true")
        raise NotImplementedError("SsrfMutator.attempt is not implemented")
