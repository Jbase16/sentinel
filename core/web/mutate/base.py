from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Optional

from ..contracts.models import ParamSpec, WebMission
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


class Mutator(Protocol):
    vuln_class: VulnerabilityClass

    def run(
        self,
        mission: WebMission,
        ctx: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int,
    ) -> List[MutationResult]: ...

