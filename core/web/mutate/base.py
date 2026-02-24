from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Optional

from pydantic import HttpUrl

from ..contracts.models import BaselineSignature, DeltaVector, ParamSpec, WebMission
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..contracts.ids import RequestId
from ..context import WebContext


class ExecutionPolicy(Protocol):
    def assert_url_allowed(self, mission: WebMission, url: str) -> None: ...
    def http_request(
        self,
        mission: WebMission,
        ctx: WebContext,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes, int, int]:  # status, headers, body, ttfb_ms, total_ms
        ...


class Differ(Protocol):
    def baseline(self, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> BaselineSignature: ...
    def diff(self, base: BaselineSignature, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> DeltaVector: ...


@dataclass(frozen=True)
class MutationOutcome:
    vuln_class: VulnerabilityClass
    target_url: str
    method: WebMethod
    param: Optional[ParamSpec]
    baseline_request_id: Optional[RequestId]
    mutated_request_id: Optional[RequestId]
    baseline: Optional[BaselineSignature]
    delta: Optional[DeltaVector]
    confirmed: bool
    notes: list[str]


class Mutator(Protocol):
    vuln_class: VulnerabilityClass

    def attempt(
        self,
        mission: WebMission,
        ctx: WebContext,
        url: str,
        method: WebMethod,
        differ: Differ,
        policy: ExecutionPolicy,
        budget_index: int,
    ) -> MutationOutcome: ...
