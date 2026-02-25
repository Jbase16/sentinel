from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Protocol, Any
from urllib.parse import urlparse, urlunparse, parse_qsl
import json
import base64

from .diff.baseline import _json_shape_hash

from .contracts.ids import RequestId, PrincipalId
from .contracts.models import BaselineSignature, DeltaVector, WebMission, HttpExchange
from .contracts.events import (
    EventEnvelope,
    EventType,
    WebMutationAttemptPayload,
    WebDeltaDetectedPayload,
)
from .contracts.enums import WebMethod, VulnerabilityClass
from .context import WebContext


class SentinelEventBus(Protocol):
    def emit(self, event: EventEnvelope) -> None: ...


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
    ) -> tuple[int, dict[str, str], bytes, int, int]: ...


class Differ(Protocol):
    def diff(self, base: BaselineSignature, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> DeltaVector: ...
    def baseline(self, status: int, headers: dict[str, str], body: bytes, ttfb_ms: int, total_ms: int) -> BaselineSignature: ...


@dataclass(frozen=True)
class BaselineHandle:
    """
    Opaque token representing a secured and retrieved baseline.
    Mutators MUST possess this token to request a mutation.
    """
    baseline_id: str
    signature: BaselineSignature
    request_id: RequestId
    principal_id: PrincipalId
    method: WebMethod
    url: str
    exchange: HttpExchange


@dataclass(frozen=True)
class MutationResult:
    """
    Returned exactly once per transport.mutate() call.
    Contains the resulting delta and full network exchange.
    """
    exchange: HttpExchange
    baseline_exchange: HttpExchange
    baseline_signature: BaselineSignature
    delta: DeltaVector
    param_spec: Any = None


class MutatingTransport:
    """
    Structural transport invariant: No payload is executed without a baseline.
    Computes delta and emits events centrally.
    """
    def __init__(self, policy: ExecutionPolicy, differ: Differ, bus: SentinelEventBus) -> None:
        self._policy = policy
        self._differ = differ
        self._bus = bus
        
        # Simple in-memory baseline registry avoiding duplicate baseline fetches
        self._baselines: Dict[str, BaselineHandle] = {}
        
    def _compute_baseline_key(self, principal_id: PrincipalId, method: WebMethod, url: str, body: Optional[bytes] = None) -> str:
        # Normalize path and parameters for shape-based equivalence
        parsed = urlparse(url)
        normalized_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        
        query_keys = sorted(list(set([k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)])))
        query_sig = ",".join(query_keys)
        
        shape_hash = ""
        if body:
            h = _json_shape_hash(body)
            if h:
                shape_hash = h
                
        return f"{principal_id}|{method.value}|{normalized_url}|{query_sig}|{shape_hash}"

    def establish_baseline(self, mission: WebMission, ctx: WebContext, method: WebMethod, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None) -> BaselineHandle:
        self._policy.assert_url_allowed(mission, url)
        
        baseline_key = self._compute_baseline_key(ctx.principal_id, method, url, body)
        if baseline_key in self._baselines:
            return self._baselines[baseline_key]
        
        # Execute network
        status, resp_headers, resp_body, ttfb_ms, total_ms = self._policy.http_request(
            mission=mission,
            ctx=ctx,
            method=method.value,
            url=url,
            headers=headers,
            body=body
        )
        
        # Mock request id generation
        request_id = RequestId(value=f"req-{ctx.bump_request_counter():08d}")
        
        body_b64 = base64.b64encode(resp_body).decode('ascii') if resp_body else None
        
        exchange = HttpExchange(
            request_id=request_id,
            url=url, # type: ignore
            method=method,
            request_headers=headers or {},
            request_body_b64=base64.b64encode(body).decode('ascii') if body else None,
            response_status=status,
            response_headers=resp_headers,
            response_body_b64=body_b64
        )
        
        sig = self._differ.baseline(status, resp_headers, resp_body, ttfb_ms, total_ms)
        
        handle = BaselineHandle(
            baseline_id=baseline_key,
            signature=sig,
            request_id=request_id,
            principal_id=ctx.principal_id,
            method=method,
            url=url,
            exchange=exchange
        )
        self._baselines[baseline_key] = handle
        return handle

    def get_registered_baseline(
        self,
        principal_id: PrincipalId,
        method: WebMethod,
        url: str,
        body: Optional[bytes] = None
    ) -> BaselineHandle:
        key = self._compute_baseline_key(principal_id, method, url, body)
        handle = self._baselines.get(key)
        if handle is None:
            raise ValueError("No baseline registered for key.")
        return handle

    def mutate(
        self,
        mission: WebMission,
        ctx: WebContext,
        handle: BaselineHandle,
        vuln_class: VulnerabilityClass,
        mutation_label: str,
        budget_index: int,
        mutated_url: str,
        mutated_method: WebMethod,
        mutated_headers: Optional[Dict[str, str]] = None,
        mutated_body: Optional[bytes] = None,
        param_spec: Any = None
    ) -> MutationResult:
        
        registered = self._baselines.get(handle.baseline_id)
        if registered is None or registered.signature != handle.signature:
            raise ValueError("Mutation requested without a registered, valid BaselineHandle.")
            
        self._policy.assert_url_allowed(mission, mutated_url)
        
        mutated_request_id = RequestId(value=f"req-{ctx.bump_request_counter():08d}")
        
        attempt_payload = WebMutationAttemptPayload(
            vuln_class=vuln_class,
            target_url=mutated_url, # type: ignore
            method=mutated_method,
            param=param_spec,
            mutation_label=mutation_label,
            baseline_request_id=handle.request_id,
            mutated_request_id=mutated_request_id,
            budget_index=budget_index
        )
        
        self._bus.emit(EventEnvelope(
            event_type=EventType.WEB_MUTATION_ATTEMPT,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=ctx.principal_id,
            request_id=mutated_request_id,
            payload=attempt_payload.model_dump(mode="json")
        ))
        
        # Execute mutation on network
        status, resp_headers, resp_body, ttfb_ms, total_ms = self._policy.http_request(
            mission=mission,
            ctx=ctx,
            method=mutated_method.value,
            url=mutated_url,
            headers=mutated_headers,
            body=mutated_body
        )
        
        delta = self._differ.diff(handle.signature, status, resp_headers, resp_body, ttfb_ms, total_ms)
        
        body_b64 = base64.b64encode(resp_body).decode('ascii') if resp_body else None
        
        # We manually structure an HttpExchange just so the orchestrator has the exact redacted sequence.
        exchange = HttpExchange(
            request_id=mutated_request_id,
            url=mutated_url, # type: ignore
            method=mutated_method,
            request_headers=mutated_headers or {},
            request_body_b64=base64.b64encode(mutated_body).decode('ascii') if mutated_body else None,
            response_status=status,
            response_headers=resp_headers,
            response_body_b64=body_b64
        )
        
        delta_payload = WebDeltaDetectedPayload(
            vuln_class=vuln_class,
            target_url=mutated_url, # type: ignore
            baseline=handle.signature.model_dump(mode="json"),
            delta=delta.model_dump(mode="json"), # type: ignore
            severity=delta.severity,
            notes=delta.notes
        )
        
        self._bus.emit(EventEnvelope(
            event_type=EventType.WEB_DELTA_DETECTED,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=ctx.principal_id,
            request_id=mutated_request_id,
            payload=delta_payload.model_dump(mode="json")
        ))
        
        return MutationResult(
            exchange=exchange,
            baseline_exchange=handle.exchange,
            baseline_signature=handle.signature,
            delta=delta,
            param_spec=param_spec
        )
