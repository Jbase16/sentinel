"""Independent proof for an acquired cross-persona navigation.

The interaction miner can discover a link present for an owning persona but absent
for its peer.  A successful peer read of that link is useful acquisition evidence,
but it is not finding authority by itself: a 2xx response may still be a soft denial
or a generic shell.  This boundary acquires legitimate owner/reader baselines for
the established three-leg BOLA oracle and, after that oracle isolates owner-private
markers, requires one bounded JSON sibling read carrying the same marker.
"""

from __future__ import annotations

import copy
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from core.behavior.interaction_adaptive import INTERACTION_ADAPTIVE_WORKFLOW
from core.behavior.normalize import stable_hash
from core.cortex.execution_policy import CandidateAction, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import ResearchPersona
from core.safety.action_classifier import CROSS_OBJECT_READ, SAFE_READ
from core.wraith.bola import _contains
from core.wraith.bola_replay import ReplayResponse, is_denied_response

CROSS_PERSONA_PROOF_MODE = "behavioral_interaction_cross_persona_proof_v1"


class InteractionCrossPersonaProofDenied(RuntimeError):
    """Raised before finding authority when the direct proof cannot be trusted."""


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise InteractionCrossPersonaProofDenied(
            "interaction_cross_persona_proof_url_is_invalid"
        )
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _body_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _object_key(value: str) -> Tuple[str, str]:
    parts = tuple(item for item in urlsplit(value).path.split("/") if item)
    if len(parts) != 2 or any(not item for item in parts):
        raise InteractionCrossPersonaProofDenied(
            "interaction_cross_persona_proof_object_route_is_unsupported"
        )
    return parts[0].lower(), parts[1]


def _api_sibling(value: str) -> str:
    parsed = urlsplit(value)
    collection, object_id = _object_key(value)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            f"/api/{collection}/{object_id}",
            "",
            "",
        )
    )


def _validate_envelope(
    authorization: AuthorizationEnvelope,
    target_origin: str,
) -> None:
    signature = authorization.attestation_signature
    if not signature:
        raise InteractionCrossPersonaProofDenied(
            "interaction_cross_persona_proof_authorization_is_unsigned"
        )
    copy_for_verification = copy.deepcopy(authorization)
    expected = copy_for_verification.sign()
    if not hmac.compare_digest(signature, expected):
        raise InteractionCrossPersonaProofDenied(
            "interaction_cross_persona_proof_authorization_signature_mismatch"
        )
    try:
        authorization.authorize_action(
            target_origin=target_origin,
            workflow=INTERACTION_ADAPTIVE_WORKFLOW,
        )
    except Exception as exc:
        raise InteractionCrossPersonaProofDenied(
            "interaction_cross_persona_proof_authorization_denied"
        ) from exc


@dataclass(frozen=True)
class CrossPersonaBaselines:
    reader_record: Mapping[str, Any] = field(repr=False)
    owner_record: Mapping[str, Any] = field(repr=False)
    requests_attempted: int = 2
    requests_sent: int = 2


@dataclass(frozen=True)
class CrossPersonaIndependentProof:
    proof_id: str
    api_request_ref: str
    ownership_proof_ref: str
    response_status: int
    matched_marker_count: int
    requests_attempted: int
    requests_sent: int
    provenance_root: str
    budget_snapshot: Mapping[str, int]
    schema_version: int = 1
    mode: str = CROSS_PERSONA_PROOF_MODE
    status: str = "completed"
    finding_authority: bool = True
    executable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "status": self.status,
            "finding_authority": self.finding_authority,
            "executable": self.executable,
            "proof_id": self.proof_id,
            "api_request_ref": self.api_request_ref,
            "ownership_proof_ref": self.ownership_proof_ref,
            "response_status": self.response_status,
            "matched_marker_count": self.matched_marker_count,
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "provenance_root": self.provenance_root,
            "budget_snapshot": dict(self.budget_snapshot),
        }


class InteractionCrossPersonaProofBoundary:
    """Acquire honest baselines and independently corroborate a BOLA verdict."""

    def __init__(
        self,
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        owner_persona: ResearchPersona,
        reader_persona: ResearchPersona,
        executors: Mapping[str, PolicyExecutor],
        owner_url: str,
        reader_url: str,
        ownership_proof_ref: str,
    ) -> None:
        self.target_origin = _origin(target_origin)
        self.authorization = authorization
        self.owner_persona = owner_persona
        self.reader_persona = reader_persona
        self.executors = dict(executors)
        self.owner_url = owner_url
        self.reader_url = reader_url
        self.ownership_proof_ref = ownership_proof_ref
        self._validate_preflight()

    def _validate_preflight(self) -> None:
        _validate_envelope(self.authorization, self.target_origin)
        if self.owner_persona.persona_id == self.reader_persona.persona_id:
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_requires_distinct_personas"
            )
        expected = {
            self.owner_persona.persona_id,
            self.reader_persona.persona_id,
        }
        if set(self.executors) != expected:
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_executor_set_mismatch"
            )
        owner_collection, owner_id = _object_key(self.owner_url)
        reader_collection, reader_id = _object_key(self.reader_url)
        if (
            _origin(self.owner_url) != self.target_origin
            or _origin(self.reader_url) != self.target_origin
            or owner_collection != reader_collection
            or owner_id == reader_id
        ):
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_object_binding_changed"
            )
        policy = self.executors[self.reader_persona.persona_id].policy
        if policy is not self.executors[self.owner_persona.persona_id].policy:
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_policy_binding_changed"
            )
        registry = policy.ownership_registry
        if (
            registry is None
            or registry.owner_of(self.owner_url) != self.owner_persona.persona_id
        ):
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_ownership_is_unavailable"
            )

    async def _baseline(
        self,
        *,
        persona: ResearchPersona,
        url: str,
    ) -> Dict[str, Any]:
        executor = self.executors[persona.persona_id]
        before = executor.policy.budget.snapshot()["total_requests"]
        status, body = await executor.send_action(
            CandidateAction(
                method="GET",
                url=url,
                hint=SAFE_READ,
                actor_persona_id=persona.persona_id,
                target_owner_persona_id=persona.persona_id,
                target_is_researcher_owned=False,
                proof_goal="cross_persona_legitimate_baseline",
            ),
            headers={},
        )
        after = executor.policy.budget.snapshot()["total_requests"]
        text = _body_text(body)
        response = ReplayResponse(
            status=int(status),
            body=text,
            body_truncated=bool(getattr(body, "body_truncated", False)),
        )
        if (
            after - before != 1
            or response.body_truncated
            or not 200 <= response.status < 300
            or is_denied_response(response)
        ):
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_baseline_failed"
            )
        return {
            "persona_id": persona.persona_id,
            "method": "GET",
            "url": url,
            "response_status": response.status,
            "response_body": response.body,
        }

    async def acquire_baselines(self) -> CrossPersonaBaselines:
        owner_record = await self._baseline(
            persona=self.owner_persona,
            url=self.owner_url,
        )
        reader_record = await self._baseline(
            persona=self.reader_persona,
            url=self.reader_url,
        )
        return CrossPersonaBaselines(
            reader_record=reader_record,
            owner_record=owner_record,
        )

    async def confirm_independent_api(
        self,
        leaked_markers: Sequence[str],
    ) -> CrossPersonaIndependentProof:
        markers = tuple(
            item for item in leaked_markers
            if isinstance(item, str) and item
        )
        if not markers:
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_has_no_private_marker"
            )
        api_url = _api_sibling(self.owner_url)
        executor = self.executors[self.reader_persona.persona_id]
        before = executor.policy.budget.snapshot()["total_requests"]
        status, body = await executor.send_action(
            CandidateAction(
                method="GET",
                url=api_url,
                hint=CROSS_OBJECT_READ,
                actor_persona_id=self.reader_persona.persona_id,
                target_owner_persona_id=self.owner_persona.persona_id,
                target_is_researcher_owned=True,
                proof_goal="independent_cross_persona_api_confirmation",
            ),
            headers={},
        )
        budget_snapshot = executor.policy.budget.snapshot()
        sent = budget_snapshot["total_requests"] - before
        text = _body_text(body)
        response = ReplayResponse(
            status=int(status),
            body=text,
            body_truncated=bool(getattr(body, "body_truncated", False)),
        )
        matched = tuple(marker for marker in markers if _contains(text, marker))
        if (
            sent != 1
            or response.body_truncated
            or not 200 <= response.status < 300
            or is_denied_response(response)
            or not matched
        ):
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_independent_api_proof_failed"
            )
        request_ref = stable_hash(
            "interaction_cross_persona_api_request",
            {
                "method": "GET",
                "url": api_url,
                "reader_persona_id": self.reader_persona.persona_id,
                "owner_persona_id": self.owner_persona.persona_id,
            },
        )
        provenance_root = (
            executor.provenance.root()
            if executor.provenance is not None
            else None
        )
        if not isinstance(provenance_root, str) or not provenance_root:
            raise InteractionCrossPersonaProofDenied(
                "interaction_cross_persona_proof_provenance_is_unavailable"
            )
        proof_payload = {
            "api_request_ref": request_ref,
            "ownership_proof_ref": self.ownership_proof_ref,
            "response_status": response.status,
            "matched_marker_count": len(matched),
            "provenance_root": provenance_root,
        }
        return CrossPersonaIndependentProof(
            proof_id=stable_hash("interaction_cross_persona_proof", proof_payload),
            api_request_ref=request_ref,
            ownership_proof_ref=self.ownership_proof_ref,
            response_status=response.status,
            matched_marker_count=len(matched),
            requests_attempted=1,
            requests_sent=sent,
            provenance_root=proof_payload["provenance_root"],
            budget_snapshot=budget_snapshot,
        )
