"""Policy-constrained execution of one authorization counterexample proposal.

This is Gate C, not a second replay engine. It rehydrates a redacted Gate B
proposal only after validating it against its original captures, then delegates
the three-leg proof oracle to :mod:`core.wraith.bola_replay`. Every leg crosses
the existing ``PolicyExecutor`` seam and is recorded by the existing conduct
provenance sink.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from core.cortex.execution_policy import DENIED_STATUS, CandidateAction, PolicyExecutor
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.vault import ResearchPersona
from core.safety.action_classifier import CROSS_OBJECT_READ as POLICY_CROSS_OBJECT_READ
from core.safety.action_classifier import SAFE_READ
from core.safety.proof_mode import ProofMode
from core.wraith import bola_replay

from .normalize import stable_hash
from .proposals import (
    CROSS_OBJECT_READ,
    AuthorizationExperimentProposal,
    ProposalLimits,
    _extract_occurrences,
    compile_authorization_proposals,
)

CONTROLLED_WORKFLOW = "behavioral_object_authorization"
AUTHORITATIVE_ENGINE = "core.wraith.bola_replay"
_EXPECTED_LEGS = ("peer_baseline", "source_baseline", "counterfactual")


class ControlledExecutionDenied(RuntimeError):
    """Raised before transport when a Gate C invariant is not satisfied."""


class _ControlledExecutionAbort(RuntimeError):
    """Abort the experiment after a baseline or sequencing failure."""


class BoundedResponseText(str):
    """String-compatible transport body carrying a non-semantic truncation bit."""

    body_truncated: bool

    def __new__(cls, value: str, *, body_truncated: bool = False):
        instance = super().__new__(cls, value)
        instance.body_truncated = bool(body_truncated)
        return instance


@dataclass(frozen=True)
class ControlledExecutionResult:
    proposal_id: str
    legacy_verdict: bola_replay.OpVerdict
    requests_attempted: int
    requests_sent: int
    policy_denials: int
    provenance_root: str
    restraint: Dict[str, Any]
    provenance: Dict[str, Any]
    independent_witness_attempted: bool = False
    independent_witness_sent: bool = False
    independent_witness_valid: bool = False
    status: str = "completed"
    authoritative_engine: str = AUTHORITATIVE_ENGINE

    @property
    def finding(self) -> Any:
        """The legacy BOLA finding, if the established oracle confirmed one."""
        return self.legacy_verdict.finding

    def to_dict(self) -> Dict[str, Any]:
        """Return a redacted scheduler summary; semantic evidence stays on finding."""
        return {
            "proposal_id": self.proposal_id,
            "status": self.status,
            "authoritative_engine": self.authoritative_engine,
            "legacy_verdict": self.legacy_verdict.verdict,
            "legacy_detail": self.legacy_verdict.detail,
            "finding_confirmed": self.finding is not None,
            "requests_attempted": self.requests_attempted,
            "requests_sent": self.requests_sent,
            "policy_denials": self.policy_denials,
            "independent_witness_attempted": self.independent_witness_attempted,
            "independent_witness_sent": self.independent_witness_sent,
            "independent_witness_valid": self.independent_witness_valid,
            "provenance_root": self.provenance_root,
            "restraint": dict(self.restraint),
            "provenance": dict(self.provenance),
        }


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ControlledExecutionDenied("target_origin_must_be_absolute_http_url")
    return f"{parsed.scheme}://{parsed.netloc}"


def _validate_envelope(envelope: AuthorizationEnvelope, target_origin: str) -> None:
    signature = envelope.attestation_signature
    if not signature:
        raise ControlledExecutionDenied("authorization_envelope_is_unsigned")
    copy_for_verification = copy.deepcopy(envelope)
    expected = copy_for_verification.sign()
    if not hmac.compare_digest(signature, expected):
        raise ControlledExecutionDenied("authorization_envelope_signature_mismatch")
    try:
        envelope.authorize_action(
            target_origin=target_origin,
            workflow=CONTROLLED_WORKFLOW,
        )
    except Exception as exc:
        raise ControlledExecutionDenied("authorization_envelope_denied_execution") from exc


def _validate_capture_origins(
    records: Sequence[Mapping[str, Any]], target_origin: str
) -> None:
    for record in records:
        url = str(record.get("url") or "")
        parsed = urlsplit(url)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme not in {"http", "https"}:
                raise ControlledExecutionDenied("capture_contains_non_http_url")
            if f"{parsed.scheme}://{parsed.netloc}" != target_origin:
                raise ControlledExecutionDenied("capture_origin_mismatch")


def _validate_personas(source: ResearchPersona, peer: ResearchPersona) -> None:
    if not source.persona_id or not peer.persona_id:
        raise ControlledExecutionDenied("persona_id_is_required")
    if source.persona_id == peer.persona_id:
        raise ControlledExecutionDenied("two_distinct_owned_personas_are_required")
    if not source.email or not peer.email:
        raise ControlledExecutionDenied("owned_personas_require_accountable_email_identity")


def validate_controlled_capture_context(
    *,
    target_origin: str,
    authorization: AuthorizationEnvelope,
    source_persona: ResearchPersona,
    peer_persona: ResearchPersona,
) -> str:
    """Validate every pre-capture identity and authorization invariant.

    This deliberately excludes transport and capture data so a URL orchestrator
    can fail closed before navigating either authenticated persona window.
    """
    normalized_origin = _origin(target_origin)
    _validate_personas(source_persona, peer_persona)
    _validate_envelope(authorization, normalized_origin)
    return normalized_origin


def _validated_proposal(
    proposal: AuthorizationExperimentProposal,
    source_records: Sequence[Mapping[str, Any]],
    peer_records: Sequence[Mapping[str, Any]],
    source: ResearchPersona,
    peer: ResearchPersona,
) -> AuthorizationExperimentProposal:
    if proposal.risk_class != CROSS_OBJECT_READ:
        raise ControlledExecutionDenied("only_cross_object_read_proposals_are_executable")
    if proposal.executable or not proposal.requires_policy_reclassification:
        raise ControlledExecutionDenied("proposal_contract_is_not_gate_b_compatible")
    if tuple(leg.name for leg in proposal.legs) != _EXPECTED_LEGS:
        raise ControlledExecutionDenied("proposal_leg_sequence_mismatch")
    if not (0 <= proposal.source_record_index < len(source_records)):
        raise ControlledExecutionDenied("proposal_source_record_is_out_of_bounds")

    fresh = compile_authorization_proposals(
        source_records,
        peer_records,
        source_world=source.persona_id,
        peer_world=peer.persona_id,
    )
    matches = [item for item in fresh.proposals if item.proposal_id == proposal.proposal_id]
    if len(matches) != 1 or matches[0].to_dict() != proposal.to_dict():
        raise ControlledExecutionDenied("proposal_does_not_match_current_captures")
    return matches[0]


def _resolve_identifier_pair(
    proposal: AuthorizationExperimentProposal,
    source_records: Sequence[Mapping[str, Any]],
    peer_records: Sequence[Mapping[str, Any]],
) -> Tuple[str, str]:
    source_hashes = {item.source_value_hash for item in proposal.mutations}
    replacement_hashes = {item.replacement_value_hash for item in proposal.mutations}
    if len(source_hashes) != 1 or len(replacement_hashes) != 1:
        raise ControlledExecutionDenied("proposal_contains_multiple_identifier_pairs")
    source_hash = next(iter(source_hashes))
    replacement_hash = next(iter(replacement_hashes))

    limits = ProposalLimits()
    source_occurrences, _ = _extract_occurrences(source_records, limits)
    peer_occurrences, _ = _extract_occurrences(peer_records, limits)
    source_values = {
        item.raw_value
        for item in source_occurrences
        if item.record_index == proposal.source_record_index
        and stable_hash("observed_value", item.raw_value) == source_hash
    }
    peer_values = {
        item.raw_value
        for item in peer_occurrences
        if stable_hash("observed_value", item.raw_value) == replacement_hash
    }
    if len(source_values) != 1 or len(peer_values) != 1:
        raise ControlledExecutionDenied("proposal_identifier_pair_is_ambiguous_or_stale")
    source_value = next(iter(source_values))
    peer_value = next(iter(peer_values))
    if source_value == peer_value:
        raise ControlledExecutionDenied("counterfactual_identifier_must_differ")
    return source_value, peer_value


def _matches_operation(
    proposal: AuthorizationExperimentProposal, op: bola_replay.ObjectScopedOp
) -> bool:
    if proposal.operation_label == op.label:
        return True
    method_and_label = f"{op.method.upper()} {op.label}"
    return proposal.operation_label == method_and_label


def _resolve_legacy_operation(
    proposal: AuthorizationExperimentProposal,
    records: Sequence[Mapping[str, Any]],
    source_value: str,
    peer_value: str,
) -> bola_replay.ObjectScopedOp:
    operations = bola_replay.find_object_scoped_ops(
        [dict(record) for record in records], source_value
    )
    matches = [op for op in operations if _matches_operation(proposal, op)]
    if len(matches) != 1:
        raise ControlledExecutionDenied("legacy_bola_cannot_resolve_exact_proposed_operation")
    op = matches[0]
    _validate_proven_read_operation(op)
    baseline = bola_replay.build_request(op, source_value, source_value)
    counterfactual = bola_replay.build_request(op, peer_value, source_value)
    baseline_blob = _request_blob(baseline)
    counterfactual_blob = _request_blob(counterfactual)
    if source_value not in baseline_blob:
        raise ControlledExecutionDenied("legacy_baseline_does_not_contain_source_identifier")
    if peer_value not in counterfactual_blob or source_value in counterfactual_blob:
        raise ControlledExecutionDenied("legacy_counterfactual_did_not_apply_exact_swap")
    return op


def _validate_proven_read_operation(op: bola_replay.ObjectScopedOp) -> None:
    """Reject operations whose captured bytes do not prove read-only semantics."""
    if op.kind == "graphql":
        query = op.op_payload.get("query") if op.op_payload else None
        if not isinstance(query, str) or not query.strip():
            raise ControlledExecutionDenied("graphql_read_requires_captured_query_document")
        if re.search(r"\b(?:mutation|subscription)\b", query, re.IGNORECASE):
            raise ControlledExecutionDenied("graphql_operation_is_not_a_read")
        if not re.match(r"^\s*(?:query\b|\{)", query, re.IGNORECASE):
            raise ControlledExecutionDenied("graphql_operation_type_is_unproven")
        return
    if op.method.upper() != "GET":
        raise ControlledExecutionDenied("rest_authorization_probe_requires_get")


def _request_blob(request: bola_replay.ReplayRequest) -> str:
    return json.dumps(
        {
            "url": request.url,
            "body": request.body,
            "headers": request.headers,
        },
        sort_keys=True,
    )


def _response_body(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _candidate_material(action: CandidateAction) -> Dict[str, Any]:
    """Return the complete non-secret intent identity used by admitted execution."""

    return {
        "method": action.method,
        "url": action.url,
        "body": action.body,
        "hint": action.hint,
        "actor_persona_id": action.actor_persona_id,
        "target_owner_persona_id": action.target_owner_persona_id,
        "target_is_researcher_owned": action.target_is_researcher_owned,
        "expected_side_effect": action.expected_side_effect,
        "proof_goal": action.proof_goal,
    }


def _candidate_for_request(
    *,
    persona: str,
    owner: str,
    hint: str,
    request: bola_replay.ReplayRequest,
) -> CandidateAction:
    return CandidateAction(
        method=request.method,
        url=request.url,
        body=request.body,
        hint=hint,
        actor_persona_id=persona,
        target_owner_persona_id=owner,
        target_is_researcher_owned=True,
        expected_side_effect="none",
        proof_goal="single_controlled_authorization_counterexample",
    )


class _PolicyReplayTransport:
    """Strict legacy-oracle adapter with an optional admitted fourth witness."""

    def __init__(
        self,
        *,
        source_persona: str,
        peer_persona: str,
        source_value: str,
        peer_value: str,
        executors: Mapping[str, PolicyExecutor],
        expected_actions: Optional[Sequence[CandidateAction]] = None,
        budget_reservation_id: Optional[str] = None,
    ) -> None:
        self.source_persona = source_persona
        self.peer_persona = peer_persona
        self.source_value = source_value
        self.peer_value = peer_value
        self.executors = executors
        self.expected_actions = (
            tuple(copy.deepcopy(expected_actions))
            if expected_actions is not None
            else None
        )
        self.budget_reservation_id = budget_reservation_id
        self.attempted = 0
        self.sent = 0
        self.independent_witness_attempted = False
        self.independent_witness_sent = False
        self.independent_witness_valid = False
        self._first_request_blob: Optional[str] = None

    def _sequence(self) -> Tuple[Tuple[str, str, str, str], ...]:
        return (
            (self.peer_persona, self.peer_value, self.peer_persona, SAFE_READ),
            (self.source_persona, self.source_value, self.source_persona, SAFE_READ),
            (
                self.source_persona,
                self.peer_value,
                self.peer_persona,
                POLICY_CROSS_OBJECT_READ,
            ),
            (self.peer_persona, self.peer_value, self.peer_persona, SAFE_READ),
        )

    async def _send_index(
        self,
        persona: str,
        request: bola_replay.ReplayRequest,
        *,
        witness: bool,
    ) -> bola_replay.ReplayResponse:
        sequence = self._sequence()
        index = self.attempted
        if index >= len(sequence) or witness != (index == 3):
            raise _ControlledExecutionAbort("request_budget_exceeded")
        expected_persona, expected_value, owner, hint = sequence[index]
        self.attempted += 1
        if persona != expected_persona:
            raise _ControlledExecutionAbort("legacy_leg_sequence_changed")
        blob = _request_blob(request)
        if index == 0:
            self._first_request_blob = blob
        if witness and blob != self._first_request_blob:
            raise _ControlledExecutionAbort("independent_witness_request_changed")
        other_value = (
            self.peer_value
            if expected_value == self.source_value
            else self.source_value
        )
        if expected_value not in blob or other_value in blob:
            raise _ControlledExecutionAbort("rehydrated_leg_identifier_mismatch")

        candidate = _candidate_for_request(
            persona=persona,
            owner=owner,
            hint=hint,
            request=request,
        )
        if self.expected_actions is not None:
            if index >= len(self.expected_actions) or _candidate_material(
                candidate
            ) != _candidate_material(self.expected_actions[index]):
                raise _ControlledExecutionAbort(
                    "admitted_runtime_action_identity_changed"
                )
        if self.budget_reservation_id is not None:
            candidate = replace(
                candidate,
                budget_reservation_id=self.budget_reservation_id,
            )

        executor = self.executors[persona]
        status, body = await executor.send_action(
            candidate,
            headers=dict(request.headers),
        )
        sent_now = int(status != DENIED_STATUS)
        self.sent += sent_now
        response = bola_replay.ReplayResponse(
            status=int(status),
            body=_response_body(body),
            body_truncated=bool(getattr(body, "body_truncated", False)),
        )
        if index < 2:
            if status == DENIED_STATUS:
                raise _ControlledExecutionAbort("baseline_denied_by_policy")
            if not 200 <= int(status) < 300 or bola_replay.is_denied_response(response):
                raise _ControlledExecutionAbort("baseline_session_is_not_usable")
        if witness:
            self.independent_witness_sent = sent_now == 1
        return response

    async def send(
        self, persona: str, request: bola_replay.ReplayRequest
    ) -> bola_replay.ReplayResponse:
        return await self._send_index(persona, request, witness=False)

    async def send_independent_witness(
        self,
        persona: str,
        request: bola_replay.ReplayRequest,
        *,
        required_markers: Sequence[str] = (),
    ) -> bola_replay.ReplayResponse:
        self.independent_witness_attempted = True
        response = await self._send_index(persona, request, witness=True)
        self.independent_witness_valid = bool(
            self.independent_witness_sent
            and 200 <= response.status < 300
            and not response.body_truncated
            and not bola_replay.is_denied_response(response)
            and all(marker in response.body for marker in required_markers)
        )
        return response


@dataclass(frozen=True)
class _PreparedAuthorization:
    proposal: AuthorizationExperimentProposal
    source_value: str
    peer_value: str
    operation: bola_replay.ObjectScopedOp
    peer_operation: bola_replay.ObjectScopedOp


class ControlledAuthorizationExecutor:
    """Execute at most one validated read experiment under a shared safety budget."""

    def __init__(
        self,
        *,
        target_origin: str,
        authorization: AuthorizationEnvelope,
        source_persona: ResearchPersona,
        peer_persona: ResearchPersona,
        executors: Mapping[str, PolicyExecutor],
    ) -> None:
        self.target_origin = _origin(target_origin)
        self.authorization = authorization
        self.source_persona = source_persona
        self.peer_persona = peer_persona
        self.executors = dict(executors)
        self._lock = asyncio.Lock()
        self._consumed = False

    def _preflight(self) -> None:
        validate_controlled_capture_context(
            target_origin=self.target_origin,
            authorization=self.authorization,
            source_persona=self.source_persona,
            peer_persona=self.peer_persona,
        )
        expected = {self.source_persona.persona_id, self.peer_persona.persona_id}
        if set(self.executors) != expected:
            raise ControlledExecutionDenied("executor_persona_set_mismatch")
        source_executor = self.executors[self.source_persona.persona_id]
        peer_executor = self.executors[self.peer_persona.persona_id]
        if source_executor.policy is not peer_executor.policy:
            raise ControlledExecutionDenied("persona_executors_must_share_one_policy_budget")
        policy = source_executor.policy
        if policy.mode != ProofMode.BOUNTY_SAFE:
            raise ControlledExecutionDenied("controlled_execution_requires_bounty_safe_mode")
        if policy.scope_filter is None:
            raise ControlledExecutionDenied("controlled_execution_requires_scope_filter")
        if source_executor.provenance is None or source_executor.provenance is not peer_executor.provenance:
            raise ControlledExecutionDenied("persona_executors_must_share_one_provenance_sink")

    def validate_preflight(self) -> None:
        """Validate the authorization/policy context without consuming the executor."""
        self._preflight()

    def _prepare(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
    ) -> _PreparedAuthorization:
        _validate_capture_origins(source_records, self.target_origin)
        _validate_capture_origins(peer_records, self.target_origin)
        validated = _validated_proposal(
            proposal,
            source_records,
            peer_records,
            self.source_persona,
            self.peer_persona,
        )
        source_value, peer_value = _resolve_identifier_pair(
            validated, source_records, peer_records
        )
        operation = _resolve_legacy_operation(
            validated,
            [source_records[validated.source_record_index]],
            source_value,
            peer_value,
        )
        peer_operation = _resolve_legacy_operation(
            validated,
            peer_records,
            peer_value,
            source_value,
        )
        return _PreparedAuthorization(
            proposal=validated,
            source_value=source_value,
            peer_value=peer_value,
            operation=operation,
            peer_operation=peer_operation,
        )

    def _admitted_actions(
        self, prepared: _PreparedAuthorization
    ) -> Tuple[CandidateAction, ...]:
        peer_request = bola_replay.build_request(
            prepared.peer_operation,
            prepared.peer_value,
            prepared.peer_value,
        )
        source_request = bola_replay.build_request(
            prepared.operation,
            prepared.source_value,
            prepared.source_value,
        )
        counterfactual_request = bola_replay.build_request(
            prepared.operation,
            prepared.peer_value,
            prepared.source_value,
        )
        return (
            _candidate_for_request(
                persona=self.peer_persona.persona_id,
                owner=self.peer_persona.persona_id,
                hint=SAFE_READ,
                request=peer_request,
            ),
            _candidate_for_request(
                persona=self.source_persona.persona_id,
                owner=self.source_persona.persona_id,
                hint=SAFE_READ,
                request=source_request,
            ),
            _candidate_for_request(
                persona=self.source_persona.persona_id,
                owner=self.peer_persona.persona_id,
                hint=POLICY_CROSS_OBJECT_READ,
                request=counterfactual_request,
            ),
            _candidate_for_request(
                persona=self.peer_persona.persona_id,
                owner=self.peer_persona.persona_id,
                hint=SAFE_READ,
                request=copy.deepcopy(peer_request),
            ),
        )

    def preview_admitted_actions(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
    ) -> Tuple[CandidateAction, ...]:
        """Rehydrate the exact four-request admitted sequence without traffic."""

        self._preflight()
        return self._admitted_actions(
            self._prepare(proposal, source_records, peer_records)
        )

    async def execute(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
    ) -> ControlledExecutionResult:
        return await self._execute(
            proposal,
            source_records,
            peer_records,
            expected_actions=None,
            budget_reservation_id=None,
            require_independent_witness=False,
        )

    async def execute_admitted(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
        *,
        expected_actions: Sequence[CandidateAction],
        budget_reservation_id: str,
    ) -> ControlledExecutionResult:
        """Execute one exact four-action sequence under an R4B reservation."""

        actions = tuple(copy.deepcopy(expected_actions))
        if (
            len(actions) != 4
            or not isinstance(budget_reservation_id, str)
            or not budget_reservation_id
            or any(item.budget_reservation_id is not None for item in actions)
        ):
            raise ControlledExecutionDenied(
                "admitted_execution_authority_contract_is_invalid"
            )
        return await self._execute(
            proposal,
            source_records,
            peer_records,
            expected_actions=actions,
            budget_reservation_id=budget_reservation_id,
            require_independent_witness=True,
        )

    async def _execute(
        self,
        proposal: AuthorizationExperimentProposal,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
        *,
        expected_actions: Optional[Sequence[CandidateAction]],
        budget_reservation_id: Optional[str],
        require_independent_witness: bool,
    ) -> ControlledExecutionResult:
        async with self._lock:
            if self._consumed:
                raise ControlledExecutionDenied("controlled_executor_already_consumed")
            self._preflight()
            prepared = self._prepare(proposal, source_records, peer_records)
            if expected_actions is not None:
                generated_actions = self._admitted_actions(prepared)
                if tuple(_candidate_material(item) for item in expected_actions) != tuple(
                    _candidate_material(item) for item in generated_actions
                ):
                    raise ControlledExecutionDenied(
                        "admitted_runtime_action_identity_changed"
                    )
            self._consumed = True

            transport = _PolicyReplayTransport(
                source_persona=self.source_persona.persona_id,
                peer_persona=self.peer_persona.persona_id,
                source_value=prepared.source_value,
                peer_value=prepared.peer_value,
                executors=self.executors,
                expected_actions=expected_actions,
                budget_reservation_id=budget_reservation_id,
            )
            status = "completed"
            try:
                verdict = await bola_replay.classify_operation(
                    prepared.operation,
                    self.source_persona.persona_id,
                    self.peer_persona.persona_id,
                    prepared.source_value,
                    prepared.peer_value,
                    transport,
                    victim_op=prepared.peer_operation,
                )
            except _ControlledExecutionAbort as exc:
                status = "aborted"
                verdict = bola_replay.OpVerdict(
                    prepared.proposal.operation_label,
                    "ERROR",
                    str(exc),
                )
            except Exception as exc:
                status = "aborted"
                verdict = bola_replay.OpVerdict(
                    prepared.proposal.operation_label,
                    "ERROR",
                    f"transport_{type(exc).__name__}",
                )

            if require_independent_witness:
                if status == "completed" and transport.attempted == transport.sent == 3:
                    peer_request = bola_replay.build_request(
                        prepared.peer_operation,
                        prepared.peer_value,
                        prepared.peer_value,
                    )
                    markers = (
                        tuple(verdict.finding.leaked)
                        if verdict.finding is not None
                        else ()
                    )
                    try:
                        await transport.send_independent_witness(
                            self.peer_persona.persona_id,
                            peer_request,
                            required_markers=markers,
                        )
                    except Exception:
                        status = "aborted"
                    if not transport.independent_witness_valid:
                        status = "aborted"
                else:
                    status = "aborted"

            source_executor = self.executors[self.source_persona.persona_id]
            peer_executor = self.executors[self.peer_persona.persona_id]
            sink = source_executor.provenance
            restraint = source_executor.restraint_summary()
            restraint["policy_denials"] = (
                len(source_executor.skipped) + len(peer_executor.skipped)
            )
            restraint["stopped_after_first_proof"] = verdict.finding is not None
            restraint["stopped_after_terminal_verdict"] = True
            restraint["independent_witness_required"] = require_independent_witness
            restraint["independent_witness_valid"] = (
                transport.independent_witness_valid
            )
            return ControlledExecutionResult(
                proposal_id=prepared.proposal.proposal_id,
                legacy_verdict=verdict,
                requests_attempted=transport.attempted,
                requests_sent=transport.sent,
                policy_denials=len(source_executor.skipped) + len(peer_executor.skipped),
                provenance_root=(sink.root() if sink is not None else "") or "",
                restraint=restraint,
                provenance=(sink.summary() if sink is not None else {}),
                independent_witness_attempted=(
                    transport.independent_witness_attempted
                ),
                independent_witness_sent=transport.independent_witness_sent,
                independent_witness_valid=transport.independent_witness_valid,
                status=status,
            )
