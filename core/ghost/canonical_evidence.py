"""Canonical EvidenceLedger adapter for finalized Ghost flow captures.

Ghost remains responsible for passive capture and operator UX.  This module is
only an adapter: it redacts each exchange, binds it to the Stage-1 identity and
operation contracts, records it in the supplied canonical ledger, and projects
planner inputs from those recorded observations.  It has no finding-promotion
or execution capability.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Sequence, Tuple

from core.behavior.compiler import (
    OperationContract,
    OperationFamily,
    OperationInstance,
    OperationOutcome,
    OperationSafety,
)
from core.behavior.normalize import normalize_exchange, stable_hash
from core.behavior.semantic_catalog import TargetSemanticCatalogBuilder
from core.epistemic.ledger import (
    CanonicalSessionReadModel,
    EvidenceLedger,
    ObservationEnvelope,
)
from core.foundry.authorization import AuthorizationEnvelope
from core.foundry.identity_adapter import stable_identity_source_ref
from core.ghost.flow import FlowStep, UserFlow
from core.ghost.identity_adapter import identity_from_ghost_capture
from core.identity import CredentialFreshness


@dataclass(frozen=True)
class GhostCanonicalFlowResult:
    session_id: str
    observation_ids: Tuple[str, ...]
    planner_operations: Tuple[OperationContract, ...]
    ledger_revision: str

    def __post_init__(self) -> None:
        if (
            not self.session_id
            or self.session_id == "global_scan"
            or self.observation_ids != tuple(sorted(set(self.observation_ids)))
            or not self.ledger_revision.startswith("canonical_session_read_model:")
        ):
            raise ValueError("canonical Ghost flow result is invalid")


def _credential_commitment(step: FlowStep) -> str:
    credential_headers = {
        name: stable_identity_source_ref("credential_value", value)
        for name, value in step.headers.items()
        if name.lower()
        in {
            "authorization",
            "cookie",
            "proxy-authorization",
            "x-api-key",
            "x-csrf-token",
        }
    }
    cookies = {
        name: stable_identity_source_ref("credential_value", value)
        for name, value in step.cookies_after_step.items()
    }
    return stable_identity_source_ref(
        "ghost_credential_commitment",
        {
            "headers": credential_headers,
            "cookies": cookies,
        },
    )


def _planner_projection(
    read_model: CanonicalSessionReadModel,
    observation_ids: Iterable[str],
) -> Tuple[OperationContract, ...]:
    admitted_ids = set(observation_ids)
    grouped: Dict[str, list[ObservationEnvelope]] = {}
    for observation in read_model.observations:
        if observation.id in admitted_ids:
            grouped.setdefault(
                observation.operation_family.family_id,
                [],
            ).append(observation)

    operations = []
    for family_id in sorted(grouped):
        observations = grouped[family_id]
        family = observations[0].operation_family
        outputs = {
            capability
            for observation in observations
            if observation.operation_instance.outcome is OperationOutcome.SUCCESS
            for capability in observation.operation_instance.outputs
        }
        operations.append(
            OperationContract(
                operation_id=family.action_id,
                label=family.label,
                requires=family.requires,
                produces=tuple(sorted(outputs, key=lambda item: item.key)),
                safety=family.safety,
                observed_success=any(
                    observation.operation_instance.outcome
                    is OperationOutcome.SUCCESS
                    for observation in observations
                ),
                source_refs=tuple(
                    sorted(
                        {
                            observation.operation_instance.source_ref
                            for observation in observations
                        }
                    )
                ),
            )
        )
    return tuple(operations)


class GhostCanonicalEvidenceAdapter:
    """Record finalized Ghost flows without owning a private truth plane."""

    def __init__(self, ledger: EvidenceLedger) -> None:
        if not isinstance(ledger, EvidenceLedger):
            raise TypeError("ledger must be an EvidenceLedger")
        self.ledger = ledger

    @staticmethod
    def _catalog_operations(
        records: Sequence[Mapping[str, object]],
        *,
        flow_id: str,
    ) -> Mapping[str, OperationContract]:
        by_origin: Dict[str, list[Mapping[str, object]]] = {}
        for record in records:
            normalized = normalize_exchange(
                record,
                source_id=str(record.get("id") or "ghost-step"),
                world_id=flow_id,
            )
            by_origin.setdefault(normalized.origin, []).append(record)

        operations: Dict[str, OperationContract] = {}
        for origin in sorted(by_origin):
            catalog = TargetSemanticCatalogBuilder().build(
                tuple(by_origin[origin]),
                target_ref=stable_hash("security_obligation_target", origin),
                target_origin=origin,
                world_id=flow_id,
            )
            operations.update(
                (operation.operation_id, operation)
                for operation in catalog.planner_operations()
            )
        return operations

    def record_flow(
        self,
        flow: UserFlow,
        *,
        session_id: str,
        envelope: AuthorizationEnvelope,
    ) -> GhostCanonicalFlowResult:
        if not isinstance(flow, UserFlow) or not flow.steps:
            raise ValueError("canonical Ghost capture requires a non-empty flow")
        if not session_id or session_id == "global_scan":
            raise ValueError("canonical Ghost capture requires an explicit session")
        if not isinstance(envelope, AuthorizationEnvelope):
            raise TypeError("envelope must be an AuthorizationEnvelope")
        if not envelope.signature_is_valid():
            raise ValueError("canonical Ghost capture requires a signed envelope")
        if any(not envelope.authorizes_origin(step.url) for step in flow.steps):
            raise ValueError("Ghost flow is outside the authorization envelope")

        records = tuple(step.to_dict() for step in flow.steps)
        normalized = tuple(
            normalize_exchange(
                record,
                source_id=f"{flow.id}:{step.id}",
                world_id=flow.id,
            )
            for record, step in zip(records, flow.steps)
        )
        catalog_operations = self._catalog_operations(records, flow_id=flow.id)
        sources_by_action: Dict[str, set[str]] = {}
        for exchange in normalized:
            sources_by_action.setdefault(exchange.action_id, set()).add(
                exchange.source_id
            )

        observations = []
        for index, (step, exchange) in enumerate(
            zip(flow.steps, normalized),
            start=1,
        ):
            contract = catalog_operations.get(exchange.action_id)
            safety = (
                contract.safety
                if contract is not None
                else OperationSafety.READ_ONLY
                if exchange.method in {"GET", "HEAD", "OPTIONS"}
                else OperationSafety.UNKNOWN
            )
            label = (
                contract.label
                if contract is not None
                else f"{exchange.method} {exchange.path_template}"
            )
            requires = contract.requires if contract is not None else ()
            produces = (
                contract.produces
                if contract is not None
                and OperationOutcome.from_status(exchange.response_status)
                is OperationOutcome.SUCCESS
                else ()
            )
            family = OperationFamily.build(
                action_id=exchange.action_id,
                label=label,
                method=exchange.method,
                requires=requires,
                safety=safety,
                source_refs=sources_by_action[exchange.action_id],
            )
            instance = OperationInstance.build(
                family_id=family.family_id,
                source_ref=exchange.source_id,
                world_ref=exchange.world_id,
                state_ref=exchange.state_id,
                response_status=exchange.response_status,
                outputs=produces,
            )

            credential_ref = _credential_commitment(step)
            identity, _lease = identity_from_ghost_capture(
                envelope,
                flow,
                step,
                session_id=session_id,
                persona_id=stable_identity_source_ref(
                    "ghost_persona",
                    {"credential_ref": credential_ref},
                ),
                target_reset_epoch=0,
                world_id=flow.id,
                target_actor_id=stable_identity_source_ref(
                    "ghost_target_actor",
                    {"credential_ref": credential_ref},
                ),
                tenant_id=stable_identity_source_ref(
                    "ghost_unresolved_tenant",
                    {
                        "origin": exchange.origin,
                        "credential_ref": credential_ref,
                    },
                ),
                credential_epoch=index,
                credential_freshness=CredentialFreshness.FRESH,
                resource_id=stable_identity_source_ref(
                    "ghost_resource",
                    {"url": step.url},
                ),
                representation_id=stable_identity_source_ref(
                    "ghost_representation",
                    {
                        "content_type": exchange.response_content_type,
                        "state_ref": exchange.state_id,
                    },
                ),
            )
            raw_output = json.dumps(
                exchange.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            observations.append(
                self.ledger.record_canonical_observation(
                    tool_name="ghost_proxy",
                    tool_args=[exchange.method, exchange.path_template],
                    target=f"{exchange.origin}{exchange.path_template}",
                    raw_output=raw_output,
                    identity=identity,
                    operation_family=family,
                    operation_instance=instance,
                    timestamp_override=step.timestamp,
                )
            )

        read_model = self.ledger.session_read_model(session_id)
        observation_ids = tuple(sorted(item.id for item in observations))
        return GhostCanonicalFlowResult(
            session_id=session_id,
            observation_ids=observation_ids,
            planner_operations=_planner_projection(read_model, observation_ids),
            ledger_revision=read_model.revision,
        )


__all__ = [
    "GhostCanonicalEvidenceAdapter",
    "GhostCanonicalFlowResult",
]
