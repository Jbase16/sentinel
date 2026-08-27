"""Transport-free R5D1 issued-capability and owned-fixture contracts.

Issued links, tokens, invitations, exports, and callback references are modeled as
one content-addressed capability type.  Public evidence retains only typed hashes and
logical bounds; bearer material is represented only by a digest.  The classifier uses
the fixed precedence ``revoked -> expired -> wrong binding -> already used -> valid``
so the same contract and presentation always produce the same decision.

This module performs no target I/O, reserves no budget, provisions no callback
receiver, and exposes no transport, receipt, effect-oracle, finding, or promotion
surface.  It grants no execution or finding authority and is not imported by a
production entry point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from .experiment_sdk import ExperimentWorldBinding, ExperimentWorldKind
from .normalize import stable_hash
from .payout_goals import ProofTopology


CAPABILITY_CONTRACT_MODE = "behavioral_capability_contract_v1"

_HASH_REF = re.compile(r"^[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_BINDING_ORDER = ("resource", "account", "audience", "operation")


def _hash_ref(value: object, prefix: Optional[str] = None) -> bool:
    return (
        isinstance(value, str)
        and _HASH_REF.fullmatch(value) is not None
        and (prefix is None or value.startswith(f"{prefix}:"))
    )


def _validate_owned_account_world(world: object) -> ExperimentWorldBinding:
    if not isinstance(world, ExperimentWorldBinding):
        raise TypeError("world must be an ExperimentWorldBinding")
    if (
        world.kind is not ExperimentWorldKind.OWNED_ACCOUNT
        or world.slot != "actor"
        or world.persona_ref is None
        or world.ownership_ref is None
        or world.role_ref is not None
        or world.lifecycle_ref is not None
    ):
        raise ValueError("capability contract requires one unqualified owned account")
    return world


class CapabilityRevocationState(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CapabilityOutcome(str, Enum):
    VALID = "valid"
    WRONG_BINDING = "wrong_binding"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ALREADY_USED = "already_used"


def _contract_payload(
    *,
    subject_ref: str,
    resource_ref: str,
    operation_ref: str,
    audience_ref: str,
    issuer_ref: str,
    tenant_ref: str,
    tenant_ownership_ref: str,
    source_evidence_ref: str,
    secret_digest: str,
    issued_at_index: int,
    expires_at_index: int,
    max_uses: int,
    revocation_state: CapabilityRevocationState,
    callback_ref: Optional[str],
    callback_scope_ref: Optional[str],
) -> Dict[str, Any]:
    return {
        "mode": CAPABILITY_CONTRACT_MODE,
        "subject_ref": subject_ref,
        "resource_ref": resource_ref,
        "operation_ref": operation_ref,
        "audience_ref": audience_ref,
        "issuer_ref": issuer_ref,
        "tenant_ref": tenant_ref,
        "tenant_ownership_ref": tenant_ownership_ref,
        "source_evidence_ref": source_evidence_ref,
        "secret_digest": secret_digest,
        "issued_at_index": issued_at_index,
        "expires_at_index": expires_at_index,
        "max_uses": max_uses,
        "revocation_state": revocation_state.value,
        "callback_ref": callback_ref,
        "callback_scope_ref": callback_scope_ref,
    }


@dataclass(frozen=True)
class IssuedCapabilityContract:
    capability_id: str
    subject_ref: str
    resource_ref: str
    operation_ref: str
    audience_ref: str
    issuer_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    source_evidence_ref: str
    secret_digest: str
    issued_at_index: int
    expires_at_index: int
    max_uses: int
    revocation_state: CapabilityRevocationState
    _owned_world: ExperimentWorldBinding = field(repr=False, compare=False)
    _world_tenant_ref: str = field(repr=False, compare=False)
    _world_tenant_ownership_ref: str = field(repr=False, compare=False)
    callback_ref: Optional[str] = None
    callback_scope_ref: Optional[str] = None
    _callback_world: Optional[ExperimentWorldBinding] = field(
        default=None,
        repr=False,
        compare=False,
    )
    mode: str = CAPABILITY_CONTRACT_MODE

    @classmethod
    def build(
        cls,
        *,
        world: ExperimentWorldBinding,
        world_tenant_ref: str,
        world_tenant_ownership_ref: str,
        subject_ref: str,
        resource_ref: str,
        operation_ref: str,
        audience_ref: str,
        issuer_ref: str,
        tenant_ref: str,
        tenant_ownership_ref: str,
        source_evidence_ref: str,
        secret_digest: str,
        issued_at_index: int,
        expires_at_index: int,
        max_uses: int,
        revocation_state: CapabilityRevocationState,
        callback_ref: Optional[str] = None,
        callback_scope_ref: Optional[str] = None,
        callback_world: Optional[ExperimentWorldBinding] = None,
    ) -> "IssuedCapabilityContract":
        owned_world = _validate_owned_account_world(world)
        if not isinstance(revocation_state, CapabilityRevocationState):
            raise TypeError("revocation_state must be a CapabilityRevocationState")
        if (
            not _hash_ref(tenant_ref, "owned_tenant")
            or not _hash_ref(tenant_ownership_ref, "ownership_proof")
            or not _hash_ref(world_tenant_ref, "owned_tenant")
            or not _hash_ref(world_tenant_ownership_ref, "ownership_proof")
        ):
            raise ValueError("issued capability contract is invalid")
        if (
            tenant_ref != world_tenant_ref
            or tenant_ownership_ref != world_tenant_ownership_ref
        ):
            raise ValueError("capability tenant binding does not match the owned world")
        payload = _contract_payload(
            subject_ref=subject_ref,
            resource_ref=resource_ref,
            operation_ref=operation_ref,
            audience_ref=audience_ref,
            issuer_ref=issuer_ref,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
            source_evidence_ref=source_evidence_ref,
            secret_digest=secret_digest,
            issued_at_index=issued_at_index,
            expires_at_index=expires_at_index,
            max_uses=max_uses,
            revocation_state=revocation_state,
            callback_ref=callback_ref,
            callback_scope_ref=callback_scope_ref,
        )
        return cls(
            capability_id=stable_hash("issued_capability_contract", payload),
            subject_ref=subject_ref,
            resource_ref=resource_ref,
            operation_ref=operation_ref,
            audience_ref=audience_ref,
            issuer_ref=issuer_ref,
            tenant_ref=tenant_ref,
            tenant_ownership_ref=tenant_ownership_ref,
            source_evidence_ref=source_evidence_ref,
            secret_digest=secret_digest,
            issued_at_index=issued_at_index,
            expires_at_index=expires_at_index,
            max_uses=max_uses,
            revocation_state=revocation_state,
            callback_ref=callback_ref,
            callback_scope_ref=callback_scope_ref,
            _owned_world=owned_world,
            _world_tenant_ref=world_tenant_ref,
            _world_tenant_ownership_ref=world_tenant_ownership_ref,
            _callback_world=callback_world,
        )

    def __post_init__(self) -> None:
        owned_world = _validate_owned_account_world(self._owned_world)
        if not isinstance(self.revocation_state, CapabilityRevocationState):
            raise TypeError("revocation_state must be a CapabilityRevocationState")
        payload = _contract_payload(
            subject_ref=self.subject_ref,
            resource_ref=self.resource_ref,
            operation_ref=self.operation_ref,
            audience_ref=self.audience_ref,
            issuer_ref=self.issuer_ref,
            tenant_ref=self.tenant_ref,
            tenant_ownership_ref=self.tenant_ownership_ref,
            source_evidence_ref=self.source_evidence_ref,
            secret_digest=self.secret_digest,
            issued_at_index=self.issued_at_index,
            expires_at_index=self.expires_at_index,
            max_uses=self.max_uses,
            revocation_state=self.revocation_state,
            callback_ref=self.callback_ref,
            callback_scope_ref=self.callback_scope_ref,
        )
        public_refs = (
            self.subject_ref,
            self.resource_ref,
            self.operation_ref,
            self.audience_ref,
            self.issuer_ref,
            self.source_evidence_ref,
        )
        logical_bounds_valid = (
            type(self.issued_at_index) is int
            and self.issued_at_index >= 0
            and type(self.expires_at_index) is int
            and self.expires_at_index > self.issued_at_index
            and type(self.max_uses) is int
            and self.max_uses >= 1
        )
        callback_absent = (
            self.callback_ref is None
            and self.callback_scope_ref is None
            and self._callback_world is None
        )
        callback_present = (
            _hash_ref(self.callback_ref)
            and _hash_ref(self.callback_scope_ref)
            and isinstance(self._callback_world, ExperimentWorldBinding)
            and self._callback_world.kind is ExperimentWorldKind.CALLBACK_RECEIVER
            and self._callback_world.callback_ref == self.callback_ref
        )
        if (
            self.capability_id != stable_hash("issued_capability_contract", payload)
            or not _hash_ref(self.capability_id, "issued_capability_contract")
            or any(not _hash_ref(item) for item in public_refs)
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or not _hash_ref(self.secret_digest, "capability_secret_digest")
            or not _hash_ref(self._world_tenant_ref, "owned_tenant")
            or not _hash_ref(
                self._world_tenant_ownership_ref,
                "ownership_proof",
            )
            or self.tenant_ref != self._world_tenant_ref
            or self.tenant_ownership_ref != self._world_tenant_ownership_ref
            or owned_world.binding_id != self._owned_world.binding_id
            or self.subject_ref != owned_world.persona_ref
            or self.audience_ref != owned_world.persona_ref
            or not logical_bounds_valid
            or not (callback_absent or callback_present)
            or self.mode != CAPABILITY_CONTRACT_MODE
        ):
            raise ValueError("issued capability contract is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "capability_id": self.capability_id,
            **_contract_payload(
                subject_ref=self.subject_ref,
                resource_ref=self.resource_ref,
                operation_ref=self.operation_ref,
                audience_ref=self.audience_ref,
                issuer_ref=self.issuer_ref,
                tenant_ref=self.tenant_ref,
                tenant_ownership_ref=self.tenant_ownership_ref,
                source_evidence_ref=self.source_evidence_ref,
                secret_digest=self.secret_digest,
                issued_at_index=self.issued_at_index,
                expires_at_index=self.expires_at_index,
                max_uses=self.max_uses,
                revocation_state=self.revocation_state,
                callback_ref=self.callback_ref,
                callback_scope_ref=self.callback_scope_ref,
            ),
        }


def _fixture_payload(
    *,
    world: ExperimentWorldBinding,
    contract: IssuedCapabilityContract,
) -> Dict[str, Any]:
    return {
        "mode": CAPABILITY_CONTRACT_MODE,
        "topology": ProofTopology.SINGLE_OWNED_ACCOUNT.value,
        "world_binding_id": world.binding_id,
        "world_ref": world.world_ref,
        "persona_ref": world.persona_ref,
        "ownership_ref": world.ownership_ref,
        "tenant_ref": contract.tenant_ref,
        "tenant_ownership_ref": contract.tenant_ownership_ref,
        "contract": contract.to_dict(),
        "disposable": True,
        "reversible": True,
        "cleanup_required": False,
        "residue_created": False,
        "orphan_risk": False,
        "target_requests_sent": 0,
        "budget_reserved": False,
        "backend_dispatch_authority": False,
        "finding_authority": False,
        "executable": False,
    }


@dataclass(frozen=True)
class CapabilityOwnedFixture:
    fixture_id: str
    contract: IssuedCapabilityContract
    world_binding_id: str
    world_ref: str
    persona_ref: str
    ownership_ref: str
    tenant_ref: str
    tenant_ownership_ref: str
    _world: ExperimentWorldBinding = field(repr=False, compare=False)
    topology: ProofTopology = ProofTopology.SINGLE_OWNED_ACCOUNT
    mode: str = CAPABILITY_CONTRACT_MODE
    disposable: bool = True
    reversible: bool = True
    cleanup_required: bool = False
    residue_created: bool = False
    orphan_risk: bool = False
    target_requests_sent: int = 0
    budget_reserved: bool = False
    backend_dispatch_authority: bool = False
    finding_authority: bool = False
    executable: bool = False

    @classmethod
    def build(
        cls,
        *,
        world: ExperimentWorldBinding,
        contract: IssuedCapabilityContract,
    ) -> "CapabilityOwnedFixture":
        owned_world = _validate_owned_account_world(world)
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if (
            owned_world.binding_id != contract._owned_world.binding_id
            or contract.subject_ref != owned_world.persona_ref
            or contract.audience_ref != owned_world.persona_ref
        ):
            raise ValueError(
                "capability contract does not bind the owned fixture world"
            )
        payload = _fixture_payload(world=owned_world, contract=contract)
        return cls(
            fixture_id=stable_hash("capability_owned_fixture", payload),
            contract=contract,
            world_binding_id=owned_world.binding_id,
            world_ref=owned_world.world_ref,
            persona_ref=owned_world.persona_ref,
            ownership_ref=owned_world.ownership_ref,
            tenant_ref=contract.tenant_ref,
            tenant_ownership_ref=contract.tenant_ownership_ref,
            _world=owned_world,
        )

    def __post_init__(self) -> None:
        world = _validate_owned_account_world(self._world)
        if not isinstance(self.contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        payload = _fixture_payload(world=world, contract=self.contract)
        if (
            self.fixture_id != stable_hash("capability_owned_fixture", payload)
            or not _hash_ref(self.fixture_id, "capability_owned_fixture")
            or self.world_binding_id != world.binding_id
            or self.world_binding_id != self.contract._owned_world.binding_id
            or self.world_ref != world.world_ref
            or self.persona_ref != world.persona_ref
            or self.ownership_ref != world.ownership_ref
            or self.contract.subject_ref != world.persona_ref
            or self.contract.audience_ref != world.persona_ref
            or self.tenant_ref != self.contract.tenant_ref
            or self.tenant_ownership_ref != self.contract.tenant_ownership_ref
            or not _hash_ref(self.world_binding_id, "experiment_world_binding")
            or not _hash_ref(self.world_ref, "world")
            or not _hash_ref(self.persona_ref)
            or not _hash_ref(self.ownership_ref, "ownership_proof")
            or not _hash_ref(self.tenant_ref, "owned_tenant")
            or not _hash_ref(self.tenant_ownership_ref, "ownership_proof")
            or self.topology is not ProofTopology.SINGLE_OWNED_ACCOUNT
            or self.mode != CAPABILITY_CONTRACT_MODE
            or not self.disposable
            or not self.reversible
            or self.cleanup_required
            or self.residue_created
            or self.orphan_risk
            or self.target_requests_sent != 0
            or self.budget_reserved
            or self.backend_dispatch_authority
            or self.finding_authority
            or self.executable
        ):
            raise ValueError("capability owned fixture is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "fixture_id": self.fixture_id,
            **_fixture_payload(world=self._world, contract=self.contract),
        }


def _presentation_payload(
    *,
    resource_ref: str,
    account_ref: str,
    audience_ref: str,
    operation_ref: str,
    at_index: int,
    use_index: int,
) -> Dict[str, Any]:
    return {
        "resource_ref": resource_ref,
        "account_ref": account_ref,
        "audience_ref": audience_ref,
        "operation_ref": operation_ref,
        "at_index": at_index,
        "use_index": use_index,
    }


@dataclass(frozen=True)
class CapabilityPresentation:
    presentation_id: str
    resource_ref: str
    account_ref: str
    audience_ref: str
    operation_ref: str
    at_index: int
    use_index: int

    @classmethod
    def build(
        cls,
        *,
        resource_ref: str,
        account_ref: str,
        audience_ref: str,
        operation_ref: str,
        at_index: int,
        use_index: int,
    ) -> "CapabilityPresentation":
        payload = _presentation_payload(
            resource_ref=resource_ref,
            account_ref=account_ref,
            audience_ref=audience_ref,
            operation_ref=operation_ref,
            at_index=at_index,
            use_index=use_index,
        )
        return cls(
            presentation_id=stable_hash("capability_presentation", payload),
            resource_ref=resource_ref,
            account_ref=account_ref,
            audience_ref=audience_ref,
            operation_ref=operation_ref,
            at_index=at_index,
            use_index=use_index,
        )

    def __post_init__(self) -> None:
        payload = _presentation_payload(
            resource_ref=self.resource_ref,
            account_ref=self.account_ref,
            audience_ref=self.audience_ref,
            operation_ref=self.operation_ref,
            at_index=self.at_index,
            use_index=self.use_index,
        )
        if (
            self.presentation_id != stable_hash("capability_presentation", payload)
            or not _hash_ref(self.presentation_id, "capability_presentation")
            or any(
                not _hash_ref(item)
                for item in (
                    self.resource_ref,
                    self.account_ref,
                    self.audience_ref,
                    self.operation_ref,
                )
            )
            or type(self.at_index) is not int
            or self.at_index < 0
            or type(self.use_index) is not int
            or self.use_index < 0
        ):
            raise ValueError("capability presentation is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "presentation_id": self.presentation_id,
            **_presentation_payload(
                resource_ref=self.resource_ref,
                account_ref=self.account_ref,
                audience_ref=self.audience_ref,
                operation_ref=self.operation_ref,
                at_index=self.at_index,
                use_index=self.use_index,
            ),
        }


def _decision_payload(
    *,
    capability_id: str,
    presentation_id: str,
    outcome: CapabilityOutcome,
    reason_ref: str,
) -> Dict[str, Any]:
    return {
        "capability_id": capability_id,
        "presentation_id": presentation_id,
        "outcome": outcome.value,
        "reason_ref": reason_ref,
    }


@dataclass(frozen=True)
class CapabilityDecision:
    decision_id: str
    capability_id: str
    presentation_id: str
    outcome: CapabilityOutcome
    reason_ref: str

    @classmethod
    def build(
        cls,
        *,
        contract: IssuedCapabilityContract,
        presentation: CapabilityPresentation,
        outcome: CapabilityOutcome,
        binding_mismatches: Tuple[str, ...] = (),
    ) -> "CapabilityDecision":
        if not isinstance(contract, IssuedCapabilityContract):
            raise TypeError("contract must be an IssuedCapabilityContract")
        if not isinstance(presentation, CapabilityPresentation):
            raise TypeError("presentation must be a CapabilityPresentation")
        if not isinstance(outcome, CapabilityOutcome):
            raise TypeError("outcome must be a CapabilityOutcome")
        normalized_mismatches = tuple(
            name for name in _BINDING_ORDER if name in binding_mismatches
        )
        if normalized_mismatches != binding_mismatches or (
            outcome is CapabilityOutcome.WRONG_BINDING
        ) != bool(binding_mismatches):
            raise ValueError("capability decision reason is invalid")
        reason_ref = stable_hash(
            "capability_reason",
            {
                "outcome": outcome.value,
                "binding_mismatches": list(binding_mismatches),
            },
        )
        payload = _decision_payload(
            capability_id=contract.capability_id,
            presentation_id=presentation.presentation_id,
            outcome=outcome,
            reason_ref=reason_ref,
        )
        return cls(
            decision_id=stable_hash("capability_decision", payload),
            capability_id=contract.capability_id,
            presentation_id=presentation.presentation_id,
            outcome=outcome,
            reason_ref=reason_ref,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, CapabilityOutcome):
            raise TypeError("outcome must be a CapabilityOutcome")
        payload = _decision_payload(
            capability_id=self.capability_id,
            presentation_id=self.presentation_id,
            outcome=self.outcome,
            reason_ref=self.reason_ref,
        )
        if (
            self.decision_id != stable_hash("capability_decision", payload)
            or not _hash_ref(self.decision_id, "capability_decision")
            or not _hash_ref(self.capability_id, "issued_capability_contract")
            or not _hash_ref(self.presentation_id, "capability_presentation")
            or not _hash_ref(self.reason_ref, "capability_reason")
        ):
            raise ValueError("capability decision is invalid")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "decision_id": self.decision_id,
            **_decision_payload(
                capability_id=self.capability_id,
                presentation_id=self.presentation_id,
                outcome=self.outcome,
                reason_ref=self.reason_ref,
            ),
        }


def _decision(
    contract: IssuedCapabilityContract,
    presentation: CapabilityPresentation,
    outcome: CapabilityOutcome,
    *,
    binding_mismatches: Tuple[str, ...] = (),
) -> CapabilityDecision:
    return CapabilityDecision.build(
        contract=contract,
        presentation=presentation,
        outcome=outcome,
        binding_mismatches=binding_mismatches,
    )


def classify_presentation(
    contract: IssuedCapabilityContract,
    presented: CapabilityPresentation,
) -> CapabilityDecision:
    """Classify one immutable presentation without consuming or dispatching it.

    ``use_index`` is zero-based: a single-use capability permits index ``0`` and
    classifies index ``1`` as already used.  Revocation wins over every other state;
    the issue/expiry window wins over binding mismatches; binding mismatches win over
    an exhausted use count.
    """

    if not isinstance(contract, IssuedCapabilityContract):
        raise TypeError("contract must be an IssuedCapabilityContract")
    if not isinstance(presented, CapabilityPresentation):
        raise TypeError("presented must be a CapabilityPresentation")

    if contract.revocation_state is CapabilityRevocationState.REVOKED:
        return _decision(contract, presented, CapabilityOutcome.REVOKED)

    if not (contract.issued_at_index <= presented.at_index < contract.expires_at_index):
        return _decision(contract, presented, CapabilityOutcome.EXPIRED)

    comparisons = {
        "resource": presented.resource_ref == contract.resource_ref,
        "account": presented.account_ref == contract.subject_ref,
        "audience": presented.audience_ref == contract.audience_ref,
        "operation": presented.operation_ref == contract.operation_ref,
    }
    mismatches = tuple(name for name in _BINDING_ORDER if not comparisons[name])
    if mismatches:
        return _decision(
            contract,
            presented,
            CapabilityOutcome.WRONG_BINDING,
            binding_mismatches=mismatches,
        )

    if presented.use_index >= contract.max_uses:
        return _decision(contract, presented, CapabilityOutcome.ALREADY_USED)

    return _decision(contract, presented, CapabilityOutcome.VALID)


__all__ = [
    "CAPABILITY_CONTRACT_MODE",
    "CapabilityDecision",
    "CapabilityOutcome",
    "CapabilityOwnedFixture",
    "CapabilityPresentation",
    "CapabilityRevocationState",
    "IssuedCapabilityContract",
    "classify_presentation",
]
