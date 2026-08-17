"""Scanner outputs adapted into canonical identity and operation atoms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from core.base.scope import canonical_origin
from core.behavior.compiler import (
    OperationFamily,
    OperationInstance,
    OperationSafety,
)
from core.behavior.normalize import stable_hash

from .context import AssessmentIdentityContext, CredentialFreshness


@dataclass(frozen=True)
class ScannerEvidenceContext:
    identity: AssessmentIdentityContext
    operation_family: OperationFamily
    operation_instance: OperationInstance


def scan_admission_binding(
    *,
    session_id: str,
    target: str,
    request_material: Mapping[str, Any],
    policy_material: Mapping[str, Any],
) -> tuple[str, str]:
    """Seal already-admitted scan inputs without granting execution authority."""

    origin = canonical_origin(target)
    if origin is None:
        raise ValueError("scan admission target must have a canonical origin")
    envelope_id = stable_hash(
        "scan_admission",
        {
            "schema": "scanner_evidence_admission_v1",
            "session_id": session_id,
            "target_origin": origin.as_url(),
            "request": dict(request_material),
            "transport_policy": dict(policy_material),
        },
    )
    return envelope_id, f"authorization_envelope:{envelope_id.rsplit(':', 1)[-1]}"


def scanner_evidence_context(
    *,
    session_id: str,
    authorization_envelope_id: str,
    authorization_envelope_ref: str,
    target: str,
    tool_name: str,
    exec_id: str,
    exit_code: int,
    tool_args: Sequence[str] = (),
    target_reset_epoch: int = 0,
    world_id: str | None = None,
) -> ScannerEvidenceContext:
    """Build explicit anonymous scanner identity; unknowns stay unknown."""

    origin = canonical_origin(target)
    if origin is None:
        raise ValueError("scanner evidence target must have a canonical origin")
    normalized_args = tuple(str(item) for item in tool_args)
    world = world_id or f"scanner:{session_id}:anonymous"
    source_ref = stable_hash(
        "source_ref",
        {
            "tool": tool_name,
            "target_origin": origin.as_url(),
            "args": normalized_args,
        },
    )
    action_id = stable_hash(
        "action",
        {
            "kind": "scanner_tool",
            "tool": tool_name,
            "target_origin": origin.as_url(),
            "args": normalized_args,
        },
    )
    family = OperationFamily.build(
        action_id=action_id,
        label=f"{tool_name} observation",
        method="TOOL",
        requires=(),
        safety=OperationSafety.UNKNOWN,
        source_refs=(source_ref,),
    )
    instance = OperationInstance.build(
        family_id=family.family_id,
        source_ref=source_ref,
        world_ref=stable_hash("world", world),
        state_ref=stable_hash(
            "state",
            {
                "session_id": session_id,
                "exec_id": exec_id,
                "exit_code": exit_code,
                "target_reset_epoch": target_reset_epoch,
            },
        ),
        response_status=0,
        outputs=(),
    )
    identity = AssessmentIdentityContext(
        session_id=session_id,
        authorization_envelope_id=authorization_envelope_id,
        authorization_envelope_ref=authorization_envelope_ref,
        target_origin=origin.as_url(),
        target_reset_epoch=target_reset_epoch,
        world_id=world,
        persona_id="persona:anonymous",
        target_actor_id="actor:anonymous",
        tenant_id="tenant:unknown",
        credential_source_ref=stable_hash("credential_source", {"kind": "none"}),
        credential_epoch=0,
        credential_freshness=CredentialFreshness.UNKNOWN,
        resource_id=stable_hash("resource", target),
        representation_id=stable_hash(
            "representation",
            {"kind": "tool_stdout", "tool": tool_name},
        ),
    )
    return ScannerEvidenceContext(
        identity=identity,
        operation_family=family,
        operation_instance=instance,
    )
