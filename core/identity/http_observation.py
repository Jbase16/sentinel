"""Canonical HTTP observation construction shared by specialist adapters."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping
from urllib.parse import urldefrag

from core.behavior.compiler import OperationFamily, OperationInstance, OperationSafety
from core.behavior.normalize import stable_hash
from core.epistemic.ledger import EvidenceLedger, ObservationEnvelope

from .context import AssessmentIdentityContext


_WORLD_REF = re.compile(r"^world:[0-9a-f]{64}$")


def http_resource_ref(url: str) -> str:
    return stable_hash("http_resource", urldefrag(url).url)


def http_representation_ref(method: str, content_type: str | None) -> str:
    return stable_hash(
        "http_representation",
        {
            "method": str(method).upper(),
            "content_type": str(content_type or "").split(";", 1)[0].strip().lower(),
        },
    )


def record_http_observation(
    ledger: EvidenceLedger,
    *,
    source: str,
    identity: AssessmentIdentityContext,
    method: str,
    url: str,
    response_status: int,
    raw_evidence: Mapping[str, Any],
) -> ObservationEnvelope:
    """Record one exact specialist result without credential-bearing request data."""

    normalized_method = str(method).upper()
    raw_output = json.dumps(
        dict(raw_evidence),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode()
    canonical_evidence = json.loads(raw_output)
    source_ref = stable_hash(
        "source_ref",
        {
            "source": source,
            "identity_digest": identity.digest,
            "method": normalized_method,
            "url": urldefrag(url).url,
            "raw_evidence": canonical_evidence,
        },
    )
    family = OperationFamily.build(
        action_id=stable_hash(
            "action",
            {
                "source": source,
                "method": normalized_method,
                "url": urldefrag(url).url,
            },
        ),
        label=f"{source} {normalized_method} {urldefrag(url).url}"[:256],
        method=normalized_method,
        requires=(),
        safety=(
            OperationSafety.READ_ONLY
            if normalized_method in {"GET", "HEAD", "OPTIONS"}
            else OperationSafety.UNKNOWN
        ),
        source_refs=(source_ref,),
    )
    instance = OperationInstance.build(
        family_id=family.family_id,
        source_ref=source_ref,
        world_ref=(
            identity.world_id
            if _WORLD_REF.fullmatch(identity.world_id)
            else stable_hash("world", identity.world_id)
        ),
        state_ref=stable_hash(
            "state",
            {
                "source": source,
                "identity_digest": identity.digest,
                "credential_epoch": identity.credential_epoch,
                "target_reset_epoch": identity.target_reset_epoch,
            },
        ),
        response_status=int(response_status),
        outputs=(),
    )
    return ledger.record_canonical_observation(
        tool_name=source,
        tool_args=[normalized_method, urldefrag(url).url],
        target=urldefrag(url).url,
        raw_output=raw_output,
        identity=identity,
        operation_family=family,
        operation_instance=instance,
    )
