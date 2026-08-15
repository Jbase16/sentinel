"""Fail-closed admission for Wraith's high-impact active proof helpers.

``capability.acquire_capability`` and ``exfiltration.exfiltrate_credentials`` are
technique libraries, not authorization boundaries.  This module is the only scan
adapter allowed to invoke them: it requires an exact, signed owned-lab manifest,
restricts traffic to the loopback origin, routes every request through the shared
policy seam, and durably records a redacted conduct receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.cortex.execution_policy import ExecutionPolicy, PolicyExecutor
from core.safety.action_classifier import AUTHZ_PROBE, CROSS_OBJECT_READ
from core.safety.ownership_registry import OwnershipRegistry
from core.safety.proof_budget import ProofBudget
from core.safety.proof_mode import ProofMode
from core.safety.provenance import ProvenanceEvent, ProvenanceSink


CAPABILITY_WORKFLOW = "wraith.capability_acquisition"
UNION_EXFILTRATION_WORKFLOW = "wraith.union_exfiltration"
ACTIVE_PROOF_RECEIPT_ENV = "SENTINELFORGE_ACTIVE_PROOF_RECEIPTS"

RawSend = Callable[..., Awaitable[Tuple[int, Any]]]
ScopeFilter = Callable[[str], bool]
EnvelopeLoader = Callable[[str], Any]


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.hostname is None:
        raise ValueError("owned-lab target must be an absolute HTTP(S) origin")
    return f"{parsed.scheme}://{parsed.netloc}"


def _manifest_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    origin = _canonical_origin(value)
    if (parsed.path not in {"", "/"}) or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("owned-lab manifest target must be an origin without path or credentials")
    return origin


def _is_loopback_origin(origin: str) -> bool:
    host = urlsplit(origin).hostname
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


class OwnedLabManifest(BaseModel):
    """Request-carried binding to one persisted, signed authorization envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    envelope_id: str = Field(..., pattern=r"^[0-9a-f]{32}$")
    target_origin: str
    authorization_signature: str = Field(..., pattern=r"^[0-9a-f]{64}$")

    @field_validator("target_origin")
    @classmethod
    def validate_target_origin(cls, value: str) -> str:
        return _manifest_origin(value)

    @property
    def manifest_ref(self) -> str:
        material = json.dumps(
            {
                "authorization_signature": self.authorization_signature,
                "envelope_id": self.envelope_id,
                "target_origin": self.target_origin,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "owned_lab_manifest:" + hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class ActiveProofOutcome:
    admitted: bool
    reason: str
    value: Any = None
    receipt_path: Optional[Path] = None
    requests_sent: int = 0


class ActiveProofAdmissionDenied(RuntimeError):
    """Raised before any target traffic when owned-lab authority is absent."""


class _DurableReceipt:
    """Small redacted receipt atomically replaced after every provenance event."""

    def __init__(
        self,
        *,
        operation: str,
        scan_mode: str,
        target: str,
        manifest: Optional[OwnedLabManifest],
        root: Optional[Path],
    ) -> None:
        self.receipt_id = f"active-proof-{uuid.uuid4().hex}"
        self.root = root or self._default_root()
        self.path = self.root / f"{self.receipt_id}.json"
        self.created_at = time.time()
        self._healthy = True
        self.payload: Dict[str, Any] = {
            "schema_version": 1,
            "receipt_id": self.receipt_id,
            "state": "reserved",
            "operation": operation,
            "scan_mode": str(scan_mode or ""),
            "target_ref": "sha256:" + hashlib.sha256(
                _canonical_origin(target).encode()
            ).hexdigest(),
            "manifest_ref": manifest.manifest_ref if manifest is not None else None,
            "authorization_ref": None,
            "policy_digest": None,
            "ownership_registry_ref": None,
            "proof_budget": None,
            "provenance_root": None,
            "conduct": [],
            "result": None,
            "reason": None,
            "created_at": self.created_at,
            "updated_at": self.created_at,
        }
        self._persist()

    @staticmethod
    def _default_root() -> Path:
        override = os.environ.get(ACTIVE_PROOF_RECEIPT_ENV)
        if override:
            return Path(override)
        data_dir = os.environ.get("SENTINEL_DATA_DIR")
        if data_dir:
            return Path(data_dir) / "active_proof_receipts"
        return Path.home() / ".sentinelforge" / "active_proof_receipts"

    def _prepare_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise RuntimeError("active proof receipt root cannot be a symlink")
        info = self.root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError("active proof receipt root ownership is invalid")
        os.chmod(self.root, 0o700)

    def _persist(self) -> None:
        try:
            self._prepare_root()
            self.payload["updated_at"] = time.time()
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=self.root
            )
            temporary = Path(temporary_name)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = -1
                    json.dump(self.payload, handle, sort_keys=True, separators=(",", ":"))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        except BaseException:
            self._healthy = False
            raise

    def assert_healthy(self) -> None:
        if not self._healthy:
            raise RuntimeError("durable active proof receipt is unavailable")

    def bind_policy(
        self,
        *,
        authorization_signature: str,
        policy_digest: str,
        ownership_registry_ref: str,
        budget: ProofBudget,
    ) -> None:
        self.payload["authorization_ref"] = f"authorization:{authorization_signature}"
        self.payload["policy_digest"] = policy_digest
        self.payload["ownership_registry_ref"] = ownership_registry_ref
        self.payload["proof_budget"] = {
            "max_total_requests": budget.max_total_requests,
            "max_requests_per_endpoint": budget.max_requests_per_endpoint,
            "max_cross_object_reads": budget.max_cross_object_reads,
            "max_privilege_mutations": budget.max_privilege_mutations,
            "max_creates": budget.max_creates,
            "allow_delete": budget.allow_delete,
            "allow_real_user_data_access": budget.allow_real_user_data_access,
        }
        self._persist()

    def sync_provenance(self, sink: ProvenanceSink) -> None:
        self.payload["provenance_root"] = sink.root()
        self.payload["conduct"] = [dict(block.payload) for block in sink.action_blocks]
        self._persist()

    def finish(self, *, state: str, reason: str, result: Optional[Dict[str, Any]]) -> None:
        self.payload["state"] = state
        self.payload["reason"] = reason
        self.payload["result"] = dict(result) if result is not None else None
        self._persist()


class _DurableProvenanceSink(ProvenanceSink):
    def __init__(self, receipt: _DurableReceipt) -> None:
        super().__init__()
        self._receipt = receipt

    def record_context(self, **kwargs: Any) -> str:
        root = super().record_context(**kwargs)
        self._receipt.sync_provenance(self)
        return root

    def record_policy_action(self, event: ProvenanceEvent) -> str:
        root = super().record_policy_action(event)
        self._receipt.sync_provenance(self)
        return root


def _receipt_or_none(
    *,
    operation: str,
    scan_mode: str,
    target: str,
    manifest: Optional[OwnedLabManifest],
    receipt_root: Optional[Path],
) -> Optional[_DurableReceipt]:
    try:
        return _DurableReceipt(
            operation=operation,
            scan_mode=scan_mode,
            target=target,
            manifest=manifest,
            root=receipt_root,
        )
    except Exception:
        return None


def _admit(
    *,
    scan_mode: str,
    target: str,
    manifest: Optional[OwnedLabManifest],
    workflow: str,
    envelope_loader: Optional[EnvelopeLoader],
) -> Tuple[Any, str]:
    if str(scan_mode or "").strip().lower() != "owned_lab":
        raise ActiveProofAdmissionDenied("active_proof_requires_owned_lab_mode")
    resolved_mode = ProofMode.for_scan_mode(
        "owned_lab",
        environment_limit=os.environ.get("SENTINEL_PROOF_MODE"),
    )
    if resolved_mode != ProofMode.LAB:
        raise ActiveProofAdmissionDenied("active_proof_posture_was_tightened_below_lab")
    if manifest is None:
        raise ActiveProofAdmissionDenied("active_proof_requires_owned_lab_manifest")
    origin = _canonical_origin(target)
    if origin != manifest.target_origin:
        raise ActiveProofAdmissionDenied("owned_lab_manifest_target_mismatch")
    if not _is_loopback_origin(origin):
        raise ActiveProofAdmissionDenied("owned_lab_active_proof_requires_loopback_target")

    if envelope_loader is None:
        from core.foundry.authorization import get_envelope

        envelope_loader = get_envelope
    envelope = envelope_loader(manifest.envelope_id)
    if envelope is None:
        raise ActiveProofAdmissionDenied("owned_lab_authorization_envelope_not_found")
    signature = str(getattr(envelope, "attestation_signature", "") or "")
    if not hmac.compare_digest(signature, manifest.authorization_signature):
        raise ActiveProofAdmissionDenied("owned_lab_authorization_signature_mismatch")
    try:
        envelope.authorize_action(target_origin=origin, workflow=workflow)
    except Exception as exc:
        raise ActiveProofAdmissionDenied("owned_lab_authorization_denied") from exc
    return envelope, origin


def _exact_scope(origin: str, scope_filter: Optional[ScopeFilter]) -> ScopeFilter:
    def allowed(url: str) -> bool:
        try:
            if _canonical_origin(url) != origin:
                return False
            return scope_filter is None or bool(scope_filter(url))
        except Exception:
            return False

    return allowed


async def _default_raw_send(method: str, url: str, body: Any = None) -> Tuple[int, Any]:
    import httpx

    headers = {"User-Agent": "SentinelForge-OwnedLab-Proof"}
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        response = await client.request(method, url, json=body, headers=headers)
    return response.status_code, {
        "headers": {key: value for key, value in response.headers.items()},
        "text": response.text,
    }


def _executor(
    *,
    origin: str,
    scope_filter: Optional[ScopeFilter],
    budget: ProofBudget,
    raw_send: Optional[RawSend],
    receipt: _DurableReceipt,
    authorization_signature: str,
) -> PolicyExecutor:
    ownership_registry = OwnershipRegistry()
    policy = ExecutionPolicy(
        ProofMode.LAB,
        scope_filter=_exact_scope(origin, scope_filter),
        budget=budget,
        ownership_registry=ownership_registry,
    )
    receipt.bind_policy(
        authorization_signature=authorization_signature,
        policy_digest=policy.digest(),
        ownership_registry_ref=ownership_registry.registry_ref,
        budget=budget,
    )
    sink = _DurableProvenanceSink(receipt)
    sink.record_context(
        target=origin,
        proof_mode=ProofMode.LAB,
        policy_digest=policy.digest(),
    )
    transport = raw_send or _default_raw_send

    async def durable_transport(method: str, url: str, body: Any = None, **kwargs: Any):
        # A receipt failure is a stop condition. PolicyExecutor deliberately treats
        # provenance as best-effort, so this transport-side check prevents a later
        # request from escaping after an on-disk receipt update fails.
        receipt.assert_healthy()
        return await transport(method, url, body, **kwargs)

    return PolicyExecutor(durable_transport, policy, provenance=sink)


async def run_capability_acquisition(
    *,
    scan_mode: str,
    target: str,
    manifest: Optional[OwnedLabManifest],
    scope_filter: Optional[ScopeFilter] = None,
    max_attempts: int = 30,
    raw_send: Optional[RawSend] = None,
    envelope_loader: Optional[EnvelopeLoader] = None,
    receipt_root: Optional[Path] = None,
    acquirers: Optional[List[Any]] = None,
) -> ActiveProofOutcome:
    """Run bounded login-SQLi/default-credential acquisition after admission."""

    receipt = _receipt_or_none(
        operation="capability_acquisition",
        scan_mode=scan_mode,
        target=target,
        manifest=manifest,
        receipt_root=receipt_root,
    )
    if receipt is None:
        return ActiveProofOutcome(False, "durable_active_proof_receipt_unavailable")
    try:
        envelope, origin = _admit(
            scan_mode=scan_mode,
            target=target,
            manifest=manifest,
            workflow=CAPABILITY_WORKFLOW,
            envelope_loader=envelope_loader,
        )
    except ActiveProofAdmissionDenied as exc:
        reason = str(exc)
        receipt.finish(state="denied", reason=reason, result={"requests_sent": 0})
        return ActiveProofOutcome(False, reason, receipt_path=receipt.path)

    bounded_attempts = max(1, min(int(max_attempts), 30))
    executor = _executor(
        origin=origin,
        scope_filter=scope_filter,
        budget=ProofBudget(
            max_total_requests=bounded_attempts * 2,
            max_requests_per_endpoint=bounded_attempts * 2,
            max_cross_object_reads=0,
            max_privilege_mutations=0,
            max_creates=0,
            allow_delete=False,
            allow_real_user_data_access=True,
        ),
        raw_send=raw_send,
        receipt=receipt,
        authorization_signature=envelope.attestation_signature,
    )

    async def send(url: str, body: Dict[str, Any]) -> Tuple[int, Dict[str, str], str]:
        status, response = await executor.send(
            "POST",
            url,
            body,
            hint=AUTHZ_PROBE,
            target_is_researcher_owned=True,
            proof_goal="bounded_owned_lab_capability_acquisition",
        )
        response = response if isinstance(response, dict) else {}
        headers = response.get("headers")
        return status, (dict(headers) if isinstance(headers, dict) else {}), str(
            response.get("text") or ""
        )

    try:
        from core.wraith.capability import acquire_capability

        capability = await acquire_capability(
            target,
            _exact_scope(origin, scope_filter),
            send=send,
            max_attempts=bounded_attempts,
            acquirers=acquirers,
        )
    except Exception:
        sent = executor.restraint_summary()["requests_sent"]
        receipt.finish(
            state="aborted",
            reason="capability_acquisition_failed",
            result={"requests_sent": sent},
        )
        return ActiveProofOutcome(
            True,
            "capability_acquisition_failed",
            receipt_path=receipt.path,
            requests_sent=sent,
        )

    sent = executor.restraint_summary()["requests_sent"]
    receipt.finish(
        state="completed",
        reason="ok",
        result={
            "requests_sent": sent,
            "capability_acquired": capability is not None,
            "acquirer": str(getattr(capability, "acquirer", "") or "") or None,
        },
    )
    return ActiveProofOutcome(True, "ok", capability, receipt.path, sent)


async def run_union_exfiltration(
    *,
    scan_mode: str,
    target: str,
    manifest: Optional[OwnedLabManifest],
    url: str,
    param: str,
    scope_filter: Optional[ScopeFilter] = None,
    max_attempts: int = 40,
    raw_send: Optional[RawSend] = None,
    envelope_loader: Optional[EnvelopeLoader] = None,
    receipt_root: Optional[Path] = None,
) -> ActiveProofOutcome:
    """Run a bounded UNION proof only against the admitted local-lab origin."""

    receipt = _receipt_or_none(
        operation="union_exfiltration",
        scan_mode=scan_mode,
        target=target,
        manifest=manifest,
        receipt_root=receipt_root,
    )
    if receipt is None:
        return ActiveProofOutcome(False, "durable_active_proof_receipt_unavailable")
    try:
        envelope, origin = _admit(
            scan_mode=scan_mode,
            target=target,
            manifest=manifest,
            workflow=UNION_EXFILTRATION_WORKFLOW,
            envelope_loader=envelope_loader,
        )
    except ActiveProofAdmissionDenied as exc:
        reason = str(exc)
        receipt.finish(state="denied", reason=reason, result={"requests_sent": 0})
        return ActiveProofOutcome(False, reason, receipt_path=receipt.path)

    bounded_attempts = max(1, min(int(max_attempts), 40))
    executor = _executor(
        origin=origin,
        scope_filter=scope_filter,
        budget=ProofBudget(
            max_total_requests=bounded_attempts + 1,
            max_requests_per_endpoint=bounded_attempts + 1,
            max_cross_object_reads=bounded_attempts + 1,
            max_privilege_mutations=0,
            max_creates=0,
            allow_delete=False,
            allow_real_user_data_access=True,
        ),
        raw_send=raw_send,
        receipt=receipt,
        authorization_signature=envelope.attestation_signature,
    )

    async def fetch(candidate_url: str) -> Tuple[int, str]:
        status, response = await executor.send(
            "GET",
            candidate_url,
            hint=CROSS_OBJECT_READ,
            target_is_researcher_owned=True,
            proof_goal="bounded_owned_lab_union_exfiltration",
        )
        response = response if isinstance(response, dict) else {}
        return status, str(response.get("text") or "")

    try:
        from core.wraith.exfiltration import exfiltrate_credentials

        result = await exfiltrate_credentials(
            url,
            param,
            fetch,
            max_attempts=bounded_attempts,
        )
    except Exception:
        sent = executor.restraint_summary()["requests_sent"]
        receipt.finish(
            state="aborted",
            reason="union_exfiltration_failed",
            result={"requests_sent": sent},
        )
        return ActiveProofOutcome(
            True,
            "union_exfiltration_failed",
            receipt_path=receipt.path,
            requests_sent=sent,
        )

    sent = executor.restraint_summary()["requests_sent"]
    receipt.finish(
        state="completed",
        reason="ok",
        result={
            "requests_sent": sent,
            "credential_rows_observed": int(getattr(result, "row_count", 0) or 0),
            "proof_observed": result is not None,
        },
    )
    return ActiveProofOutcome(True, "ok", result, receipt.path, sent)
