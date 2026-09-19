"""Persistent, receipt-bound Candidate Workbench for Verify selections.

The workbench is a deterministic projection of one canonical session/finding.
It persists only sanitized request structure and response commitments.  It has
no transport and no finding-promotion capability.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.behavior.normalize import normalize_exchange, stable_hash
from core.behavior.lineage import ValueLineageLedger, RehydrationDenied
from core.behavior.receipts import BehavioralReceiptStore, COMPLETED
from core.epistemic.ledger import CanonicalSessionReadModel, Finding, ObservationEnvelope
from core.ghost.flow import FlowStep
from core.identity import CredentialFreshness
from core.verify.promoter import ArtifactSanitizer, sanitize_headers


_SAFE_HEADER_VALUES = frozenset({"accept", "content-type", "user-agent"})
_MAX_WORKBENCH_BYTES = 2 * 1024 * 1024


def _capture_commitment(step: FlowStep) -> str:
    return stable_hash("candidate_capture", {
        "method": step.method.upper(), "url": step.url,
        "headers": step.headers, "request_body": step.request_body,
        "response_status": step.response_status,
        "response_headers": step.response_headers, "response_body": step.response_body,
    })


def _require_unambiguous_body(step: FlowStep) -> None:
    """Refuse raw forms whose meaning is lost by the retained parsed commitment."""
    body = step.request_body
    media = (step.request_content_type or next((
        value for name, value in step.headers.items() if name.lower() == "content-type"
    ), "")).split(";", 1)[0].strip().lower()
    if not body:
        return
    if media in {"application/json", "application/graphql+json"} or body.lstrip().startswith(("{", "[")):
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("ambiguous object")
                result[key] = value
            return result

        try:
            json.loads(body, object_pairs_hook=unique_object)
        except (TypeError, ValueError):
            raise ValueError("Verify reproduction requires an unambiguous request body") from None
    elif media == "application/x-www-form-urlencoded":
        names = [name for name, _ in parse_qsl(body, keep_blank_values=True)]
        if len(names) != len(set(names)):
            raise ValueError("Verify reproduction requires an unambiguous request body")


def _sanitized_url_value(url: str, *, path_template: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("Verify workbench URL is not a credential-free HTTP(S) URL")
    query = urlencode(
        [(name, "$VALUE") for name, _value in parse_qsl(parts.query, keep_blank_values=True)],
        safe="$",
    )
    return urlunsplit((parts.scheme, parts.netloc, path_template, query, ""))


def _sanitized_url(step: FlowStep) -> str:
    exchange = normalize_exchange(step.to_dict(), source_id=step.id)
    return _sanitized_url_value(step.url, path_template=exchange.path_template)


def _sanitized_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    sanitized, _legend = sanitize_headers(headers)
    return {
        name: value if name.lower() in _SAFE_HEADER_VALUES else (
            value if "$" in value else "$REDACTED"
        )
        for name, value in sorted(sanitized.items())
    }


def _shape_commitment(step: FlowStep) -> tuple[Dict[str, Any], Dict[str, Any], str]:
    exchange = normalize_exchange(step.to_dict(), source_id=step.id)
    response_hash = hashlib.sha256(
        step.response_body.encode("utf-8", errors="replace")
    ).hexdigest()
    return exchange.request_shape, exchange.response_shape, response_hash


@dataclass(frozen=True)
class ReproEvidenceSelection:
    exchange_index: int
    observation_id: str
    receipt_id: str
    provenance_root: str
    method: str
    sanitized_url: str
    sanitized_headers: Tuple[Tuple[str, str], ...]
    request_shape: Dict[str, Any]
    response_status: int
    response_shape: Dict[str, Any]
    response_body_sha256: str
    selection_commitment: str
    request_body_template: str = ""
    capture_commitment: str = ""
    dependency_refs: Tuple[str, ...] = ()

    @classmethod
    def build(
        cls,
        *,
        exchange_index: int,
        step: FlowStep,
        observation_id: str,
        receipt_id: str,
        provenance_root: str,
        sanitizer: Optional[ArtifactSanitizer] = None,
        dependency_refs: Tuple[str, ...] = (),
    ) -> "ReproEvidenceSelection":
        if isinstance(exchange_index, bool) or exchange_index < 0:
            raise ValueError("exchange index is invalid")
        request_shape, response_shape, response_hash = _shape_commitment(step)
        sanitizer = sanitizer or ArtifactSanitizer((step,))
        if step.request_body_truncated or step.response_body_truncated:
            raise ValueError("Verify reproduction requires complete captured evidence")
        material = {
            "exchange_index": exchange_index,
            "observation_id": observation_id,
            "receipt_id": receipt_id,
            "provenance_root": provenance_root,
            "method": step.method.upper(),
            "sanitized_url": sanitizer.url(step.url),
            # Arbitrary header values are not committed by normalized captures.
            # Authentication and other values are reviewer-supplied placeholders.
            "sanitized_headers": {
                name: value if name == "content-type" or name in {
                    "authorization", "cookie", "proxy-authorization",
                    "x-api-key", "x-csrf-token", "x-xsrf-token",
                } else "$REDACTED"
                for name, value in sanitizer.headers(step.headers)[0].items()
            },
            "request_shape": sanitizer.value(request_shape),
            "response_status": step.response_status,
            "response_shape": sanitizer.value(response_shape),
            "response_body_sha256": response_hash,
            "request_body_template": sanitizer.body(step.request_body),
            "capture_commitment": _capture_commitment(step),
            "dependency_refs": list(dependency_refs),
        }
        return cls(
            exchange_index=exchange_index,
            observation_id=observation_id,
            receipt_id=receipt_id,
            provenance_root=provenance_root,
            method=material["method"],
            sanitized_url=material["sanitized_url"],
            sanitized_headers=tuple(sorted(material["sanitized_headers"].items())),
            request_shape=material["request_shape"],
            response_status=step.response_status,
            response_shape=material["response_shape"],
            response_body_sha256=response_hash,
            selection_commitment=stable_hash("verify_repro_selection", material),
            request_body_template=material["request_body_template"],
            capture_commitment=material["capture_commitment"],
            dependency_refs=dependency_refs,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exchange_index": self.exchange_index,
            "observation_id": self.observation_id,
            "receipt_id": self.receipt_id,
            "provenance_root": self.provenance_root,
            "method": self.method,
            "sanitized_url": self.sanitized_url,
            "sanitized_headers": dict(self.sanitized_headers),
            "request_shape": self.request_shape,
            "response_status": self.response_status,
            "response_shape": self.response_shape,
            "response_body_sha256": self.response_body_sha256,
            "selection_commitment": self.selection_commitment,
            "request_body_template": self.request_body_template,
            "capture_commitment": self.capture_commitment,
            "dependency_refs": list(self.dependency_refs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReproEvidenceSelection":
        selection = cls(
            exchange_index=value["exchange_index"],
            observation_id=value["observation_id"],
            receipt_id=value["receipt_id"],
            provenance_root=value["provenance_root"],
            method=value["method"],
            sanitized_url=value["sanitized_url"],
            sanitized_headers=tuple(sorted(dict(value["sanitized_headers"]).items())),
            request_shape=dict(value["request_shape"]),
            response_status=value["response_status"],
            response_shape=dict(value["response_shape"]),
            response_body_sha256=value["response_body_sha256"],
            selection_commitment=value["selection_commitment"],
            request_body_template=value.get("request_body_template", ""),
            capture_commitment=value.get("capture_commitment", ""),
            dependency_refs=tuple(value.get("dependency_refs", ())),
        )
        material = selection.to_dict()
        material.pop("selection_commitment")
        material["sanitized_headers"] = dict(selection.sanitized_headers)
        if selection.selection_commitment != stable_hash(
            "verify_repro_selection",
            material,
        ):
            raise ValueError("Verify selection commitment mismatch")
        return selection


@dataclass(frozen=True)
class CandidateWorkbench:
    workbench_id: str
    canonical_session_id: str
    finding_id: str
    finding_commitment: str
    target_url: str
    target_origin: str
    selections: Tuple[ReproEvidenceSelection, ...] = ()
    secret_fingerprints: Tuple[Tuple[int, str], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 2,
            "workbench_id": self.workbench_id,
            "canonical_session_id": self.canonical_session_id,
            "finding_id": self.finding_id,
            "finding_commitment": self.finding_commitment,
            "target_url": self.target_url,
            "target_origin": self.target_origin,
            "selections": [item.to_dict() for item in self.selections],
            "secret_fingerprints": [list(item) for item in self.secret_fingerprints],
        }


class CandidateWorkbenchStore:
    def __init__(
        self,
        root: Optional[Path] = None,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
        config=None,
    ) -> None:
        self.root = root or self._default_root()
        self.receipt_store = receipt_store or BehavioralReceiptStore()
        self.config = config

    @staticmethod
    def _default_root() -> Path:
        data_dir = os.environ.get("SENTINEL_DATA_DIR")
        base = Path(data_dir) if data_dir else Path.home() / ".sentinelforge"
        return base / "verify_workbenches"

    def _prepare_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or self.root.is_symlink()
            or info.st_uid != os.geteuid()
        ):
            raise ValueError("Verify workbench root attributes are unsafe")
        os.chmod(self.root, 0o700)

    def _path(self, workbench_id: str) -> Path:
        if not workbench_id.startswith("verify_workbench:"):
            raise ValueError("Verify workbench id is invalid")
        digest = workbench_id.removeprefix("verify_workbench:")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("Verify workbench id is invalid")
        return self.root / f"{digest}.json"

    def workbench_id_for(
        self,
        read_model: CanonicalSessionReadModel,
        *,
        finding_id: str,
    ) -> str:
        finding = self._finding(read_model, finding_id)
        return stable_hash(
            "verify_workbench",
            {
                "session_id": read_model.session_id,
                "finding_id": finding.id,
                "finding_commitment": finding.commitment,
            },
        )

    @staticmethod
    def _finding(read_model: CanonicalSessionReadModel, finding_id: str) -> Finding:
        if read_model.session_id == "global_scan":
            raise ValueError("Verify workbench forbids global_scan")
        finding = next(
            (item for item in read_model.findings if item.id == finding_id),
            None,
        )
        if finding is None or finding.session_id != read_model.session_id:
            raise ValueError("Verify workbench requires a finding in the exact session")
        if not finding.commitment:
            raise ValueError("Verify workbench finding commitment is unavailable")
        return finding

    @staticmethod
    def _target(read_model: CanonicalSessionReadModel, finding: Finding) -> str:
        cited = {item.observation_id for item in finding.citations}
        observation = next(
            (item for item in read_model.observations if item.id in cited),
            None,
        )
        if observation is None:
            raise ValueError("Verify workbench finding has no active cited observation")
        return observation.target

    def open(
        self,
        read_model: CanonicalSessionReadModel,
        *,
        finding_id: str,
    ) -> CandidateWorkbench:
        finding = self._finding(read_model, finding_id)
        target = self._target(read_model, finding)
        parts = urlsplit(target)
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
        ):
            raise ValueError("Verify workbench target is not a credential-free HTTP(S) URL")
        workbench_id = self.workbench_id_for(
            read_model,
            finding_id=finding.id,
        )
        path = self._path(workbench_id)
        if path.exists():
            return self.load(
                workbench_id,
                read_model=read_model,
            )
        workbench = CandidateWorkbench(
            workbench_id=workbench_id,
            canonical_session_id=read_model.session_id,
            finding_id=finding.id,
            finding_commitment=finding.commitment,
            target_url=f"{parts.scheme}://{parts.netloc}",
            target_origin=f"{parts.scheme}://{parts.netloc}",
        )
        self._write(workbench)
        return workbench

    def select_exchange(
        self,
        workbench: CandidateWorkbench,
        *,
        exchange_index: int,
        step: FlowStep,
        observation_id: str,
        receipt_id: str,
        read_model: CanonicalSessionReadModel,
    ) -> CandidateWorkbench:
        return self.select_exchanges(
            workbench,
            exchanges=((exchange_index, step, observation_id, receipt_id),),
            read_model=read_model,
        )

    def select_exchanges(
        self,
        workbench: CandidateWorkbench,
        *,
        exchanges: Sequence[Tuple[int, FlowStep, str, str]],
        read_model: CanonicalSessionReadModel,
        replace_existing: bool = False,
        capture_steps: Optional[Sequence[FlowStep]] = None,
        sensitive_values: Sequence[str] = (),
    ) -> CandidateWorkbench:
        finding = self._finding(read_model, workbench.finding_id)
        if (
            workbench.canonical_session_id != read_model.session_id
            or workbench.finding_commitment != finding.commitment
        ):
            raise ValueError("Verify workbench canonical binding changed")
        if not exchanges:
            raise ValueError("Verify selection batch is empty")

        captured = tuple(capture_steps) if capture_steps is not None else tuple(
            item[1] for item in exchanges
        )
        # Keep raw captures ephemeral. Only sanitized templates and commitments
        # enter the existing owned draft store.
        records = [step.to_dict() for step in captured]
        lineage = ValueLineageLedger(records, world_id=read_model.session_id)
        selected_sources = {
            normalize_exchange(step.to_dict(), source_id=step.id).source_id
            for _, step, _, _ in exchanges
        }
        try:
            required = set(lineage.required_sources(selected_sources))
        except RehydrationDenied as exc:
            raise ValueError("Verify reproduction lineage is unavailable or ambiguous") from exc
        if not required <= selected_sources:
            raise ValueError("Verify selection omits a recorded proof prerequisite")
        sanitizer = ArtifactSanitizer(
            captured, secret_fingerprints=workbench.secret_fingerprints,
            sensitive_values=sensitive_values,
            redact_response_values=True,
        )

        cited = {item.observation_id for item in finding.citations}
        selections = {} if replace_existing else {
            item.exchange_index: item for item in workbench.selections
        }
        batch_indices = set()
        for exchange_index, step, observation_id, receipt_id in exchanges:
            if exchange_index in batch_indices:
                raise ValueError("Verify selection batch contains duplicate indices")
            batch_indices.add(exchange_index)
            proof = next(
                (
                    item
                    for item in finding.active_proof
                    if item.observation_id == observation_id
                    and item.receipt_id == receipt_id
                ),
                None,
            )
            if proof is None or observation_id not in cited:
                raise ValueError("Verify selection is not finding/receipt bound")
            receipt = self.receipt_store.load(
                receipt_id.removeprefix("behavioral-")
            )
            if receipt is None or receipt.state != COMPLETED:
                raise ValueError("Verify selection receipt is not completed")
            observation = next(
                (item for item in read_model.observations if item.id == observation_id),
                None,
            )
            if isinstance(observation, ObservationEnvelope) and (
                observation.session_id != read_model.session_id
                or observation.operation_family.method != step.method.upper()
                or observation.operation_instance.response_status != step.response_status
            ):
                raise ValueError("Verify capture does not match its canonical observation")
            if isinstance(observation, ObservationEnvelope):
                if observation.identity.credential_freshness is not CredentialFreshness.FRESH:
                    raise ValueError("Verify capture canonical identity is stale")
                self._validate_capture(step, observation)
            source = normalize_exchange(step.to_dict(), source_id=step.id).source_id
            by_source = {
                normalize_exchange(item.to_dict(), source_id=item.id).source_id: item
                for item in captured
            }
            dependencies = tuple(sorted(
                stable_hash("candidate_dependency", {
                    "producer": _capture_commitment(by_source[item.producer_source_ref]),
                    "consumer": _capture_commitment(by_source[item.consumer_source_ref]),
                    "capability": item.capability.to_dict(),
                    "producer_locator": item.producer_locator.to_dict(),
                    "consumer_locator": item.consumer_locator.to_dict(),
                }) for item in lineage.bindings
                if item.consumer_source_ref == source
            ))
            selections[exchange_index] = ReproEvidenceSelection.build(
                exchange_index=exchange_index,
                step=step,
                observation_id=observation_id,
                receipt_id=receipt_id,
                provenance_root=proof.provenance_root,
                sanitizer=sanitizer,
                dependency_refs=dependencies,
            )

        updated = replace(
            workbench,
            selections=tuple(selections[index] for index in sorted(selections)),
            secret_fingerprints=sanitizer.fingerprints(),
        )
        if sanitizer.contains_secret(updated.to_dict()):
            raise ValueError("Verify workbench artifact sanitization refused")
        self._write(updated)
        return updated

    def _validate_capture(self, step: FlowStep, observation: ObservationEnvelope) -> None:
        """Require existing request commitments, never infer them from a response."""
        from core.base.config import get_config
        from core.epistemic.cas import ContentAddressableStorage
        from core.foundry.identity_adapter import stable_identity_source_ref
        from core.ghost.canonical_evidence import _credential_commitment

        if observation.tool.name != "ghost_proxy":
            raise ValueError("Verify reproduction requires retained request commitments")
        _require_unambiguous_body(step)
        config = self.config or get_config()
        if not (config.storage.evidence_path / "blobs").is_dir():
            raise ValueError("Verify canonical capture is unavailable")
        blob = ContentAddressableStorage(config).load(observation.blob_hash)
        try:
            stored = json.loads(blob) if blob is not None else None
        except (TypeError, ValueError):
            stored = None
        normalized = normalize_exchange(
            step.to_dict(), source_id=f"{observation.identity.world_id}:{step.id}",
            world_id=observation.identity.world_id,
        )
        if (
            stored != normalized.to_dict()
            or normalized.source_id != observation.operation_instance.source_ref
            or normalized.action_id != observation.operation_family.action_id
            or observation.identity.resource_id != stable_identity_source_ref("ghost_resource", {"url": step.url})
            or observation.identity.persona_id != stable_identity_source_ref(
                "ghost_persona", {"credential_ref": _credential_commitment(step)},
            )
            or (
                "content-type" in step.headers
                and step.headers["content-type"].split(";", 1)[0].strip().lower()
                != normalized.request_content_type
            )
        ):
            raise ValueError("Verify capture does not match canonical request and response evidence")

    def populate_from_recorded(
        self, workbench: CandidateWorkbench, *, read_model: CanonicalSessionReadModel,
    ) -> CandidateWorkbench:
        """Project an existing owned Ghost flow; never record or probe new traffic."""
        from core.ghost.flow import UserFlow, _flow_store_dir

        finding = self._finding(read_model, workbench.finding_id)
        cited = {item.observation_id for item in finding.citations}
        observations = [item for item in read_model.observations if item.id in cited]
        worlds = {item.identity.world_id for item in observations}
        if (
            len(worlds) != 1 or not observations
            or any(item.tool.name != "ghost_proxy" for item in observations)
        ):
            raise ValueError("SubmissionCandidate requires receipt-bound workbench steps from retained captures")
        world = next(iter(worlds))
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", world) is None:
            raise ValueError("Verify recorded capture identity is invalid")
        descriptor = -1
        try:
            descriptor = os.open(_flow_store_dir() / f"{world}.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > 16 * 1024 * 1024:
                raise ValueError("Verify recorded capture attributes are unsafe")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                flow = UserFlow.from_dict(json.load(handle))
        except (OSError, ValueError, TypeError, KeyError):
            raise ValueError("Verify recorded capture is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if flow.id != world:
            raise ValueError("Verify recorded capture identity changed")
        by_source = {item.operation_instance.source_ref: item for item in observations}
        if len(by_source) != len(observations) or len({
            item.identity.credential_epoch for item in observations
        }) != len(observations):
            raise ValueError("Verify recorded capture order is ambiguous")
        proof_by_observation = {item.observation_id: item for item in finding.active_proof}
        exchanges = []
        for index, step in enumerate(flow.steps):
            source = normalize_exchange(step.to_dict(), source_id=f"{world}:{step.id}", world_id=world).source_id
            observation = by_source.get(source)
            if observation is not None:
                if observation.identity.credential_epoch != index + 1:
                    raise ValueError("Verify recorded capture order changed")
                exchanges.append((index, step, observation.id, proof_by_observation[observation.id].receipt_id))
        if {item[2] for item in exchanges} != cited:
            raise ValueError("Verify recorded capture omits canonical proof evidence")
        return self.select_exchanges(
            workbench, exchanges=tuple(exchanges), read_model=read_model,
            capture_steps=tuple(flow.steps), replace_existing=True,
        )

    def discard(self, workbench_id: str) -> Dict[str, Any]:
        """Remove only this store's owned disposable draft; report cleanup failure."""
        path = self._path(workbench_id)
        try:
            info = path.lstat()
            if (
                self.root.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("Verify workbench cleanup ownership is unsafe")
            path.unlink()
            return {"status": "removed", "orphaned_owned_state_possible": False}
        except FileNotFoundError:
            return {"status": "absent", "orphaned_owned_state_possible": False}
        except (OSError, ValueError):
            return {"status": "failed", "orphaned_owned_state_possible": True}

    def _write(self, workbench: CandidateWorkbench) -> None:
        self._prepare_root()
        payload = json.dumps(
            workbench.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(payload.encode("utf-8")) > _MAX_WORKBENCH_BYTES:
            raise ValueError("Verify workbench exceeds the owned draft size limit")
        descriptor, name = tempfile.mkstemp(
            prefix=".verify-workbench-",
            suffix=".tmp",
            dir=self.root,
        )
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path(workbench.workbench_id))
        finally:
            if temporary.exists():
                temporary.unlink()

    def load(
        self,
        workbench_id: str,
        *,
        read_model: CanonicalSessionReadModel,
    ) -> CandidateWorkbench:
        path = self._path(workbench_id)
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid()
                or info.st_size > _MAX_WORKBENCH_BYTES
            ):
                raise ValueError("Verify workbench file attributes are unsafe")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                value = json.load(handle)
        except OSError as exc:
            raise ValueError("Verify workbench file cannot be opened safely") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(value, Mapping):
            raise ValueError("Verify workbench root is invalid")
        if value.get("schema_version") != 2:
            raise ValueError("Verify workbench schema is invalid")
        finding = self._finding(read_model, value["finding_id"])
        selections = tuple(
            ReproEvidenceSelection.from_dict(item)
            for item in value.get("selections", [])
        )
        workbench = CandidateWorkbench(
            workbench_id=value["workbench_id"],
            canonical_session_id=value["canonical_session_id"],
            finding_id=value["finding_id"],
            finding_commitment=value["finding_commitment"],
            target_url=value["target_url"],
            target_origin=value["target_origin"],
            selections=selections,
            secret_fingerprints=tuple(tuple(item) for item in value.get("secret_fingerprints", ())),
        )
        expected = stable_hash(
            "verify_workbench",
            {
                "session_id": read_model.session_id,
                "finding_id": finding.id,
                "finding_commitment": finding.commitment,
            },
        )
        canonical_target = self._target(read_model, finding)
        target_parts = urlsplit(canonical_target)
        expected_target_url = f"{target_parts.scheme}://{target_parts.netloc}"
        expected_target_origin = (
            f"{target_parts.scheme}://{target_parts.netloc}"
        )
        if (
            workbench.workbench_id != workbench_id
            or workbench.workbench_id != expected
            or workbench.canonical_session_id != read_model.session_id
            or workbench.finding_commitment != finding.commitment
            or workbench.target_url != expected_target_url
            or workbench.target_origin != expected_target_origin
        ):
            raise ValueError("Verify workbench canonical binding is invalid")
        cited = {item.observation_id for item in finding.citations}
        active_proof = {
            (item.observation_id, item.receipt_id, item.provenance_root)
            for item in finding.active_proof
        }
        for selection in selections:
            if (
                selection.observation_id not in cited
                or (
                    selection.observation_id,
                    selection.receipt_id,
                    selection.provenance_root,
                )
                not in active_proof
            ):
                raise ValueError("Verify workbench proof binding became invalid")
            receipt = self.receipt_store.load(
                selection.receipt_id.removeprefix("behavioral-")
            )
            if receipt is None or receipt.state != COMPLETED:
                raise ValueError("Verify workbench receipt became invalid")
        return workbench


__all__ = [
    "CandidateWorkbench",
    "CandidateWorkbenchStore",
    "ReproEvidenceSelection",
]
