"""Persistent, receipt-bound Candidate Workbench for Verify selections.

The workbench is a deterministic projection of one canonical session/finding.
It persists only sanitized request structure and response commitments.  It has
no transport and no finding-promotion capability.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.behavior.normalize import normalize_exchange, stable_hash
from core.behavior.receipts import BehavioralReceiptStore, COMPLETED
from core.epistemic.ledger import CanonicalSessionReadModel, Finding
from core.ghost.flow import FlowStep
from core.verify.promoter import sanitize_headers


_SAFE_HEADER_VALUES = frozenset({"accept", "content-type", "user-agent"})
_MAX_WORKBENCH_BYTES = 2 * 1024 * 1024


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

    @classmethod
    def build(
        cls,
        *,
        exchange_index: int,
        step: FlowStep,
        observation_id: str,
        receipt_id: str,
        provenance_root: str,
    ) -> "ReproEvidenceSelection":
        if isinstance(exchange_index, bool) or exchange_index < 0:
            raise ValueError("exchange index is invalid")
        request_shape, response_shape, response_hash = _shape_commitment(step)
        material = {
            "exchange_index": exchange_index,
            "observation_id": observation_id,
            "receipt_id": receipt_id,
            "provenance_root": provenance_root,
            "method": step.method.upper(),
            "sanitized_url": _sanitized_url(step),
            "sanitized_headers": _sanitized_headers(step.headers),
            "request_shape": request_shape,
            "response_status": step.response_status,
            "response_shape": response_shape,
            "response_body_sha256": response_hash,
        }
        return cls(
            exchange_index=exchange_index,
            observation_id=observation_id,
            receipt_id=receipt_id,
            provenance_root=provenance_root,
            method=material["method"],
            sanitized_url=material["sanitized_url"],
            sanitized_headers=tuple(sorted(material["sanitized_headers"].items())),
            request_shape=request_shape,
            response_status=step.response_status,
            response_shape=response_shape,
            response_body_sha256=response_hash,
            selection_commitment=stable_hash("verify_repro_selection", material),
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "workbench_id": self.workbench_id,
            "canonical_session_id": self.canonical_session_id,
            "finding_id": self.finding_id,
            "finding_commitment": self.finding_commitment,
            "target_url": self.target_url,
            "target_origin": self.target_origin,
            "selections": [item.to_dict() for item in self.selections],
        }


class CandidateWorkbenchStore:
    def __init__(
        self,
        root: Optional[Path] = None,
        *,
        receipt_store: Optional[BehavioralReceiptStore] = None,
    ) -> None:
        self.root = root or self._default_root()
        self.receipt_store = receipt_store or BehavioralReceiptStore()

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
        target_exchange = normalize_exchange({"url": target}, source_id="finding-target")
        workbench = CandidateWorkbench(
            workbench_id=workbench_id,
            canonical_session_id=read_model.session_id,
            finding_id=finding.id,
            finding_commitment=finding.commitment,
            target_url=_sanitized_url_value(
                target,
                path_template=target_exchange.path_template,
            ),
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
    ) -> CandidateWorkbench:
        finding = self._finding(read_model, workbench.finding_id)
        if (
            workbench.canonical_session_id != read_model.session_id
            or workbench.finding_commitment != finding.commitment
        ):
            raise ValueError("Verify workbench canonical binding changed")
        if not exchanges:
            raise ValueError("Verify selection batch is empty")

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
            selections[exchange_index] = ReproEvidenceSelection.build(
                exchange_index=exchange_index,
                step=step,
                observation_id=observation_id,
                receipt_id=receipt_id,
                provenance_root=proof.provenance_root,
            )

        updated = replace(
            workbench,
            selections=tuple(selections[index] for index in sorted(selections)),
        )
        self._write(updated)
        return updated

    def _write(self, workbench: CandidateWorkbench) -> None:
        self._prepare_root()
        payload = json.dumps(
            workbench.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
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
        if value.get("schema_version") != 1:
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
        target_exchange = normalize_exchange(
            {"url": canonical_target},
            source_id="finding-target",
        )
        expected_target_url = _sanitized_url_value(
            canonical_target,
            path_template=target_exchange.path_template,
        )
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
