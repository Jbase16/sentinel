"""Deterministic, receipt-gated reporting owner for one canonical finding.

``SubmissionCandidate`` is a draft artifact only.  It has no transport and no
submission authority.  Its claim surface comes exclusively from one canonical
finding, while its reproduction steps come exclusively from one persisted
Candidate Workbench.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from core.behavior.normalize import stable_hash
from core.behavior.receipts import COMPLETED, ReceiptStoreError, re_full_sha256
from core.epistemic.ledger import CanonicalSessionReadModel
from core.verify.workbench import (
    CandidateWorkbenchStore,
    ReproEvidenceSelection,
)


def _prefixed_sha256(value: str, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and re_full_sha256(
        value[len(prefix) :]
    )


@dataclass(frozen=True)
class CandidateProofBinding:
    observation_id: str
    receipt_id: str
    provenance_root: str

    def __post_init__(self) -> None:
        if (
            not _prefixed_sha256(self.observation_id, "obs-")
            or not _prefixed_sha256(self.receipt_id, "behavioral-")
            or not re_full_sha256(self.provenance_root)
        ):
            raise ValueError("SubmissionCandidate proof binding is invalid")

    def to_dict(self) -> Dict[str, str]:
        return {
            "observation_id": self.observation_id,
            "receipt_id": self.receipt_id,
            "provenance_root": self.provenance_root,
        }


@dataclass(frozen=True)
class CandidateStep:
    exchange_index: int
    method: str
    sanitized_url: str
    sanitized_headers: Tuple[Tuple[str, str], ...]
    request_shape_json: str
    response_status: int
    response_shape_json: str
    response_body_sha256: str
    proof: CandidateProofBinding
    selection_commitment: str

    @classmethod
    def from_selection(cls, selection: ReproEvidenceSelection) -> "CandidateStep":
        return cls(
            exchange_index=selection.exchange_index,
            method=selection.method,
            sanitized_url=selection.sanitized_url,
            sanitized_headers=selection.sanitized_headers,
            request_shape_json=json.dumps(
                selection.request_shape,
                sort_keys=True,
                separators=(",", ":"),
            ),
            response_status=selection.response_status,
            response_shape_json=json.dumps(
                selection.response_shape,
                sort_keys=True,
                separators=(",", ":"),
            ),
            response_body_sha256=selection.response_body_sha256,
            proof=CandidateProofBinding(
                observation_id=selection.observation_id,
                receipt_id=selection.receipt_id,
                provenance_root=selection.provenance_root,
            ),
            selection_commitment=selection.selection_commitment,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exchange_index": self.exchange_index,
            "method": self.method,
            "sanitized_url": self.sanitized_url,
            "sanitized_headers": dict(self.sanitized_headers),
            "request_shape": json.loads(self.request_shape_json),
            "response_status": self.response_status,
            "response_shape": json.loads(self.response_shape_json),
            "response_body_sha256": self.response_body_sha256,
            "proof": self.proof.to_dict(),
            "selection_commitment": self.selection_commitment,
        }


@dataclass(frozen=True)
class SubmissionCandidate:
    candidate_digest: str
    canonical_session_id: str
    canonical_revision: str
    finding_id: str
    finding_commitment: str
    workbench_id: str
    title: str
    severity: str
    summary: str
    remediation: Optional[str]
    confirmation_level: str
    target_url: str
    citation_observation_ids: Tuple[str, ...]
    active_proof: Tuple[CandidateProofBinding, ...]
    steps: Tuple[CandidateStep, ...]

    def __post_init__(self) -> None:
        if self.canonical_session_id == "global_scan":
            raise ValueError("SubmissionCandidate cannot use global_scan")
        expected = stable_hash("submission_candidate", _candidate_material(self))
        if self.candidate_digest != expected:
            raise ValueError("SubmissionCandidate digest mismatch")

    def to_dict(self) -> Dict[str, Any]:
        return {
            **_candidate_material(self),
            "candidate_digest": self.candidate_digest,
        }


def _candidate_material(candidate: SubmissionCandidate) -> Dict[str, Any]:
    return _candidate_material_from_values({
        "canonical_session_id": candidate.canonical_session_id,
        "canonical_revision": candidate.canonical_revision,
        "finding_id": candidate.finding_id,
        "finding_commitment": candidate.finding_commitment,
        "workbench_id": candidate.workbench_id,
        "title": candidate.title,
        "severity": candidate.severity,
        "summary": candidate.summary,
        "remediation": candidate.remediation,
        "confirmation_level": candidate.confirmation_level,
        "target_url": candidate.target_url,
        "citation_observation_ids": candidate.citation_observation_ids,
        "active_proof": candidate.active_proof,
        "steps": candidate.steps,
    })


def _candidate_material_from_values(values: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "canonical_session_id": values["canonical_session_id"],
        "canonical_revision": values["canonical_revision"],
        "finding_id": values["finding_id"],
        "finding_commitment": values["finding_commitment"],
        "workbench_id": values["workbench_id"],
        "claims": {
            "title": values["title"],
            "severity": values["severity"],
            "summary": values["summary"],
            "remediation": values["remediation"],
            "confirmation_level": values["confirmation_level"],
            "target_url": values["target_url"],
        },
        "citation_observation_ids": list(values["citation_observation_ids"]),
        "active_proof": [item.to_dict() for item in values["active_proof"]],
        "steps": [item.to_dict() for item in values["steps"]],
    }


def build_submission_candidate(
    read_model: CanonicalSessionReadModel,
    *,
    workbench_id: str,
    workbench_store: CandidateWorkbenchStore,
) -> SubmissionCandidate:
    """Build one immutable draft from current canonical and workbench state."""

    if read_model.session_id == "global_scan":
        raise ValueError("SubmissionCandidate forbids global_scan")
    workbench = workbench_store.load(workbench_id, read_model=read_model)
    finding = next(
        (item for item in read_model.findings if item.id == workbench.finding_id),
        None,
    )
    if finding is None or not finding.commitment:
        raise ValueError("SubmissionCandidate canonical finding is unavailable")
    if not workbench.selections:
        raise ValueError("SubmissionCandidate requires receipt-bound workbench steps")

    observation_ids = {item.id for item in read_model.observations}
    cited_ids = tuple(sorted({item.observation_id for item in finding.citations}))
    if not cited_ids or any(item not in observation_ids for item in cited_ids):
        raise ValueError("SubmissionCandidate finding citations are inactive")

    proof_bindings = tuple(
        sorted(
            (
                CandidateProofBinding(
                    observation_id=item.observation_id,
                    receipt_id=item.receipt_id,
                    provenance_root=item.provenance_root,
                )
                for item in finding.active_proof
            ),
            key=lambda item: (
                item.observation_id,
                item.receipt_id,
                item.provenance_root,
            ),
        )
    )
    if not proof_bindings:
        raise ValueError("SubmissionCandidate requires active canonical proof")
    for proof in proof_bindings:
        receipt = workbench_store.receipt_store.load(
            proof.receipt_id.removeprefix("behavioral-")
        )
        if receipt is None or receipt.state != COMPLETED:
            raise ValueError("SubmissionCandidate active proof receipt is not completed")

    proof_set = {
        (item.observation_id, item.receipt_id, item.provenance_root)
        for item in proof_bindings
    }
    steps = tuple(
        CandidateStep.from_selection(item) for item in workbench.selections
    )
    if any(
        (
            item.proof.observation_id,
            item.proof.receipt_id,
            item.proof.provenance_root,
        )
        not in proof_set
        for item in steps
    ):
        raise ValueError("SubmissionCandidate step is not active-proof bound")

    values = {
        "canonical_session_id": read_model.session_id,
        "canonical_revision": read_model.revision,
        "finding_id": finding.id,
        "finding_commitment": finding.commitment,
        "workbench_id": workbench.workbench_id,
        "title": finding.title,
        "severity": finding.severity,
        "summary": finding.description,
        "remediation": finding.remediation,
        "confirmation_level": finding.confirmation_level,
        "target_url": workbench.target_url,
        "citation_observation_ids": cited_ids,
        "active_proof": proof_bindings,
        "steps": steps,
    }
    return SubmissionCandidate(
        candidate_digest=stable_hash(
            "submission_candidate",
            _candidate_material_from_values(values),
        ),
        **values,
    )


def resolve_submission_candidate(
    read_model: CanonicalSessionReadModel,
    *,
    finding_id: Optional[str] = None,
    workbench_store: Optional[CandidateWorkbenchStore] = None,
) -> SubmissionCandidate:
    """Resolve one explicit candidate, or the sole valid session candidate."""

    store = workbench_store or CandidateWorkbenchStore()
    if finding_id:
        try:
            workbench_id = store.workbench_id_for(
                read_model,
                finding_id=finding_id,
            )
            return build_submission_candidate(
                read_model,
                workbench_id=workbench_id,
                workbench_store=store,
            )
        except ReceiptStoreError as exc:
            raise ValueError(
                "SubmissionCandidate receipt state is unavailable"
            ) from exc

    candidates = []
    for finding in sorted(read_model.findings, key=lambda item: item.id):
        try:
            workbench_id = store.workbench_id_for(
                read_model,
                finding_id=finding.id,
            )
            candidates.append(build_submission_candidate(
                read_model,
                workbench_id=workbench_id,
                workbench_store=store,
            ))
        except (ValueError, ReceiptStoreError):
            continue
    if len(candidates) != 1:
        raise ValueError(
            "Report generation requires one explicit finding_id or exactly one "
            "valid SubmissionCandidate"
        )
    return candidates[0]


@dataclass(frozen=True)
class RenderedCandidateStep:
    index: int
    method: str
    url: str
    prose: str
    curl: str
    response_status: int
    response_excerpt: str
    markdown: str
    observation_id: str
    receipt_id: str
    selection_commitment: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "method": self.method,
            "url": self.url,
            "prose": self.prose,
            "curl": self.curl,
            "response_status": self.response_status,
            "response_excerpt": self.response_excerpt,
            "markdown": self.markdown,
            "observation_id": self.observation_id,
            "receipt_id": self.receipt_id,
            "selection_commitment": self.selection_commitment,
        }


@dataclass(frozen=True)
class SubmissionCandidateRender:
    candidate_digest: str
    render_digest: str
    steps: Tuple[RenderedCandidateStep, ...]
    placeholder_legend: Tuple[Tuple[str, str], ...]
    markdown: str

    @property
    def steps_to_reproduce(self) -> Tuple[str, ...]:
        return tuple(item.markdown for item in self.steps)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_digest": self.candidate_digest,
            "render_digest": self.render_digest,
            "steps_to_reproduce": list(self.steps_to_reproduce),
            "placeholder_legend": dict(self.placeholder_legend),
            "entries": [item.to_dict() for item in self.steps],
            "markdown": self.markdown,
        }


def _render_step(step: CandidateStep, *, index: int) -> RenderedCandidateStep:
    lines = [f"curl -X {step.method}"]
    for name, value in step.sanitized_headers:
        lines.append(f"  -H {shlex.quote(f'{name}: {value}')}")
    request_shape = json.loads(step.request_shape_json)
    if request_shape.get("kind") != "none":
        lines.append(
            "  --data "
            + shlex.quote(json.dumps(request_shape, sort_keys=True))
        )
    lines.append(f"  {shlex.quote(step.sanitized_url)}")
    curl = " \\\n".join(lines)
    response_excerpt = json.dumps(
        {
            "status": step.response_status,
            "shape": json.loads(step.response_shape_json),
            "body_sha256": step.response_body_sha256,
            "observation_id": step.proof.observation_id,
            "receipt_id": step.proof.receipt_id,
        },
        sort_keys=True,
        indent=2,
    )
    prose = f"Send the receipt-bound `{step.method}` request to `{step.sanitized_url}`."
    markdown = (
        f"{prose}\n\n```bash\n{curl}\n```\n\n"
        f"**Committed response evidence:**\n```json\n{response_excerpt}\n```"
    )
    return RenderedCandidateStep(
        index=index,
        method=step.method,
        url=step.sanitized_url,
        prose=prose,
        curl=curl,
        response_status=step.response_status,
        response_excerpt=response_excerpt,
        markdown=markdown,
        observation_id=step.proof.observation_id,
        receipt_id=step.proof.receipt_id,
        selection_commitment=step.selection_commitment,
    )


def render_submission_candidate(
    candidate: SubmissionCandidate,
) -> SubmissionCandidateRender:
    """Render only candidate-owned claims; no caller-provided prose is accepted."""

    expected = stable_hash("submission_candidate", _candidate_material(candidate))
    if candidate.candidate_digest != expected:
        raise ValueError("SubmissionCandidate digest mismatch")
    steps = tuple(
        _render_step(step, index=index)
        for index, step in enumerate(candidate.steps, start=1)
    )
    legend: Dict[str, str] = {
        "$VALUE": "a target-specific value supplied by the triager",
        "$REDACTED": "a sensitive request header value",
    }
    for step in candidate.steps:
        for _name, value in step.sanitized_headers:
            for placeholder in ("$TOKEN", "$CSRF_TOKEN", "$API_KEY", "$SESSION_ID"):
                if placeholder in value:
                    legend[placeholder] = "an operator-supplied credential placeholder"

    lines = [
        f"# {candidate.title}",
        "",
        f"**Draft candidate:** `{candidate.candidate_digest}`",
        f"**Severity:** {candidate.severity}",
        f"**Confirmation:** {candidate.confirmation_level}",
        f"**Target:** `{candidate.target_url}`",
        "",
        "## Summary",
        "",
        candidate.summary,
        "",
        "## Steps to Reproduce",
        "",
    ]
    for step in steps:
        lines.extend((f"### {step.index}.", "", step.markdown, ""))
    lines.extend(("## Evidence Bindings", ""))
    for proof in candidate.active_proof:
        lines.append(
            f"- `{proof.observation_id}` / `{proof.receipt_id}` / "
            f"provenance `{proof.provenance_root}`"
        )
    if candidate.remediation:
        lines.extend(("", "## Suggested Remediation", "", candidate.remediation))
    markdown = "\n".join(lines).strip() + "\n"
    material = {
        "candidate_digest": candidate.candidate_digest,
        "steps": [item.to_dict() for item in steps],
        "placeholder_legend": dict(sorted(legend.items())),
        "markdown": markdown,
    }
    return SubmissionCandidateRender(
        candidate_digest=candidate.candidate_digest,
        render_digest=stable_hash("submission_candidate_render", material),
        steps=steps,
        placeholder_legend=tuple(sorted(legend.items())),
        markdown=markdown,
    )


def candidate_report_payload(
    candidate: SubmissionCandidate,
    *,
    rendered: Optional[SubmissionCandidateRender] = None,
) -> Dict[str, Any]:
    """Return the sole endpoint-facing report shape for a candidate."""

    rendered = rendered or render_submission_candidate(candidate)
    if rendered.candidate_digest != candidate.candidate_digest:
        raise ValueError("SubmissionCandidate render binding mismatch")
    return {
        "candidate_digest": candidate.candidate_digest,
        "render_digest": rendered.render_digest,
        "canonical_revision": candidate.canonical_revision,
        "finding_id": candidate.finding_id,
        "finding_commitment": candidate.finding_commitment,
        "workbench_id": candidate.workbench_id,
        "title": candidate.title,
        "severity": candidate.severity,
        "confirmation_level": candidate.confirmation_level,
        "target": candidate.target_url,
        "asset": candidate.target_url,
        "summary": candidate.summary,
        "steps_to_reproduce": list(rendered.steps_to_reproduce),
        "impact": None,
        "remediation": candidate.remediation,
        "evidence": [item.to_dict() for item in candidate.active_proof],
        "markdown": rendered.markdown,
        "claims": _candidate_material(candidate)["claims"],
    }


def candidate_section_content(
    candidate: SubmissionCandidate,
    *,
    section: str,
) -> str:
    """Render a named report section without accepting caller or model claims."""

    rendered = render_submission_candidate(candidate)
    if section == "executive_summary":
        return f"## Executive Summary\n\n{candidate.summary}"
    if section == "attack_narrative":
        steps = "\n\n".join(rendered.steps_to_reproduce)
        return f"## Evidence-Bound Reproduction\n\n{steps}"
    if section == "technical_findings":
        return rendered.markdown
    if section == "risk_assessment":
        return (
            "## Risk Assessment\n\n"
            f"Severity: **{candidate.severity}**  \n"
            f"Confirmation: **{candidate.confirmation_level}**"
        )
    if section == "remediation_roadmap":
        remediation = candidate.remediation or "No canonical remediation is recorded."
        return f"## Remediation Roadmap\n\n{remediation}"
    raise ValueError("Unsupported candidate report section")


__all__ = [
    "CandidateProofBinding",
    "CandidateStep",
    "RenderedCandidateStep",
    "SubmissionCandidate",
    "SubmissionCandidateRender",
    "build_submission_candidate",
    "candidate_section_content",
    "candidate_report_payload",
    "render_submission_candidate",
    "resolve_submission_candidate",
]
