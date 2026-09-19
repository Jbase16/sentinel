"""Deterministic, receipt-gated reporting owner for one canonical finding.

``SubmissionCandidate`` is a draft artifact only.  It has no transport and no
submission authority. Its claim surface comes exclusively from one canonical
finding. Reproduction uses retained captured requests or an explicitly
non-replayable evidence attestation, projected through the disposable Workbench.
"""

from __future__ import annotations

import json
import shlex
import hashlib
from dataclasses import dataclass, replace
from typing import Any, Dict, Mapping, Optional, Tuple

from core.behavior.normalize import stable_hash
from core.behavior.receipts import (
    COMPLETED, BehavioralExecutionReceipt, ReceiptStoreError, re_full_sha256,
)
from core.epistemic.ledger import (
    CanonicalSessionReadModel, ObservationEnvelope, _canonical_finding_commitment,
)
from core.identity import CredentialFreshness
from core.verify.promoter import ArtifactSanitizer
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
    request_body_template: str = ""
    capture_commitment: str = ""
    dependency_refs: Tuple[str, ...] = ()

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
            request_body_template=selection.request_body_template,
            capture_commitment=selection.capture_commitment,
            dependency_refs=selection.dependency_refs,
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
            "request_body_template": self.request_body_template,
            "capture_commitment": self.capture_commitment,
            "dependency_refs": list(self.dependency_refs),
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
    reproduction_kind: str
    lineage_digest: str
    attestation_json: Optional[str]
    impact: str
    effect_class: str

    @property
    def replayable(self) -> bool:
        return self.reproduction_kind == "replayable_recipe"

    @property
    def attestation(self) -> Optional[Dict[str, Any]]:
        return json.loads(self.attestation_json) if self.attestation_json else None

    def __post_init__(self) -> None:
        if self.canonical_session_id == "global_scan":
            raise ValueError("SubmissionCandidate cannot use global_scan")
        if self.reproduction_kind not in {"replayable_recipe", "evidence_attestation"}:
            raise ValueError("SubmissionCandidate reproduction kind is invalid")
        if self.replayable != bool(self.steps) or self.replayable == bool(self.attestation_json):
            raise ValueError("SubmissionCandidate reproduction shape is invalid")
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
        "reproduction_kind": candidate.reproduction_kind,
        "lineage_digest": candidate.lineage_digest,
        "attestation_json": candidate.attestation_json,
        "impact": candidate.impact,
        "effect_class": candidate.effect_class,
    })


def _candidate_material_from_values(values: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": 2,
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
        "reproduction_kind": values["reproduction_kind"],
        "replayable": values["reproduction_kind"] == "replayable_recipe",
        "lineage_digest": values["lineage_digest"],
        "attestation": json.loads(values["attestation_json"]) if values["attestation_json"] else None,
        "impact": values["impact"],
        "effect_class": values["effect_class"],
    }


def _contains(value: Any, key: str, expected: Any) -> bool:
    if isinstance(value, Mapping):
        return value.get(key) == expected or any(
            _contains(item, key, expected) for item in value.values()
        )
    if isinstance(value, (tuple, list)):
        return any(_contains(item, key, expected) for item in value)
    return False


def _proof_source(read_model, finding, store):
    """Read existing claim eligibility; never promote or reinterpret an oracle."""
    if (
        finding.session_id != read_model.session_id
        or finding.confirmation_level != "confirmed"
        or finding.commitment != _canonical_finding_commitment(finding)
    ):
        raise ValueError("SubmissionCandidate canonical claim is invalid")
    proofs = tuple(finding.active_proof)
    lineages = {(item.receipt_id, item.provenance_root) for item in proofs}
    if len(lineages) != 1:
        raise ValueError("SubmissionCandidate requires exactly one active receipt lineage")
    if len(proofs) != len(set(proofs)):
        raise ValueError("SubmissionCandidate proof bindings are ambiguous")
    cited_ids = {item.observation_id for item in finding.citations}
    if cited_ids != {item.observation_id for item in proofs}:
        raise ValueError("SubmissionCandidate citations require complete proof binding")
    observations = tuple(sorted(
        (item for item in read_model.observations if item.id in cited_ids),
        key=lambda item: item.id,
    ))
    if len(observations) != len(cited_ids) or not observations:
        raise ValueError("SubmissionCandidate finding citations are inactive")
    receipt_id, provenance = next(iter(lineages))
    try:
        loaded = store.receipt_store.load(receipt_id.removeprefix("behavioral-"))
        if not isinstance(loaded, BehavioralExecutionReceipt):
            raise ValueError("SubmissionCandidate active proof receipt is unavailable")
        receipt = BehavioralExecutionReceipt.from_dict(loaded.to_dict())
    except (OSError, ReceiptStoreError, TypeError, KeyError) as exc:
        raise ValueError("SubmissionCandidate active proof receipt is unavailable") from exc
    if receipt.state != COMPLETED or not receipt.outcome or receipt.receipt_id != receipt_id:
        raise ValueError("SubmissionCandidate active proof receipt is not completed")
    for observation in observations:
        if (
            not isinstance(observation, ObservationEnvelope)
            or observation.session_id != read_model.session_id
            or observation.identity.credential_freshness is CredentialFreshness.STALE
            or (
                observation.operation_family.method != "LOCAL"
                and observation.identity.credential_freshness is not CredentialFreshness.FRESH
            )
        ):
            raise ValueError("SubmissionCandidate proof identity is stale or cross-session")
        identity = observation.identity
        if (
            receipt.context.target_ref != stable_hash("behavioral_receipt_target", identity.target_origin)
            or receipt.context.envelope_ref != stable_hash("behavioral_receipt_envelope", identity.authorization_envelope_id)
            or stable_hash("behavioral_receipt_persona", identity.persona_id) not in {
                receipt.context.source_persona_ref, receipt.context.peer_persona_ref,
            }
        ):
            raise ValueError("SubmissionCandidate receipt identity does not match")

    local = any(item.operation_family.method == "LOCAL" for item in observations)
    evidence = None
    if local:
        from core.behavior.capability_effect_evidence import (
            CapabilityEffectEvidence, evaluate_replay_leak, replay_leak_finding_material,
        )
        if len(observations) != 1 or observations[0].tool.name != "capability_effect_evidence":
            raise ValueError("SubmissionCandidate LOCAL proof has no supported attestation")
        try:
            evidence = CapabilityEffectEvidence.from_mapping(
                receipt.outcome["capability_effect_evidence"]
            )
            eligible = evaluate_replay_leak(evidence).eligible
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("SubmissionCandidate attestation evidence is unavailable") from exc
        observation = observations[0]
        if (
            not eligible
            or evidence.source_receipt_id != receipt_id
            or evidence.evidence_root != provenance
            or evidence.assessment_session_id != read_model.session_id
            or evidence.identity_binding != observation.identity.to_dict()
            or hashlib.sha256(evidence.to_json_bytes()).hexdigest() != observation.blob_hash
        ):
            raise ValueError("SubmissionCandidate attestation is not eligible")
        material = replay_leak_finding_material(evidence)
        if any(getattr(finding, key) != material[key] for key in (
            "title", "severity", "description", "remediation", "confirmation_level", "metadata",
        )):
            raise ValueError("SubmissionCandidate attestation claim differs from canonical evidence")
    else:
        outcome = receipt.outcome
        if (
            not _contains(outcome, "provenance_root", provenance)
            or _contains(outcome, "finding_confirmed", False)
            or _contains(outcome, "oracle_verdict", "refuted")
            or _contains(outcome, "oracle_verdict", "inconclusive")
            or _contains(outcome, "orphaned_owned_state_possible", True)
            or not (
                _contains(outcome, "finding_confirmed", True)
                or _contains(outcome, "oracle_verdict", "confirmed")
                or _contains(outcome, "status", "confirmed")
            )
        ):
            raise ValueError("SubmissionCandidate receipt does not support this claim")
    return receipt, observations, evidence


def build_submission_candidate(
    read_model: CanonicalSessionReadModel,
    *,
    workbench_id: str,
    workbench_store: CandidateWorkbenchStore,
) -> SubmissionCandidate:
    """Assemble a minimized draft from one currently eligible receipt lineage."""
    if read_model.session_id == "global_scan":
        raise ValueError("SubmissionCandidate forbids global_scan")
    workbench = workbench_store.load(workbench_id, read_model=read_model)
    finding = next(
        (item for item in read_model.findings if item.id == workbench.finding_id), None,
    )
    if finding is None or not finding.commitment:
        raise ValueError("SubmissionCandidate canonical finding is unavailable")
    receipt, observations, evidence = _proof_source(read_model, finding, workbench_store)
    if evidence is None:
        # A draft is disposable, not a second evidence authority. Reproject the
        # retained capture each time so edits or stale draft selections cannot
        # turn into a different request attributed to the same receipt.
        workbench = workbench_store.populate_from_recorded(workbench, read_model=read_model)
    sanitizer = ArtifactSanitizer(secret_fingerprints=workbench.secret_fingerprints)
    proof_bindings = tuple(sorted((
        CandidateProofBinding(item.observation_id, item.receipt_id, item.provenance_root)
        for item in finding.active_proof
    ), key=lambda item: (item.observation_id, item.receipt_id, item.provenance_root)))
    cited_ids = tuple(sorted({item.observation_id for item in finding.citations}))
    proof_set = {(item.observation_id, item.receipt_id, item.provenance_root) for item in proof_bindings}
    attestation = None
    steps = ()
    if evidence is not None:
        if workbench.selections:
            raise ValueError("SubmissionCandidate attestation cannot contain replay steps")
        # All five phases and verified cleanup support the canonical D claim.
        # Omit producer/runtime/identity detail; retain their evidence-root binding.
        attestation = {
            "replayable": False,
            "label": "Receipt-bound evidence attestation (non-replayable)",
            "source_receipt_id": evidence.source_receipt_id,
            "evidence_root": evidence.evidence_root,
            "source_execution_id": evidence.source_execution_id,
            "observations": evidence.to_dict()["observations"],
            "oracle": evidence.to_dict()["oracle"],
            "cleanup": evidence.to_dict()["cleanup"],
            "limitation": (
                "Attests retained target-reported protected-effect exposure only; "
                "does not independently prove distinct backend state mutations. "
                "No request endpoint or replay recipe is retained."
            ),
        }
        attestation = sanitizer.value(attestation)
    else:
        if not workbench.selections:
            raise ValueError("SubmissionCandidate requires receipt-bound workbench steps")
        retained = []
        seen = set()
        for selection in workbench.selections:
            key = (selection.observation_id, selection.receipt_id, selection.provenance_root)
            if key not in proof_set or not selection.capture_commitment:
                raise ValueError("SubmissionCandidate step is not active-proof bound")
            # A repeated rendering selection is disposable, but distinct captured
            # requests or distinct proof observations must never be merged.
            identity = (*key, selection.capture_commitment)
            if identity in seen:
                continue
            seen.add(identity)
            step = CandidateStep.from_selection(selection)
            material = step.to_dict()
            material.pop("exchange_index")
            material.pop("selection_commitment")
            retained.append(replace(
                step, exchange_index=len(retained),
                selection_commitment=stable_hash("candidate_minimal_step", material),
            ))
        steps = tuple(retained)
        if {item.proof.observation_id for item in steps} != set(cited_ids):
            raise ValueError("SubmissionCandidate reproduction omits cited proof evidence")
    lineage_digest = stable_hash("candidate_receipt_lineage", {
        "session_id": read_model.session_id,
        "receipt": receipt.to_dict(),
        "active_proof": [item.to_dict() for item in proof_bindings],
        "observations": [item.commitment for item in observations],
    })
    # Unrelated session events do not change this minimal claim's revision.
    revision = stable_hash("candidate_canonical_revision", {
        "finding": finding.commitment, "lineage": lineage_digest,
    })
    impact = finding.metadata.get("impact") or finding.metadata.get("impact_assessment")
    effect_class = finding.metadata.get("finding_class")
    values = {
        "canonical_session_id": read_model.session_id,
        "canonical_revision": revision,
        "finding_id": finding.id,
        "finding_commitment": finding.commitment,
        "workbench_id": workbench.workbench_id,
        "title": sanitizer.text(finding.title),
        "severity": sanitizer.text(finding.severity),
        "summary": sanitizer.text(finding.description),
        "remediation": sanitizer.text(finding.remediation) if finding.remediation else None,
        "confirmation_level": finding.confirmation_level,
        "target_url": sanitizer.url(workbench.target_url),
        "citation_observation_ids": cited_ids,
        "active_proof": proof_bindings,
        "steps": steps,
        "reproduction_kind": "evidence_attestation" if evidence is not None else "replayable_recipe",
        "lineage_digest": lineage_digest,
        "attestation_json": json.dumps(attestation, sort_keys=True, separators=(",", ":")) if attestation else None,
        "impact": sanitizer.text(impact) if isinstance(impact, str) and impact else "unknown",
        "effect_class": sanitizer.text(effect_class) if isinstance(effect_class, str) and effect_class else "unknown",
    }
    material = _candidate_material_from_values(values)
    if sanitizer.contains_secret(material):
        raise ValueError("SubmissionCandidate artifact sanitization refused")
    return SubmissionCandidate(
        candidate_digest=stable_hash("submission_candidate", material), **values,
    )


def resolve_submission_candidate(
    read_model: CanonicalSessionReadModel,
    *,
    finding_id: Optional[str] = None,
    workbench_store: Optional[CandidateWorkbenchStore] = None,
) -> SubmissionCandidate:
    """Resolve one explicit candidate, or the sole valid session candidate."""

    store = workbench_store or CandidateWorkbenchStore()
    def workbench_for(finding_id: str) -> str:
        finding = next((item for item in read_model.findings if item.id == finding_id), None)
        if finding is None:
            raise ValueError("SubmissionCandidate canonical finding is unavailable")
        _receipt, _observations, evidence = _proof_source(read_model, finding, store)
        return store.open(read_model, finding_id=finding_id).workbench_id

    if finding_id:
        try:
            workbench_id = workbench_for(finding_id)
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
            workbench_id = workbench_for(finding.id)
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
    lines = [f"curl -X {shlex.quote(step.method)}"]
    for name, value in step.sanitized_headers:
        lines.append(f"  -H {shlex.quote(f'{name}: {value}')}")
    if step.request_body_template:
        lines.append(
            "  --data "
            + shlex.quote(step.request_body_template)
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
        "## Steps to Reproduce" if candidate.replayable else "## Evidence Attestation (non-replayable)",
        "",
    ]
    if not candidate.replayable:
        lines.extend((
            "This draft attests recorded evidence. It contains no replayable request recipe.",
            "", "```json", json.dumps(candidate.attestation, sort_keys=True, indent=2), "```", "",
        ))
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
    lines.extend(("", "## Impact", "", candidate.impact,
                  "", f"Effect class: {candidate.effect_class}"))
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
        "impact": candidate.impact,
        "effect_class": candidate.effect_class,
        "reproduction_kind": candidate.reproduction_kind,
        "replayable": candidate.replayable,
        "lineage_digest": candidate.lineage_digest,
        "attestation": candidate.attestation,
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
        if not candidate.replayable:
            return rendered.markdown
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
