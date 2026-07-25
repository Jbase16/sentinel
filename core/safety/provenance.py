"""
core/safety/provenance.py

Conduct provenance for the bounty-safe executor — NOT a new ledger.

This is a thin adapter over the EXISTING replay/Merkle substrate (core/replay).
It exists because the most important proof path (minimal_amplification / owned_proof
/ self_escalation → PolicyExecutor.send_action → raw HTTP) bypassed the capsule /
evidence architecture, so nothing recorded what the proof actually did. Attaching a
`ProvenanceSink` at the PolicyExecutor seam — the last common checkpoint before any
outbound proof action — means modules cannot self-certify their conduct: every
allowed request AND every policy denial becomes an immutable, content-addressed
Merkle block, and the head of that chain is a triager-verifiable provenance root.

Ownership boundary (kept deliberately clean):
  * proof modules own SEMANTIC evidence — authorization_matrix_delta, novelty_claims,
    object_class_sensitivity, intended_invariant/observed_violation, markers.
  * the executor/sink owns CONDUCT evidence — what was sent, who sent it, its risk
    class, whether policy allowed/denied it, the status, the budget after, and hashes
    of the request/response (never the raw bytes).

Determinism: nothing time-varying is hashed. Two identical action sequences produce
the same root — otherwise the root is cryptographic glitter. Redaction: never store
raw headers, tokens, or full bodies — only sha256 hashes and coarse shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.replay.merkle import MerkleEngine
from core.replay.models import MerkleBlock

# One block per executor action (MVP — do not over-model). allowed/denied lives in
# the payload, not the kind, so the whole conduct trail is one homogeneous chain.
ACTION_KIND = "policy.action"
CONTEXT_KIND = "scan.context"


def _origin(target: str) -> str:
    try:
        p = urlparse(target if "://" in target else "http://" + target)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return str(target)


def _url_path(url: str) -> str:
    # Path only — drop scheme/host and (critically) any query string, which must
    # never carry sensitive data into the record.
    try:
        return urlparse(url).path or url
    except Exception:
        return str(url)


def _is_2xx(status: Any) -> bool:
    try:
        return 200 <= int(status) < 300
    except Exception:
        return False


def body_hash(body: Any) -> Optional[str]:
    """sha256 over the canonical body — never the raw body itself."""
    if body is None:
        return None
    try:
        return "sha256:" + MerkleEngine.compute_hash(body)
    except Exception:
        return "sha256:" + MerkleEngine.compute_hash(str(body))


def response_shape(resp: Any) -> Dict[str, Any]:
    """Coarse CONDUCT shape of a response — never semantic content. Marker detection
    is the proof module's job, not the executor's, so it deliberately isn't here."""
    if isinstance(resp, dict):
        return {"body_kind": "object", "json_keys": sorted(str(k) for k in resp.keys())[:24]}
    if isinstance(resp, list):
        return {"body_kind": "array", "len": len(resp)}
    if isinstance(resp, str):
        return {"body_kind": "text", "empty": resp == ""}
    if resp is None:
        return {"body_kind": "none"}
    return {"body_kind": type(resp).__name__}


@dataclass
class ProvenanceEvent:
    """One executor action, redacted to conduct evidence. `seq` is assigned by the
    sink (the sequencer); everything else is supplied by the executor."""
    method: str
    url_path: str
    action_class: str
    policy_mode: str
    allowed: bool
    seq: int = 0
    actor_persona_id: Optional[str] = None
    denial_reason: Optional[str] = None
    target_owner_persona_id: Optional[str] = None
    target_is_researcher_owned: Optional[bool] = None
    status: Optional[int] = None
    request_body_hash: Optional[str] = None
    response_body_hash: Optional[str] = None
    response_summary: Dict[str, Any] = field(default_factory=dict)
    budget_snapshot_after: Dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> Dict[str, Any]:
        # Deterministic: NO timestamps. seq is carried in the block meta, not here.
        return {
            "actor_persona_id": self.actor_persona_id,
            "method": self.method,
            "url_path": self.url_path,
            "action_class": self.action_class,
            "policy_mode": self.policy_mode,
            "allowed": self.allowed,
            "denial_reason": self.denial_reason,
            "target_owner_persona_id": self.target_owner_persona_id,
            "target_is_researcher_owned": self.target_is_researcher_owned,
            "status": self.status,
            "request_body_hash": self.request_body_hash,
            "response_body_hash": self.response_body_hash,
            "response_summary": self.response_summary,
            "budget_after": self.budget_snapshot_after,
        }


class ProvenanceSink:
    """An append-only Merkle chain of executor conduct, built on the existing
    MerkleEngine. Each block's parent is the previous head, so the head id
    transitively commits to the entire sequence — that head IS the provenance root."""

    def __init__(self):
        self.blocks: List[MerkleBlock] = []
        self._head: Optional[str] = None
        self._seq = 0

    # -- recording -----------------------------------------------------------

    def record_context(self, *, target: str, proof_mode: str, policy_digest: str = "",
                       tool_versions: Optional[Dict[str, str]] = None) -> str:
        """Genesis block binding the DETERMINISTIC conduct context (no scan id, no
        time) so the root commits to 'this target, under this policy'."""
        payload = {"target_origin": _origin(target), "proof_mode": proof_mode,
                   "policy_digest": policy_digest, "tool_versions": tool_versions or {}}
        return self._append(CONTEXT_KIND, payload, {"seq": self._next()})

    def record_policy_action(self, event: ProvenanceEvent) -> str:
        event.seq = self._next()
        return self._append(ACTION_KIND, event.to_payload(), {"seq": event.seq})

    def _append(self, kind: str, payload: Dict[str, Any], meta: Dict[str, Any]) -> str:
        parents = [self._head] if self._head else []
        block = MerkleEngine.create_block(parents, kind, payload, meta)
        self.blocks.append(block)
        self._head = block.id
        return block.id

    def _next(self) -> int:
        s = self._seq
        self._seq += 1
        return s

    # -- reading -------------------------------------------------------------

    def root(self) -> Optional[str]:
        return self._head

    @property
    def action_blocks(self) -> List[MerkleBlock]:
        return [b for b in self.blocks if b.kind == ACTION_KIND]

    def event_range(self) -> Dict[str, int]:
        seqs = [int(b.meta.get("seq", 0)) for b in self.action_blocks]
        return {"start_seq": min(seqs), "end_seq": max(seqs)} if seqs else {}

    def verify(self) -> bool:
        """Every block's id must match its content (tamper-evidence)."""
        return all(MerkleEngine.verify_block(b) for b in self.blocks)

    def summary(self) -> Dict[str, Any]:
        """Redacted aggregate for the bounty report — conduct, not content."""
        acts = self.action_blocks

        def _count(pred) -> int:
            return sum(1 for b in acts if pred(b.payload))

        sent = _count(lambda p: p.get("allowed"))
        denied = _count(lambda p: not p.get("allowed"))
        owned_only = not any(
            b.payload.get("allowed") and b.payload.get("target_is_researcher_owned") is False
            for b in acts)
        return {
            "root": self._head,
            "format": "scan_capsule_merkle_dag",
            "events": len(acts),
            "policy_mode": acts[-1].payload.get("policy_mode") if acts else None,
            "actions_sent": sent,
            "actions_denied_by_policy": denied,
            "destructive_actions_sent": _count(
                lambda p: p.get("allowed") and p.get("action_class") == "DESTRUCTIVE"),
            "destructive_actions_denied": _count(
                lambda p: not p.get("allowed") and p.get("action_class") == "DESTRUCTIVE"),
            "cross_object_reads_2xx": _count(
                lambda p: p.get("allowed") and p.get("action_class") == "CROSS_OBJECT_READ"
                and _is_2xx(p.get("status"))),
            "owned_test_accounts_only": owned_only,
            "capsule_export_available": bool(acts),
        }

    def export_capsule(self, path, *, capsule_id: str, config: Optional[Dict[str, Any]] = None,
                       policy_digest: str = "", model_identity: str = "",
                       tool_versions: Optional[Dict[str, str]] = None) -> None:
        """Persist the chain as a .capsule (JSONL) via the existing CapsuleRecorder,
        so a triager can be handed the full conduct trail, not just the root."""
        from core.replay.persistence import CapsuleRecorder
        with CapsuleRecorder(path) as rec:
            rec.start(capsule_id=capsule_id, config=config or {},
                      tool_versions=tool_versions or {}, policy_digest=policy_digest,
                      model_identity=model_identity)
            for b in self.blocks:
                rec.write_block(b)
