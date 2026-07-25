"""
Canonical attack-path contract derived from the causal graph DTO.

This module is the boundary between:
  - deterministic graph truth (attack_chains in graph DTO), and
  - narrative layers (LLM/chat/reporting).

Narrative layers should consume this contract instead of inferring paths from
raw findings or heuristics.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional


def _to_str_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _coerce_int(value: Any, default: int = 0, minimum: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    if parsed < minimum:
        return minimum
    return parsed


def _coerce_float(value: Any, default: float = 0.0, minimum: float = 0.0) -> float:
    try:
        parsed = float(value)
    except Exception:
        parsed = default
    if parsed < minimum:
        return minimum
    return parsed


_ATTACK_PATH_TERM_RE = re.compile(
    r"\b(?:attack\s+paths?|attack\s+chains?|exploit\s+chains?|kill\s*chains?)\b",
    re.IGNORECASE,
)
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_NUMBER_RE = re.compile(r"\b(\d+)\b")
_NEGATIVE_CLAIM_RE = re.compile(r"\b(?:no|none|zero|without)\b", re.IGNORECASE)


def extract_attack_chains(graph_dto: Dict[str, Any], *, max_chains: int = 25) -> List[Dict[str, Any]]:
    """
    Extract and normalize attack chains from a graph DTO.
    """
    raw = graph_dto.get("attack_chains")
    if not isinstance(raw, list):
        return []

    out: List[Dict[str, Any]] = []
    for chain in raw[: max(0, max_chains)]:
        if not isinstance(chain, dict):
            continue

        chain_id = str(chain.get("id") or "").strip()
        node_ids = _to_str_list(chain.get("node_ids"))
        labels = _to_str_list(chain.get("labels"))
        length = _coerce_int(chain.get("length"), default=len(node_ids), minimum=0)
        score = _coerce_float(chain.get("score"), default=0.0, minimum=0.0)

        if not chain_id:
            chain_id = f"chain_{len(out) + 1}"
        if not node_ids and not labels:
            continue
        if length <= 0:
            length = max(len(node_ids), len(labels))

        out.append(
            {
                "id": chain_id,
                "node_ids": node_ids,
                "labels": labels,
                "entry_node": str(chain.get("entry_node") or (node_ids[0] if node_ids else "")),
                "leaf_node": str(chain.get("leaf_node") or (node_ids[-1] if node_ids else "")),
                "length": length,
                "score": score,
            }
        )

    return out


def build_attack_path_contract(
    *,
    session_id: str,
    graph_dto: Dict[str, Any],
    max_chains: int = 25,
) -> Dict[str, Any]:
    """
    Build the canonical, deterministic attack-path contract.
    """
    chains = extract_attack_chains(graph_dto, max_chains=max_chains)
    chain_count = len(chains)

    hash_input = {
        "session_id": str(session_id or ""),
        "chains": chains,
    }
    graph_hash = hashlib.sha256(
        json.dumps(hash_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        "session_id": str(session_id or ""),
        "graph_hash": graph_hash,
        "chain_count": chain_count,
        "has_attack_paths": chain_count > 0,
        "chain_ids": [str(chain.get("id") or "") for chain in chains],
        "chains": chains,
    }


def is_attack_path_question(question: str) -> bool:
    """
    Heuristic detector for user questions specifically about attack paths/chains.
    """
    q = str(question or "").strip().lower()
    if not q:
        return False

    direct_phrases = (
        "attack path",
        "attack paths",
        "attack chain",
        "attack chains",
        "exploit chain",
        "kill chain",
        "killchain",
        "critical path",
        "path to compromise",
    )
    if any(phrase in q for phrase in direct_phrases):
        return True

    if "path" in q and ("exploit" in q or "compromise" in q or "attack" in q):
        return True
    if "chain" in q and ("exploit" in q or "attack" in q):
        return True
    return False


def render_attack_path_response(contract: Dict[str, Any], *, max_chains: int = 3) -> str:
    """
    Deterministic user-facing answer for attack-path questions.
    """
    session_id = str(contract.get("session_id") or "unknown")
    graph_hash = str(contract.get("graph_hash") or "")
    chains = contract.get("chains")
    if not isinstance(chains, list):
        chains = []

    chain_count = _coerce_int(contract.get("chain_count"), default=len(chains), minimum=0)
    if chain_count <= 0:
        return (
            f"Graph-validated attack paths for session {session_id}: 0.\n"
            "No confirmed attack chain currently exists in the deterministic causal graph.\n"
            f"graph_hash={graph_hash}"
        ).strip()

    lines: List[str] = [
        f"Graph-validated attack paths for session {session_id}: {chain_count}.",
        f"graph_hash={graph_hash}",
        "Top chains:",
    ]
    for chain in chains[: max(1, max_chains)]:
        chain_id = str(chain.get("id") or "chain")
        labels = chain.get("labels")
        if isinstance(labels, list) and labels:
            label_text = " -> ".join(str(item) for item in labels if str(item))
        else:
            node_ids = chain.get("node_ids")
            label_text = " -> ".join(str(item) for item in node_ids if str(item)) if isinstance(node_ids, list) else ""
        if not label_text:
            label_text = "(chain labels unavailable)"
        lines.append(f"- {chain_id}: {label_text}")

    return "\n".join(lines).strip()


def _extract_stated_count(text: str) -> Optional[int]:
    if not _ATTACK_PATH_TERM_RE.search(text):
        return None
    match = _NUMBER_RE.search(text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def _line_references_chain_id(text: str, valid_chain_ids: List[str]) -> bool:
    if not valid_chain_ids:
        return False
    tokens = {
        token.strip().lower()
        for token in _TOKEN_SPLIT_RE.split(text)
        if token and token.strip()
    }
    if not tokens:
        return False
    return any(chain_id.lower() in tokens for chain_id in valid_chain_ids)


def sanitize_attack_path_claims(
    text: str,
    contract: Dict[str, Any],
    *,
    require_chain_ids: bool = True,
    max_chain_refs: int = 6,
) -> Dict[str, Any]:
    """
    Post-generation guardrail for narrative text that mentions attack paths.

    Rules:
      - If graph chain count is 0 and text mentions attack paths/chains, replace
        output with deterministic "0 graph-validated paths" response.
      - If graph has chains and require_chain_ids=True, attack-path claim lines
        must either:
          1) reference at least one valid chain ID, or
          2) state the exact graph chain count.
        Non-compliant lines are removed and a guardrail note is appended.
    """
    raw = str(text or "").strip()
    if not raw:
        return {
            "text": "",
            "modified": False,
            "reason": "empty",
            "removed_claims": 0,
            "chain_count": 0,
            "chain_ids": [],
        }

    chain_count = _coerce_int(contract.get("chain_count"), default=0, minimum=0)
    chain_ids = [cid for cid in _to_str_list(contract.get("chain_ids")) if cid]

    if chain_count <= 0:
        if _ATTACK_PATH_TERM_RE.search(raw):
            return {
                "text": render_attack_path_response(contract),
                "modified": True,
                "reason": "no_graph_paths",
                "removed_claims": 1,
                "chain_count": 0,
                "chain_ids": [],
            }
        return {
            "text": raw,
            "modified": False,
            "reason": "no_attack_terms",
            "removed_claims": 0,
            "chain_count": 0,
            "chain_ids": [],
        }

    if not require_chain_ids or not chain_ids:
        return {
            "text": raw,
            "modified": False,
            "reason": "id_check_disabled",
            "removed_claims": 0,
            "chain_count": chain_count,
            "chain_ids": chain_ids,
        }

    lines = raw.splitlines()
    kept_lines: List[str] = []
    removed_claims = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            kept_lines.append(line)
            continue
        if not _ATTACK_PATH_TERM_RE.search(stripped):
            kept_lines.append(line)
            continue

        # Contradicting "no paths" claims are never allowed when graph has chains.
        if _NEGATIVE_CLAIM_RE.search(stripped):
            removed_claims += 1
            continue

        if _line_references_chain_id(stripped, chain_ids):
            kept_lines.append(line)
            continue

        stated_count = _extract_stated_count(stripped)
        if stated_count is not None and stated_count == chain_count:
            kept_lines.append(line)
            continue

        removed_claims += 1

    if removed_claims <= 0:
        return {
            "text": raw,
            "modified": False,
            "reason": "compliant",
            "removed_claims": 0,
            "chain_count": chain_count,
            "chain_ids": chain_ids,
        }

    kept_text = "\n".join(kept_lines).strip()
    if not kept_text:
        return {
            "text": render_attack_path_response(contract),
            "modified": True,
            "reason": "all_claims_removed",
            "removed_claims": removed_claims,
            "chain_count": chain_count,
            "chain_ids": chain_ids,
        }

    chain_ref_text = ", ".join(chain_ids[: max(1, max_chain_refs)])
    guarded = (
        f"{kept_text}\n\n"
        f"[Guardrail] Removed {removed_claims} unvalidated attack-path claim(s). "
        f"Reference graph chain IDs only: {chain_ref_text}."
    ).strip()
    return {
        "text": guarded,
        "modified": True,
        "reason": "removed_unvalidated_claims",
        "removed_claims": removed_claims,
        "chain_count": chain_count,
        "chain_ids": chain_ids,
    }


__all__ = [
    "build_attack_path_contract",
    "extract_attack_chains",
    "is_attack_path_question",
    "render_attack_path_response",
    "sanitize_attack_path_claims",
]
