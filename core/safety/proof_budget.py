"""
core/safety/proof_budget.py

A hard ceiling on how much a scan is allowed to *do* while proving a class. The
point is to confirm capability without consuming it: prove the door unlocks
without walking the whole building.

Endpoint counting is done on the TEMPLATE, not the concrete URL — `/api/files/500`
and `/api/files/501` are the same endpoint, so id-enumeration burns the
per-endpoint budget fast and stops, instead of quietly sweeping a population one
distinct URL at a time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Tuple
from urllib.parse import urlparse

from core.safety.action_classifier import (
    CROSS_OBJECT_READ, OWNED_CREATE, PRIVILEGE_MUTATION,
)

# Path segments that are object ids get collapsed so enumeration shares one key.
_NUM_RE = re.compile(r"^\d+$")
_IDT_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*_\d+$")           # note_901, file_500
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-", re.IGNORECASE)


def endpoint_key(url: str) -> str:
    """Collapse id-like path segments to `*` so a by-id endpoint is one bucket."""
    try:
        p = urlparse(url or "")
    except Exception:
        p = None
    path = (p.path if (p and p.path) else (url or ""))
    host = p.netloc if p else ""
    out = ["*" if (seg and (_NUM_RE.match(seg) or _IDT_RE.match(seg) or _UUID_RE.match(seg)))
           else seg
           for seg in path.split("/")]
    return f"{host}{'/'.join(out)}"


@dataclass
class ProofBudget:
    max_total_requests: int = 500
    max_requests_per_endpoint: int = 5
    max_cross_object_reads: int = 1
    max_privilege_mutations: int = 2
    max_creates: int = 8
    allow_delete: bool = False
    allow_real_user_data_access: bool = True

    _total: int = field(default=0, init=False)
    _per_endpoint: Dict[str, int] = field(default_factory=dict, init=False)
    _cross: int = field(default=0, init=False)
    _priv: int = field(default=0, init=False)
    _creates: int = field(default=0, init=False)

    def allows(self, action_class: str, ep_key: str) -> Tuple[bool, str]:
        if self._total >= self.max_total_requests:
            return False, "total_request_budget_exhausted"
        if self._per_endpoint.get(ep_key, 0) >= self.max_requests_per_endpoint:
            return False, f"per_endpoint_budget_exhausted ({ep_key})"
        if action_class == CROSS_OBJECT_READ and self._cross >= self.max_cross_object_reads:
            return False, "cross_object_read_budget_exhausted"
        if action_class == PRIVILEGE_MUTATION and self._priv >= self.max_privilege_mutations:
            return False, "privilege_mutation_budget_exhausted"
        if action_class == OWNED_CREATE and self._creates >= self.max_creates:
            return False, "create_budget_exhausted"
        return True, "ok"

    def record(self, action_class: str, ep_key: str) -> None:
        self._total += 1
        self._per_endpoint[ep_key] = self._per_endpoint.get(ep_key, 0) + 1
        if action_class == CROSS_OBJECT_READ:
            self._cross += 1
        elif action_class == PRIVILEGE_MUTATION:
            self._priv += 1
        elif action_class == OWNED_CREATE:
            self._creates += 1

    def snapshot(self) -> Dict[str, int]:
        return {"total_requests": self._total, "cross_object_reads": self._cross,
                "privilege_mutations": self._priv, "creates": self._creates,
                "endpoints_touched": len(self._per_endpoint)}
