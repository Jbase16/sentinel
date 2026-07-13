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
import secrets
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence, Tuple
from urllib.parse import urlparse

from core.safety.action_classifier import (
    CROSS_OBJECT_READ, OWNED_CREATE, PRIVILEGE_MUTATION,
)

# Path segments that are object ids get collapsed so enumeration shares one key.
_NUM_RE = re.compile(r"^\d+$")
_IDT_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*_\d+$")           # note_901, file_500
_PREFIXED_OPAQUE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]*_[A-Za-z0-9]{12,}$"
)  # note_7fa9f13a2b4c5d6e
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-", re.IGNORECASE)


def endpoint_key(url: str) -> str:
    """Collapse id-like path segments to `*` so a by-id endpoint is one bucket."""
    try:
        p = urlparse(url or "")
    except Exception:
        p = None
    path = (p.path if (p and p.path) else (url or ""))
    host = p.netloc if p else ""
    out = ["*" if (seg and (
               _NUM_RE.match(seg)
               or _IDT_RE.match(seg)
               or _PREFIXED_OPAQUE_RE.match(seg)
               or _UUID_RE.match(seg)
           ))
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
    _reservations: Dict[str, Tuple[Tuple[str, str], ...]] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _reservation_counter: int = field(default=0, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def _reserved_counts(self) -> Tuple[int, Dict[str, int], int, int, int]:
        entries = [entry for sequence in self._reservations.values() for entry in sequence]
        per_endpoint: Dict[str, int] = {}
        cross = 0
        privilege = 0
        creates = 0
        for action_class, ep_key in entries:
            per_endpoint[ep_key] = per_endpoint.get(ep_key, 0) + 1
            if action_class == CROSS_OBJECT_READ:
                cross += 1
            elif action_class == PRIVILEGE_MUTATION:
                privilege += 1
            elif action_class == OWNED_CREATE:
                creates += 1
        return len(entries), per_endpoint, cross, privilege, creates

    def _allows_counts(
        self,
        action_class: str,
        ep_key: str,
        *,
        total: int,
        per_endpoint: Dict[str, int],
        cross: int,
        privilege: int,
        creates: int,
    ) -> Tuple[bool, str]:
        if total >= self.max_total_requests:
            return False, "total_request_budget_exhausted"
        if per_endpoint.get(ep_key, 0) >= self.max_requests_per_endpoint:
            return False, f"per_endpoint_budget_exhausted ({ep_key})"
        if action_class == CROSS_OBJECT_READ and cross >= self.max_cross_object_reads:
            return False, "cross_object_read_budget_exhausted"
        if action_class == PRIVILEGE_MUTATION and privilege >= self.max_privilege_mutations:
            return False, "privilege_mutation_budget_exhausted"
        if action_class == OWNED_CREATE and creates >= self.max_creates:
            return False, "create_budget_exhausted"
        return True, "ok"

    def allows(
        self,
        action_class: str,
        ep_key: str,
        *,
        reservation_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        with self._lock:
            if reservation_id is not None:
                sequence = self._reservations.get(reservation_id)
                if not sequence:
                    return False, "budget_reservation_missing_or_exhausted"
                if sequence[0] != (action_class, ep_key):
                    return False, "budget_reservation_sequence_mismatch"
                return True, "ok"
            reserved_total, reserved_per, reserved_cross, reserved_priv, reserved_creates = (
                self._reserved_counts()
            )
            per_endpoint = dict(self._per_endpoint)
            for key, count in reserved_per.items():
                per_endpoint[key] = per_endpoint.get(key, 0) + count
            return self._allows_counts(
                action_class,
                ep_key,
                total=self._total + reserved_total,
                per_endpoint=per_endpoint,
                cross=self._cross + reserved_cross,
                privilege=self._priv + reserved_priv,
                creates=self._creates + reserved_creates,
            )

    def try_reserve(
        self,
        actions: Sequence[Tuple[str, str]],
    ) -> Tuple[Optional[str], str]:
        """Atomically reserve an ordered sequence without counting it as traffic."""

        if not actions:
            return None, "budget_reservation_requires_actions"
        normalized = tuple((str(action_class), str(ep_key)) for action_class, ep_key in actions)
        with self._lock:
            reserved_total, reserved_per, reserved_cross, reserved_priv, reserved_creates = (
                self._reserved_counts()
            )
            total = self._total + reserved_total
            per_endpoint = dict(self._per_endpoint)
            for key, count in reserved_per.items():
                per_endpoint[key] = per_endpoint.get(key, 0) + count
            cross = self._cross + reserved_cross
            privilege = self._priv + reserved_priv
            creates = self._creates + reserved_creates
            for action_class, ep_key in normalized:
                allowed, reason = self._allows_counts(
                    action_class,
                    ep_key,
                    total=total,
                    per_endpoint=per_endpoint,
                    cross=cross,
                    privilege=privilege,
                    creates=creates,
                )
                if not allowed:
                    return None, reason
                total += 1
                per_endpoint[ep_key] = per_endpoint.get(ep_key, 0) + 1
                if action_class == CROSS_OBJECT_READ:
                    cross += 1
                elif action_class == PRIVILEGE_MUTATION:
                    privilege += 1
                elif action_class == OWNED_CREATE:
                    creates += 1
            self._reservation_counter += 1
            reservation_id = (
                f"budget_reservation:{self._reservation_counter}:"
                f"{secrets.token_urlsafe(24)}"
            )
            self._reservations[reservation_id] = normalized
            return reservation_id, "ok"

    def release_reservation(self, reservation_id: str) -> int:
        """Release all unused slots and return how many were freed."""

        with self._lock:
            sequence = self._reservations.pop(reservation_id, ())
            return len(sequence)

    def reservation_remaining(self, reservation_id: str) -> int:
        with self._lock:
            return len(self._reservations.get(reservation_id, ()))

    def skip_reservation_entries(self, reservation_id: str, count: int) -> int:
        """Atomically release the next ``count`` unused ordered slots."""

        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("reservation skip count must be a non-negative integer")
        with self._lock:
            sequence = self._reservations.get(reservation_id)
            if sequence is None:
                raise ValueError("budget reservation does not exist")
            skipped = min(count, len(sequence))
            remaining = sequence[skipped:]
            if remaining:
                self._reservations[reservation_id] = remaining
            else:
                del self._reservations[reservation_id]
            return skipped

    def record(
        self,
        action_class: str,
        ep_key: str,
        status: Optional[int] = None,
        *,
        reservation_id: Optional[str] = None,
    ) -> None:
        with self._lock:
            if reservation_id is not None:
                sequence = self._reservations.get(reservation_id)
                if not sequence or sequence[0] != (action_class, ep_key):
                    raise RuntimeError("budget reservation changed after policy approval")
                remaining = sequence[1:]
                if remaining:
                    self._reservations[reservation_id] = remaining
                else:
                    del self._reservations[reservation_id]
            self._total += 1
            self._per_endpoint[ep_key] = self._per_endpoint.get(ep_key, 0) + 1
            # A denied cross-object read (403/404) read NOTHING, so it doesn't
            # consume the "how much of others' data did you actually read" budget.
            succeeded = status is None or (200 <= int(status) < 300)
            if action_class == CROSS_OBJECT_READ:
                if succeeded:
                    self._cross += 1
            elif action_class == PRIVILEGE_MUTATION:
                self._priv += 1
            elif action_class == OWNED_CREATE:
                self._creates += 1

    def snapshot(self) -> Dict[str, int]:
        return {"total_requests": self._total, "cross_object_reads": self._cross,
                "privilege_mutations": self._priv, "creates": self._creates,
                "endpoints_touched": len(self._per_endpoint)}
