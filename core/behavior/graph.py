"""Bounded passive action/state graph and relational coverage accounting."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from .models import NormalizedExchange
from .normalize import stable_hash


@dataclass(frozen=True)
class GraphLimits:
    max_worlds: int = 32
    max_actions: int = 4_096
    max_states: int = 8_192
    max_transitions: int = 32_768
    max_content_variants_per_action: int = 64

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ObservationResult:
    accepted: bool
    new_world: bool = False
    new_action: bool = False
    new_state: bool = False
    new_transition: bool = False
    reason: str = "ok"


class BehaviorGraph:
    """In-memory passive model.

    The graph is intentionally persistence-free and execution-free.  It stores
    structural descriptors and hashes only.  Hard limits make ingestion safe even
    when a target returns adversarially unique responses.
    """

    def __init__(self, limits: Optional[GraphLimits] = None):
        self.limits = limits or GraphLimits()
        self.actions: Dict[str, Dict[str, Any]] = {}
        self.states: Dict[str, Dict[str, Any]] = {}
        self.transitions: Dict[str, Dict[str, Any]] = {}
        self._world_heads: Dict[str, str] = {}
        self._action_worlds: Dict[str, Set[str]] = {}
        self._action_states: Dict[str, Set[str]] = {}
        self._action_content_hashes: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()
        self.observations = 0
        self.duplicate_transitions = 0
        self.dropped: Dict[str, int] = {
            "worlds": 0,
            "actions": 0,
            "states": 0,
            "transitions": 0,
            "content_variants": 0,
        }

    def observe(self, exchange: NormalizedExchange) -> ObservationResult:
        with self._lock:
            return self._observe_locked(exchange)

    def _observe_locked(self, exchange: NormalizedExchange) -> ObservationResult:
        self.observations += 1
        new_world = exchange.world_id not in self._world_heads
        if new_world and len(self._world_heads) >= self.limits.max_worlds:
            self.dropped["worlds"] += 1
            return ObservationResult(False, reason="world_limit")

        new_action = exchange.action_id not in self.actions
        if new_action and len(self.actions) >= self.limits.max_actions:
            self.dropped["actions"] += 1
            return ObservationResult(False, new_world=new_world, reason="action_limit")

        new_state = exchange.state_id not in self.states
        if new_state and len(self.states) >= self.limits.max_states:
            self.dropped["states"] += 1
            return ObservationResult(
                False, new_world=new_world, new_action=new_action, reason="state_limit"
            )

        previous_state = self._world_heads.get(exchange.world_id)
        transition_descriptor = {
            "previous_state_id": previous_state,
            "action_id": exchange.action_id,
            "next_state_id": exchange.state_id,
        }
        transition_id = stable_hash("transition", transition_descriptor)
        new_transition = transition_id not in self.transitions
        if new_transition and len(self.transitions) >= self.limits.max_transitions:
            self.dropped["transitions"] += 1
            return ObservationResult(
                False,
                new_world=new_world,
                new_action=new_action,
                new_state=new_state,
                reason="transition_limit",
            )

        if new_action:
            self.actions[exchange.action_id] = exchange.action_descriptor()
        if new_state:
            self.states[exchange.state_id] = exchange.state_descriptor()
        if new_transition:
            self.transitions[transition_id] = {
                **transition_descriptor,
                "world_ids": {exchange.world_id},
                "observations": 1,
            }
        else:
            transition = self.transitions[transition_id]
            transition["world_ids"].add(exchange.world_id)
            transition["observations"] += 1
            self.duplicate_transitions += 1

        self._world_heads[exchange.world_id] = exchange.state_id
        self._action_worlds.setdefault(exchange.action_id, set()).add(exchange.world_id)
        self._action_states.setdefault(exchange.action_id, set()).add(exchange.state_id)
        if exchange.response_body_hash:
            hashes = self._action_content_hashes.setdefault(exchange.action_id, set())
            if exchange.response_body_hash not in hashes:
                if len(hashes) < self.limits.max_content_variants_per_action:
                    hashes.add(exchange.response_body_hash)
                else:
                    self.dropped["content_variants"] += 1

        return ObservationResult(
            True,
            new_world=new_world,
            new_action=new_action,
            new_state=new_state,
            new_transition=new_transition,
        )

    def coverage(self) -> Dict[str, Any]:
        with self._lock:
            return self._coverage_locked()

    def _coverage_locked(self) -> Dict[str, Any]:
        cross_world = {
            action_id for action_id, worlds in self._action_worlds.items() if len(worlds) >= 2
        }
        structural_divergences = {
            action_id for action_id in cross_world if len(self._action_states.get(action_id, set())) >= 2
        }
        content_variants = {
            action_id
            for action_id in cross_world
            if len(self._action_content_hashes.get(action_id, set())) >= 2
        }
        return {
            "observations": self.observations,
            "worlds": len(self._world_heads),
            "actions": len(self.actions),
            "states": len(self.states),
            "transitions": len(self.transitions),
            "duplicate_transitions": self.duplicate_transitions,
            "cross_world_actions": len(cross_world),
            "cross_world_structural_divergences": len(structural_divergences),
            "cross_world_content_variants": len(content_variants),
            "dropped": dict(self.dropped),
        }

    def snapshot(self) -> Dict[str, Any]:
        """Return a deterministic JSON-safe diagnostic snapshot."""
        with self._lock:
            transitions = {
                key: {
                    **value,
                    "world_ids": sorted(value["world_ids"]),
                }
                for key, value in sorted(self.transitions.items())
            }
            return {
                "schema_version": 1,
                "mode": "passive_shadow",
                "coverage": self._coverage_locked(),
                "actions": {key: self.actions[key] for key in sorted(self.actions)},
                "states": {key: self.states[key] for key in sorted(self.states)},
                "transitions": transitions,
                "world_heads": {key: self._world_heads[key] for key in sorted(self._world_heads)},
            }
