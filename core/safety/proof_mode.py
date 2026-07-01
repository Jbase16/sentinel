"""
core/safety/proof_mode.py

The execution posture for a scan. Same reasoning core, three envelopes:

  LAB          maximize confirmed blast radius (validate against owned labs)
  BOUNTY_SAFE  minimize impact while confirming exploitability (real programs)
  PASSIVE      infer only — no active exploit execution at all

The split is deliberate: don't castrate the lab engine to make the bounty engine
safe. LAB imposes no restrictions (the executor is a pass-through), so existing
behavior and tests are untouched. BOUNTY_SAFE allows only a narrow set of action
classes and a tight proof budget; UNKNOWN is denied by omission. PASSIVE allows
reads and nothing else.
"""

from __future__ import annotations

from typing import Optional, Set, Tuple

from core.safety.action_classifier import (
    AUTHZ_PROBE, CROSS_OBJECT_READ, OWNED_CREATE, OWNED_UPDATE_LOW_RISK,
    PRIVILEGE_MUTATION, SAFE_READ,
)
from core.safety.proof_budget import ProofBudget


class ProofMode:
    LAB = "lab"
    BOUNTY_SAFE = "bounty_safe"
    PASSIVE = "passive"

    _ALIASES = {"bounty": BOUNTY_SAFE, "bounty_safe": BOUNTY_SAFE, "safe": BOUNTY_SAFE,
                "lab": LAB, "passive": PASSIVE, "recon": PASSIVE}

    @classmethod
    def normalize(cls, value: Optional[str]) -> str:
        return cls._ALIASES.get((value or "lab").strip().lower(), cls.LAB)


_BOUNTY_ALLOWED: Set[str] = {
    SAFE_READ, OWNED_CREATE, OWNED_UPDATE_LOW_RISK, AUTHZ_PROBE,
    PRIVILEGE_MUTATION,        # only on an owned account; wielding is bounded by budget
    CROSS_OBJECT_READ,         # bounded to max_cross_object_reads (default 1)
}
_PASSIVE_ALLOWED: Set[str] = {SAFE_READ}


def rules_for(mode: str) -> Tuple[Optional[Set[str]], ProofBudget]:
    """Return (allowed_classes | None, budget). `None` allowed-set means "all
    classes allowed" (LAB); the budget is effectively unlimited there."""
    mode = ProofMode.normalize(mode)
    if mode == ProofMode.BOUNTY_SAFE:
        return _BOUNTY_ALLOWED, ProofBudget(
            max_total_requests=400, max_requests_per_endpoint=3,
            max_cross_object_reads=1, max_privilege_mutations=2, max_creates=4,
            allow_delete=False, allow_real_user_data_access=False,
        )
    if mode == ProofMode.PASSIVE:
        return _PASSIVE_ALLOWED, ProofBudget(
            max_total_requests=200, max_requests_per_endpoint=3,
            max_cross_object_reads=0, max_privilege_mutations=0, max_creates=0,
            allow_delete=False, allow_real_user_data_access=False,
        )
    # LAB: unrestricted — the executor becomes a pass-through.
    _INF = 10 ** 9
    return None, ProofBudget(
        max_total_requests=_INF, max_requests_per_endpoint=_INF,
        max_cross_object_reads=_INF, max_privilege_mutations=_INF, max_creates=_INF,
        allow_delete=True, allow_real_user_data_access=True,
    )
