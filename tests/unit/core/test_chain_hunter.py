"""
Unit tests for the self-directing hunt (core/cortex/chain_hunter) — phase 3.

The loop must: escalate (a proven chain unlocks follow-ons → a deeper chain next
iteration), converge (stop when nothing new is proved or unlocked), stay bounded
(max_iterations), and never crash on a failing step.
"""

import pytest

from core.cortex.chain_hunter import ChainHunter, HuntResult


class _Proposal:
    def __init__(self, steps, goal):
        self.steps, self.goal = steps, goal

    def signature(self):
        return (tuple(self.steps), self.goal)


class _Verif:
    def __init__(self, proposal):
        self.proposal = proposal


def _chain(steps, goal):
    return _Verif(_Proposal(steps, goal))


# ─────────────────────────────── escalation ─────────────────────────────────

@pytest.mark.asyncio
async def test_hunt_escalates_then_converges():
    # iter1: only SQLi known → one shallow chain; proving it unlocks IDOR.
    # iter2: with IDOR, a deeper chain to account_takeover appears; nothing new
    # unlocks after → converge.
    async def synthesize(findings):
        has_idor = any("idor" in str(f.get("type", "")).lower() for f in findings)
        chains = [_chain(["sqli"], "data_exfiltration")]
        if has_idor:
            chains.append(_chain(["sqli", "idor"], "account_takeover"))
        return chains

    async def verify_chains(chains):
        return list(chains)  # everything verifies in this mock

    async def expand(fresh, findings):
        # A proven SQLi unlocks an IDOR follow-on (returned every call; the
        # engine dedups it so iter2 sees nothing new).
        return [{"type": "IDOR (active verification)", "target": "https://x/api/1"}]

    res = await ChainHunter(max_iterations=5).hunt(
        [{"type": "SQLi", "target": "https://x/s?q=1"}],
        synthesize=synthesize, verify_chains=verify_chains, expand=expand,
    )
    assert isinstance(res, HuntResult)
    assert res.iterations == 2                       # escalated once, then converged
    assert len(res.verified) == 2                    # shallow + deep chain
    assert {v.proposal.goal for v in res.verified} == {"data_exfiltration", "account_takeover"}
    assert len(res.findings_added) == 1              # the unlocked IDOR
    assert res.top_goal == "account_takeover"        # highest-impact reached


# ─────────────────────────────── convergence ────────────────────────────────

@pytest.mark.asyncio
async def test_converges_when_nothing_unlocked():
    async def synthesize(findings):
        return [_chain(["sqli"], "data_exfiltration")]

    async def verify_chains(chains):
        return list(chains)

    async def expand(fresh, findings):
        return []  # nothing further unlocks

    res = await ChainHunter().hunt(
        [{"type": "SQLi", "target": "t"}],
        synthesize=synthesize, verify_chains=verify_chains, expand=expand,
    )
    assert res.iterations == 1
    assert len(res.verified) == 1


@pytest.mark.asyncio
async def test_stops_when_no_chain_synthesized():
    async def synthesize(findings):
        return []

    res = await ChainHunter().hunt(
        [], synthesize=synthesize,
        verify_chains=lambda c: _async([]), expand=lambda v, f: _async([]),
    )
    assert res.iterations == 1
    assert res.verified == []


@pytest.mark.asyncio
async def test_stops_when_nothing_newly_verified():
    async def synthesize(findings):
        return [_chain(["sqli"], "data_exfiltration")]

    async def verify_chains(chains):
        return []  # nothing confirms

    res = await ChainHunter().hunt(
        [{"type": "SQLi", "target": "t"}],
        synthesize=synthesize, verify_chains=verify_chains, expand=lambda v, f: _async([]),
    )
    assert res.iterations == 1
    assert res.verified == []


# ─────────────────────────────── bounded ────────────────────────────────────

@pytest.mark.asyncio
async def test_respects_max_iterations_under_endless_escalation():
    counter = {"n": 0}

    async def synthesize(findings):
        counter["n"] += 1
        # A genuinely new chain every call → never converges on its own.
        return [_chain([f"step{counter['n']}"], "data_exfiltration")]

    async def verify_chains(chains):
        return list(chains)

    async def expand(fresh, findings):
        # Always unlocks a brand-new primitive → endless without the cap.
        return [{"type": f"NEW{counter['n']}", "target": f"t{counter['n']}"}]

    res = await ChainHunter(max_iterations=3).hunt(
        [{"type": "SQLi", "target": "t"}],
        synthesize=synthesize, verify_chains=verify_chains, expand=expand,
    )
    assert res.iterations == 3  # hard stop at the cap


# ─────────────────────────────── fault isolation ────────────────────────────

@pytest.mark.asyncio
async def test_synthesize_failure_does_not_crash():
    async def boom(findings):
        raise RuntimeError("omega exploded")

    res = await ChainHunter().hunt(
        [{"type": "SQLi", "target": "t"}],
        synthesize=boom, verify_chains=lambda c: _async([]), expand=lambda v, f: _async([]),
    )
    assert res.verified == []  # degraded, not raised


async def _async(value):
    return value
