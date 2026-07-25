"""
Unit tests for the multi-proposer exploit-chain ensemble (core/cortex/chain_arbiter).

Guards the contract that makes "keep both chain engines" safe:
  - cortex chains are OBSERVED, omega chains are HYPOTHESIZED, and the label survives.
  - the arbiter runs proposers best-effort (a raising proposer never breaks it),
    normalizes different score scales onto a common [0,1], dedups, and ranks.
  - the omega proposer genuinely synthesizes goal-reaching chains from primitives.
"""

import pytest

from core.cortex import chain_arbiter as ca


@pytest.fixture(autouse=True)
def _init_sequence_authority():
    # omega emits GraphEvents whose construction needs the global sequence
    # authority (initialized from DB at app startup). Stand it up for tests.
    from core.base.sequence import GlobalSequenceAuthority as GSA
    GSA._initialized = True
    GSA()
    yield


# ----------------------------------------------------------- cortex proposer

@pytest.mark.asyncio
async def test_cortex_proposer_adapts_dto_as_observed():
    dto = {"attack_chains": [
        {"labels": ["recon", "open-redirect", "token-leak"], "node_ids": ["n1", "n2", "n3"], "score": 4.0},
        {"labels": [], "node_ids": [], "score": 9.0},  # empty -> skipped
    ]}
    ctx = ca.ChainContext(target="x.test", graph_dto=dto)
    props = await ca.CortexChainProposer().propose(ctx)
    assert len(props) == 1
    assert props[0].epistemic == ca.OBSERVED
    assert props[0].source == "cortex"
    assert props[0].length == 3


# ------------------------------------------------------------ omega proposer

@pytest.mark.asyncio
async def test_omega_proposer_synthesizes_hypothesized_goal_chains():
    findings = [
        {"type": "Missing Authentication", "title": "unauthenticated api", "severity": "LOW",
         "target": "https://x.test/api", "message": "no auth required"},
        {"type": "IDOR", "title": "insecure direct object reference", "severity": "MEDIUM",
         "target": "https://x.test/api/users/1", "message": "object reference manipulable"},
        {"type": "SSRF", "title": "server-side request forgery", "severity": "HIGH",
         "target": "https://x.test/fetch", "message": "ssrf metadata service"},
    ]
    ctx = ca.ChainContext(target="x.test", findings=findings)
    props = await ca.OmegaChainProposer().propose(ctx)
    assert props, "omega should synthesize chains from independent primitives"
    assert all(p.epistemic == ca.HYPOTHESIZED for p in props)
    # Chains must reach a named adversary goal.
    assert all(p.goal for p in props)
    assert any(p.steps[-1].startswith("⇒") for p in props)


@pytest.mark.asyncio
async def test_omega_proposer_empty_on_untyped_findings():
    # Findings with no recognizable primitive pattern -> no chains, no crash.
    findings = [{"type": "Missing Security Header", "title": "missing hsts",
                 "severity": "LOW", "target": "https://x.test"}]
    props = await ca.OmegaChainProposer().propose(ca.ChainContext(target="x.test", findings=findings))
    assert props == []


# ----------------------------------------------------------------- arbiter

@pytest.mark.asyncio
async def test_arbiter_merges_normalizes_and_ranks():
    dto = {"attack_chains": [
        {"labels": ["a", "b"], "node_ids": ["a", "b"], "score": 2.0},
        {"labels": ["a", "b", "c"], "node_ids": ["a", "b", "c"], "score": 8.0},
    ]}
    findings = [
        {"type": "Missing Authentication", "title": "no auth", "severity": "LOW",
         "target": "https://x.test/api", "message": "unauthenticated"},
        {"type": "IDOR", "title": "idor", "severity": "MEDIUM",
         "target": "https://x.test/u/1", "message": "insecure direct object reference"},
    ]
    ctx = ca.ChainContext(target="x.test", findings=findings, graph_dto=dto)
    out = await ca.ChainArbiter.default().arbitrate(ctx, top_n=25)

    assert out, "ensemble should produce chains"
    # Both epistemic classes represented (observed from cortex, hypothesized from omega).
    kinds = {p.epistemic for p in out}
    assert ca.OBSERVED in kinds and ca.HYPOTHESIZED in kinds
    # All scores normalized to [0,1] and globally ranked descending.
    assert all(0.0 <= p.score <= 1.0 for p in out)
    assert out == sorted(out, key=lambda p: p.score, reverse=True)


@pytest.mark.asyncio
async def test_arbiter_survives_a_raising_proposer():
    class Boom:
        name = "boom"
        async def propose(self, ctx):
            raise RuntimeError("kaboom")

    dto = {"attack_chains": [{"labels": ["a", "b"], "node_ids": ["a", "b"], "score": 1.0}]}
    arb = ca.ChainArbiter().register(Boom()).register(ca.CortexChainProposer())
    out = await arb.arbitrate(ca.ChainContext(target="x.test", graph_dto=dto))
    assert len(out) == 1  # cortex survives the boom


def test_dedup_observed_beats_hypothesized():
    obs = ca.ChainProposal(source="cortex", method="observed-correlation",
                           epistemic=ca.OBSERVED, steps=["a", "b"], length=2, score=0.5)
    hyp = ca.ChainProposal(source="omega", method="semantic-synthesis",
                           epistemic=ca.HYPOTHESIZED, steps=["A", "B"], length=2, score=0.9)
    merged = ca.ChainArbiter._dedup([hyp, obs])
    assert len(merged) == 1
    assert merged[0].epistemic == ca.OBSERVED
    assert set(merged[0].sources) == {"cortex", "omega"}
