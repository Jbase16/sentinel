"""
Unit tests for the chain verifier (core/cortex/chain_verifier) — phase 2, loop closure.

A hypothesized omega chain becomes a VERIFIED killchain only if its live-testable
steps confirm; a single refuted testable step breaks it; a chain with no testable
step stays HYPOTHESIZED and is never asserted as fact.
"""

import pytest

from core.cortex import chain_arbiter as ca
from core.cortex import chain_verifier as cv


def _omega_chain(prim_types_targets, goal="account_takeover"):
    """Build a HYPOTHESIZED omega-style proposal with raw primitive steps."""
    steps = [
        {"step": i + 1, "primitive_type": pt, "target": tgt, "confidence": 0.8}
        for i, (pt, tgt) in enumerate(prim_types_targets)
    ]
    return ca.ChainProposal(
        source="omega", method="semantic-synthesis", epistemic=ca.HYPOTHESIZED,
        steps=[f"{pt}@{tgt}" for pt, tgt in prim_types_targets] + [f"⇒ {goal}"],
        length=len(steps), score=0.9, goal=goal, raw={"steps": steps},
    )


def _mock(outcomes):
    """verify_step driven by a url -> outcome map (True/False/None).
    Missing urls default to None (inconclusive), which must NOT refute."""
    async def step(vclass, url):
        outcome = outcomes.get(url, None)
        return outcome, {True: "confirmed", False: "disproven", None: "inconclusive"}[outcome]
    return step


@pytest.mark.asyncio
async def test_verified_when_all_testable_steps_confirm():
    chain = _omega_chain([("idor_pattern", "https://x.test/api/users/1"),
                          ("ssrf_pattern", "https://x.test/fetch")])
    step = _mock({"https://x.test/api/users/1": True, "https://x.test/fetch": True})
    res = await cv.ChainVerifier().verify_chain(chain, step)
    assert res.verdict == cv.VERIFIED
    assert chain.epistemic == cv.VERIFIED      # promotion is reflected on the proposal
    assert res.confirmed == 2 and res.tested == 2


@pytest.mark.asyncio
async def test_refuted_when_a_testable_step_fails():
    chain = _omega_chain([("idor_pattern", "https://x.test/api/users/1"),
                          ("ssrf_pattern", "https://x.test/fetch")])
    step = _mock({"https://x.test/api/users/1": True,
                  "https://x.test/fetch": False})  # ssrf explicitly disproven
    res = await cv.ChainVerifier().verify_chain(chain, step)
    assert res.verdict == cv.REFUTED
    assert chain.epistemic == cv.REFUTED


@pytest.mark.asyncio
async def test_inconclusive_step_does_not_refute():
    # One step confirms, the other is inconclusive (None) -> VERIFIED, not refuted.
    chain = _omega_chain([("idor_pattern", "https://x.test/u/1"),
                          ("ssrf_pattern", "https://x.test/fetch")])
    step = _mock({"https://x.test/u/1": True})  # fetch -> None (inconclusive)
    res = await cv.ChainVerifier().verify_chain(chain, step)
    assert res.verdict == cv.VERIFIED
    assert res.confirmed == 1

    # ALL steps inconclusive -> stays hypothesized, never refuted.
    chain2 = _omega_chain([("idor_pattern", "https://x.test/u/9")])
    res2 = await cv.ChainVerifier().verify_chain(chain2, _mock({}))
    assert res2.verdict == cv.HYPOTHESIZED


@pytest.mark.asyncio
async def test_stays_hypothesized_when_no_testable_steps():
    # missing_auth / file_upload aren't in PRIMITIVE_TO_VULN_CLASS -> not testable.
    chain = _omega_chain([("missing_auth", "https://x.test/api"),
                          ("file_upload", "https://x.test/upload")])
    res = await cv.ChainVerifier().verify_chain(chain, _mock({}))
    assert res.verdict == cv.HYPOTHESIZED
    assert chain.epistemic == ca.HYPOTHESIZED   # unchanged


@pytest.mark.asyncio
async def test_observed_chains_are_not_retested():
    cortex_chain = ca.ChainProposal(
        source="cortex", method="observed-correlation", epistemic=ca.OBSERVED,
        steps=["a", "b"], length=2, score=0.5,
    )
    res = await cv.ChainVerifier().verify_chain(cortex_chain, _mock({"a": False}))
    assert res.verdict == ca.OBSERVED
    assert cortex_chain.epistemic == ca.OBSERVED


@pytest.mark.asyncio
async def test_step_error_is_not_a_refutation():
    async def boom_then_ok(vclass, url):
        if "idor" in vclass:
            raise RuntimeError("network blip")
        return True, "confirmed"
    chain = _omega_chain([("idor_pattern", "https://x.test/u/1"),
                          ("ssrf_pattern", "https://x.test/fetch")])
    res = await cv.ChainVerifier().verify_chain(chain, boom_then_ok)
    # idor errored (skipped, not refuted); ssrf confirmed -> VERIFIED
    assert res.verdict == cv.VERIFIED
    assert res.confirmed == 1


@pytest.mark.asyncio
async def test_sqli_pattern_step_is_live_testable():
    # SQLI_PATTERN was added to omega's vocabulary; it must map to the SQLi
    # verifier class so a confirmed SQLi promotes its chain to a killchain.
    chain = _omega_chain([("sqli_pattern", "https://x.test/search?q=a")],
                         goal="data_exfiltration")
    res = await cv.ChainVerifier().verify_chain(chain, _mock({"https://x.test/search?q=a": True}))
    assert res.verdict == cv.VERIFIED
    assert res.confirmed == 1


@pytest.mark.asyncio
async def test_verify_partitions_the_set():
    good = _omega_chain([("idor_pattern", "https://x.test/u/1")], goal="account_takeover")
    bad = _omega_chain([("ssrf_pattern", "https://x.test/fetch")], goal="data_exfiltration")
    untestable = _omega_chain([("missing_auth", "https://x.test/api")], goal="auth_bypass")
    step = _mock({"https://x.test/u/1": True,        # good confirms
                  "https://x.test/fetch": False})    # bad disproven; untestable n/a
    report = await cv.ChainVerifier().verify([good, bad, untestable], step)
    assert report["counts"] == {cv.VERIFIED: 1, cv.REFUTED: 1, "untested": 1, "input": 3}
