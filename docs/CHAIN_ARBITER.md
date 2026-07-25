# Chain Arbiter — multi-proposer exploit-chain ensemble

## Why

SentinelForge has **two** exploit-chain engines that find *different* things (measured, not assumed):

| | `cortex/causal_graph` | `omega/NEXUS` |
|---|---|---|
| Method | `all_simple_paths` over the **observed** correlation graph | goal-directed BFS over a **semantic** enablement model |
| Answers | "what attack paths are *present* in what we detected" | "what primitive sequences could *causally reach an adversary goal*" |
| Needs | observed correlation edges between findings | only typed primitives (no observed edges) |
| Blind spot | chains whose edges were never observed | anything that isn't a *typed* primitive |
| Epistemics | **observed** | **hypothesized** |
| Runtime | coupled to DB/runtime | pure function of its inputs |

Demonstrated: on 5 independent primitives (`missing_auth, idor, ssrf, weak_cors, file_upload`) with **zero** observed correlations, omega synthesized 6 goal-reaching chains (priv-esc, RCE, account-takeover, data-exfil); cortex by construction finds ~0 multi-step chains there. Their union strictly dominates either alone.

So we **keep both** — not as silent parallel writers fighting over one `attack_chains` field, but as **proposers under an arbiter** (the same propose → arbitrate pattern `cortex/arbitration.py` already uses for decisions).

## The epistemic rule (this is the whole point)

cortex chains are *observed*; omega chains are *hypothesized*. **Never present a hypothesis as observed fact** — that's the generic-scanner noise the verification gate exists to kill. Therefore:

- The existing operator-facing `graph_attack_paths` (observed-correlation paths) stays **cortex-only**.
- The merged ensemble is surfaced in an additive `arbitrated_chains` field where every chain carries `source`, `method`, and **`epistemic`** (`observed` | `hypothesized`).
- The closed loop (next phase) feeds *hypothesized* omega chains to the verifier (`wraith`/Ghost); survivors are **promoted** to observed. A hypothesis only becomes fact by surviving verification — exactly like the finding gate.

## Architecture

```
ChainContext(findings, issues, graph_dto, target, session_id)
        │
        ▼
   ChainArbiter
     ├─ CortexChainProposer  → adapts graph_dto["attack_chains"]   (epistemic: observed)
     └─ OmegaChainProposer   → PrimitiveCollector → NEXUS.execute  (epistemic: hypothesized)
        │
        ▼  normalize scores per-source → dedup by signature (merge sources) → rank → top N
   List[ChainProposal]  ──►  results: additive `arbitrated_chains` (graph_attack_paths untouched)
```

### Contracts

- `ChainProposal` — canonical chain: `source`, `method`, `epistemic`, `steps: List[str]`, `goal`, `length`, `score` (0–1 after arbitration), `confidence`, `node_ids` (cortex linkage), `raw`, `sources` (when merged).
- `ChainProposer` (Protocol) — `name: str`; `async propose(ctx) -> List[ChainProposal]`. **Must never raise** into the arbiter; failures degrade to `[]`.
- `ChainArbiter.arbitrate(ctx, top_n) -> List[ChainProposal]` — runs every proposer best-effort, min-max normalizes each source's scores to `[0,1]` (so omega's 0–10 impact scale and cortex's scale rank fairly), dedups by `(steps, goal)` signature (merging `sources`), ranks by score.

### Where it slots in

`get_scan_results` (`core/server/routers/scans.py`), right after `graph_dto` is built. Best-effort, mirroring the verification gate: any failure leaves the existing cortex output completely intact.

## Phasing

1. **✅ Ensemble read-path.** Proposer interface + both proposers + arbiter; surface `arbitrated_chains` additively. Non-breaking — `graph_attack_paths` unchanged. (`core/cortex/chain_arbiter.py`)
2. **✅ Closed loop.** Hypothesized omega chains → `ChainVerifier` re-tests each step's primitive with wraith's `VulnVerifier` (scope+host gated, budget-capped, bug_bounty mode only) → a chain whose steps confirm is **promoted to `verified`** and persisted as a HIGH issue ("Verified Exploit Chain → {goal}"); unconfirmed chains stay `hypothesized`, refuted ones drop. Absence of a confirmation is never a refutation. (`core/cortex/chain_verifier.py`; wired in `scans.py` Phase-2 block)
3. **✅ Self-direction.** `core/cortex/chain_hunter.py` `ChainHunter` runs the hunt iteratively: synthesize → verify → **expand** → repeat. A verified chain's terminal primitive unlocks follow-on vuln classes (omega enablement); the scan's `expand` discovers + verifies THOSE specifically, folds confirmations back in, and re-synthesizes — deepening toward higher goals until it converges. Bounded (`max_iterations`, shared probe budget); never raises into the loop. Wired in `scans.py` (replaces the single-pass block). Live: on unauth Juice Shop it converges at iteration 1 (the SQLi→IDOR follow-on needs auth) — `[chain_hunt] iterations=1 verified=2 escalation_unlocked=0`.
4. **Consolidation.** Once the loop self-directs, retire the orphaned `aegis` entry-point duplication; `aegis` chain *execution* (PoC) becomes the loop's evidence-capture arm.

### A note on URL recovery

omega normalizes a primitive's target to its bare host, dropping the path/params
the verifier needs. `OmegaChainProposer` rebuilds `(primitive_type, host) → concrete URL`
from the originating findings and re-attaches it to each step (`step["url"]`), so chain
steps are actually live-verifiable. Without this, every chain stays untestable.

## Non-goals (for phase 1)

- No deletion of cortex or omega — both are proposers.
- No UI contract change — `arbitrated_chains` is additive; existing fields untouched.
- No live verification of omega hypotheses yet (phase 2). Until then omega chains are labeled `hypothesized` and never counted as confirmed findings.
