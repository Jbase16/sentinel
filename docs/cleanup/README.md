# SentinelForge Cleanup Ledger

Evidence-based cleanup of accreted dead code / forks. **Nothing is deleted from
this map alone** — it is the reviewable inventory; deletions happen in small,
suite-green, reversible commits after a human decision.

## Source

Whole-repo reachability audit (2026-07-02). Every module classified by
**reachability from verified entry points**, never by age — a January file that a
router imports is LIVE; a file added last week that nothing reaches is ORPHAN.

Verified runtime roots: `core.__main__`, `core.server.api` (+ its routers:
scans, ai, system, ghost, verify, foundry, forge, cortex, realtime),
`sentinelforge.cli.sentinel`. (`core.engine.headless_runner.__init__` raises, so
it is not a live path.)

## Key files

- `cleanup_candidates.md` — the action list, tiered by **review safety**.
- `reachability_summary.md` — per-cluster analysis (execution_policy ×3, the
  report/submission fork, provenance systems, dead packages).
- `do_not_delete.md` / `summary.json` — verdicts + evidence for all 377 core modules.
- `pytest_blockers.md` — the duplicate-basename collision (fixed in Phase 0).
- `ui_reachability_summary.md` — the 59-file Swift app (separate track).
- `duplicate_clusters.md`, `dynamic_loading_review.md`, `non_core_surfaces.md`,
  `whole_repo_inventory.tsv` — supporting evidence.

## Plan & status

- [x] **Phase 0 — fix the ruler.** `pytest tests/` now collects under
  `--import-mode=importlib`; audit landed here as the tracked ledger.
- [ ] **Phase 1 — Tier 1 dead code.** Delete ORPHAN_STRONG in per-package batches
  (`git rm` → full suite green → commit). Pilot: `core.web.browser` ✅ (0dae419, empty pkg).
  Remaining: `core.web.{evidence,mutate,auth,replay}`, `core.{fuzz,analyze,payloads,
  doppelganger,executor,observer,monitoring,debugging}`, `core.server.tls`, etc.
- [ ] **Phase 2 — Tier 2 test-only.** Per-cluster: delete module + its tests, or keep.
- [ ] **Phase 3 — DEFER (product decisions, not cleanup).** report/submission fork
  (incl. the newer unwired Phase-6 path), the 3 `execution_policy` modules (rename,
  don't merge), the 3 provenance systems, `replay_capsule`, the `__main__` tools.
- [ ] **Phase 4 — UI.** Remove exact-duplicate root Swift files + tracked
  `.build/.lock`, only after a green Xcode build.

**Definition of done:** full suite runs clean; Tier 1 removed; Tier 2 decided;
forks deferred with a note; UI dupes removed.
