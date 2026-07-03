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
- [~] **Phase 1 — Tier 1 dead code.** Clean whole-dead subsystems removed (44 files,
  ~4.6k LOC, suite green throughout, each reversible):
  - pilot `core.web.browser` (0dae419)
  - batch 1 `core.web.{evidence,mutate,auth,replay}` + web.mission, web.contracts.validation (d0929db)
  - batch 2 `core.{doppelganger,executor,observer,system}` closure (ce0e17b)
  - batch 3 `core.{fuzz,analyze,payloads,monitoring,debugging}` + server.tls,
    toolkit.tool_callbacks, engine.{runner,scan_orchestrator} (0bc8ad6)
  - per-module pass (98b4c74, 91abefa, 5ed4ca4, f96523f): removed confirmed true-orphans
    — `core.recon` cluster + its exclusive `data.evidence`/`data.findings`,
    `core.sentient.{service,economics,ethics}`, `core.scope`,
    `data.pressure_graph.attribution`, `web.js_intel` (13 files, 1816 LOC).
  - **Per-module care caught two that a bulk sweep would have wrongly deleted:**
    `core.aegis.bridge` is imported (relative) by `aegis.manager`; `core.web.evidence_service`
    is imported (relative) by `web.orchestrator`. Held.
  - **Remaining Tier 1 is now cluster/subsystem-level, not orphan-level:**
    - `core.aegis.*` — mixed cluster (bridge↔manager, plus test-only members).
    - `core.web.*` — `context/transport/crawler/orchestrator/auth_manager/evidence_service/
      event_bus/diff/contracts` form a **script-and-test-only web subsystem** (reachable only
      via `scripts/smoke_test_*` + some tests, NOT the FastAPI runtime). This is a
      "keep the web.* subsystem at all?" decision → Phase 3, not Tier-1 cleanup.

  **Phase 1 total so far: 57 files, ~6,400 LOC removed; suite green throughout (1616).**
- [ ] **Phase 2 — Tier 2 test-only.** Per-cluster: delete module + its tests, or keep.
- [ ] **Phase 3 — DEFER (product decisions, not cleanup).** report/submission fork
  (incl. the newer unwired Phase-6 path), the 3 `execution_policy` modules (rename,
  don't merge), the 3 provenance systems, `replay_capsule`, the `__main__` tools.
- [ ] **Phase 4 — UI.** Remove exact-duplicate root Swift files + tracked
  `.build/.lock`, only after a green Xcode build.

**Definition of done:** full suite runs clean; Tier 1 removed; Tier 2 decided;
forks deferred with a note; UI dupes removed.
