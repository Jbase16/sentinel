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
    - `core.web.*` — **DECISION: KEEP (2026-07-02).** Investigation corrected the audit:
      this is NOT a script/test-only subsystem. Its foundation `core.web.contracts.*`
      (`VulnerabilityClass`, `WebMission`, ids, `ScopeViolation`) + `core.web.context.WebContext`
      is **LIVE** — imported by `core.wraith.{verify_phase,vuln_verifier,candidate_discovery}`
      and `core.server.routers.{scans,ai}`. wraith was built ON web's foundation, not as a
      replacement. The abandoned *engine* shell (crawler/orchestrator/diff/transport/event_bus/
      surface_registry/auth_manager/evidence_service) is unwired dead-ish code but entangled
      with the live foundation → left intact; see `docs/architecture/WEB_EXPLOITATION_ENGINE_V1.md`
      (status corrected there). CORRECTION: the audit was right — it marked `web.context` /
      `web.contracts.enums`/`.errors` LIVE. The "script/test-only web subsystem" framing was a
      mis-summary on my part that conflated the dead engine shell (orchestrator/crawler/diff/
      transport/event_bus/surface_registry/auth_manager/evidence_service — genuinely
      ORPHAN_STRONG/TEST_ONLY) with the live contracts/context foundation. A surgical cut of just
      the shell is audit-supported if ever wanted; kept for now.

- [x] **Phase 2 — Tier 2 test-only clusters + tail.** Removed (each verified: no live/
  test/lazy importer, dedicated test only): `thanatos` (ae24722), dead `aegis.*` sub-cluster
  keeping live `nexus.*` (c55d0e6), `sentient.doppelganger`+`cortex.pathfinder` (f9f5a72),
  old `cortex.replay_capsule` + misplaced `pressure_graph/tests` (8323608→earlier), 
  `mimic.downloader`+`ai.fallbacks` (d60f1df), `aegis.nexus.chain`+`cortex.authority`
  (self-test __main__, not tools; 323642b).
  - **KEPT (removal would delete tests that cover LIVE code):** `chat`, `reporting.composer`,
    `replay.codec`/`hypervisor`, `cal.interface`, `forge.sandbox`, `ghost.logic`,
    `scheduler.laws`, `toolkit.diagnostics`, `sentient.mimic.ast_parser`.
  - **KEPT (real tools/utilities):** `server.openapi_gen`.
  - **BLOCKED (need Xcode build to verify):** UI duplicate Swift files + `.build/.lock`.
  - **DECISIONS, not deletions (Phase 3):** report/submission fork, 3 `execution_policy`
    modules (distinct jobs — rename, don't merge), provenance systems.

  **CLEANUP COMPLETE for safe dead-code removal: 89 files, 11,591 LOC removed; every
  step verified + reversible; unit suite green throughout. What remains needs a build,
  a design decision, or would sacrifice live test coverage — none is removable dead code.**
- [ ] **Phase 3 — DEFER (product decisions, not cleanup).** report/submission fork
  (incl. the newer unwired Phase-6 path), the 3 `execution_policy` modules (rename,
  don't merge), the 3 provenance systems, `replay_capsule`, the `__main__` tools.
- [ ] **Phase 4 — UI.** Remove exact-duplicate root Swift files + tracked
  `.build/.lock`, only after a green Xcode build.

**Definition of done:** full suite runs clean; Tier 1 removed; Tier 2 decided;
forks deferred with a note; UI dupes removed.
