# SentinelForge Cleanup Reachability Summary

## Counts
- Core Python modules: 377
- Runtime reachable from verified roots: 236
- Reachable only from tests: 69
- ORPHAN_STRONG verdict: 50
- ORPHAN_REVIEW verdict: 10
- Duplicate basename clusters: 20 total; 8 requested clusters present
- Runtime roots used: core.__main__, core.engine.headless_runner, core.server.api, core.server.routers.ai, core.server.routers.cortex, core.server.routers.forge, core.server.routers.foundry, core.server.routers.ghost, core.server.routers.realtime, core.server.routers.scans, core.server.routers.system, core.server.routers.verify, sentinelforge.cli.sentinel

## Entry Surface Evidence
- `README.md` documents `python3 -m uvicorn core.server.api:app --reload --port 8765`.
- `.github/copilot-instructions.md` and startup docs mention `python -m core.server.api` / `uvicorn core.server.api:app`.
- `scripts/start_backend.sh` and docs mention `python -m sentinelforge.cli.sentinel start`; `core.__main__` imports that CLI.
- `core.server.api` mounts `scans`, `ai`, `system`, `ghost`, `verify`, `foundry`, `forge`, `cortex`, and realtime routers.
- `core.engine.headless_runner.HeadlessRunner.__init__` raises `RuntimeError`, so it is an entry root by request but not a viable current scan path.

## Execution Policy
- `core.base.execution_policy`: verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; importers=core.base.context;core.server.routers.scans; tests=tests/unit/intel/test_policy_enforcement_bridge.py; last=ff8d3b0 2026-02-23.
- `core.cortex.execution_policy`: verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; importers=core.server.routers.scans; tests=tests/unit/core/test_execution_policy.py;tests/unit/core/test_minimal_amplification.py;tests/unit/core/test_owned_proof.py; last=8039750 2026-07-02.
- `core.wraith.execution_policy`: verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no; importers=core.toolkit.internal_tools.api_discoverer;core.toolkit.internal_tools.oob_probe;core.toolkit.internal_tools.persona_diff;core.toolkit.internal_tools.vuln_verifier;core.toolkit.internal_tools.wraith_verify;core.wraith.mutation_engine;core.wraith.oob_detector;core.wraith.personas;core.wraith.vuln_verifier; tests=tests/core/wraith/test_execution_policy.py;tests/core/wraith/test_oob.py; last=ff8d3b0 2026-02-23.
- Responsibility split: `core.base.execution_policy` is scan/session policy data used by `ScopeContext` and scan restrictions; `core.cortex.execution_policy` is bounty-safe proof action gating plus provenance emission; `core.wraith.execution_policy` is Wraith internal outbound HTTP runtime enforcement for internal tools.
- Current scans use `core.base.execution_policy` in `core.server.routers.scans` when constructing `ScopeContext`; Wraith internal tools use `core.wraith.execution_policy`; bounty-safe proof execution uses `core.cortex.execution_policy.PolicyExecutor`.
- None of the three is safely dead based on this evidence. Consolidation would require a contract-level design separating scan policy DTOs, proof intent/action policy, and HTTP runtime enforcement before any code moves.

## Report / Submission Paths
- `core.bounty`: verdict=LIVE, runtime=yes, test_only=no; importers=none; tests=none; last=ff8d3b0 2026-02-23.
- `core.bounty.h1_client`: verdict=FORK_DECISION, runtime=yes, test_only=no; importers=core.server.routers.scans; tests=none; last=7d63772 2026-03-24.
- `core.reporting.bounty_report`: verdict=FORK_DECISION, runtime=yes, test_only=no; importers=core.server.routers.scans; tests=tests/integration/test_full_scan.py;tests/integration/test_report_view_consistency.py;tests/unit/test_bounty_report.py;tests/unit/test_repro.py; last=0efceab 2026-07-02.
- `core.reporting.composer`: verdict=TEST_ONLY, runtime=no, test_only=yes; importers=none; tests=tests/integration/test_full_scan.py;tests/unit/test_reporting.py; last=8cdffc5 2026-01-08.
- `core.reporting.cvss_scorer`: verdict=LIVE, runtime=yes, test_only=no; importers=core.reporting.bounty_report; tests=tests/unit/test_repro.py; last=e3e9c38 2026-02-17.
- `core.reporting.poc_generator`: verdict=LIVE, runtime=yes, test_only=no; importers=core.server.routers.cortex; tests=tests/integration/test_report_view_consistency.py;tests/unit/test_poc_generator_real.py;tests/unit/test_reporting.py; last=5f46ae0 2026-05-21.
- `core.reporting.report_composer`: verdict=LIVE, runtime=yes, test_only=no; importers=core.server.routers.cortex; tests=tests/integration/test_report_view_consistency.py;tests/unit/test_report_composer_real.py; last=5f46ae0 2026-05-21.
- `core.reporting.repro`: verdict=LIVE, runtime=yes, test_only=no; importers=core.reporting.bounty_report; tests=tests/unit/test_repro.py; last=6bc1970 2026-06-30.
- `core.reporting.submission_render`: verdict=FORK_DECISION, runtime=no, test_only=yes; importers=none; tests=tests/unit/test_submission_render.py; last=5550e1a 2026-07-02.
- `core.reporting.types`: verdict=LIVE, runtime=yes, test_only=no; importers=core.reporting.composer;core.reporting.poc_generator;core.reporting.report_composer; tests=none; last=8cdffc5 2026-01-08.
- `core.submission`: verdict=FORK_DECISION, runtime=no, test_only=yes; importers=none; tests=none; last=6733b5b 2026-06-07.
- `core.submission.h1_client`: verdict=FORK_DECISION, runtime=no, test_only=yes; importers=core.submission; tests=tests/unit/test_h1_submission.py; last=6733b5b 2026-06-07.
- `/bounty-report` is implemented in `core.server.routers.scans` and imports `core.reporting.bounty_report.build_report` inside the handler.
- The wired HackerOne scope client is `core.bounty.h1_client`, imported by scan start for `bounty_json` / `bounty_handle`.
- `core.reporting.submission_render` and `core.submission.h1_client` are test-supported newer submission pieces, but not reachable from the FastAPI scan roots in this audit: Newer but unwired; test-only but possibly intended replacement.
- Human decision required: keep ingestion/report generation separate from operator-confirmed H1 submission, or wire the Phase 6 submission path deliberately. Do not delete the newer path by default.

Recent edits on fork paths:
### core/submission/h1_client.py
```
6733b5b 2026-06-07 Jbase16 feat(submission): Phase 6-PT3 — HackerOne report-submission API client
```
### core/reporting/submission_render.py
```
5550e1a 2026-07-02 Jbase16 feat(reporting): researcher-voice scope-of-testing note in H1 submission render
1713d0c 2026-06-07 Jbase16 feat(reporting): Phase 6-PT2 — submission-grade renderer (researcher voice, no scanner tells)
```
### core/bounty/h1_client.py
```
7d63772 2026-03-24 Jbase16 Finishing touches.
7ea750e 2026-03-23 Jbase16 Fixes.
7bc68e5 2026-03-21 Jbase16 Clean up.
ff8d3b0 2026-02-23 Jbase16 feat(scope): enforce ScopeContext boundaries at runtime
```
### core/reporting/bounty_report.py
```
0efceab 2026-07-02 Jbase16 feat(reporting): render Conduct Provenance section in markdown bounty report
6bc1970 2026-06-30 Jbase16 feat(reporting): render real reproduction + evidence from confirmed findings' metadata
5f46ae0 2026-05-21 Jbase16 feat: program-scope ingestion, calibration hardening, AI scan-expert
b0c3125 2026-02-23 Jbase16 fix(reporting): align bounty schema and add PoC DB fallback
e3e9c38 2026-02-17 Jbase16 feat(scanner): enforce scope and persist dedup fingerprints
```

## Replay / Provenance / Ledger
- `core.replay.codec`: verdict=TEST_ONLY, runtime=no, test_only=yes; importers=none; tests=tests/unit/test_merkle_integrity.py.
- `core.replay.hypervisor`: verdict=TEST_ONLY, runtime=no, test_only=yes; importers=none; tests=tests/integration/test_butterfly_effect.py;tests/integration/test_replay_semantics.py;tests/unit/test_hypervisor.py.
- `core.replay.merkle`: verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; importers=core.epistemic.ledger;core.replay.codec;core.replay.hypervisor;core.safety.provenance; tests=tests/integration/test_butterfly_effect.py;tests/integration/test_replay_semantics.py;tests/unit/core/test_provenance.py;tests/unit/test_hypervisor.py;tests/unit/test_merkle_integrity.py;tests/unit/test_persistence.py.
- `core.replay.models`: verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; importers=core.replay.codec;core.replay.hypervisor;core.replay.merkle;core.replay.persistence;core.safety.provenance; tests=tests/integration/test_butterfly_effect.py;tests/integration/test_replay_semantics.py;tests/unit/test_hypervisor.py;tests/unit/test_merkle_integrity.py;tests/unit/test_persistence.py.
- `core.replay.persistence`: verdict=LIVE, runtime=yes, test_only=no; importers=core.safety.provenance; tests=tests/unit/core/test_provenance.py;tests/unit/test_persistence.py.
- `core.cortex.replay_capsule`: verdict=ORPHAN_REVIEW, runtime=no, test_only=no; importers=none; tests=none.
- `core.epistemic.ledger`: verdict=LIVE, runtime=yes, test_only=no; importers=core.ai.ai_engine;core.base.task_router;core.cortex.replay_capsule;core.replay.hypervisor; tests=tests/integration/test_butterfly_effect.py;tests/integration/test_replay_semantics.py;tests/unit/test_ledger_determinism.py.
- `core.safety.provenance`: verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; importers=core.cortex.execution_policy;core.server.routers.scans; tests=tests/unit/core/test_execution_policy.py;tests/unit/core/test_minimal_amplification.py;tests/unit/core/test_provenance.py.
- `core.cortex.execution_policy`: verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; importers=core.server.routers.scans; tests=tests/unit/core/test_execution_policy.py;tests/unit/core/test_minimal_amplification.py;tests/unit/core/test_owned_proof.py.
- Existing Merkle/capsule substrate: `core.replay.merkle` and `core.replay.models` define deterministic content-addressed blocks; `core.replay.codec` and `core.replay.persistence` encode/persist capsules; `core.cortex.replay_capsule` is an older scan capsule model.
- Runtime-wired today: `core.safety.provenance` is reached through `core.cortex.execution_policy` and the bounty-safe proof path; `core.epistemic.ledger` is reached from runtime via task/session infrastructure. Several replay modules are test-only or review-only.
- `PolicyExecutor._emit_provenance` records every allowed and denied proof action to `ProvenanceSink.record_policy_action`; `ProvenanceSink.export_capsule` persists through `core.replay.persistence.CapsuleRecorder`.
- Duplicate provenance systems exist in shape: the epistemic ledger records observations/findings, replay/capsule records scan history, and safety provenance records conduct blocks. They are not equivalent and should not be merged without a persistence/ownership design.
- Remaining unpersisted by default: the provenance sink is in-memory unless the caller exports the capsule; reports can include the root/summary, but persistence is caller-driven.

## Scan Path
- Bounty-safe request-mode normalization, scope enforcement, HackerOne scope ingestion, policy restrictions, action bridge, Strategos dispatch, proof lifting, and bounty report generation all live inside `core.server.routers.scans`.
- The handler calls `core.bounty.h1_client`, `core.base.scope`, `core.base.context`, `core.base.execution_policy`, `core.intel.policy_enforcer`, `core.engine.scanner_engine`, `core.cortex.reasoning`, and later proof/report modules.
- Obvious refactor seams for later human work: scope/H1 ingestion, restrictions-to-policy adaptation, action dispatch bridge, result/provenance lifting, and bounty report rendering. Do not refactor during cleanup until reachability/test blockers are resolved.

## Dead-Package Candidates
- `core.analyze`: all ORPHAN_STRONG; modules=1; verdicts=ORPHAN_STRONG=1.
- `core.chat`: tests-only feature; modules=2; verdicts=TEST_ONLY=2.
- `core.data.pressure_graph.tests`: tests-only feature; modules=5; verdicts=TEST_ONLY=5.
- `core.debugging`: all ORPHAN_STRONG; modules=1; verdicts=ORPHAN_STRONG=1.
- `core.doppelganger`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=3; verdicts=DUPLICATE_CLUSTER=1, ORPHAN_STRONG=2.
- `core.executor`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=6; verdicts=DUPLICATE_CLUSTER=1, ORPHAN_STRONG=5.
- `core.fuzz`: all ORPHAN_STRONG; modules=2; verdicts=ORPHAN_STRONG=2.
- `core.intel.extractors`: tests-only feature; modules=5; verdicts=TEST_ONLY=5.
- `core.intel.selection`: tests-only feature; modules=2; verdicts=TEST_ONLY=2.
- `core.monitoring`: all ORPHAN_STRONG; modules=1; verdicts=ORPHAN_STRONG=1.
- `core.observer`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=5; verdicts=DUPLICATE_CLUSTER=1, ORPHAN_STRONG=4.
- `core.payloads`: all ORPHAN_STRONG; modules=1; verdicts=ORPHAN_STRONG=1.
- `core.recon`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=3; verdicts=ORPHAN_REVIEW=1, ORPHAN_STRONG=2.
- `core.scope`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=3; verdicts=DUPLICATE_CLUSTER=1, ORPHAN_STRONG=2.
- `core.sentient.cronus`: tests-only feature; modules=4; verdicts=TEST_ONLY=4.
- `core.submission`: newer-unwired fork; modules=2; verdicts=FORK_DECISION=2.
- `core.system`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=1; verdicts=DUPLICATE_CLUSTER=1.
- `core.thanatos`: mixed ORPHAN_REVIEW / TEST_ONLY; modules=13; verdicts=DUPLICATE_CLUSTER=2, ORPHAN_STRONG=1, TEST_ONLY=10.
- `core.web.auth`: all ORPHAN_STRONG; modules=4; verdicts=ORPHAN_STRONG=4.
- `core.web.browser`: all ORPHAN_STRONG; modules=2; verdicts=ORPHAN_STRONG=2.
- `core.web.diff`: tests-only feature; modules=3; verdicts=TEST_ONLY=3.
- `core.web.evidence`: all ORPHAN_STRONG; modules=3; verdicts=ORPHAN_STRONG=3.
- `core.web.mutate`: all ORPHAN_STRONG; modules=6; verdicts=ORPHAN_STRONG=6.
- `core.web.replay`: all ORPHAN_STRONG; modules=2; verdicts=ORPHAN_STRONG=2.
