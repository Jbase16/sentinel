# Duplicate/Fork Cluster Analysis
Classifier note: duplicate status is not deletion evidence. Runtime/test reachability remains authoritative; responsibility overlap requires human review.
## __init__.py
- Responsibility read: duplicate by basename only.
- `core` (core/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: core.recon.behavioral; test importers: tests/integration/test_cronus/__init__.py, tests/integration/test_mimic/__init__.py, tests/integration/test_nexus/__init__.py.
- `core.aegis` (core/aegis/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=9ab56a8 2026-01-02 Jbase16. core importers: none; test importers: none.
- `core.aegis.nexus` (core/aegis/nexus/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=5075a87 2026-01-14 Jbase16. core importers: none; test importers: none.
- `core.analyze` (core/analyze/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.base` (core/base/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.bounty` (core/bounty/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=ff8d3b0 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.cal` (core/cal/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=c27d090 2026-01-22 Jbase16. core importers: none; test importers: none.
- `core.chat` (core/chat/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=306f676 2025-12-23 Jbase16. core importers: none; test importers: none.
- `core.contracts` (core/contracts/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=b147159 2025-12-19 Jbase16. core importers: none; test importers: none.
- `core.cortex` (core/cortex/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=a29e3eb 2026-02-15 Jbase16. core importers: none; test importers: none.
- `core.data` (core/data/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.data.migrations` (core/data/migrations/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=c73647a 2026-01-02 Jbase16. core importers: core.data.db; test importers: none.
- `core.data.pressure_graph` (core/data/pressure_graph/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=ac6cbcc 2025-12-28 Jbase16. core importers: none; test importers: none.
- `core.data.pressure_graph.tests` (core/data/pressure_graph/tests/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=9641480 2025-12-28 Jbase16. core importers: none; test importers: none.
- `core.doppelganger` (core/doppelganger/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=7905715 2026-01-03 Jbase16. core importers: none; test importers: none.
- `core.engine` (core/engine/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.epistemic` (core/epistemic/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=31e6178 2026-01-05 Jbase16. core importers: none; test importers: none.
- `core.executor` (core/executor/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=44e7eb4 2026-01-03 Jbase16. core importers: core.system.orchestrator; test importers: none.
- `core.forge` (core/forge/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=dcbccb3 2025-12-30 Jbase16. core importers: none; test importers: none.
- `core.foundry` (core/foundry/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=a19f887 2026-06-12 Jbase16. core importers: none; test importers: none.
- `core.fuzz` (core/fuzz/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.ghost` (core/ghost/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=6ec45ef 2025-12-23 Jbase16. core importers: none; test importers: none.
- `core.intel` (core/intel/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=5f46ae0 2026-05-21 Jbase16. core importers: none; test importers: none.
- `core.intel.compilers` (core/intel/compilers/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=5f46ae0 2026-05-21 Jbase16. core importers: none; test importers: none.
- `core.intel.extractors` (core/intel/extractors/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=5f46ae0 2026-05-21 Jbase16. core importers: none; test importers: none.
- `core.intel.selection` (core/intel/selection/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=30b2850 2026-06-07 Jbase16. core importers: none; test importers: none.
- `core.observer` (core/observer/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=44e7eb4 2026-01-03 Jbase16. core importers: core.system.orchestrator; test importers: none.
- `core.omega` (core/omega/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=7d63772 2026-03-24 Jbase16. core importers: core.omega.manager; test importers: tests/integration/test_omega/__init__.py.
- `core.payloads` (core/payloads/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.recon` (core/recon/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.replay` (core/replay/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=059fb29 2026-01-06 Jbase16. core importers: none; test importers: none.
- `core.scheduler` (core/scheduler/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=a29e3eb 2026-02-15 Jbase16. core importers: none; test importers: none.
- `core.scope` (core/scope/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=e3e9c38 2026-02-17 Jbase16. core importers: none; test importers: none.
- `core.sentient` (core/sentient/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=4e31779 2025-12-28 Jbase16. core importers: none; test importers: none.
- `core.sentient.cronus` (core/sentient/cronus/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=4e31779 2025-12-28 Jbase16. core importers: core.omega; test importers: tests/unit/test_cronus.py.
- `core.sentient.mimic` (core/sentient/mimic/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=d8c2c72 2026-01-02 Jbase16. core importers: none; test importers: none.
- `core.server` (core/server/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.server.routers` (core/server/routers/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=e199070 2026-01-09 Jbase16. core importers: none; test importers: none.
- `core.submission` (core/submission/__init__.py) verdict=FORK_DECISION, runtime=no, test_only=yes, last=6733b5b 2026-06-07 Jbase16. core importers: none; test importers: none.
- `core.thanatos` (core/thanatos/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=9ab56a8 2026-01-02 Jbase16. core importers: none; test importers: none.
- `core.toolkit` (core/toolkit/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.toolkit.internal_tools` (core/toolkit/internal_tools/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=aba331b 2026-02-15 Jbase16. core importers: none; test importers: none.
- `core.utils` (core/utils/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: none; test importers: none.
- `core.verify` (core/verify/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=5993b11 2026-06-06 Jbase16. core importers: none; test importers: none.
- `core.web` (core/web/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.web.auth` (core/web/auth/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=7bc68e5 2026-03-21 Jbase16. core importers: none; test importers: none.
- `core.web.browser` (core/web/browser/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.web.contracts` (core/web/contracts/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: tests/unit/test_verify_phase.py.
- `core.web.diff` (core/web/diff/__init__.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.web.evidence` (core/web/evidence/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.web.mutate` (core/web/mutate/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.web.replay` (core/web/replay/__init__.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=0b41d41 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.wraith` (core/wraith/__init__.py) verdict=LIVE, runtime=yes, test_only=no, last=6ec45ef 2025-12-23 Jbase16. core importers: none; test importers: none.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## base.py
- Responsibility read: duplicate by basename only.
- `core.intel.extractors.base` (core/intel/extractors/base.py) verdict=TEST_ONLY, runtime=no, test_only=yes, last=5f46ae0 2026-05-21 Jbase16. core importers: core.intel.extractors, core.intel.extractors.bugcrowd, core.intel.extractors.generic_url, core.intel.extractors.hackerone, core.intel.resolver; test importers: tests/unit/intel/test_extractor_bugcrowd.py, tests/unit/intel/test_extractor_hackerone.py, tests/unit/intel/test_generic_url_extractor.py, tests/unit/intel/test_resolver.py.
- `core.web.auth.base` (core/web/auth/base.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=7bc68e5 2026-03-21 Jbase16. core importers: core.web.auth, core.web.auth.form_login, core.web.auth.scripted_login; test importers: none.
- `core.web.mutate.base` (core/web/mutate/base.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=0cdf465 2026-02-24 Jbase16. core importers: core.web.mutate.reflection, core.web.mutate.sqli, core.web.mutate.ssrf; test importers: none.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## engine.py
- Responsibility read: duplicate by basename only.
- `core.cal.engine` (core/cal/engine.py) verdict=LIVE, runtime=yes, test_only=no, last=b98ee9a 2026-01-01 Jbase16. core importers: core.ai.strategy, core.cal.interface, core.cortex.reasoning, core.cortex.scanner_bridge; test importers: tests/integration/test_cal_system_integration.py, tests/integration/test_system_loop.py, tests/unit/core/cal/test_cal.py, tests/verification/verify_cal_core.py.
- `core.doppelganger.engine` (core/doppelganger/engine.py) verdict=ORPHAN_STRONG, runtime=no, test_only=no, last=7d63772 2026-03-24 Jbase16. core importers: core.system.orchestrator; test importers: none.
- `core.reasoning.engine` (core/reasoning/engine.py) verdict=LIVE, runtime=yes, test_only=no, last=7bc68e5 2026-03-21 Jbase16. core importers: core.server.api; test importers: tests/core/reasoning/test_graph_contamination.py, tests/core/reasoning/test_reasoning_logic.py.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## events.py
- Responsibility read: often duplicate by basename only; package context differs.
- `core.contracts.events` (core/contracts/events.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=f8810c7 2026-02-06 Jbase16. core importers: core.contracts, core.cortex.authority, core.cortex.events, core.cortex.manager, core.cortex.nexus_context, core.cortex.session, core.cronus.manager, core.cronus.session, core.mimic.manager, core.mimic.session, core.reasoning.engine, core.scheduler.strategos; test importers: tests/core/contracts/test_causal_isolation.py, tests/core/contracts/test_contracts_phase0.py, tests/core/cortex/test_nexus_phase1.py, tests/core/cronus/test_cronus_phase2.py, tests/core/reasoning/test_graph_contamination.py, tests/core/reasoning/test_reasoning_logic.py, tests/integration/test_strategos_hybrid.py, tests/unit/test_strategos_hybrid_unit.py.
- `core.cortex.events` (core/cortex/events.py) verdict=DO_NOT_TOUCH, runtime=yes, test_only=no, last=e583193 2026-02-14 Jbase16. core importers: core.aegis.nexus.recoil, core.cal.engine, core.cortex.authority, core.cortex.event_store, core.cortex.manager, core.cortex.narrator, core.cortex.nexus_context, core.cortex.reasoning, core.cortex.subscriptions, core.cronus.manager, core.data.migrations.migration_runner, core.data.pressure_graph.manager (+14 more); test importers: tests/core/contracts/test_contracts_phase0.py, tests/core/cortex/test_nexus_phase1.py, tests/core/cronus/test_cronus_phase2.py, tests/core/reasoning/test_graph_contamination.py, tests/core/reasoning/test_reasoning_logic.py, tests/integration/test_cal_system_integration.py, tests/integration/test_decision_emission.py, tests/integration/test_scan_failure.py, tests/integration/test_strategos_hybrid.py, tests/unit/test_command_validation.py (+3 more).
- `core.epistemic.events` (core/epistemic/events.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=c36fa52 2026-01-05 Jbase16. core importers: core.epistemic.ledger; test importers: none.
- `core.observer.events` (core/observer/events.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=b4e4090 2026-01-03 Jbase16. core importers: core.observer, core.observer.bus, core.observer.feedback, core.observer.sinks; test importers: none.
- `core.scheduler.events` (core/scheduler/events.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=08a3276 2025-12-17 Jason Phillips. core importers: core.scheduler.strategos; test importers: tests/unit/test_strategos_safety.py.
- `core.web.contracts.events` (core/web/contracts/events.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=7d63772 2026-03-24 Jbase16. core importers: core.web.auth_manager, core.web.contracts.schemas, core.web.contracts.validation, core.web.crawler, core.web.event_bus, core.web.evidence_service, core.web.js_intel, core.web.transport; test importers: tests/test_mutating_transport.py.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## execution_policy.py
- Responsibility read: duplicate by responsibility likely; confirm before consolidation.
- `core.base.execution_policy` (core/base/execution_policy.py) verdict=DO_NOT_TOUCH, runtime=yes, test_only=no, last=ff8d3b0 2026-02-23 Jbase16. core importers: core.base.context, core.server.routers.scans; test importers: tests/unit/intel/test_policy_enforcement_bridge.py.
- `core.cortex.execution_policy` (core/cortex/execution_policy.py) verdict=DO_NOT_TOUCH, runtime=yes, test_only=no, last=8039750 2026-07-02 Jbase16. core importers: core.server.routers.scans; test importers: tests/unit/core/test_execution_policy.py, tests/unit/core/test_minimal_amplification.py, tests/unit/core/test_owned_proof.py.
- `core.wraith.execution_policy` (core/wraith/execution_policy.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=ff8d3b0 2026-02-23 Jbase16. core importers: core.toolkit.internal_tools.api_discoverer, core.toolkit.internal_tools.oob_probe, core.toolkit.internal_tools.persona_diff, core.toolkit.internal_tools.vuln_verifier, core.toolkit.internal_tools.wraith_verify, core.wraith.mutation_engine, core.wraith.oob_detector, core.wraith.personas, core.wraith.vuln_verifier; test importers: tests/core/wraith/test_execution_policy.py, tests/core/wraith/test_oob.py.
- Human decision: keep all three until policy layers are separated by contract: scan/session policy, bounty-safe proof executor, and Wraith internal HTTP runtime are different jobs today.

## h1_client.py
- Responsibility read: duplicate by responsibility likely; confirm before consolidation.
- `core.bounty.h1_client` (core/bounty/h1_client.py) verdict=FORK_DECISION, runtime=yes, test_only=no, last=7d63772 2026-03-24 Jbase16. core importers: core.server.routers.scans; test importers: none.
- `core.submission.h1_client` (core/submission/h1_client.py) verdict=FORK_DECISION, runtime=no, test_only=yes, last=6733b5b 2026-06-07 Jbase16. core importers: core.submission; test importers: tests/unit/test_h1_submission.py.
- Human decision: decide whether HackerOne scope ingestion (`core.bounty`) and report submission (`core.submission`) are separate products or a planned migration. Do not delete the newer unwired submission path as stale by age.

## manager.py
- Responsibility read: often duplicate by basename only; package context differs.
- `core.aegis.manager` (core/aegis/manager.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=38857b2 2026-01-03 Jbase16. core importers: none; test importers: none.
- `core.cortex.manager` (core/cortex/manager.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=3c0bfb5 2026-01-14 Jbase16. core importers: core.server.api; test importers: tests/core/cortex/test_nexus_phase1.py.
- `core.cronus.manager` (core/cronus/manager.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=a0f637c 2026-02-14 Jbase16. core importers: core.server.api; test importers: tests/core/cronus/test_cronus_phase2.py.
- `core.data.pressure_graph.manager` (core/data/pressure_graph/manager.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=a5de9f2 2026-02-14 Jbase16. core importers: core.aegis.manager, core.base.session, core.data.pressure_graph, core.system.orchestrator; test importers: tests/unit/core/test_pressure_graph_manager.py.
- `core.mimic.manager` (core/mimic/manager.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=5075a87 2026-01-14 Jbase16. core importers: core.server.api; test importers: none.
- `core.omega.manager` (core/omega/manager.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=d55c0e5 2025-12-27 Jbase16. core importers: none; test importers: none.
- `core.thanatos.manager` (core/thanatos/manager.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=yes, last=b3929eb 2026-01-04 Jbase16. core importers: none; test importers: tests/test_thanatos_wrappers.py.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## models.py
- Responsibility read: often duplicate by basename only; package context differs.
- `core.aegis.models` (core/aegis/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=yes, last=38857b2 2026-01-03 Jbase16. core importers: core.aegis.bridge, core.aegis.graph, core.aegis.manager, core.aegis.passive_ingest; test importers: none.
- `core.cortex.models` (core/cortex/models.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=0aaf44f 2026-01-08 Jbase16. core importers: core.cortex.graph_analyzer, core.cortex.insight_engine, core.server.routers.cortex; test importers: tests/unit/test_graph_analyzer.py.
- `core.data.pressure_graph.models` (core/data/pressure_graph/models.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=e707350 2026-01-08 Jbase16. core importers: core.aegis.bridge, core.aegis.manager, core.data.pressure_graph, core.data.pressure_graph.attribution, core.data.pressure_graph.counterfactual, core.data.pressure_graph.explanation, core.data.pressure_graph.manager, core.data.pressure_graph.min_fix_set, core.data.pressure_graph.propagator, core.data.pressure_graph.tests.test_models, core.data.pressure_graph.tests.test_propagator, core.data.pressure_graph.tests.test_property_based (+2 more); test importers: none.
- `core.doppelganger.models` (core/doppelganger/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=b4e4090 2026-01-03 Jbase16. core importers: core.doppelganger.engine, core.system.orchestrator; test importers: none.
- `core.executor.models` (core/executor/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=b4e4090 2026-01-03 Jbase16. core importers: core.executor, core.executor.harness, core.executor.http_harness, core.executor.interlock, core.executor.oracle, core.system.orchestrator; test importers: none.
- `core.mimic.models` (core/mimic/models.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=d76d861 2026-01-10 Jbase16. core importers: core.mimic.downloader, core.mimic.miners.routes, core.mimic.miners.secrets, core.mimic.session; test importers: tests/verification/verify_mimic_integration.py.
- `core.omega.models` (core/omega/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=b152503 2026-01-10 Jbase16. core importers: none; test importers: none.
- `core.reasoning.models` (core/reasoning/models.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=57c3f28 2026-01-10 Jbase16. core importers: core.reasoning.engine; test importers: tests/core/reasoning/test_reasoning_logic.py.
- `core.replay.models` (core/replay/models.py) verdict=DO_NOT_TOUCH, runtime=yes, test_only=no, last=b714249 2026-01-06 Jbase16. core importers: core.replay.codec, core.replay.hypervisor, core.replay.merkle, core.replay.persistence, core.safety.provenance; test importers: tests/integration/test_butterfly_effect.py, tests/integration/test_replay_semantics.py, tests/unit/test_hypervisor.py, tests/unit/test_merkle_integrity.py, tests/unit/test_persistence.py.
- `core.scope.models` (core/scope/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=e3e9c38 2026-02-17 Jbase16. core importers: core.scope, core.scope.enforcer; test importers: none.
- `core.sentient.models` (core/sentient/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=62ead1e 2026-01-03 Jbase16. core importers: core.executor.interlock, core.executor.models, core.sentient.economics, core.sentient.ethics, core.sentient.service, core.system.orchestrator; test importers: none.
- `core.thanatos.models` (core/thanatos/models.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=yes, last=f02d066 2026-01-05 Jbase16. core importers: core.executor.http_harness, core.executor.models, core.executor.oracle, core.system.orchestrator, core.thanatos.anomaly_client, core.thanatos.anomaly_tester, core.thanatos.axiom_synthesizer, core.thanatos.manager, core.thanatos.mutations, core.thanatos.ontology_breaker, core.thanatos.scope_gate; test importers: none.
- `core.web.contracts.models` (core/web/contracts/models.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=7d63772 2026-03-24 Jbase16. core importers: core.web.auth.base, core.web.auth.form_login, core.web.auth.scripted_login, core.web.auth_manager, core.web.contracts.events, core.web.contracts.schemas, core.web.crawler, core.web.diff.baseline, core.web.diff.delta, core.web.evidence.bundle, core.web.evidence_service, core.web.js_intel (+11 more); test importers: scripts/test_auth_isolation.py, tests/test_mutating_transport.py, tests/unit/test_candidate_discovery.py.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## orchestrator.py
- Responsibility read: duplicate by responsibility likely; confirm before consolidation.
- `core.engine.orchestrator` (core/engine/orchestrator.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=7ea750e 2026-03-23 Jbase16. core importers: none; test importers: tests/verification/verify_command_deck.py.
- `core.system.orchestrator` (core/system/orchestrator.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=8249a58 2026-01-04 Jbase16. core importers: none; test importers: none.
- `core.web.orchestrator` (core/web/orchestrator.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=333b679 2026-02-25 Jbase16. core importers: none; test importers: none.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## session.py
- Responsibility read: often duplicate by basename only; package context differs.
- `core.base.session` (core/base/session.py) verdict=DO_NOT_TOUCH, runtime=yes, test_only=no, last=6c38c18 2026-05-27 Jbase16. core importers: core.ai.strategy, core.ghost.proxy, core.server.routers.ai, core.server.routers.ghost, core.server.routers.scans, core.wraith.auth_diff_scanner, core.wraith.automator, core.wraith.session_bridge, core.wraith.vuln_verifier; test importers: tests/integration/test_cal_system_integration.py, tests/integration/test_full_scan.py, tests/integration/test_ghost_lazarus_integration.py, tests/integration/test_ghost_wraith_e2e.py, tests/integration/test_system_loop.py, tests/unit/test_session_lifecycle.py, tests/verification/test_session_log_cap.py, tests/verification/verify_architecture.py, tests/verification/verify_cal_integration.py, tests/verification/verify_ghost.py (+2 more).
- `core.cortex.session` (core/cortex/session.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=e5c5cdc 2026-01-10 Jbase16. core importers: core.cortex.manager; test importers: tests/core/cortex/test_nexus_phase1.py.
- `core.cronus.session` (core/cronus/session.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=e5c5cdc 2026-01-10 Jbase16. core importers: none; test importers: none.
- `core.mimic.session` (core/mimic/session.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=7bc68e5 2026-03-21 Jbase16. core importers: core.mimic.manager; test importers: tests/verification/verify_mimic_integration.py.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## types.py
- Responsibility read: duplicate by basename only.
- `core.cal.types` (core/cal/types.py) verdict=LIVE, runtime=yes, test_only=no, last=b98ee9a 2026-01-01 Jbase16. core importers: core.ai.strategy, core.cal.engine, core.cal.interface, core.cortex.reasoning, core.cortex.scanner_bridge, core.ghost.proxy, core.sentient.mimic.route_miner, core.wraith.automator; test importers: tests/integration/test_cal_system_integration.py, tests/integration/test_system_loop.py, tests/unit/core/cal/test_cal.py, tests/verification/verify_cal_core.py.
- `core.reporting.types` (core/reporting/types.py) verdict=LIVE, runtime=yes, test_only=no, last=8cdffc5 2026-01-08 Jbase16. core importers: core.reporting.composer, core.reporting.poc_generator, core.reporting.report_composer; test importers: none.
- `core.sentient.mimic.types` (core/sentient/mimic/types.py) verdict=LIVE, runtime=yes, test_only=no, last=d8c2c72 2026-01-02 Jbase16. core importers: core.sentient.mimic, core.sentient.mimic.model_inferencer, core.sentient.mimic.route_miner, core.sentient.mimic.shadow_spec; test importers: none.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

## vuln_verifier.py
- Responsibility read: duplicate by responsibility likely; confirm before consolidation.
- `core.toolkit.internal_tools.vuln_verifier` (core/toolkit/internal_tools/vuln_verifier.py) verdict=DUPLICATE_CLUSTER, runtime=no, test_only=no, last=7965f3c 2026-02-23 Jbase16. core importers: none; test importers: none.
- `core.wraith.vuln_verifier` (core/wraith/vuln_verifier.py) verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, last=a852b66 2026-06-27 Jbase16. core importers: core.server.routers.ai, core.server.routers.scans, core.toolkit.internal_tools.vuln_verifier, core.wraith.verify_phase; test importers: tests/unit/test_verify_endpoint.py, tests/unit/test_verify_phase.py, tests/unit/test_vuln_verifier_fixes.py.
- Human decision: review responsibility, importers, and tests before consolidating; basename alone is weak evidence.

