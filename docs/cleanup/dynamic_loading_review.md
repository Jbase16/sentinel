# Dynamic Loading Review
Static import reachability can miss these surfaces. Treat affected modules as review-required, not automatically dead.

## core
- Path: `core/__init__.py`
- Referenced by string/dynamic literal: core/aegis/economic_recon.py, core/aegis/graph.py, core/aegis/manager.py, core/aegis/nexus/primitives.py, core/aegis/value_mapper.py, core/ai/ai_engine.py, core/ai/exec_protocol.py, core/ai/fallbacks.py, core/ai/reporting.py, core/ai/scan_briefing.py, core/ai/strategy.py, core/analyze/__init__.py (+339 more)
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.__main__
- Path: `core/__main__.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.aegis.bridge
- Path: `core/aegis/bridge.py`
- Dynamic terms in file: registry
- Current verdict: ORPHAN_STRONG; runtime_reachable=no; test_only=no.

## core.aegis.nexus.chain
- Path: `core/aegis/nexus/chain.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.aegis.nexus.primitives
- Path: `core/aegis/nexus/primitives.py`
- Dynamic terms in file: getattr(
- Has `__main__` block.
- CLI shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.aegis.nexus.recoil
- Path: `core/aegis/nexus/recoil.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ai.ai_engine
- Path: `core/ai/ai_engine.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/integration/test_ghost_wraith_e2e.py, tests/integration/test_system_loop.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ai.debate
- Path: `core/ai/debate.py`
- Referenced by string/dynamic literal: tests/unit/core/test_trinity_hardening.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ai.exec_protocol
- Path: `core/ai/exec_protocol.py`
- Referenced by string/dynamic literal: core/ai/ai_engine.py, tests/security/test_exec_injection.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ai.reporting
- Path: `core/ai/reporting.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.base
- Path: `core/base/__init__.py`
- Referenced by string/dynamic literal: core/base/sequence.py, core/base/task_router.py, core/intel/policy_enforcer.py, core/scheduler/decisions.py, tests/integration/test_api_basic.py, tests/integration/test_butterfly_effect.py, tests/integration/test_pty_interaction.py, tests/integration/test_replay_semantics.py, tests/unit/test_capability_model_config.py, tests/unit/test_config_singleton.py, tests/unit/test_ledger_determinism.py, tests/unit/test_teardown_deadline.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.base.config
- Path: `core/base/config.py`
- Dynamic terms in file: TOOLS, getattr(
- Referenced by string/dynamic literal: tests/integration/test_api_basic.py, tests/integration/test_pty_interaction.py, tests/unit/test_capability_model_config.py, tests/unit/test_config_singleton.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.base.context
- Path: `core/base/context.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.base.scope
- Path: `core/base/scope.py`
- Dynamic terms in file: Registry
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.base.sequence
- Path: `core/base/sequence.py`
- Referenced by string/dynamic literal: core/scheduler/decisions.py, tests/integration/test_butterfly_effect.py, tests/integration/test_replay_semantics.py, tests/unit/test_ledger_determinism.py
- Has `__main__` block.
- CLI shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.base.session
- Path: `core/base/session.py`
- Referenced by string/dynamic literal: tests/unit/test_teardown_deadline.py
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.base.task_router
- Path: `core/base/task_router.py`
- Dynamic terms in file: Registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.base.teardown
- Path: `core/base/teardown.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_teardown_deadline.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.bounty.h1_client
- Path: `core/bounty/h1_client.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: FORK_DECISION; runtime_reachable=yes; test_only=no.

## core.cal
- Path: `core/cal/__init__.py`
- Referenced by string/dynamic literal: core/cortex/policy.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cal.interface
- Path: `core/cal/interface.py`
- Dynamic terms in file: Registry
- Router/tool/registry shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.cal.parser
- Path: `core/cal/parser.py`
- Referenced by string/dynamic literal: core/cortex/policy.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cal.safe_eval
- Path: `core/cal/safe_eval.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.contracts
- Path: `core/contracts/__init__.py`
- Referenced by string/dynamic literal: core/contracts/events.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.contracts.budget
- Path: `core/contracts/budget.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.contracts.events
- Path: `core/contracts/events.py`
- Dynamic terms in file: Registry, TOOLS, registry
- Has `__main__` block.
- CLI shape detected.
- Router/tool/registry shape detected.
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.cortex
- Path: `core/cortex/__init__.py`
- Referenced by string/dynamic literal: core/cortex/authority.py, core/engine/scanner_engine.py, tests/core/cortex/test_nexus_phase1.py, tests/integration/test_ghost_lazarus_integration.py, tests/unit/test_phase2_nexus_context.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.arbitration
- Path: `core/cortex/arbitration.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.authority
- Path: `core/cortex/authority.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.cortex.capability_tiers
- Path: `core/cortex/capability_tiers.py`
- Dynamic terms in file: TOOLS
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.causal_graph
- Path: `core/cortex/causal_graph.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: core/data/constants.py, core/wraith/mutation_engine.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.chain_arbiter
- Path: `core/cortex/chain_arbiter.py`
- Dynamic terms in file: getattr(
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.chain_hunter
- Path: `core/cortex/chain_hunter.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.events
- Path: `core/cortex/events.py`
- Dynamic terms in file: getattr(, registry
- Referenced by string/dynamic literal: tests/integration/test_ghost_lazarus_integration.py
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.cortex.execution_policy
- Path: `core/cortex/execution_policy.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.cortex.manager
- Path: `core/cortex/manager.py`
- Dynamic terms in file: getattr(
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.cortex.nexus_context
- Path: `core/cortex/nexus_context.py`
- Referenced by string/dynamic literal: core/data/constants.py, tests/unit/test_phase2_nexus_context.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.policy
- Path: `core/cortex/policy.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.replay_capsule
- Path: `core/cortex/replay_capsule.py`
- Dynamic terms in file: Registry, getattr(, registry
- Router/tool/registry shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.cortex.scanner_bridge
- Path: `core/cortex/scanner_bridge.py`
- Referenced by string/dynamic literal: core/engine/scanner_engine.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cortex.session
- Path: `core/cortex/session.py`
- Referenced by string/dynamic literal: tests/core/cortex/test_nexus_phase1.py
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.cortex.subscriptions
- Path: `core/cortex/subscriptions.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.cronus.manager
- Path: `core/cronus/manager.py`
- Dynamic terms in file: getattr(
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.data
- Path: `core/data/__init__.py`
- Referenced by string/dynamic literal: core/data/dedup_store.py, core/engine/scanner_engine.py, core/toolkit/finding_verifier.py, tests/integration/test_db_concurrency.py, tests/integration/test_scan_failure.py, tests/unit/core/engine/test_scanner_engine.py, tests/unit/test_ledger_determinism.py, tests/unit/test_report_composer_real.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.data.blackbox
- Path: `core/data/blackbox.py`
- Referenced by string/dynamic literal: tests/integration/test_db_concurrency.py
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.data.db
- Path: `core/data/db.py`
- Referenced by string/dynamic literal: core/engine/scanner_engine.py, core/toolkit/finding_verifier.py, tests/integration/test_db_concurrency.py, tests/integration/test_scan_failure.py, tests/unit/core/engine/test_scanner_engine.py
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.data.evidence
- Path: `core/data/evidence.py`
- Referenced by string/dynamic literal: tests/unit/test_report_composer_real.py
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.data.evidence_store
- Path: `core/data/evidence_store.py`
- Referenced by string/dynamic literal: tests/unit/test_report_composer_real.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.data.findings
- Path: `core/data/findings.py`
- Referenced by string/dynamic literal: tests/unit/test_ledger_determinism.py
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.data.findings_store
- Path: `core/data/findings_store.py`
- Referenced by string/dynamic literal: tests/unit/test_ledger_determinism.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.data.pressure_graph.manager
- Path: `core/data/pressure_graph/manager.py`
- Dynamic terms in file: entry_points
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.data.pressure_graph.min_fix_set
- Path: `core/data/pressure_graph/min_fix_set.py`
- Dynamic terms in file: entry_points
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.data.pressure_graph.propagator
- Path: `core/data/pressure_graph/propagator.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.data.pressure_graph.tests.test_v2_logic
- Path: `core/data/pressure_graph/tests/test_v2_logic.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.data.risk
- Path: `core/data/risk.py`
- Referenced by string/dynamic literal: core/data/constants.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.engine
- Path: `core/engine/__init__.py`
- Referenced by string/dynamic literal: core/engine/scanner_engine.py, tests/unit/core/engine/test_scanner_engine.py, tests/unit/test_pty_cleanup.py, tests/unit/test_pty_fencing.py, tests/unit/test_scan_watchdog.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.engine.pty_manager
- Path: `core/engine/pty_manager.py`
- Dynamic terms in file: Registry, registry
- Referenced by string/dynamic literal: tests/unit/test_pty_cleanup.py, tests/unit/test_pty_fencing.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.engine.scanner_engine
- Path: `core/engine/scanner_engine.py`
- Dynamic terms in file: InternalTool, TOOLS, getattr(, registry
- Referenced by string/dynamic literal: core/engine/scan_orchestrator.py, tests/unit/core/engine/test_scanner_engine.py, tests/unit/test_scan_watchdog.py
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.engine.vanguard
- Path: `core/engine/vanguard.py`
- Referenced by string/dynamic literal: core/engine/scanner_engine.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.errors
- Path: `core/errors.py`
- Dynamic terms in file: TOOLS
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.forge
- Path: `core/forge/__init__.py`
- Referenced by string/dynamic literal: tests/unit/core/test_trinity_hardening.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.forge.validator
- Path: `core/forge/validator.py`
- Dynamic terms in file: __import__
- Referenced by string/dynamic literal: tests/unit/core/test_trinity_hardening.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.authorization
- Path: `core/foundry/authorization.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_authorization.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.challenges
- Path: `core/foundry/challenges.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_challenges.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.driver_playwright
- Path: `core/foundry/driver_playwright.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_driver_playwright.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.planner
- Path: `core/foundry/planner.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_planner.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.recipe
- Path: `core/foundry/recipe.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_recipe.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.recorder
- Path: `core/foundry/recorder.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_recorder.py
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.foundry.replay
- Path: `core/foundry/replay.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_foundry_replay.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.signup
- Path: `core/foundry/signup.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_foundry_signup.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.foundry.vault
- Path: `core/foundry/vault.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_vault.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ghost
- Path: `core/ghost/__init__.py`
- Referenced by string/dynamic literal: core/verify/__init__.py, tests/unit/test_ghost_router.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ghost.flow
- Path: `core/ghost/flow.py`
- Dynamic terms in file: registry
- Referenced by string/dynamic literal: core/verify/__init__.py, tests/unit/test_flow_capture.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ghost.flow_diff
- Path: `core/ghost/flow_diff.py`
- Referenced by string/dynamic literal: tests/unit/test_flow_diff.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ghost.mutations
- Path: `core/ghost/mutations.py`
- Referenced by string/dynamic literal: tests/unit/test_mutation_library.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ghost.proxy
- Path: `core/ghost/proxy.py`
- Dynamic terms in file: getattr(, registry
- Referenced by string/dynamic literal: core/server/routers/ghost.py, tests/unit/test_ghost_router.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.ghost.replay
- Path: `core/ghost/replay.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_replay_engine.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.intel
- Path: `core/intel/__init__.py`
- Referenced by string/dynamic literal: core/intel/compilers/__init__.py, core/intel/extractors/__init__.py, core/verify/__init__.py, scripts/sentinel_token.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.intel.policy_enforcer
- Path: `core/intel/policy_enforcer.py`
- Dynamic terms in file: TOOLS, getattr(, registry
- Referenced by string/dynamic literal: core/verify/__init__.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.intel.program_scope
- Path: `core/intel/program_scope.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.intel.registrar
- Path: `core/intel/registrar.py`
- Router/tool/registry shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.intel.resolver
- Path: `core/intel/resolver.py`
- Dynamic terms in file: registry
- Router/tool/registry shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.intel.selection.scorer
- Path: `core/intel/selection/scorer.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_program_scorer.py
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.intel.token_store
- Path: `core/intel/token_store.py`
- Referenced by string/dynamic literal: scripts/sentinel_token.py
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.mimic.downloader
- Path: `core/mimic/downloader.py`
- Referenced by string/dynamic literal: tests/unit/core/mimic/test_asset_downloader.py
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.net.adapter
- Path: `core/net/adapter.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.net.http_factory
- Path: `core/net/http_factory.py`
- Referenced by string/dynamic literal: core/base/config.py, core/intel/extractors/generic_url.py, core/intel/verifier.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.observer.bus
- Path: `core/observer/bus.py`
- Dynamic terms in file: getattr(
- Current verdict: ORPHAN_STRONG; runtime_reachable=no; test_only=no.

## core.omega
- Path: `core/omega/__init__.py`
- Referenced by string/dynamic literal: core/omega/manager.py
- Has `__main__` block.
- CLI shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.recon.behavioral
- Path: `core/recon/behavioral.py`
- Dynamic terms in file: TOOLS, getattr(
- Router/tool/registry shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.reporting.bounty_report
- Path: `core/reporting/bounty_report.py`
- Referenced by string/dynamic literal: tests/unit/test_bounty_report.py
- Current verdict: FORK_DECISION; runtime_reachable=yes; test_only=no.

## core.reporting.composer
- Path: `core/reporting/composer.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_report_composer_real.py
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.reporting.report_composer
- Path: `core/reporting/report_composer.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_report_composer_real.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.reporting.repro
- Path: `core/reporting/repro.py`
- Referenced by string/dynamic literal: tests/unit/test_repro.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.reporting.submission_render
- Path: `core/reporting/submission_render.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: core/submission/h1_client.py, tests/unit/test_submission_render.py
- Current verdict: FORK_DECISION; runtime_reachable=no; test_only=yes.

## core.safety.ownership_registry
- Path: `core/safety/ownership_registry.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.scheduler.decisions
- Path: `core/scheduler/decisions.py`
- Dynamic terms in file: getattr(
- Has `__main__` block.
- CLI shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.scheduler.laws
- Path: `core/scheduler/laws.py`
- Dynamic terms in file: getattr(
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.scheduler.modes
- Path: `core/scheduler/modes.py`
- Dynamic terms in file: Registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.scheduler.registry
- Path: `core/scheduler/registry.py`
- Dynamic terms in file: Registry, TOOLS, registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.scheduler.strategos
- Path: `core/scheduler/strategos.py`
- Dynamic terms in file: Registry, TOOLS, getattr(, registry
- Referenced by string/dynamic literal: core/engine/scan_orchestrator.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.sentient.cronus.differ
- Path: `core/sentient/cronus/differ.py`
- Dynamic terms in file: getattr(
- Has `__main__` block.
- CLI shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.sentient.cronus.hunter
- Path: `core/sentient/cronus/hunter.py`
- Dynamic terms in file: getattr(
- Has `__main__` block.
- CLI shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.sentient.cronus.time_machine
- Path: `core/sentient/cronus/time_machine.py`
- Dynamic terms in file: getattr(
- Has `__main__` block.
- CLI shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.sentient.mimic.ast_parser
- Path: `core/sentient/mimic/ast_parser.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.sentient.mimic.downloader
- Path: `core/sentient/mimic/downloader.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.server
- Path: `core/server/__init__.py`
- Referenced by string/dynamic literal: core/intel/compilers/__init__.py, core/server/routers/realtime.py, sentinelforge/cli/sentinel.py, tests/integration/test_cors_security.py, tests/integration/test_pty_interaction.py, tests/integration/test_scan_failure.py, tests/unit/test_command_validation.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.api
- Path: `core/server/api.py`
- Dynamic terms in file: TOOLS, getattr(
- Referenced by string/dynamic literal: sentinelforge/cli/sentinel.py, tests/unit/test_command_validation.py
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.server.openapi_gen
- Path: `core/server/openapi_gen.py`
- Has `__main__` block.
- CLI shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.server.routers
- Path: `core/server/routers/__init__.py`
- Referenced by string/dynamic literal: core/intel/compilers/__init__.py, core/server/routers/realtime.py, tests/integration/test_cors_security.py, tests/integration/test_pty_interaction.py, tests/integration/test_scan_failure.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.ai
- Path: `core/server/routers/ai.py`
- Dynamic terms in file: getattr(
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.auth
- Path: `core/server/routers/auth.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.cortex
- Path: `core/server/routers/cortex.py`
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.forge
- Path: `core/server/routers/forge.py`
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.foundry
- Path: `core/server/routers/foundry.py`
- Referenced by string/dynamic literal: tests/unit/test_foundry_router.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.ghost
- Path: `core/server/routers/ghost.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_ghost_router.py
- CLI shape detected.
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.realtime
- Path: `core/server/routers/realtime.py`
- Referenced by string/dynamic literal: tests/integration/test_cors_security.py, tests/integration/test_pty_interaction.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.scans
- Path: `core/server/routers/scans.py`
- Dynamic terms in file: Registry, TOOLS, getattr(, registry
- Referenced by string/dynamic literal: core/engine/scan_orchestrator.py, core/intel/compilers/__init__.py, core/intel/compilers/scope_compiler.py, tests/integration/test_scan_failure.py, tests/unit/intel/test_scope_compiler.py, tests/unit/test_session_lifecycle.py
- Router/tool/registry shape detected.
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.server.routers.system
- Path: `core/server/routers/system.py`
- Dynamic terms in file: TOOLS, getattr(, registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.routers.verify
- Path: `core/server/routers/verify.py`
- Referenced by string/dynamic literal: tests/unit/test_verify_console.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.server.state
- Path: `core/server/state.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/unit/test_command_validation.py
- Current verdict: DO_NOT_TOUCH; runtime_reachable=yes; test_only=no.

## core.submission
- Path: `core/submission/__init__.py`
- Referenced by string/dynamic literal: tests/unit/test_h1_submission.py
- Current verdict: FORK_DECISION; runtime_reachable=no; test_only=yes.

## core.submission.h1_client
- Path: `core/submission/h1_client.py`
- Referenced by string/dynamic literal: tests/unit/test_h1_submission.py
- Current verdict: FORK_DECISION; runtime_reachable=no; test_only=yes.

## core.thanatos.mutations
- Path: `core/thanatos/mutations.py`
- Dynamic terms in file: Registry
- Router/tool/registry shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.toolkit
- Path: `core/toolkit/__init__.py`
- Dynamic terms in file: TOOLS, registry
- Referenced by string/dynamic literal: core/engine/scanner_engine.py, core/toolkit/vuln_rules.py, tests/core/wraith/test_oob.py, tests/core/wraith/test_verifier.py, tests/integration/test_tool_diagnostics.py, tests/unit/test_command_validation.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.diagnostics
- Path: `core/toolkit/diagnostics.py`
- Dynamic terms in file: TOOLS, registry
- Referenced by string/dynamic literal: tests/integration/test_tool_diagnostics.py
- Router/tool/registry shape detected.
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.toolkit.finding_verifier
- Path: `core/toolkit/finding_verifier.py`
- Referenced by string/dynamic literal: core/cortex/chain_verifier.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.installer
- Path: `core/toolkit/installer.py`
- Dynamic terms in file: TOOLS, registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.internal_tool
- Path: `core/toolkit/internal_tool.py`
- Dynamic terms in file: InternalTool, registry
- Referenced by string/dynamic literal: tests/core/wraith/test_oob.py, tests/core/wraith/test_verifier.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.internal_tools
- Path: `core/toolkit/internal_tools/__init__.py`
- Dynamic terms in file: InternalTool, registry
- Referenced by string/dynamic literal: tests/core/wraith/test_oob.py, tests/core/wraith/test_verifier.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.internal_tools.api_discoverer
- Path: `core/toolkit/internal_tools/api_discoverer.py`
- Dynamic terms in file: InternalTool
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.internal_tools.oob_probe
- Path: `core/toolkit/internal_tools/oob_probe.py`
- Dynamic terms in file: InternalTool, registry
- Referenced by string/dynamic literal: tests/core/wraith/test_oob.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.internal_tools.persona_diff
- Path: `core/toolkit/internal_tools/persona_diff.py`
- Dynamic terms in file: InternalTool
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.internal_tools.vuln_verifier
- Path: `core/toolkit/internal_tools/vuln_verifier.py`
- Dynamic terms in file: InternalTool
- Router/tool/registry shape detected.
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=no; test_only=no.

## core.toolkit.internal_tools.wraith_verify
- Path: `core/toolkit/internal_tools/wraith_verify.py`
- Dynamic terms in file: InternalTool, getattr(
- Referenced by string/dynamic literal: tests/core/wraith/test_verifier.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.raw_classifier
- Path: `core/toolkit/raw_classifier.py`
- Dynamic terms in file: plugin, plugins
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.registry
- Path: `core/toolkit/registry.py`
- Dynamic terms in file: InternalTool, Registry, TOOLS, registry
- Referenced by string/dynamic literal: core/toolkit/internal_tools/__init__.py, tests/unit/test_command_validation.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.tools
- Path: `core/toolkit/tools.py`
- Dynamic terms in file: TOOLS, getattr(, registry
- Referenced by string/dynamic literal: core/engine/scanner_engine.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.toolkit.vuln_rules
- Path: `core/toolkit/vuln_rules.py`
- Dynamic terms in file: Registry, plugin, plugins, registry
- Referenced by string/dynamic literal: core/data/constants.py, core/engine/scanner_engine.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.verify
- Path: `core/verify/__init__.py`
- Dynamic terms in file: registry
- Referenced by string/dynamic literal: scripts/calibration_50_end_to_end.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.verify.console
- Path: `core/verify/console.py`
- Referenced by string/dynamic literal: scripts/calibration_50_end_to_end.py, tests/unit/test_verify_console.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.verify.promoter
- Path: `core/verify/promoter.py`
- Referenced by string/dynamic literal: tests/unit/test_verify_promoter.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.web.crawler
- Path: `core/web/crawler.py`
- Dynamic terms in file: Registry, registry
- Referenced by string/dynamic literal: tests/unit/test_candidate_discovery.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.web.evidence_service
- Path: `core/web/evidence_service.py`
- Dynamic terms in file: getattr(, registry
- CLI shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.web.js_intel
- Path: `core/web/js_intel.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: ORPHAN_REVIEW; runtime_reachable=no; test_only=no.

## core.web.orchestrator
- Path: `core/web/orchestrator.py`
- Dynamic terms in file: Registry, registry
- Router/tool/registry shape detected.
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=no; test_only=no.

## core.web.surface_registry
- Path: `core/web/surface_registry.py`
- Dynamic terms in file: Registry
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.web.transport
- Path: `core/web/transport.py`
- Dynamic terms in file: registry
- Current verdict: TEST_ONLY; runtime_reachable=no; test_only=yes.

## core.wraith
- Path: `core/wraith/__init__.py`
- Referenced by string/dynamic literal: core/verify/__init__.py, core/wraith/bola_probe.py, core/wraith/bola_scale.py, core/wraith/verify_phase.py, scripts/calibration_36_gitlab.py, scripts/calibration_50_end_to_end.py, scripts/calibration_60_airtable_unauth.py, tests/core/wraith/test_auth_diff_scanner.py, tests/core/wraith/test_session_manager.py, tests/unit/test_verify_console.py, tests/unit/test_verify_phase.py, tests/unit/test_vuln_verifier_fixes.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.auth_diff_scanner
- Path: `core/wraith/auth_diff_scanner.py`
- Dynamic terms in file: InternalTool, getattr(
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.bola
- Path: `core/wraith/bola.py`
- Referenced by string/dynamic literal: core/wraith/bola_probe.py, core/wraith/bola_scale.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.candidate_discovery
- Path: `core/wraith/candidate_discovery.py`
- Dynamic terms in file: Registry, registry
- Referenced by string/dynamic literal: core/wraith/verify_phase.py, scripts/calibration_36_gitlab.py, scripts/calibration_60_airtable_unauth.py
- Router/tool/registry shape detected.
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.capability
- Path: `core/wraith/capability.py`
- Dynamic terms in file: getattr(, registry
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.execution_policy
- Path: `core/wraith/execution_policy.py`
- Dynamic terms in file: InternalTool, Registry, getattr(
- Router/tool/registry shape detected.
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.wraith.oob_detector
- Path: `core/wraith/oob_detector.py`
- Dynamic terms in file: registry
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.owned_proof
- Path: `core/wraith/owned_proof.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.persona_auth
- Path: `core/wraith/persona_auth.py`
- Referenced by string/dynamic literal: core/verify/__init__.py, scripts/calibration_36_gitlab.py, scripts/calibration_50_end_to_end.py, scripts/calibration_60_airtable_unauth.py, tests/unit/test_verify_console.py, tests/unit/test_verify_phase.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.personas
- Path: `core/wraith/personas.py`
- Referenced by string/dynamic literal: core/intel/compilers/persona_compiler.py, tests/core/wraith/test_auth_diff_scanner.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.session_manager
- Path: `core/wraith/session_manager.py`
- Dynamic terms in file: getattr(
- Referenced by string/dynamic literal: tests/core/wraith/test_session_manager.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.verify_phase
- Path: `core/wraith/verify_phase.py`
- Dynamic terms in file: getattr(, registry
- Referenced by string/dynamic literal: scripts/calibration_36_gitlab.py, scripts/calibration_50_end_to_end.py, scripts/calibration_60_airtable_unauth.py
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## core.wraith.vuln_verifier
- Path: `core/wraith/vuln_verifier.py`
- Dynamic terms in file: InternalTool, getattr(
- Referenced by string/dynamic literal: tests/unit/test_vuln_verifier_fixes.py
- Router/tool/registry shape detected.
- Current verdict: DUPLICATE_CLUSTER; runtime_reachable=yes; test_only=no.

## core.wraith.waf_retry
- Path: `core/wraith/waf_retry.py`
- Dynamic terms in file: getattr(
- Current verdict: LIVE; runtime_reachable=yes; test_only=no.

## Requested Dynamic-Ish Surfaces
- `core.forge.validator`: verdict=LIVE, runtime=yes, test_only=no, dynamic=yes, evidence=runtime_reachable; string_ref=tests/unit/core/test_trinity_hardening.py; contains_dynamic_loader=__import__.
- `core.data.pressure_graph.min_fix_set`: verdict=LIVE, runtime=yes, test_only=no, dynamic=yes, evidence=runtime_reachable; contains_dynamic_loader=entry_points.
- `core.data.pressure_graph.manager`: verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no, dynamic=yes, evidence=runtime_reachable; contains_dynamic_loader=entry_points; duplicate_basename.
