# Do Not Delete / High-Risk Modules
These modules may look stale, duplicated, or small, but the evidence says cleanup risk is high.

- `core.base.context` (core/base/context.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; tool_or_router_shape; duplicate_basename.
- `core.base.execution_policy` (core/base/execution_policy.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; duplicate_basename.
- `core.base.scope` (core/base/scope.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; tool_or_router_shape.
- `core.base.session` (core/base/session.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=tests/unit/test_teardown_deadline.py; duplicate_basename.
- `core.bounty.h1_client` (core/bounty/h1_client.py): verdict=FORK_DECISION, runtime=yes, test_only=no; evidence=runtime_reachable; tool_or_router_shape; duplicate_basename; known_report_submission_fork.
- `core.cortex.events` (core/cortex/events.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=tests/integration/test_ghost_lazarus_integration.py; duplicate_basename.
- `core.cortex.execution_policy` (core/cortex/execution_policy.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; tool_or_router_shape; duplicate_basename.
- `core.cortex.minimal_amplification` (core/cortex/minimal_amplification.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; known_recent_bounty_safe.
- `core.cortex.reasoning` (core/cortex/reasoning.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable.
- `core.data.blackbox` (core/data/blackbox.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=tests/integration/test_db_concurrency.py.
- `core.data.db` (core/data/db.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=core/engine/scanner_engine.py,core/toolkit/finding_verifier.py,tests/integration/test_db_concurrency.py,tests/integration/test_scan_failure.py.
- `core.engine.scanner_engine` (core/engine/scanner_engine.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=core/engine/scan_orchestrator.py,tests/unit/core/engine/test_scanner_engine.py,tests/unit/test_scan_watchdog.py; tool_or_router_shape.
- `core.replay.merkle` (core/replay/merkle.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable.
- `core.replay.models` (core/replay/models.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; duplicate_basename.
- `core.safety.action_classifier` (core/safety/action_classifier.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable.
- `core.safety.ownership_registry` (core/safety/ownership_registry.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; tool_or_router_shape; known_recent_bounty_safe.
- `core.safety.proof_budget` (core/safety/proof_budget.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable.
- `core.safety.proof_mode` (core/safety/proof_mode.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable.
- `core.safety.provenance` (core/safety/provenance.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; known_recent_bounty_safe.
- `core.server.api` (core/server/api.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=sentinelforge/cli/sentinel.py,tests/unit/test_command_validation.py; tool_or_router_shape.
- `core.server.routers.scans` (core/server/routers/scans.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=core/engine/scan_orchestrator.py,core/intel/compilers/__init__.py,core/intel/compilers/scope_compiler.py,tests/integration/test_scan_failure.py; tool_or_router_shape.
- `core.server.state` (core/server/state.py): verdict=DO_NOT_TOUCH, runtime=yes, test_only=no; evidence=runtime_reachable; string_ref=tests/unit/test_command_validation.py.
- `core.wraith.execution_policy` (core/wraith/execution_policy.py): verdict=DUPLICATE_CLUSTER, runtime=yes, test_only=no; evidence=runtime_reachable; tool_or_router_shape; duplicate_basename.

## Explicit User-Flagged Safe Path
- `core.cortex.minimal_amplification`: DO_NOT_TOUCH; tests=tests/unit/core/test_minimal_amplification.py; runtime=yes.
- `core.safety.provenance`: DO_NOT_TOUCH; tests=tests/unit/core/test_execution_policy.py;tests/unit/core/test_minimal_amplification.py;tests/unit/core/test_provenance.py; runtime=yes.
- `core.safety.ownership_registry`: DO_NOT_TOUCH; tests=tests/unit/core/test_execution_policy.py;tests/unit/core/test_minimal_amplification.py;tests/unit/core/test_ownership_registry.py; runtime=yes.
