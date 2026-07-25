# Non-Core Surfaces Supplement

## Scope
- Covers tracked non-`core/`, non-`ui/`, non-`tests/` script/config/tool entry surfaces. It does not classify docs as deletable; docs need human product/history review.
- Script/config/tool-like tracked files inventoried: 37

## Runtime / Operator Entry Points
- `scripts/calibration_36_gitlab.py`: python_main;imports_core; core_imports=core.base.session;core.wraith.candidate_discovery;core.wraith.verify_phase; last=27f5498 2026-05-27.
- `scripts/calibration_50_end_to_end.py`: python_main;imports_core; core_imports=core.base.session;core.data.findings_store;core.reporting.bounty_report;core.server.routers.verify;core.verify.console;core.wraith.verify_phase; last=ef6532b 2026-06-06.
- `scripts/calibration_60_airtable_unauth.py`: python_main;imports_core; core_imports=core.base.session;core.wraith.verify_phase; last=4f4b665 2026-06-07.
- `scripts/check_circular_imports.py`: python_main;dynamic_import; core_imports=none; last=6da1a7b 2026-01-05.
- `scripts/check_schema_drift.py`: python_main;imports_core; core_imports=core.web.contracts.events;core.web.contracts.models; last=333b679 2026-02-25.
- `scripts/dummy_server.py`: python_main; core_imports=none; last=ae925dd 2026-02-24.
- `scripts/generate_web_schemas.py`: python_main;imports_core; core_imports=core.web.contracts.events;core.web.contracts.models; last=333b679 2026-02-25.
- `scripts/inspect_scan.py`: cli_argparse;python_main; core_imports=none; last=5f46ae0 2026-05-21.
- `scripts/preflight.py`: operator_preflight;cli_argparse;python_main;dynamic_import; core_imports=none; last=5f46ae0 2026-05-21.
- `scripts/sentinel_discover.py`: cli_argparse;python_main;imports_core; core_imports=core.intel;core.intel.program_scope;core.intel.selection; last=5177ce6 2026-06-07.
- `scripts/sentinel_ingest.py`: cli_argparse;python_main;imports_core; core_imports=core.intel;core.intel.compilers;core.intel.extractors.base;core.intel.policy_enforcer;core.intel.registrar; last=5f46ae0 2026-05-21.
- `scripts/sentinel_rank.py`: cli_argparse;python_main;imports_core; core_imports=core.intel.program_scope;core.intel.selection; last=30b2850 2026-06-07.
- `scripts/sentinel_token.py`: cli_argparse;python_main;imports_core; core_imports=core.intel;core.intel.token_store; last=5f46ae0 2026-05-21.
- `scripts/smoke_test_idor.py`: python_main;imports_core; core_imports=core.web.auth_manager;core.web.context;core.web.contracts.enums;core.web.contracts.ids;core.web.contracts.models;core.web.crawler;core.web.event_bus;core.web.orchestrator; last=a9dc61e 2026-02-26.
- `scripts/smoke_test_orchestrator.py`: python_main;imports_core; core_imports=core.web.context;core.web.contracts.ids;core.web.contracts.models;core.web.crawler;core.web.event_bus;core.web.orchestrator; last=c579c09 2026-02-24.
- `scripts/start_backend.sh`: backend_start_entry; core_imports=none; last=44c8129 2026-01-09.
- `scripts/test_auth_isolation.py`: python_main;imports_core; core_imports=core.web.auth_manager;core.web.context;core.web.contracts.enums;core.web.contracts.ids;core.web.contracts.models;core.web.diff.baseline;core.web.diff.delta;core.web.event_bus;core.web.transport; last=ae925dd 2026-02-24.
- `scripts/verify_forge_access.py`: python_main;imports_core; core_imports=core.base.config; last=333b679 2026-02-25.
- `tools/lint_structure.py`: python_main; core_imports=none; last=dcbccb3 2025-12-30.
- `tools/ops/annotate_inline_comments.py`: python_main; core_imports=none; last=8610a33 2025-12-19.
- `tools/ops/cleanup_disposition.py`: cli_argparse;python_main; core_imports=none; last=dcbccb3 2025-12-30.
- `tools/ops/debug_cortex.py`: python_main; core_imports=none; last=8610a33 2025-12-19.
- `tools/ops/manual_scan.py`: python_main;imports_core; core_imports=core.base.session;core.data.db;core.engine.scanner_engine; last=8610a33 2025-12-19.
- `tools/ops/run_headless_scan_with_narrator.py`: python_main;imports_core; core_imports=core.cortex.narrator;core.scheduler.decisions; last=8610a33 2025-12-19.
- `tools/ops/run_real_scan_headless.py`: python_main;imports_core; core_imports=core.cortex.events;core.cortex.narrator;core.scheduler.decisions;core.scheduler.modes;core.scheduler.strategos; last=8610a33 2025-12-19.
- `tools/ops/start_sentinel_brain.py`: python_main; core_imports=none; last=8610a33 2025-12-19.
- `tools/ops/strip_banners.py`: python_main; core_imports=none; last=8610a33 2025-12-19.
- `tools/ops/test_tools_install.py`: python_main;imports_core; core_imports=core.toolkit.tools; last=8610a33 2025-12-19.
- `tools/ops/verify_strategic_logging.py`: python_main;imports_core; core_imports=core.cortex.events;core.scheduler.modes;core.scheduler.strategos; last=8610a33 2025-12-19.

## Config Surfaces
- `Makefile`: support_or_config; last=e58d306 2026-02-24.
- `pyproject.toml`: support_or_config; last=5cce91b 2026-01-07.
- `scripts/local-security-check.sh`: support_or_config; last=9d9a1b3 2025-12-26.
- `scripts/start_backend.sh`: backend_start_entry; last=44c8129 2026-01-09.
- `tools/ops/start_servers.sh`: support_or_config; last=8610a33 2025-12-19.

## Cleanup Warning
- Do not delete scripts just because they are outside `core/`; several are operator CLIs or calibration/smoke entry points importing live `core` code.
- Docs and archive material are inventoried in `whole_repo_inventory.tsv` but intentionally not classified as stale by static reachability.
