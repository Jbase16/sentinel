# Technical Specification: Repository Hygiene and Structural Remediation

## Technical Context
- Languages: Python 3.11+ (core engine, tooling), Swift (macOS UI). Primary cleanup surface is Python + repo filesystem metadata.
- Repo layout: `core/` (Python engine), `ui/` (SwiftPM app), `docs/` (architecture/task docs), `tools/ops/` (ops scripts), `tests/` (unit/integration/verification), `models/` (artifacts), `assets/` (wordlists), `.zencoder/` (chat artifacts), `.zenflow/`, `.github/` workflows, venvs (`.venv/`, `venv/`).
- Tooling assumptions: git available; pytest present; no new dependencies to be added. Existing helper `tools/lint_structure.py` for structure checks.

## Technical Implementation Brief
- Build a deterministic "Disposition Engine" that classifies files into `{delete, archive, keep}` with evidence. It consumes: filesystem metadata (size, type), git history (last touch, deletion ancestry), reference graph (imports/references), and doc freshness.
- Produce two artifacts: (1) Deletion list with rationale and evidence hash; (2) Partial-confidence list with per-file clarifying questions. No destructive actions executed.
- Provide an optional Archive Manifest (for Desktop archive folder) for `.md` task/history files where risk > 0.
- Safety rails: hard-block model assets (`models/`), build infra (`Dockerfile`, `docker-compose.yml`, `.github/workflows`), IPC surfaces, and tests unless evidence explicitly shows redundancy and user confirms.

## Source Code Structure
- New module: `tools/ops/cleanup_disposition.py`
  - Entry CLI: `python -m tools.ops.cleanup_disposition --mode {scan}`
  - Steps: inventory → evidence extraction → disposition scoring → emit reports.
- Reports emitted to `archive_stage/`:
  - `deletion_list.json`: definitive deletions with rationale, evidence.
  - `partial_confidence.json`: candidates with questions.
  - `archive_manifest.json`: files recommended for Desktop archive with source paths.
- Reuse `tools/lint_structure.py` to validate structure after proposed deletions (simulation only).

## Contracts
- Data classes (Python):
  - `Evidence`: `{path, size_bytes, mtime, git_last_commit, git_deleted_previously: bool, references: [paths], type: {code, doc, asset, build, test, model}}`
  - `DispositionRecord`: `{path, disposition: {delete|archive|keep|unknown}, confidence: float, rationale: str, questions: [str], evidence: Evidence}`
  - `ReportBundle`: `{deletion: [DispositionRecord], partial: [DispositionRecord], archive: [DispositionRecord]}`
- Invariants:
  - `deletion` contains only `disposition=delete` with `confidence >= 0.9` and empty `questions`.
  - `partial` contains `confidence < 0.9` or non-empty `questions`.
  - `archive` limited to docs with `type=doc` and `questions` empty.
- Heuristics (extensible ruleset):
  - Stale doc: `.md` with no commits in N days and superseded filename in same dir (e.g., `*_summary*` newer than `*_plan*`).
  - Orphaned code: no inbound references in repo + last commit > N days + tests absent.
  - Generated/temp: `.pytest_cache/`, `__pycache__/`, `.build/`, `.swiftpm/`, venvs → auto-delete list.
  - Protected roots: `models/`, `core/api*`, `ui/Sources`, `.github/workflows`, `Dockerfile*`, `docker-compose.yml`, `requirements.txt`, `README.md`, `AGENTS.md`, `docs/architecture.md`.

## Delivery Phases
1) **Inventory & Evidence Harness**: implement `Evidence` extraction (fs metadata + git history + type tagging) and emit raw inventory JSON.
2) **Disposition Engine**: implement rules to populate `DispositionRecord` sets; enforce invariants; generate `deletion_list.json`, `partial_confidence.json`, `archive_manifest.json`.
3) **Safety Simulation**: dry-run structure check by simulating deletion set against `tools/lint_structure.py` and import/reference scans; flag any breakage into partial list.
4) **User Review Aids**: augment partial records with targeted questions; generate summary table; optional script to copy archive candidates to Desktop (no execution by default).
5) **Final Validation**: run tests/lint (non-destructive) to ensure proposed deletions wouldn’t fail baseline CI when applied (simulate by excluding deletion set during discovery checks).

## Verification Strategy
- Commands (non-destructive):
  - `python -m tools.ops.cleanup_disposition --mode scan` (produces reports only)
  - `python -m compileall core` (sanity on surviving tree if needed)
  - `python -m pytest tests` (baseline health; expect pass before/after recommendations)
  - `python tools/lint_structure.py` (structure sanity)
- MCP/Helpers: none required; rely on git + local Python. If partial questions remain, user review answers resolve final state.
- For each phase, verify:
  - Phase 1: inventory JSON exists with evidence fields populated.
  - Phase 2: reports honor invariants (automated assertion inside script).
  - Phase 3: structure check passes with deletion set simulated.
  - Phase 4: partial list includes questions; archive manifest present for doc candidates.
  - Phase 5: pytest + lint pass on current tree (no deletions applied).