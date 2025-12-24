# Feature Specification: Repository Hygiene and Structural Remediation

## User Stories

### User Story 1 - Curated Deletion
**Acceptance Scenarios**:
1. **Given** the current repository state, **When** the cleanup analysis runs, **Then** it produces a list of files safe to delete with explicit rationales and zero false positives.
2. **Given** flagged questionable files, **When** the user reviews the partial-confidence list, **Then** the user can approve/deny each with minimal extra context needed.

### User Story 2 - Preservation with Audit Trail
**Acceptance Scenarios**:
1. **Given** legacy docs with uncertain status, **When** the system recommends archiving, **Then** the user can move them to a Desktop archive folder with a manifest noting their origin.
2. **Given** repository history, **When** decisions are generated, **Then** git history is referenced to justify staleness or redundancy.

### User Story 3 - Structural Integrity
**Acceptance Scenarios**:
1. **Given** the cleanup recommendations, **When** the repo structure is reorganized, **Then** essential build/CI/runtime paths remain intact.
2. **Given** the target state, **When** size reduction occurs, **Then** no critical security or model assets are removed inadvertently.

---

## Requirements
- Produce a definitive deletion list with rationale for each file; zero ambiguity items only.
- Produce a partial-confidence list with targeted questions per file to resolve status.
- Use git history to justify obsolescence (e.g., last-touch date, superseded paths, deleted references).
- Identify and propose a standard archive path (Desktop archive folder) for legacy .md task/history files when removal risk is non-zero.
- Preserve project integrity: do not break build/CI/runtime; flag any build/ops artifacts that look unused but risky to drop.
- Focus first on file-size reduction and structural clarity; consider directory consolidation opportunities.
- Deliver outputs in a reviewable format (lists + rationale + questions), not an automated destructive action.

## Success Criteria
- Deletion list contains only items with high confidence and supporting rationale.
- Partial-confidence list includes clarifying questions specific enough for quick user decisions.
- Archive recommendation includes manifest of archived items and origin paths.
- No critical functionality, pipelines, or security posture is degraded post-cleanup.
- Recommendations trace back to evidence (git history, duplication, superseded docs/code).