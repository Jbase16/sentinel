# Calibration Run #21 — Report data-source unification

Operator-reported discrepancies after re-running about.gitlab.com through
the app: the Report Generator, Bounty tab, Proof Lab, and Target Scan tab
all showed DIFFERENT findings, counts, and types for the same scan. Root
cause: they read from different data sources. This run unifies them.

**Verdict:** ✅ Five operator-reported mismatches resolved; the Report
Generator now describes the actual scan in the same vocabulary as every
other view. 508 reporting+intel+classifier tests passing.

---

## The reported symptoms (all real)

1. Report Generator showed 8 findings (3 med + 5 low) with stale types
   (`subdomain_discovery`, `vulnerability`, `misconfig`) — mismatching the
   Target Scan tab's 17 (7 med + 10 info).
2. Bounty tab showed 2 medium, mismatching both.
3. Proof Lab "Available Findings" listed every item as "Untitled Finding".
4. Report MD evidence list dumped **2362** artifacts.
5. Report finding headings were inconsistent: `### 1. subdomain_discovery`,
   `### 2. vulnerability`, `### 6. misconfig`, `### 4. Multiple IP Addresses`.

## The single root cause behind 1, 4, 5

`get_finding_store()` returns a **global singleton** that accumulates
findings from EVERY scan ever run (dedup showed "first seen 2026-02-24,
seen 240x"). The Report Generator read it; the Bounty report read
`db.get_findings(session_id)` (session-scoped); the Target Scan tab read
the live session stream. Three views, three sources.

The "stale types" (`vulnerability`/`misconfig`/`subdomain_discovery`) were
old findings from a prior AI-reasoning vocabulary the current classifier
doesn't use. The 2362 evidence artifacts were the global EvidenceStore's
lifetime accumulation.

## Fixes

### Session-scope the Report Generator (the big one)

- `ReportGenerateRequest` gained `session_id`.
- `generate_report` is now async and resolves the session: explicit
  `session_id` → most-recent session → global fallback. It pulls
  `db.get_findings(session_id)` + `db.get_evidence(session_id)` and builds
  a session-scoped composer via a `_ListStore` adapter.
- **Result:** report now shows 17 findings (7 MEDIUM + 10 INFO) — exactly
  matching the Target Scan tab — with 6 session-scoped evidence artifacts.

### Severity table was empty — field-name mismatch

`_build_summary` read `f.get("risk", "unknown")` but findings carry
`severity`. Every finding counted as "unknown" → empty severity table even
with 17 findings. **Fix:** read `severity` first, fall back to `risk`.

### Distinct finding headings

7 missing-header findings rendered as 7 identical `### Missing Security
Header` lines. **Fix:** `_finding_heading()` composes `type: detail` from
metadata (header name / port / version), so each reads
`### Missing Security Header: content-security-policy`,
`### Open Port: port 8443`, `### DNS Record: about.gitlab.com A 172.64...`.

### Evidence render cap

Even session-scoped, a scan can produce many artifacts. Capped the
rendered list at 25 with a "… and N more" summary line.

### Proof Lab "Untitled Finding" (Swift)

`ReportView.swift` read `finding.title` (only set by the bounty endpoint);
raw findings carry `type`/`message`. **Fix:** `finding.title ?? message ??
type`. Also added `sessionId` to the Swift `generateReport` call so the app
can pin the report to the active scan (backend also defaults to latest).

## The remaining (by-design) difference: findings vs. issues

Symptoms 2 and 4 — Bounty showing 2 medium incl. "Dangerous HTTP Verbs
Enabled," which isn't in the Target Scan findings — are NOT a bug:

- **Target Scan tab + Report Generator** show raw *findings* (classifier
  output).
- **Bounty report** merges *issues* (promoted/correlated findings) +
  findings, then groups by (type, asset). "Dangerous HTTP Verbs Enabled"
  is an *issue*, and the 7 missing headers group into 1 → 2 entries.

This is intentional: the Bounty report is the submission-ready artifact
(deduped, grouped, issue-enriched); the Report Generator is the full
assessment (every finding). Documented here so the distinction is explicit
rather than looking like a mismatch. A future unification could surface
issues in the Target Scan tab too, but that's a product decision, not a bug.

## The meta-pattern, again

Every symptom traced to a **field/source contract that was never tested
end-to-end against real data**: global-vs-session store, `risk` vs
`severity`, `title` vs `type`. Same class as the Run #20 bugs (composer ↔
EvidenceStore dict shape; PoC ↔ classifier vocabulary). The fix pattern
held: read the REAL data shape, via the REAL module, reproduce the REAL
discrepancy, test it.

## Verified live

Session-scoped report for about.gitlab.com (139475bf):
```
Severity table:  7 MEDIUM + 10 INFO  (== Target Scan tab)
Evidence:        6 artifacts          (was 2362)
Headings:        Missing Security Header: content-security-policy
                 Open Port: port 8443
                 DNS Record: about.gitlab.com A 172.64.144.122
                 ...  (17 distinct, self-describing)
```

## Test deltas

| Suite | Before | After |
|---|---|---|
| test_report_composer_real | 19 | 22 (+3 severity/heading) |
| reporting + intel + classifier combined | 505 | **508** |

Zero regressions.
