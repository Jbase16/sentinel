# Calibration Run #20 — Report Composer Tab (deep audit + brilliance pass)

The app's smoke test passed (Run #19), so the focus moved to the Report
Composer tab — the three features that turn findings into a submittable
deliverable: **Report Generator**, **Bounty**, and **Proof Lab**. Each
was traced UI → API → backend, tested live against the real
about.gitlab.com session, and fixed/enhanced.

**Verdict:** ✅ All three now produce real, useful output. Three classes
of bug found — one hard crash, one silently-empty feature, two
quality defects — all fixed with regression tests against the REAL data
shapes that surfaced them. 505 reporting+intel+classifier tests passing.

---

## Feature 1: Report Generator — was throwing HTTP 500

`POST /v1/cortex/reporting/generate` → `AttributeError: 'int' object has
no attribute 'get'`.

**Root cause:** `EvidenceStore.get_all()` returns a dict keyed by
evidence-id. The composer's `_safe_list_evidence` did `list(that_dict)`,
which yields the **keys (ints)**, not the entries. The markdown renderer
then called `.get("type")` on an int.

**Why it wasn't caught:** there are TWO `ReportComposer` classes —
`composer.py` (older) and `report_composer.py` (the one the API uses).
The existing test covered the former. The actually-executed code had
zero real coverage.

**Fix:** `_as_entry_list()` helper (dict → `.values()`, filter
non-dicts), applied to both evidence and findings; hardened the renderer
with an `isinstance` guard + real evidence keys (tool/summary). New test
file against the REAL composer reproduces the exact crash. Endpoint now
returns 200.

## Feature 2: Proof Lab — returned 200 but produced NOTHING

The most insidious bug: every PoC request returned a valid-looking
response with `commands: []` and the note "Finding type not mapped to a
specialized template." The Proof Lab was non-functional for **100% of
real findings**.

**Root cause (two layers):**
1. **Vocabulary mismatch** — the classifier emits `"Open Port"`,
   `"Missing Security Header"` (Title Case, spaces); the PoC templates
   dispatched on `"open_port"` (snake_case). NOTHING matched, including
   the types that HAD templates. Every finding fell through to the empty
   generic fallback.
2. **Field extraction** — the generator read `host`/`port` from
   top-level finding fields, but the classifier stores them in
   `metadata` + the `target` URL. Even a matched template had no host.

**Fix:**
- `_normalize_ftype()` maps real type names → template categories via
  substring matching (so "Java Framework Detected" and "Php Framework
  Detected" both → version_disclosure).
- `_parse_target()` + metadata extraction pulls host/port/scheme/path
  from where they actually live.
- New templates for the real finding types: missing_header (curl -I,
  names the specific header), cookie_misconfig, directory_listing,
  subdomain, version_disclosure, and a generic http_fetch for
  nikto/ssrf/backup/etc.
- https-default for unknown scheme (web targets are https-first).
- All commands still pass the existing safety allowlist + deny-patterns.

**Verified live:** every real finding type now produces specific,
safe, copy-pasteable commands:
```
Missing Security Header → curl -sS -I https://about.gitlab.com/
                          (note: `content-security-policy` should be ABSENT)
Open Port              → nc -zv about.gitlab.com 8443
                          nmap -sV -p 8443 about.gitlab.com   (port from metadata!)
DNS Record             → dig +short about.gitlab.com A/AAAA/CNAME
```

## Feature 3: Bounty Report — worked, but two quality defects

`GET /v1/scans/sessions/{id}/bounty-report` returned 200 with a real
HackerOne-ready document (CVSS 3.1 vectors, TOC, steps, impact,
remediation, cross-scan dedup annotations — genuinely solid). But the
live output exposed:

1. **Grammar bug:** "A medium severity Missing Security Header
   vulnerability **appears to was identified**" — the LOW-confidence
   hedge `" appears to"` was concatenated mid-clause. **Fix:**
   restructured to "A potential ... vulnerability was flagged" /
   "may be present" — grammatical in both confidence branches.

2. **Over-dedup:** all 7 distinct missing-header findings (same
   type+asset, different header) collapsed into ONE report naming only
   one header; the other 6 were silently dropped. Same for multiple
   open ports on one host. **Fix:** `build_reports` now GROUPS by
   (type, asset) and enumerates every instance's distinguishing label
   (`_distinguishing_label`: header/port/version) — so the report reads
   "This finding covers 7 instances: `content-security-policy`,
   `x-frame-options`, ..." None dropped.

New `test_bounty_report.py` (there were zero before) locks both fixes.

## The recurring meta-bug across all three

Every one of these was a **contract between two modules that was never
tested end-to-end against real data**:
- composer ↔ EvidenceStore (dict vs list shape)
- PoC generator ↔ classifier (type-name vocabulary)
- bounty dedup ↔ real multi-instance findings

And in two cases a *passing test existed but covered the wrong thing*
(duplicate ReportComposer module; no bounty test at all). This is the
same lesson as the Phase 2C scope round-trip (tested a test-local parser)
and the Run #17 inline-comment bug: **a green test only means something
if you've confirmed it exercises the code the live system runs.** The
fix pattern throughout: test against the REAL data shape, via the REAL
module, reproducing the REAL failure.

## Test deltas

| Suite | Before | After |
|---|---|---|
| test_report_composer_real | — | 13 (new) |
| test_poc_generator_real | — | 31 (new, parametrized) |
| test_bounty_report | — | 22 (new) |
| **reporting + intel + classifier combined** | ~445 | **505** |

Zero regressions. All three Report Composer features verified live
against the about.gitlab.com session.

## What an operator gets now

The Report Composer tab is now a real deliverable pipeline:
- **Report Generator** → a clean security-assessment markdown report
- **Bounty** → a HackerOne-ready per-finding report with CVSS vectors,
  enumerated instances, steps, impact, remediation, dedup annotations
- **Proof Lab** → safe, copy-pasteable verification commands specific to
  each finding type

The thing that turns "Sentinel found something" into "here's a report I
can submit" works end-to-end.
