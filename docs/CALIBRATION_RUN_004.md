# Calibration Run #4 — 2026-05-14

Fourth calibration. Goal: address the "engine only uses 4 of ~22 tools"
gap by running in `standard` mode and against the richer lab at :3003.

**Verdict:** Standard mode against MegaShop produced **26 findings, 7
promoted issues (6 HIGH), 3 HIGH-severity findings** including
`.git/config` exposed and an SSRF indicator. This is the first run that
produced actual bounty-grade signal. The "few tools running" problem was
half mode-overlay (bug_bounty disabled brute-force tools) and half
tool-precondition gaps (wraith_* need personas/OOB config); both are
now mapped.

---

## Setup (delta from RUN_003)

| Component | RUN_003 | RUN_004 |
|---|---|---|
| Target | `http://127.0.0.1:3002` (nginx default) | `http://127.0.0.1:3003` (MegaShop e-commerce) |
| Mode | `bug_bounty` | **`standard`** |
| `gobuster` available | disabled by overlay | **enabled** |
| `feroxbuster` available | disabled by overlay | **enabled** |
| Scope | unchanged | unchanged |

Session ID: `a8736214-d565-462c-b9a6-4ff7c1972661`
Total wall time: **143.95s**

---

## The actual finding signal

### High-severity findings (3)

| Tool | Type | Detail |
|---|---|---|
| `scanner` | Backup Artifact Exposed | **`.git/config`** — exposed git directory, attacker can clone source + walk history for secrets |
| `scanner` | SSRF Indicator | `http://127.0.0.1` — likely an in-app URL parameter that accepts internal URLs |
| `nikto` | Missing `X-Content-Type-Options` header | Lower-end HIGH; some programs treat as Medium |

### Issues promoted (7)

| Severity | Title | Count |
|---|---|---|
| HIGH | Exposed Administrative Interface | 3 |
| HIGH | Backup / Source Artifact Exposure | 3 |
| MEDIUM | Outdated Framework Version | 1 |

This is the first run where the `findings` table grew an `issues` table
counterpart > 0. The promotion rules exist and fire for the right finding
shapes — feroxbuster's directory-enumeration output promotes cleanly.

### Finding-source breakdown

| Tool | Findings | Notes |
|---|---|---|
| `httpx` | 8 | Same Missing Security Header noise as before |
| `gobuster` | 6 | Directory Enumeration findings |
| `feroxbuster` | 2 | Including the `.git/config` HIGH |
| `nikto` | 19 (raw) → 5 unique | Includes the X-Content-Type-Options HIGH |
| `nuclei_safe` | 0 | Still finding nothing — see Open #1 |

---

## Empirical comparison: RUN_001 → RUN_002 → RUN_003 → RUN_004

| Metric | RUN_001 | RUN_002 | RUN_003 | RUN_004 |
|---|---|---|---|---|
| Wall time | 4.25s | 23.11s | 140.68s | **143.95s** |
| Tools dispatched | 1 (wrong) | 1 | 4 | **5** |
| SCAN_COMMIT rows | 1 | 1 | 4 | **5** |
| Findings | 6 | 6 | 13 | **26** |
| Issues promoted | 0 | 0 | 0 | **7** |
| HIGH findings | 0 | 0 | 1 | **3** |
| Graph edges | 0 | 0 | 0 | **3** |
| Termination | walk-away | walk-away | Mission Complete | Mission Complete |

The first row where `issues` is > 0 is RUN_004. That's the inflection
point — the engine is now producing post-rule-evaluated signal, not raw
tool output.

---

## The tool-coverage map

This is the answer to "why aren't more tools running?"

| Tool | Registered? | Installed? | Ran in RUN_004? | Why not |
|---|:---:|:---:|:---:|---|
| `httpx` | ✓ | ✓ | ✓ | — |
| `nikto` | ✓ | ✓ | ✓ | — |
| `nuclei_safe` | ✓ | ✓ | ✓ | — |
| `nuclei_mutating` | ✓ | ✓ | ✗ | Likely cost-modifier gate or per-intent dispatch cap (only 2 of 3 vuln_scan slots used) |
| `nuclei` (legacy) | ✓ | ✓ | ✗ | Superseded by `nuclei_safe`/`nuclei_mutating` |
| `gobuster` | ✓ | ✓ | ✓ | — (was disabled in bug_bounty mode) |
| `feroxbuster` | ✓ | ✓ | ✓ | — (was disabled in bug_bounty mode) |
| `nmap` | ✓ | ✓ | ✗ | Policy: blocked on loopback (correct) |
| `naabu` | ✓ | ✓ | ✗ | Policy: blocked on loopback (correct) |
| `subfinder` | ✓ | ✓ | ✗ | Policy: requires public domain (correct for `127.0.0.1`) |
| `dnsx` | ✓ | ✓ | ✗ | Same — DNS recon irrelevant for IP target |
| `amass` | ✓ | ✓ | ✗ | Same — public-domain requirement |
| `masscan` | ✓ | ✓ | ✗ | Requires root + port-scanner block on loopback |
| `testssl` | ✓ | ✓ | ✗ | Policy: target is HTTP, no HTTPS listener (correct) |
| `sslyze` | ✓ | ✗ | ✗ | Not installed; would be blocked by HTTPS policy anyway |
| `pshtt` | ✓ | ✗ | ✗ | Not installed; HTTPS-only |
| `whatweb` | ✓ | ✗ | ✗ | Not installed |
| `wafw00f` | ✓ | ✗ | ✗ | Not installed |
| `dirsearch` | ✓ | ✗ | ✗ | Not installed |
| `httprobe` | ✓ | ✗ | ✗ | Not installed |
| `api_discoverer` | ✓ | ✓ (internal) | ✗ | Not selected by current intent mapping |
| `wraith_verify` | ✓ | ✓ (internal) | ✗ | **Precondition: no query-parameter URLs discovered** |
| `wraith_persona_diff` | ✓ | ✓ (internal) | ✗ | **Precondition: `knowledge.personas` not configured** |
| `wraith_oob_probe` | ✓ | ✓ (internal) | ✗ | **Precondition: `knowledge.oob` not configured** |

**Of 24 registered tools, 18 are installed.** Of those 18, 5 ran in
RUN_004. The remaining 13 are blocked by:

- **Correct safety policies (6 tools):** nmap/naabu/masscan/subfinder/dnsx/amass/testssl — these *should* be skipped against a loopback HTTP target.
- **Missing installations (6 tools):** sslyze/pshtt/whatweb/wafw00f/dirsearch/httprobe — install gap.
- **Precondition gaps (3 wraith_* tools + api_discoverer):** require runtime config (personas/OOB) or prior findings (query-param URLs).
- **Per-intent dispatch cap (1):** `nuclei_mutating` selected but not dispatched — only 2 of 3 vuln_scan slots used (1/3 = nuclei_safe, 2/3 = nikto, 3/3 missing).

**Of the 13 non-running tools, only 4 are gaps we can directly close:** the wraith preconditions + missing install + api_discoverer intent assignment.

---

## Concrete next moves

### Most impactful — unlock wraith_persona_diff for MegaShop

Add `--personas` to `pysentinel.py` and pass a list with admin/user/anonymous
profiles for MegaShop. This is the **single biggest signal unlock** — IDOR
detection is the kind of finding that pays bounties, and MegaShop (e-commerce
with orders/users/cart) is exactly the shape persona-diff exploits.

```python
# pysentinel.py:
parser.add_argument("--personas", type=str, help="JSON file with persona profiles")
# request payload:
payload["personas"] = json.loads(Path(args.personas).read_text())
```

### Second — fix `bug_bounty` mode for local/loopback targets

The current overlay disables `gobuster`/`feroxbuster` with "Brute force is
boring." On a public-internet bounty target, that's fine — there's surface
discovery via subfinder/dnsx. On loopback/private targets, those DNS tools
are also blocked, leaving surface_enum with zero tools. Two options:

1. **Conditional disable:** keep gobuster/feroxbuster disabled in
   bug_bounty mode for public-domain targets, but enable them for private
   targets where there's no alternative.
2. **Add a "local" mode** that's `bug_bounty` + brute-force enabled, for
   calibration and CTF work.

### Third — investigate `nuclei_mutating` non-dispatch

Selected for vuln_scan as "3/3" in RUN_003 but dispatched only as "1/3,
2/3" with no 3/3 in RUN_004. Either the dispatch slot cap was hit or the
mode overlay applies a cost_modifier that drops it. Worth tracing once we
have higher-priority items fixed.

### Fourth — install missing scanners

`whatweb`, `wafw00f`, `dirsearch`, `httprobe`, `sslyze`, `pshtt`. These are
all `pip install` or `brew install` away. Worth doing in one batch.

---

## What's working that wasn't before

- **Findings → issues promotion fires for feroxbuster output.** 7 issues
  in this run vs 0 in every prior run. The rule engine works on
  directory-enumeration-shaped findings.
- **Knowledge graph populating.** 3 edges in this run vs 0 prior.
- **Multi-phase progression with parallel dispatch.** Surface_enum and
  vuln_scan both ran multiple tools in parallel within an intent.
- **AI/Ollama integration active throughout.** Multiple `POST /api/generate`
  calls visible in the backend log during finding classification.
- **Clean Mission Complete termination.** Not walk-away.

## What's still open

- **wraith_* preconditions** — biggest unlock remaining.
- **`/v1/scans/start --personas` plumbing in pysentinel.py** — small CLI patch.
- **Bug_bounty mode design for non-public targets** — design question.
- **Session lifecycle still doesn't close** (Bug #4 from RUN_001/002/003).
- **Some installed tools never dispatched** (api_discoverer most notable).
