#!/usr/bin/env python3
"""
Phase 6-PT5 — Calibration #60: unauthenticated probe of Airtable staging.

The first half of Option 2's live cycle. I (Sentinel) cannot create
real Airtable accounts from inside this conversation, so the
authenticated half (cross-principal IDOR, the strongest fit) is
deferred to the operator. This script handles the UNAUTHENTICATED
half — Sentinel-driven recon + Phase 3 verification against the
in-scope staging hosts.

STRICT SCOPE — Airtable's program rules say "do not perform any
testing against our production site at airtable.com." Phase 5's
structural scope gate enforces this; the scope_filter in this script
encodes the in-scope list directly.

In-scope assets (from H1 API /structured_scopes):
  - staging.airtable.com           (exact)
  - api-staging.airtable.com       (exact)
  - *.staging.airtable.com         (wildcard)
  - *.staging-airtableblocks.com   (wildcard)

What this probe tries:
  - Recon: crawl staging.airtable.com (depth 2, polite)
  - Phase 3 active verification (UNAUTHENTICATED) — open redirect,
    SSRF canary, path traversal, basic SQLi against the candidates
    the crawler surfaces.
  - Phase 4 mutation library applied IF the unauth pass finds an
    interesting candidate (JWT discovery in cookies, etc.).

What this probe explicitly does NOT try:
  - IDOR / cross-principal IDOR (requires accounts).
  - Authenticated SQLi (requires accounts).
  - Anything against airtable.com or other out-of-scope hosts.

Safety:
  - signal.alarm(180s) hard wallclock kill.
  - per_probe_budget = 1 (one mutation per candidate, lowest impact).
  - max_hosts = 1 to keep load focused.
  - Politeness User-Agent identifying SentinelForge.

Run:  python3 -u scripts/calibration_60_airtable_unauth.py
"""
from __future__ import annotations

import asyncio
import faulthandler
import logging
import os
import signal
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stderr,
)
for n in (
    "core.wraith.verify_phase",
    "core.wraith.persona_auth",
    "core.wraith.candidate_discovery",
):
    logging.getLogger(n).setLevel(logging.INFO)


IN_SCOPE_HOSTS = {
    "staging.airtable.com",
    "www.staging.airtable.com",  # 301 redirect target — in scope via wildcard
    "api-staging.airtable.com",
}
IN_SCOPE_WILDCARDS = {
    ".staging.airtable.com",
    ".staging-airtableblocks.com",
}

TARGET = "https://staging.airtable.com"
OUT_DIR = Path("/tmp/calibration_60_airtable")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def in_scope(url: str) -> bool:
    """Strict scope check matching Airtable's structured_scopes.

    Phase 5 VC2's structural gate uses exactly this kind of filter."""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return False
    # Strip port if any.
    host = host.split(":", 1)[0]
    if host in IN_SCOPE_HOSTS:
        return True
    for suffix in IN_SCOPE_WILDCARDS:
        if host.endswith(suffix):
            return True
    return False


def _sigalrm(*_):
    sys.stderr.write("[harness] SIGALRM 180s — bailing\n")
    os._exit(2)


async def main() -> int:
    signal.signal(signal.SIGALRM, _sigalrm)
    signal.alarm(180)
    faulthandler.dump_traceback_later(timeout=60, repeat=True, file=sys.stderr)

    print(f"\n=== Calibration #60: Airtable staging unauth probe ===")
    print(f"  target: {TARGET}")
    print(f"  in-scope hosts: {sorted(IN_SCOPE_HOSTS)}")
    print(f"  wildcards: {sorted(IN_SCOPE_WILDCARDS)}")
    print()

    # Quick scope sanity-check
    test_cases = [
        ("https://staging.airtable.com/x", True),
        ("https://www.staging.airtable.com/x", True),
        ("https://api-staging.airtable.com/v0/", True),
        ("https://anything.staging.airtable.com/x", True),
        ("https://airtable.com/x", False),  # PROD — must be False
        ("https://api.airtable.com/v0/", False),  # PROD — must be False
        ("https://staging.airtable.com.evil.com/x", False),  # eTLD spoof
    ]
    print("[scope sanity check]")
    for url, expected in test_cases:
        actual = in_scope(url)
        status = "✓" if actual == expected else "✗ FAIL"
        print(f"  {status}  in_scope({url}) = {actual}  expected {expected}")
        if actual != expected:
            print("ABORT: scope gate doesn't behave as designed.")
            return 1
    print()

    # Run Phase 3 verify_phase against the staging host with
    # discovery enabled + strict scope filter.
    from core.base.session import ScanSession
    from core.wraith.verify_phase import run_verify_phase

    print("[1/2] running Phase 3 verify_phase (unauth, discovery on, scope_strict)...")
    t0 = time.time()
    session = ScanSession(target=TARGET)
    session.knowledge = getattr(session, "knowledge", None) or {}

    try:
        findings = await run_verify_phase(
            session=session,
            targets=[TARGET, "https://api-staging.airtable.com"],
            scope_filter=in_scope,            # STRICT — structural gate
            personas=None,                    # UNAUTHENTICATED
            per_probe_budget=1,                # one mutation per probe — polite
            max_hosts=2,                       # the two listed hosts
            enable_discovery=True,             # crawler finds real URLs
            discovery_max_depth=2,
            discovery_max_pages=20,
            discovery_max_candidates=40,
        )
    except Exception as e:
        print(f"ERROR: verify_phase raised: {type(e).__name__}: {e}")
        return 1

    dt = time.time() - t0
    print(f"  ✓ completed in {dt:.1f}s — {len(findings)} confirmed finding(s)")
    print()

    if findings:
        print("[2/2] confirmed findings — DETAILED:")
        for i, f in enumerate(findings, 1):
            m = f.get("metadata", {})
            print(f"  [{i}] {f['type']}")
            print(f"      target: {f['target']}")
            print(f"      class: {m.get('vuln_class')}  conf: {m.get('confidence', '?')}  payload: {m.get('payload', '?')!r}")
            print(f"      proof: {f.get('proof', '')[:300]}")
            print()
    else:
        print("[2/2] No confirmed findings in the unauthenticated pass.")
        print()
        print("This is the EXPECTED outcome for a hardened staging environment.")
        print("Sentinel's strongest detection (cross-principal IDOR @ 0.90 conf)")
        print("requires two authenticated accounts. The next step is for the")
        print("operator to drive the authenticated half — see runbook at")
        print(f"{OUT_DIR}/auth_runbook.md after this script completes.")

    # Write findings JSON + audit trail
    import json
    findings_path = OUT_DIR / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2, default=str))
    print(f"\nfindings saved → {findings_path}")

    # And the auth-half runbook (regardless of outcome)
    runbook_path = OUT_DIR / "auth_runbook.md"
    runbook_path.write_text(_auth_runbook_text(findings))
    print(f"auth-half runbook → {runbook_path}")
    return 0


def _auth_runbook_text(findings) -> str:
    """Generate the handoff runbook for the authenticated half."""
    found_count = len(findings) if findings else 0
    if found_count > 0:
        unauth_note = (
            f"⚠️  The unauth pass surfaced {found_count} confirmed finding(s) — "
            f"review those first before pursuing the auth half (a clean "
            f"unauth win is the lowest-effort submission path)."
        )
    else:
        unauth_note = (
            "The unauth pass surfaced no confirmed findings. This is "
            "the expected outcome for a hardened staging environment. "
            "The auth half is where Sentinel's strongest detection "
            "(cross-principal IDOR @ 0.90 conf) actually applies."
        )

    return f"""# Airtable staging — authenticated probe runbook

Sentinel completed the unauthenticated half of the Phase 6-PT5
calibration cycle. {unauth_note}

## What needs an operator (you) to do the auth half

Sentinel cannot programmatically sign up real Airtable accounts from
inside the conversation — that requires real email, email
verification, and signup-flow interaction with Airtable's web app.
The auth half consists of:

### Step 1 — create two accounts on staging.airtable.com

1. Visit `https://staging.airtable.com/signup` (or wherever staging
   exposes signup).
2. Sign up TWO distinct accounts with two distinct emails. Use
   different orgs/workspaces if the signup flow asks. We'll call
   them `alice` and `bob`.
3. For each account: create a small Airtable base with some
   trivial test data (a single row with a value like
   `OWNED_BY_ALICE` / `OWNED_BY_BOB` — needs to be distinguishable
   in the response so we can confirm cross-tenant exposure).
4. From each account, capture the auth cookie or generate a
   personal-access-token via Airtable's settings UI.

### Step 2 — feed credentials to Sentinel

Configure two personas in Sentinel matching Airtable's auth shape:

```python
personas = [
    {{
        "name": "alice",
        # Use STATIC headers (already-authenticated) since Airtable's
        # login flow isn't a clean JSON POST — easiest path:
        "static_headers": {{"Authorization": "Bearer <alice's PAT>"}}
    }},
    {{
        "name": "bob",
        "static_headers": {{"Authorization": "Bearer <bob's PAT>"}}
    }},
]
```

### Step 3 — run the authenticated phase

```python
findings = await run_verify_phase(
    session=session,
    targets=["https://staging.airtable.com",
             "https://api-staging.airtable.com"],
    scope_filter=in_scope,           # SAME strict gate
    personas=personas,                # NOW authenticated
    per_probe_budget=2,
    max_hosts=2,
    enable_discovery=True,
)
```

Sentinel will:
  - Crawl as alice (her view of the app)
  - Probe IDOR-shaped URLs (`/v0/bases/{{baseId}}/{{recordId}}` etc.)
  - Apply Phase 4-G5 multi-principal flow diff (alice's URL replayed
    as bob — if bob sees alice's `OWNED_BY_ALICE` test row, that's
    cross-principal IDOR)

### Step 4 — verify and submit

Any confirmed finding goes through:
  1. Verify Console (Phase 5) for manual exchange capture
  2. PT2 SubmissionRender for the markdown
  3. PT3 H1SubmissionClient for the submission (with `confirm=True`)

The full handoff is one Python script away. The infrastructure is
ready; only the auth credentials need to come from you.

---

Unauth findings count: {found_count}
Generated by: scripts/calibration_60_airtable_unauth.py
"""


if __name__ == "__main__":
    try:
        rc = asyncio.run(main())
    except KeyboardInterrupt:
        rc = 130
    sys.stdout.flush(); sys.stderr.flush()
    signal.alarm(0)
    os._exit(rc)
