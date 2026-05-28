#!/usr/bin/env python3
"""
Calibration Run #36 — Phase 3 verify_phase against a live H1 target.

What this harness validates (in order of importance):
  1. CRAWLER discovers real URLs on about.gitlab.com (NOT the
     Juice-Shop-flavored _SEED_PROBES paths).
  2. CLASSIFIER produces (url, label, vuln_class) tuples for those
     real URLs.
  3. SCOPE FILTER hard-gates: every probe URL is in scope, every
     out-of-scope URL is rejected.
  4. VULNVERIFIER runs against discovered URLs without crashing
     on real-world response shapes (a class of bugs unit tests
     can't expose).
  5. NO DOS-LIKE BEHAVIOR — we cap aggressively (low depth, low
     page count, low per-probe budget).

What this harness does NOT validate:
  * Authenticated probing (no gitlab.com persona configured here —
    that's a separate piece of work tied to H1 API + signup flow).
  * Full bug_bounty mode tools (nmap/nuclei/subfinder — those are
    already calibrated in Run #17, #18, #21).
  * Submission-ready findings (would need triage, repro, etc.).

Why about.gitlab.com (vs gitlab.com proper):
  * Smaller surface — easier to reason about results.
  * Lower production-impact — marketing site, not user-facing app.
  * Still in-scope on the gitlab.com H1 program.
  * Earlier calibration runs (#21) already touched it.

Conservative caps (stay polite):
  * max_depth=2, max_pages=15 (a small crawl, not a full mirror)
  * max_candidates=30 (cap on what we hand the verifier)
  * per_probe_budget=2 (one boundary payload, one mutation; not 5+)
  * Strict scope: ONLY about.gitlab.com is allowed.

Backstops:
  * ScanSession auto-installs the teardown deadman (10s ceiling
    on interpreter shutdown — fixed in commit 6c38c18).
  * This script also has its own SIGALRM kill at 120s wall-clock
    via signal.setitimer.
  * os._exit at end so we don't depend on clean asyncio shutdown.

Run:  python3 -u scripts/calibration_36_gitlab.py
"""
from __future__ import annotations

import asyncio
import faulthandler
import logging
import os
import signal
import sys
import time

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stderr,
)
# Whitelist the modules we want chatty.
for name in ("core.wraith.verify_phase", "core.wraith.candidate_discovery", "core.wraith.persona_auth"):
    logging.getLogger(name).setLevel(logging.INFO)


TARGET = os.environ.get("CALIBRATION_TARGET", "https://about.gitlab.com")
TARGET_HOST = "about.gitlab.com"  # what scope_filter allows


def _scope_filter(url: str) -> bool:
    """STRICT scope: only about.gitlab.com (any path, any query)."""
    from urllib.parse import urlparse
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return False
    # Must be EXACTLY about.gitlab.com (no sneaky `about.gitlab.com.evil.com`).
    return host == TARGET_HOST or host == "about.gitlab.com:443"


async def main() -> int:
    # Hard wall-clock kill at 120s in case anything misbehaves at the
    # network layer despite the deadman.
    def _alarm(_signum, _frame):
        sys.stderr.write("[harness] SIGALRM 120s wall-clock — bailing\n")
        os._exit(2)
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(120)

    # faulthandler periodic dump in case we get stuck somewhere — every
    # 30s prints all thread stacks to stderr. Cheap insurance.
    faulthandler.dump_traceback_later(timeout=30, repeat=True, file=sys.stderr)

    from core.base.session import ScanSession
    from core.wraith.candidate_discovery import discover_candidates
    from core.wraith.verify_phase import run_verify_phase

    print(f"\n=== Calibration #36: verify_phase against {TARGET} ===\n", flush=True)
    print(f"scope_filter: STRICT → {TARGET_HOST} only", flush=True)
    print(f"deadman: ScanSession auto-installs 10s ceiling", flush=True)
    print(f"wallclock alarm: 120s", flush=True)
    print()

    session = ScanSession(target=TARGET)
    session.knowledge = getattr(session, "knowledge", None) or {}

    # ----- Step 1: crawler discovery (independently observable) -----
    print("--- discover_candidates() ---", flush=True)
    t0 = time.time()
    candidates = await discover_candidates(
        target=TARGET,
        scope_filter=_scope_filter,
        max_depth=2,
        max_pages=15,
        max_candidates=30,
        timeout=8.0,
    )
    dt_discovery = time.time() - t0
    print(f"discovery completed in {dt_discovery:.1f}s — {len(candidates)} candidate(s)", flush=True)
    if not candidates:
        print("  (no candidates — discovery found nothing classifiable)")
    else:
        # Group by vuln_class for readability.
        by_class: dict = {}
        for url, label, vc in candidates:
            by_class.setdefault(vc, []).append((url, label))
        for vc in sorted(by_class):
            urls = by_class[vc]
            print(f"  {vc}: {len(urls)} URL(s)")
            for url, _label in urls[:5]:  # show first 5 per class
                print(f"      • {url[:120]}")
            if len(urls) > 5:
                print(f"      … +{len(urls) - 5} more")

    # Scope-sanity check: every candidate URL MUST pass scope_filter.
    out_of_scope = [u for u, _, _ in candidates if not _scope_filter(u)]
    print(f"\nscope check: {len(out_of_scope)} out-of-scope candidate(s) "
          f"(MUST be 0)", flush=True)
    assert not out_of_scope, f"scope violation: {out_of_scope[:3]}"

    # ----- Step 2: run_verify_phase (the real test) -----
    print("\n--- run_verify_phase() ---", flush=True)
    t0 = time.time()
    findings = await run_verify_phase(
        session=session,
        targets=[TARGET],
        scope_filter=_scope_filter,
        personas=None,  # anonymous probing only
        per_probe_budget=2,
        max_candidates=40,
        max_hosts=1,
        enable_discovery=True,
        discovery_max_depth=2,
        discovery_max_pages=15,
        discovery_max_candidates=30,
    )
    dt_verify = time.time() - t0
    print(f"verify_phase completed in {dt_verify:.1f}s — {len(findings)} finding(s)", flush=True)

    if findings:
        print("\n--- confirmed findings ---")
        for i, f in enumerate(findings, 1):
            m = f["metadata"]
            print(f"  [{i}] {f['type']}")
            print(f"      target: {f['target']}")
            print(f"      class: {m.get('vuln_class')}  conf: {m.get('confidence'):.2f}  payload: {m.get('payload')!r}")
            print(f"      proof: {f['proof'][:150]}")
    else:
        print("\n(no confirmed findings — expected for a hardened production target)")

    # ----- Step 3: summary -----
    print("\n=== Run #36 summary ===")
    print(f"target:           {TARGET}")
    print(f"scope:            STRICT → {TARGET_HOST}")
    print(f"discovery time:   {dt_discovery:.1f}s")
    print(f"discovery yield:  {len(candidates)} probe candidates")
    print(f"verify time:      {dt_verify:.1f}s")
    print(f"confirmed:        {len(findings)} finding(s)")
    print(f"total wallclock:  {dt_discovery + dt_verify:.1f}s")

    return 0


if __name__ == "__main__":
    try:
        rc = asyncio.run(main())
    except KeyboardInterrupt:
        rc = 130
    # os._exit to bypass any orphan-thread teardown (the deadman switch
    # would catch it within 10s but skip the wait entirely).
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
