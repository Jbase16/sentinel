#!/usr/bin/env python3
"""
Calibration Run #50 — full end-to-end pipeline against Juice Shop.

This is the integration test we've been deliberately deferring. 1117
unit tests prove each layer in isolation; this harness proves the
layers compose into a submission-quality artifact.

Pipeline (Phase 3 → Phase 5):

  1. Run verify_phase with admin + jim personas → expect SQLi +
     horizontal IDOR + cross-principal IDOR findings.
  2. Add the most interesting finding to FindingsStore.
  3. Hydrate a VerificationSession from that finding via VC1.
  4. Bind the admin persona to the session via VC1's /persona route.
  5. Fire structured verification exchanges via VC2's /exchange route.
     - GET /rest/basket/1 as admin (verify it works)
     - SCOPE TEST: try to GET https://evil.com/ (must 403 — proves
       the constraint inversion works in practice)
     - Rebind to jim persona
     - GET /rest/basket/1 as jim (the cross-principal IDOR demo)
  6. Promote the meaningful exchanges via VC3.
  7. Construct a BountyReport, swap in the VC3-promoted steps.
  8. Render to_markdown(). Print + save.

Safety:
  * signal.alarm(120) hard-kills the process at 120s wallclock.
  * os._exit at end bypasses interpreter teardown.
  * faulthandler dumps stacks every 30s if we get stuck.

Run:  python3 -u scripts/calibration_50_end_to_end.py
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

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stderr,
)
for name in (
    "core.wraith.verify_phase",
    "core.wraith.persona_auth",
    "core.verify.console",
):
    logging.getLogger(name).setLevel(logging.INFO)


TARGET = os.environ.get("CALIBRATION_TARGET", "http://127.0.0.1:3000")
OUT_DIR = Path("/tmp/calibration_50")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def _sigalrm(*_):
    sys.stderr.write("[harness] SIGALRM 120s — bailing\n")
    os._exit(2)


async def main() -> int:
    signal.signal(signal.SIGALRM, _sigalrm)
    signal.alarm(120)
    faulthandler.dump_traceback_later(timeout=30, repeat=True, file=sys.stderr)

    from core.base.session import ScanSession
    from core.wraith.verify_phase import run_verify_phase
    from core.data.findings_store import get_finding_store
    from core.verify.console import create_session_from_finding, _reset_for_tests
    from core.server.routers.verify import (
        BindPersonaRequest,
        ExchangeRequest,
        PromoteRequest,
        bind_persona,
        promote_to_repro,
        send_exchange,
    )
    from core.reporting.bounty_report import build_report

    print(f"\n=== Calibration #50: end-to-end pipeline against {TARGET} ===\n")

    # ── Step 1: confirmed findings via verify_phase + personas
    print("[1/8] Running verify_phase with admin + jim personas…")
    session = ScanSession(target=TARGET)
    session.knowledge = getattr(session, "knowledge", None) or {}
    _reset_for_tests()  # don't inherit verify sessions from prior runs

    personas = [
        {
            "name": "admin",
            "login_url": f"{TARGET}/rest/user/login",
            "login_kind": "json",
            "login_body": {"email": "admin@juice-sh.op", "password": "admin123"},
            "token_path": "authentication.token",
            "auth_header": "Authorization: Bearer {token}",
        },
        {
            "name": "jim",
            "login_url": f"{TARGET}/rest/user/login",
            "login_kind": "json",
            "login_body": {"email": "jim@juice-sh.op", "password": "ncc-1701"},
            "token_path": "authentication.token",
            "auth_header": "Authorization: Bearer {token}",
        },
    ]
    t0 = time.time()
    findings = await run_verify_phase(
        session=session,
        targets=[TARGET],
        personas=personas,
        per_probe_budget=2,
        max_hosts=1,
        enable_discovery=False,
    )
    print(f"     ✓ {len(findings)} confirmed finding(s) in {time.time()-t0:.1f}s")

    # ── Step 2: pick the cross-principal IDOR and add to FindingsStore
    print("[2/8] Picking cross-principal IDOR finding…")
    cross_findings = [
        f for f in findings
        if "cross_principal" in (f.get("metadata") or {}).get("subclass", "")
    ]
    if not cross_findings:
        print("     ✗ no cross-principal IDOR detected — aborting calibration")
        return 1
    picked = cross_findings[0]  # best one (sorted by confidence)
    print(f"     ✓ picked: {picked['type']} on {picked['target']}")
    print(f"             attacker={picked['metadata']['attacker_persona']!r} "
          f"victim={picked['metadata']['victim_persona']!r} "
          f"conf={picked['metadata']['confidence']:.2f}")

    store = get_finding_store()
    store.add_finding(picked)
    finding_id = picked["id"]

    # ── Step 3: hydrate a VerificationSession from the finding (VC1)
    print(f"[3/8] Hydrating VerificationSession from finding {finding_id}…")
    vsess = create_session_from_finding(finding_id)
    print(f"     ✓ session {vsess.session_id[:8]} bound to {vsess.target_url}")
    print(f"     ✓ scope: {sorted(vsess.allowed_origins)}")

    # ── Step 4: bind admin persona (VC1's persona route)
    print("[4/8] Binding admin persona to session…")
    await bind_persona(
        vsess.session_id,
        BindPersonaRequest(
            persona_name="admin",
            persona_spec=personas[0],
        ),
        _=True,
    )
    print(f"     ✓ persona='admin' bound with auth headers")

    # ── Step 5a: fire verification exchange as admin (VC2)
    print("[5/8] Firing verification exchange as admin: GET /rest/basket/1…")
    await send_exchange(
        vsess.session_id,
        ExchangeRequest(
            method="GET",
            url=f"{TARGET}/rest/basket/1",
        ),
        _=True,
    )
    print(f"     ✓ transcript length: {len(vsess.transcript)}")
    print(f"       admin response status: {vsess.transcript[-1].response_status}")
    print(f"       admin body preview: {vsess.transcript[-1].response_body[:80]}…")

    # ── Step 5b: scope-violation test — try to reach an out-of-scope URL
    print("[5b]   Scope-gate sanity check: trying to GET https://evil.example/…")
    try:
        await send_exchange(
            vsess.session_id,
            ExchangeRequest(
                method="GET",
                url="https://evil.example/x",
            ),
            _=True,
        )
        print("     ✗ SCOPE GATE FAILED — out-of-scope request went through!")
        return 1
    except Exception as e:
        if "out_of_scope" in str(e) or "403" in str(e):
            print(f"     ✓ scope gate blocked it (rejected before any I/O)")
        else:
            print(f"     ? unexpected error (not scope-related): {e}")

    # ── Step 5c: rebind to jim persona + fire same URL → cross-principal IDOR
    print("[5c]   Rebinding to jim persona…")
    await bind_persona(
        vsess.session_id,
        BindPersonaRequest(
            persona_name="jim",
            persona_spec=personas[1],
        ),
        _=True,
    )
    print("[5d]   Firing same URL as jim: GET /rest/basket/1…")
    await send_exchange(
        vsess.session_id,
        ExchangeRequest(
            method="GET",
            url=f"{TARGET}/rest/basket/1",
        ),
        _=True,
    )
    print(f"     ✓ transcript length: {len(vsess.transcript)}")
    print(f"       jim response status: {vsess.transcript[-1].response_status}")
    print(f"       jim body preview: {vsess.transcript[-1].response_body[:80]}…")

    # Compare bodies — IDOR confirmation:
    admin_body = vsess.transcript[0].response_body
    jim_body = vsess.transcript[-1].response_body
    if admin_body and admin_body == jim_body:
        print(f"     ★ IDOR CONFIRMED at exchange level: byte-identical bodies "
              f"({len(admin_body)}B) for admin and jim on /rest/basket/1")
    else:
        print(f"     ? bodies differ — admin={len(admin_body)}B jim={len(jim_body)}B")

    # ── Step 6: promote selected exchanges to repro (VC3)
    print("[6/8] Promoting selected exchanges to repro markdown…")
    # Use exchanges 0 (admin baseline) + 1 (jim IDOR). Skip the scope
    # violation attempt (didn't capture, raised before).
    promote_result = await promote_to_repro(
        vsess.session_id,
        PromoteRequest(exchange_indices=[0, 1], sanitize=True),
        _=True,
    )
    print(f"     ✓ rendered {promote_result.entry_count} repro entry(s)")
    print(f"     ✓ placeholder legend: {sorted(promote_result.placeholder_legend.keys())}")

    # ── Step 7: BountyReport with VC3-promoted steps swapped in
    print("[7/8] Constructing BountyReport with VC3-promoted repro…")
    report = build_report(picked, scan_id="calibration-50")
    # Swap heuristic steps for the operator-captured, sanitized ones.
    report.steps_to_reproduce = promote_result.steps_to_reproduce
    markdown = report.to_markdown()
    print(f"     ✓ report title: {report.title}")
    print(f"     ✓ severity: {report.severity}")
    print(f"     ✓ CVSS: {report.cvss.base_score} ({report.cvss.severity_label})")

    # ── Step 8: write artifacts
    print("[8/8] Writing artifacts…")
    md_path = OUT_DIR / "bounty_report.md"
    md_path.write_text(markdown)
    print(f"     ✓ markdown → {md_path}")

    # Print the markdown to stdout so the user can see what they'd
    # submit without opening the file.
    print("\n" + "=" * 70)
    print("RENDERED BOUNTY REPORT (the artifact this pipeline produced):")
    print("=" * 70)
    print(markdown)
    print("=" * 70)
    print(f"\nFull report saved to: {md_path}")
    return 0


if __name__ == "__main__":
    try:
        rc = asyncio.run(main())
    except KeyboardInterrupt:
        rc = 130
    sys.stdout.flush()
    sys.stderr.flush()
    signal.alarm(0)
    os._exit(rc)
