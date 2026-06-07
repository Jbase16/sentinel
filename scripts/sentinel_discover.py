#!/usr/bin/env python3
"""
sentinel-discover — Phase 6-PT1 companion CLI.

Goal: bridge the gap between "Sentinel knows how to ingest one program"
(scripts/sentinel_ingest.py) and "Sentinel knows what's out there"
(this script).

Discover pulls every bounty-offering program from HackerOne's hacker
API (using the credentials in token_store), persists a lightweight
ProgramScope JSON per program under ~/.sentinelforge/intel/, then runs
the Phase 6-PT1 ranker over them. The operator gets a recommendation
list.

The persisted ProgramScopes are LIGHTWEIGHT — handle/name/scope_count
only — because fetching per-program details for 293 programs is slow
(~5 minutes). The lightweight pass is enough to rank by Sentinel-fit.
The actual full ingest (with restrictions, personas, full scope_rules)
is run on demand for the top-ranked candidate(s) via sentinel_ingest.

Usage:
    python3 scripts/sentinel_discover.py
    # → persists ~/.sentinelforge/intel/*.json + prints ranking

    python3 scripts/sentinel_discover.py --refresh
    # → re-fetch even if cached

    python3 scripts/sentinel_discover.py --top 10 --verbose
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from core.intel import token_store


INTEL_DIR = Path.home() / ".sentinelforge" / "intel"
DISCOVERY_CACHE = INTEL_DIR / "discover-cache.json"
H1_API_BASE = "https://api.hackerone.com/v1"


def _sigalrm(*_):
    sys.stderr.write("[discover] SIGALRM 180s — bailing\n")
    os._exit(2)


def _fetch_all_h1_programs(handle: str, token: str) -> List[Dict[str, Any]]:
    """Walk paginated /hackers/programs and return every bounty-offering,
    publicly-accessible program's API attributes dict."""
    client = httpx.Client(
        auth=httpx.BasicAuth(handle, token),
        timeout=30.0,
        headers={
            "Accept": "application/json",
            "User-Agent": "SentinelForge/Phase6-discover",
        },
    )
    all_progs: List[Dict[str, Any]] = []
    url = f"{H1_API_BASE}/hackers/programs?page%5Bsize%5D=100"
    pages = 0
    while url and pages < 20:
        try:
            r = client.get(url)
        except Exception as e:
            print(
                f"[discover] page fetch failed at page {pages}: "
                f"{type(e).__name__}: {e}",
                file=sys.stderr,
            )
            break
        if r.status_code != 200:
            print(
                f"[discover] HTTP {r.status_code} at page {pages}: "
                f"{r.text[:200]}",
                file=sys.stderr,
            )
            break
        data = r.json()
        for entry in data.get("data", []):
            attrs = entry.get("attributes", {})
            if not attrs.get("offers_bounties"):
                continue
            if attrs.get("state") != "public_mode":
                continue
            # We add a scope_count proxy from the relationships;
            # not fetching per-program detail keeps this scan fast.
            rels = entry.get("relationships", {})
            scope_data = rels.get("structured_scopes", {}).get("data", [])
            attrs["_scope_count"] = len(scope_data)
            all_progs.append(attrs)
        url = data.get("links", {}).get("next")
        pages += 1
    print(
        f"[discover] fetched {len(all_progs)} bounty-offering programs "
        f"across {pages} pages",
        file=sys.stderr,
    )
    return all_progs


def _persist_as_program_scope(attrs: Dict[str, Any], out_dir: Path) -> Optional[Path]:
    """Write a lightweight ProgramScope-shaped JSON for one program.

    The schema_version is 1.1 (matches ProgramScope.SCHEMA_VERSION).
    scope_rules use the discovered count to create N placeholder
    DOMAIN entries — exact patterns aren't known until full ingest,
    but the count is what PT1's scorer cares about."""
    from core.intel.program_scope import (
        Persona,
        Platform,
        ProgramScope,
        ScopeRule,
        ScopeRuleType,
    )
    handle = attrs.get("handle")
    if not handle:
        return None
    out_path = out_dir / f"{handle}-program-scope.json"
    # Build placeholder scope_rules of the right COUNT (PT1 only needs the count).
    n_scopes = int(attrs.get("_scope_count", 0))
    placeholder_rules = [
        ScopeRule(
            pattern=f"{handle}-asset-{i}.unknown",
            rule_type=ScopeRuleType.DOMAIN,
            in_scope=True,
            notes="lightweight-discovery: count-only, exact pattern not fetched",
        )
        for i in range(n_scopes)
    ]
    program = ProgramScope(
        handle=handle,
        platform=Platform.HACKERONE,
        name=attrs.get("name") or handle,
        source_url=f"{H1_API_BASE}/hackers/programs/{handle}",
        fetched_at=datetime.now(timezone.utc),
        scope_rules=placeholder_rules,
        personas=[],
        signup_endpoint=None,
        restrictions=[],
        rate_limit_rps=None,
        # H1 API doesn't expose per-program bounty max in the list
        # endpoint; leaving None lets PT1 use the per-class typical
        # ranges as ceilings. Full ingest of the top candidates will
        # populate this if available.
        payout_max_usd=None,
        raw_content_hash="discover-only",
        extractor_version="discover-0.1",
        extraction_confidence=0.5,  # lightweight; full ingest improves this
    )
    out_path.write_text(json.dumps(program.to_dict(), indent=2))
    return out_path


def _filter_for_first_attempt(
    programs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """For a new researcher's first paid attempt, exclude programs where
    duplicate risk is highest. This is a HARD filter (drops them
    entirely), not a saturation penalty — those would still rank
    visible. We want them off the recommendation list.

    Operator can override by editing the filter list or by skipping
    this step via --no-filter.
    """
    # Hard-skip: top-tier programs where every IDOR has been reported 50x
    # and every new researcher gets duplicate-rejected on day 1.
    HARD_SKIP_HANDLES = {
        # The biggest programs on the platform.
        "gitlab", "paypal", "google", "microsoft", "github", "x",
        "twitter", "uber", "shopify", "dropbox", "airbnb",
        # HackerOne's own program — meta and tough for first attempt.
        "security",
        # Mature mega-platforms.
        "slack", "coinbase", "snapchat", "linkedin", "att", "adobe",
        # Programs that don't fit Sentinel's web-app-with-auth profile.
        # (Crypto / hardware / embedded — different attack surface entirely.)
        "valve", "weasel-printers",
    }
    survivors = []
    for p in programs:
        handle = p.get("handle", "")
        if handle in HARD_SKIP_HANDLES:
            continue
        # NOTE: we used to drop programs with _scope_count < 2 here,
        # but H1's LIST endpoint doesn't populate the structured_scopes
        # relationship — only the per-program detail call does. Lightweight
        # discovery would drop everything. PT1's scorer handles
        # scope_size=0 gracefully (multiplier floors at 0.3); the saturation
        # prior is the main differentiator at this stage.
        survivors.append(p)
    print(
        f"[discover] filter: {len(programs)} → {len(survivors)} after "
        f"hard-skip + min-scope",
        file=sys.stderr,
    )
    return survivors


def _print_table(rankings: list, top_n: int) -> None:
    print()
    print(f"{'Rank':<5} {'Score':>10}  {'Scope':>5}  {'Pers':>5}  {'Sat':>4}  Program")
    print("─" * 80)
    for i, s in enumerate(rankings[:top_n], start=1):
        sat_pct = f"{int(s.saturation_penalty * 100)}%"
        print(
            f"{i:<5} ${s.final_score:>9,.0f}  "
            f"{s.scope_size:>5}  {s.verified_persona_count:>5}  "
            f"{sat_pct:>4}  {s.program_name} ({s.program_handle})"
        )
    print()


def _print_verbose(rankings: list, top_n: int) -> None:
    for i, s in enumerate(rankings[:top_n], start=1):
        print(f"\n=== #{i}: {s.program_name} ({s.program_handle}) ===")
        print(f"  expected value:   ${s.final_score:,.0f}")
        print(f"  scope size:       {s.scope_size} listed assets")
        print(f"  saturation prior: {int(s.saturation_penalty * 100)}%")
        print(f"  top vuln fits:")
        for tc in s.top_vuln_classes:
            print(
                f"    • {tc['name']} [{tc['cwe']}] — "
                f"conf {tc['confidence']:.2f}, "
                f"EV ${tc['ev_contribution_usd']:,.0f} "
                f"(from {tc['source_phase']})"
            )


def main() -> int:
    ap = argparse.ArgumentParser(description="Discover + rank H1 programs.")
    ap.add_argument(
        "--top", type=int, default=10,
        help="Top N to print (default: 10).",
    )
    ap.add_argument(
        "--refresh", action="store_true",
        help="Re-fetch the H1 program list even if a cache exists.",
    )
    ap.add_argument(
        "--verbose", action="store_true",
        help="Show per-program EV breakdown.",
    )
    ap.add_argument(
        "--no-filter", action="store_true",
        help="Skip the first-attempt hard-skip filter (show all bounty programs).",
    )
    args = ap.parse_args()

    signal.signal(signal.SIGALRM, _sigalrm)
    signal.alarm(180)

    INTEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Acquire program list (cached or fresh).
    if DISCOVERY_CACHE.exists() and not args.refresh:
        all_progs = json.loads(DISCOVERY_CACHE.read_text())
        print(
            f"[discover] using cached list ({len(all_progs)} programs); "
            f"--refresh to re-fetch",
            file=sys.stderr,
        )
    else:
        cred = token_store.get("hackerone")
        if not cred:
            print(
                "no HackerOne credential found. Run "
                "`scripts/sentinel_token.py add hackerone --handle <h>` first.",
                file=sys.stderr,
            )
            return 1
        all_progs = _fetch_all_h1_programs(cred.handle, cred.token)
        DISCOVERY_CACHE.write_text(json.dumps(all_progs))

    # 2. Filter for first-paid-attempt suitability.
    if not args.no_filter:
        candidates = _filter_for_first_attempt(all_progs)
    else:
        candidates = all_progs

    # 3. Persist each candidate as a lightweight ProgramScope JSON.
    persisted = 0
    for p in candidates:
        path = _persist_as_program_scope(p, INTEL_DIR)
        if path is not None:
            persisted += 1
    print(
        f"[discover] persisted {persisted} lightweight ProgramScope "
        f"JSONs to {INTEL_DIR}",
        file=sys.stderr,
    )

    # 4. Rank via PT1's scorer.
    from core.intel.program_scope import ProgramScope
    from core.intel.selection import rank_programs

    loaded = []
    for path in sorted(INTEL_DIR.glob("*-program-scope.json")):
        try:
            data = json.loads(path.read_text())
            loaded.append(ProgramScope.from_dict(data))
        except Exception as e:
            print(f"warning: skip {path.name}: {e}", file=sys.stderr)
            continue
    rankings = rank_programs(loaded)

    print(
        f"\nRanked {len(rankings)} candidates "
        f"(top {min(args.top, len(rankings))} below):",
    )
    _print_table(rankings, args.top)
    if args.verbose:
        _print_verbose(rankings, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
