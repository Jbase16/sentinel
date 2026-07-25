#!/usr/bin/env python3
"""
sentinel-rank — Phase 6-PT1 CLI for the target/program scorer.

Loads ingested ProgramScope JSON files from one or more directories
and ranks them by Sentinel-fit expected value. The operator reads the
output as a recommendation list for which programs to attempt next.

Usage:

  # Rank every program previously ingested.
  python3 scripts/sentinel_rank.py \\
      --intel-dir ~/.sentinelforge/intel \\
      --intel-dir /tmp/intel-gitlab \\
      --intel-dir /tmp/intel-paypal

  # Show the top 5 with one-line summaries (default).
  # Add --verbose to dump the per-class EV breakdown for each.

  # Or read straight from stdin (one program-scope.json per line).

Output format: a ranked table for human reading + a JSON blob (when
--json) for further processing.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from core.intel.program_scope import ProgramScope
from core.intel.selection import ProgramFitScore, rank_programs


def _load_programs_from_dir(d: Path) -> List[ProgramScope]:
    """Load every *-program-scope.json file from `d`."""
    out: List[ProgramScope] = []
    if not d.exists():
        print(f"warning: intel dir {d} doesn't exist; skipping", file=sys.stderr)
        return out
    for p in sorted(d.glob("*-program-scope.json")):
        try:
            with p.open() as f:
                data = json.load(f)
            scope = ProgramScope.from_dict(data)
            out.append(scope)
        except Exception as e:
            print(
                f"warning: could not load {p}: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            continue
    return out


def _print_table(rankings: List[ProgramFitScore], top_n: int) -> None:
    """Operator-readable ranked table."""
    print()
    print(f"{'Rank':<5} {'Score':>10}  {'Scope':>5}  {'Pers':>5}  {'Sat':>4}  Program")
    print("─" * 80)
    for i, s in enumerate(rankings[:top_n], start=1):
        sat_pct = f"{int(s.saturation_penalty * 100)}%"
        print(
            f"{i:<5} ${s.final_score:>9,.0f}  "
            f"{s.scope_size:>5}  {s.verified_persona_count:>5}  "
            f"{sat_pct:>4}  {s.program_name}"
        )
    print()


def _print_verbose(rankings: List[ProgramFitScore], top_n: int) -> None:
    """Per-program detailed breakdown — useful when picking which one to
    actually attempt next."""
    for i, s in enumerate(rankings[:top_n], start=1):
        print(f"\n=== #{i}: {s.program_name} (${s.final_score:,.0f} EV) ===")
        print(f"  handle:           {s.program_handle or '-'}")
        print(f"  scope size:       {s.scope_size} domains")
        print(f"  scope mult:       ×{s.scope_multiplier:.2f}")
        print(f"  verified personas:{s.verified_persona_count}")
        print(f"  persona mult:     ×{s.persona_multiplier:.2f}")
        print(f"  saturation:       {int(s.saturation_penalty * 100)}% "
              f"(score reduced by this much)")
        print(f"  raw EV:           ${s.capabilities_match_usd:,.0f}")
        print(f"  top vuln fits:")
        for tc in s.top_vuln_classes:
            print(
                f"    • {tc['name']} "
                f"[{tc['cwe']}] — conf {tc['confidence']:.2f}, "
                f"EV ${tc['ev_contribution_usd']:,.0f} "
                f"(from {tc['source_phase']})"
            )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Rank ingested bug-bounty programs by Sentinel-fit EV.",
    )
    ap.add_argument(
        "--intel-dir",
        type=Path,
        action="append",
        default=[],
        help=(
            "Directory containing *-program-scope.json files from "
            "sentinel_ingest. Pass multiple times to merge sources."
        ),
    )
    ap.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top programs to print (default: 10).",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="Show per-program EV breakdown after the ranked table.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON for further processing (suppresses the human table).",
    )
    args = ap.parse_args()

    programs: List[ProgramScope] = []
    if args.intel_dir:
        for d in args.intel_dir:
            programs.extend(_load_programs_from_dir(d))
    else:
        print(
            "no --intel-dir provided; nothing to rank. "
            "Try `--intel-dir ~/.sentinelforge/intel`.",
            file=sys.stderr,
        )
        return 1

    if not programs:
        print(
            "no programs loaded — did sentinel_ingest run successfully?",
            file=sys.stderr,
        )
        return 1

    rankings = rank_programs(programs)

    if args.json:
        out = [r.to_dict() for r in rankings]
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print(
        f"\nRanked {len(rankings)} program(s) by Sentinel-fit "
        f"expected value (top {min(args.top, len(rankings))}):"
    )
    _print_table(rankings, args.top)
    if args.verbose:
        _print_verbose(rankings, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
