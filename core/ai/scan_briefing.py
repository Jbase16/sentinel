"""
core/ai/scan_briefing.py

Scan Intelligence Briefing — a deterministic, computed-once digest of an
ENTIRE scan, built for the AI Assistant (Calibration Run #24).

WHY THIS EXISTS
---------------
The chat model (gemma2-9B) has an 8192-token context ceiling. A large scan
cannot be injected verbatim, so the chat path historically truncated to the
first 30 findings / 20 issues. That makes the assistant *blind* to the rest
and makes quantitative answers ("how many criticals?", "list all open
ports") WRONG on any non-trivial scan — it was counting a sample.

An expert doesn't memorize every line; they hold an accurate executive
summary and look up details on demand. This module computes that executive
summary. It is:

  * COMPLETE   — every count is over ALL findings/issues, never a sample.
  * ACCURATE   — pure computed truth, not LLM-generated (cannot hallucinate).
  * COMPACT    — bounded output (~400-700 tokens) regardless of scan size,
                 via capped enumerations with explicit "+N more" markers so
                 the model knows when a list was clipped.
  * DETERMINISTIC — stable ordering (severity rank, then count-desc), so the
                 same scan always yields the same briefing (testable).

The briefing is injected at the TOP of the chat context, ABOVE the
(possibly truncated) per-finding detail, so the model always holds the
whole scan's shape even when it can only see some individual findings.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

# Canonical severity order (worst first). Anything unrecognized is bucketed
# under UNKNOWN so it is surfaced rather than silently miscounted.
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
_CONFIDENCE_ORDER = ("confirmed", "probable", "hypothesized", "unknown")


def _norm_severity(value: Any) -> str:
    """Normalize a finding severity to a canonical bucket."""
    text = str(value or "").strip().upper()
    return text if text in _SEVERITY_ORDER else ("UNKNOWN" if not text else text)


def severity_rank(value: Any) -> int:
    """
    Sort key where LOWER == MORE severe (CRITICAL=0 … UNKNOWN=last).

    Used to order the per-finding detail so that when the chat context is
    capped, the model sees the WORST findings, not an arbitrary slice.
    """
    sev = _norm_severity(value)
    try:
        return _SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(_SEVERITY_ORDER)


# Generic question words that should NOT match findings (else every finding
# looks "relevant"). Kept small and security-domain-aware.
_QUESTION_STOPWORDS = frozenset({
    "the", "and", "what", "which", "show", "tell", "about", "any", "are",
    "was", "were", "for", "you", "find", "found", "this", "that", "with",
    "how", "many", "give", "list", "more", "did", "does", "have", "has",
    "from", "scan", "finding", "findings", "issue", "issues", "all", "there",
    "can", "could", "would", "should", "explain", "describe", "details",
})


def select_relevant_findings(
    question: str,
    findings: Sequence[Dict[str, Any]],
    *,
    limit: int = 30,
) -> List[Dict[str, Any]]:
    """
    Choose which findings get FULL per-finding detail in the chat context
    (Calibration Run #25 — drill-down).

    The detail slice is capped by the 8192-token budget, so a naive
    "most-severe N" cut hides any finding the user actually asked about when
    it is not in the top N. This selector ranks by:
      1. relevance to the question — term overlap with a finding's
         id/type/target/message/metadata, so "what about port 8443?" surfaces
         the 8443 finding even if it is rank-90 by severity;
      2. then severity (most severe first) to fill the remaining slots.

    Deterministic; falls back to pure severity order when the question has no
    meaningful (non-stopword) terms.
    """
    items = [f for f in findings if isinstance(f, dict)]
    if not items:
        return []

    terms = {
        t for t in re.findall(r"[a-z0-9._:/-]{3,}", (question or "").lower())
        if t not in _QUESTION_STOPWORDS
    }

    def relevance(f: Dict[str, Any]) -> int:
        if not terms:
            return 0
        parts = [str(f.get(k, "")) for k in ("id", "type", "target", "message")]
        meta = f.get("metadata")
        if isinstance(meta, dict):
            parts += [f"{k} {v}" for k, v in meta.items()]
        hay = " ".join(parts).lower()
        return sum(1 for t in terms if t in hay)

    # relevance desc, then most-severe first (-rank), then stable id tiebreak.
    ranked = sorted(
        items,
        key=lambda f: (relevance(f), -severity_rank(f.get("severity")), str(f.get("id", ""))),
        reverse=True,
    )
    return ranked[:limit]


def _host_of(finding: Dict[str, Any]) -> str:
    """
    Best-effort host extraction. Prefer explicit metadata.host, then the
    finding's target (parsed), then 'unknown'. Findings carry hosts in
    several shapes (metadata.host for ports, bare hostnames for DNS), so we
    are defensive.
    """
    meta = finding.get("metadata")
    if isinstance(meta, dict):
        host = meta.get("host") or meta.get("hostname")
        if host:
            return str(host)
    target = str(finding.get("target") or "").strip()
    if not target:
        return "unknown"
    # target may be a bare host or a URL.
    if "://" in target:
        netloc = urlparse(target).netloc or target
        return netloc.split("@")[-1].split(":")[0] or target
    return target.split("/")[0].split(":")[0]


def _ports_from(findings: Sequence[Dict[str, Any]]) -> List[int]:
    """Collect every unique open port across the whole scan, sorted."""
    ports: set[int] = set()
    for f in findings:
        meta = f.get("metadata")
        if not isinstance(meta, dict):
            continue
        raw = meta.get("port")
        if raw is None:
            continue
        try:
            ports.add(int(raw))
        except (TypeError, ValueError):
            continue
    return sorted(ports)


def _capped(pairs: Sequence[tuple[str, int]], limit: int) -> str:
    """Render 'name ×count · name ×count … (+K more)' with a hard cap."""
    shown = pairs[:limit]
    rendered = " · ".join(f"{name} ×{count}" for name, count in shown)
    remainder = len(pairs) - len(shown)
    if remainder > 0:
        rendered += f" · (+{remainder} more types)" if rendered else f"(+{remainder} more)"
    return rendered or "none"


def build_scan_briefing(
    findings: Sequence[Dict[str, Any]],
    issues: Sequence[Dict[str, Any]],
    *,
    target: str = "unknown",
    session_id: Optional[str] = None,
    graph_dto: Optional[Dict[str, Any]] = None,
    tool_runs: Optional[Sequence[Dict[str, Any]]] = None,
    max_types: int = 12,
    max_hosts: int = 10,
    max_chains: int = 5,
    max_issues: int = 6,
) -> str:
    """
    Build the complete, compact Scan Intelligence Briefing string.

    Args:
        findings: ALL raw findings for the session (not a truncated slice).
        issues:   ALL enriched issues for the session.
        target:   The scan target (for the header).
        session_id: Optional session id (for the header).
        graph_dto: Optional export_dto() output for graph/chain/pressure data.
        tool_runs: Optional list of {tool,target,exit_code,timed_out,canceled}
                   dicts for coverage-gap reporting.
        max_*: enumeration caps to bound token size on huge scans.

    Returns:
        A multi-line briefing. Counts/totals are always complete; only
        enumerations are capped (with explicit "+N more" markers).
    """
    findings = [f for f in findings if isinstance(f, dict)]
    issues = [i for i in issues if isinstance(i, dict)]
    total_f = len(findings)
    total_i = len(issues)

    lines: List[str] = []
    header = (
        f"SCAN INTELLIGENCE BRIEFING — complete digest over ALL "
        f"{total_f} finding(s) / {total_i} issue(s)."
    )
    lines.append(header)
    lines.append(
        "Quote the KEY TOTALS numbers verbatim when asked 'how many' — they are "
        "exact, computed over EVERY finding. NEVER recount a list yourself; you "
        "will miscount. Per-finding detail shown later may be truncated."
    )
    sess = f" · Session: {session_id}" if session_id else ""
    lines.append(f"Target: {target}{sess}")

    if total_f == 0 and total_i == 0:
        lines.append(
            "No findings or issues recorded for this session yet — the scan "
            "produced no results, or has not run. Say so plainly if asked."
        )
        return "\n".join(lines)

    # Compute every aggregate once, over ALL findings.
    sev_counts = Counter(_norm_severity(f.get("severity")) for f in findings)
    type_counts = Counter(str(f.get("type") or "unknown") for f in findings)
    host_counts = Counter(_host_of(f) for f in findings)
    ports = _ports_from(findings)
    sev_render = " · ".join(
        f"{sev} {sev_counts.get(sev, 0)}"
        for sev in _SEVERITY_ORDER
        if sev_counts.get(sev, 0) > 0
    )

    # --- KEY TOTALS: explicit, labeled, copy-able numbers FIRST ---
    # The model answers "how many X" by copying these, instead of recounting a
    # long list (a 9B model miscounted a 99-port list as 79 — Run #24 live test).
    lines.append("KEY TOTALS (exact — quote these directly, do not recount):")
    lines.append(f"- Findings (total): {total_f}")
    lines.append(f"- Issues (total): {total_i}")
    lines.append(f"- Open ports (distinct): {len(ports)}")
    lines.append(f"- Hosts (distinct): {len(host_counts)}")
    lines.append(f"- Finding types (distinct): {len(type_counts)}")
    lines.append(f"- Severity counts: {sev_render or 'none'}")

    # --- Detailed breakdowns (capped enumerations; counts above are authoritative) ---
    type_pairs = sorted(type_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    lines.append(f"Finding types ({len(type_pairs)}): {_capped(type_pairs, max_types)}")

    host_pairs = sorted(host_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    lines.append(f"Hosts ({len(host_pairs)}): {_capped(host_pairs, max_hosts)}")

    if ports:
        lines.append(f"Open ports ({len(ports)} distinct): {', '.join(str(p) for p in ports)}")

    # --- Issues by confidence + top issues ---
    if issues:
        conf_counts = Counter(
            str(i.get("confirmation_level") or "unknown").strip().lower() for i in issues
        )
        conf_render = " · ".join(
            f"{c} {conf_counts.get(c, 0)}"
            for c in _CONFIDENCE_ORDER
            if conf_counts.get(c, 0) > 0
        )
        lines.append(f"Issues by confidence: {conf_render or 'none'}")

        # Top issues by score (desc). Score may be missing/non-numeric.
        def _score(issue: Dict[str, Any]) -> float:
            for key in ("score", "raw_score"):
                try:
                    return float(issue.get(key))
                except (TypeError, ValueError):
                    continue
            return -1.0

        top = sorted(issues, key=_score, reverse=True)[:max_issues]
        rendered_issues = []
        for i in top:
            conf = str(i.get("confirmation_level") or "?").upper()
            title = str(i.get("title") or i.get("type") or "Untitled")
            sc = _score(i)
            sc_str = f" (score {sc:g})" if sc >= 0 else ""
            rendered_issues.append(f"[{conf}] {title}{sc_str}")
        if rendered_issues:
            extra = len(issues) - len(top)
            suffix = f" · (+{extra} more)" if extra > 0 else ""
            lines.append("Top issues: " + " · ".join(rendered_issues) + suffix)

    # --- Causal attack graph (chains / pressure points) ---
    if isinstance(graph_dto, dict):
        counts = graph_dto.get("count", {}) if isinstance(graph_dto.get("count"), dict) else {}
        nodes = int(counts.get("nodes", 0) or 0)
        edges = int(counts.get("edges", 0) or 0)
        chains = graph_dto.get("attack_chains", [])
        chains = [c for c in chains if isinstance(c, dict)] if isinstance(chains, list) else []
        longest = max((int(c.get("length", 0) or 0) for c in chains), default=0)
        if nodes or edges or chains:
            lines.append(
                f"Attack graph: {nodes} nodes, {edges} edges · "
                f"{len(chains)} graph-validated chain(s) (longest {longest} steps)"
            )
        for c in chains[:max_chains]:
            labels = c.get("labels")
            if isinstance(labels, list) and labels:
                path = " → ".join(str(x) for x in labels if str(x))
            else:
                ids = c.get("node_ids", [])
                path = " → ".join(str(x) for x in ids) if isinstance(ids, list) else ""
            score = c.get("score", "?")
            lines.append(f"  chain {c.get('id', '?')} (score {score}): {path or '(unlabeled)'}")

        pressure = graph_dto.get("pressure_points", [])
        if isinstance(pressure, list):
            pp_rendered = []
            for pp in pressure[:3]:
                if not isinstance(pp, dict):
                    continue
                pp_rendered.append(
                    f"{pp.get('finding_title', 'unknown')} "
                    f"(blocks {pp.get('attack_paths_blocked', 0)} paths)"
                )
            if pp_rendered:
                lines.append("Pressure points: " + " · ".join(pp_rendered))

    # --- Coverage gaps (failed/timed-out tools = blind spots) ---
    if tool_runs:
        failed = [
            r for r in tool_runs
            if isinstance(r, dict) and (
                r.get("timed_out") or r.get("canceled") or r.get("exit_code") not in (0, None)
            )
        ]
        if failed:
            gap_render = []
            for r in failed[:5]:
                reason = (
                    "TIMED OUT" if r.get("timed_out")
                    else "CANCELED" if r.get("canceled")
                    else f"exit={r.get('exit_code')}"
                )
                gap_render.append(f"{r.get('tool', '?')} on {r.get('target', '?')} ({reason})")
            lines.append(
                "Coverage gaps (findings may be MISSING here): "
                + " · ".join(gap_render)
            )

    return "\n".join(lines)
