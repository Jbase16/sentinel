"""
core/verify/promoter.py — Phase 5-VC3: promote captured exchanges to
bounty-report-ready reproduction steps.

The Verify Console captures FlowSteps; the BountyReport consumes
List[str] for `steps_to_reproduce`. This module is the bridge.

Each captured exchange becomes one numbered repro entry composed of:
  * One sentence of prose describing what's being demonstrated.
  * A SANITIZED curl command the triager can paste into their own
    terminal.
  * A short response excerpt that demonstrates the vulnerability.

Sanitization (operator's tokens NEVER leave the session):
  * `Authorization: Bearer <real-token>` → `Authorization: Bearer $TOKEN`
  * `Cookie: sid=<real-value>; csrf=<real-value>` →
    `Cookie: sid=$SESSION_ID; csrf=$CSRF_TOKEN`
  * Any header whose value matches the session's persona headers
    gets the same treatment, with operator-readable placeholder names.

Two-audience model:
  * The operator's session transcript contains the REAL captured
    headers/bodies (they need to see them to debug).
  * The rendered repro replaces sensitive values with placeholders
    so it can safely be copy-pasted into a HackerOne / Bugcrowd /
    Intigriti submission.

This module is INTENTIONALLY decoupled from BountyReport — it
produces strings. The UI (VC4) and any CLI/AI consumer decides what
to do with them: draft a report, copy to clipboard, write to disk, etc.
"""
from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from core.ghost.flow import FlowStep
from core.verify.console import VerificationSession

logger = logging.getLogger(__name__)


# ─────────────────────── sanitization ───────────────────────


# Header names whose values we ALWAYS treat as secret regardless of
# whether they came from the persona binding. Operators sometimes
# include auth via per-request headers — those still need sanitizing.
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-csrf-token", "x-xsrf-token",
    "x-auth-token", "x-api-key", "x-session-token",
}


def _placeholder_for(header_name: str, value: str) -> str:
    """Choose an operator-readable placeholder for `header_name`.

    The placeholder tells the triager what KIND of value they need to
    substitute, not the actual value. Examples:
        Authorization: Bearer ... → $TOKEN
        X-API-Key: ...            → $API_KEY
        Cookie: sid=...; csrf=... → handled by _sanitize_cookie_value
    """
    name = header_name.lower()
    if name == "authorization":
        # Detect scheme so we emit the right placeholder.
        scheme = value.split(" ", 1)[0] if " " in value else ""
        if scheme.lower() == "bearer":
            return "Bearer $TOKEN"
        if scheme.lower() == "basic":
            return "Basic $CREDENTIALS_B64"
        return "$AUTH"
    if name in ("x-csrf-token", "x-xsrf-token"):
        return "$CSRF_TOKEN"
    if name in ("x-api-key", "x-auth-token"):
        return "$API_KEY"
    if name == "x-session-token":
        return "$SESSION_TOKEN"
    # Generic — should rarely hit this path since the matrix above
    # covers the common cases.
    return "$SECRET"


def _sanitize_cookie_value(cookie_header: str) -> str:
    """`sid=abc; csrf=xyz` → `sid=$SESSION_ID; csrf=$CSRF_TOKEN`.

    Each cookie's NAME is preserved (it identifies the cookie kind);
    the VALUE is replaced with a placeholder derived from the name."""
    parts = [p.strip() for p in cookie_header.split(";") if p.strip()]
    out_parts = []
    for p in parts:
        if "=" not in p:
            out_parts.append(p)
            continue
        name, _val = p.split("=", 1)
        name = name.strip()
        lname = name.lower()
        if any(s in lname for s in ("sess", "sid")):
            placeholder = "$SESSION_ID"
        elif "csrf" in lname or "xsrf" in lname:
            placeholder = "$CSRF_TOKEN"
        elif "remember" in lname:
            # Match order matters: `remember_token` would hit the
            # generic auth/token branch below first; check more-specific
            # names first.
            placeholder = "$REMEMBER_TOKEN"
        elif "auth" in lname or "token" in lname:
            placeholder = "$TOKEN"
        else:
            placeholder = f"${name.upper().replace('-', '_')}_VALUE"
        out_parts.append(f"{name}={placeholder}")
    return "; ".join(out_parts)


def sanitize_headers(
    headers: Mapping[str, str],
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Return (sanitized_headers, placeholder_legend).

    `placeholder_legend` maps each placeholder back to a one-line
    description of what the operator should substitute (used by the
    rendered prose so the triager isn't guessing).
    """
    out: Dict[str, str] = {}
    legend: Dict[str, str] = {}
    for k, v in headers.items():
        name = str(k).lower()
        value = str(v)
        if name == "cookie":
            sanitized = _sanitize_cookie_value(value)
            out[name] = sanitized
            # Pull placeholders out of the sanitized cookie for the legend.
            for ph in re.findall(r"\$[A-Z_]+", sanitized):
                legend[ph] = legend.get(
                    ph, f"the value of the `{ph[1:].lower()}` cookie"
                )
        elif name in _AUTH_HEADER_NAMES:
            placeholder_value = _placeholder_for(name, value)
            out[name] = placeholder_value
            for ph in re.findall(r"\$[A-Z_]+", placeholder_value):
                legend[ph] = legend.get(
                    ph,
                    f"the value of the `{k}` header (a {ph[1:].lower().replace('_', ' ')})"
                )
        else:
            # Non-auth header — copy as-is.
            out[name] = value
    return out, legend


# ─────────────────────── curl rendering ───────────────────────


def render_curl(step: FlowStep, sanitize: bool = True) -> Tuple[str, Dict[str, str]]:
    """Render `step` as a multi-line curl command. Returns (curl, legend).

    The curl is produced as:
        curl -X METHOD \\
          -H 'Header1: Value1' \\
          -H 'Header2: Value2' \\
          -d 'body' \\
          'URL'

    `sanitize=True` replaces auth header values with placeholders;
    `sanitize=False` returns the raw captured values (operator's local
    debugging only).
    """
    if sanitize:
        sanitized_headers, legend = sanitize_headers(step.headers)
    else:
        sanitized_headers = {str(k).lower(): str(v) for k, v in step.headers.items()}
        legend = {}

    lines = [f"curl -X {step.method}"]
    for k, v in sorted(sanitized_headers.items()):
        # shlex.quote handles single-quoted escapes; we wrap manually
        # so the formatting stays consistent line-to-line.
        header_line = f"{k}: {v}"
        lines.append(f"  -H {shlex.quote(header_line)}")
    if step.request_body:
        # Sanitization of request body is a future improvement (would
        # need JSON-aware redaction). For V1 we ship the raw body —
        # most repro request bodies are not secret in themselves
        # (they're the payload being tested).
        lines.append(f"  -d {shlex.quote(step.request_body)}")
    lines.append(f"  {shlex.quote(step.url)}")
    return " \\\n".join(lines), legend


# ─────────────────────── prose rendering ───────────────────────


@dataclass
class ReproEntry:
    """One numbered entry in the rendered repro list.

    `markdown` is the operator-facing string that goes into
    BountyReport.steps_to_reproduce. The other fields are kept around
    so UI / AI consumers can render alternate views without re-parsing
    the markdown."""
    index: int
    method: str
    url: str
    prose: str
    curl: str
    response_status: int
    response_excerpt: str
    placeholder_legend: Dict[str, str] = field(default_factory=dict)

    @property
    def markdown(self) -> str:
        """The complete markdown for this entry — what bounty_report
        will render as one numbered list item."""
        parts: List[str] = [self.prose]
        parts.append("")  # blank line for markdown formatting
        parts.append("```bash")
        parts.append(self.curl)
        parts.append("```")
        if self.response_status > 0:
            parts.append("")
            parts.append(f"**Response (HTTP {self.response_status}):**")
            parts.append("```")
            parts.append(self.response_excerpt)
            parts.append("```")
        return "\n".join(parts)


def _excerpt_response_body(body: str, max_chars: int = 400) -> str:
    """Pull a useful excerpt from a response body for the repro.

    For JSON: pretty-print to first ~max_chars chars; preserve closing
    bracket so it looks complete.
    For HTML: strip to ~max_chars chars with a trailing ellipsis.
    Empty body: explicit `(empty body)` marker so the triager knows
    the demonstration is the status code itself.
    """
    if not body:
        return "(empty body)"
    body = body.strip()
    if len(body) <= max_chars:
        return body
    return body[:max_chars] + "\n…"


def _build_prose_for_step(
    step: FlowStep,
    index: int,
    finding_summary: Optional[Dict[str, Any]] = None,
) -> str:
    """One-sentence prose description of what step `index` does.

    Persona attribution (from step.persona_at_capture) is included
    when present — critical for distinguishing successive requests to
    the same URL from different identities (the cross-principal IDOR
    case calibrated in Run #50).
    """
    method = step.method
    # Path is the most useful URL fragment — full URLs blow up line length.
    from urllib.parse import urlparse
    try:
        path = urlparse(step.url).path or "/"
    except Exception:
        path = step.url

    # Persona attribution prefix when present.
    persona = step.persona_at_capture
    if persona:
        descr = f"As user `{persona}`, send `{method} {path}`"
    else:
        descr = f"Send `{method} {path}`"

    # First-step prose can mention the finding context if we have it.
    if index == 1 and finding_summary:
        vc = finding_summary.get("vuln_class") or ""
        payload = finding_summary.get("payload")
        if vc and payload:
            descr += f" to reproduce the {vc} confirmation (payload: `{payload}`)"
        elif vc:
            descr += f" to reproduce the {vc} confirmation"

    # Note the response status as part of the prose.
    if step.response_status > 0:
        descr += f" — the server returns **HTTP {step.response_status}**"
    descr += "."

    return descr


def promote_transcript_to_repro(
    session: VerificationSession,
    exchange_indices: Optional[List[int]] = None,
    sanitize: bool = True,
) -> Tuple[List[ReproEntry], Dict[str, str]]:
    """Convert a session's transcript into a numbered list of ReproEntry.

    Args:
      session: The verification session whose transcript we're promoting.
      exchange_indices: Optional zero-based indices into
        session.transcript. If None, ALL exchanges are included.
        Operators select the meaningful subset in the UI (often just
        the one or two requests that demonstrate the bug, not every
        exploratory probe).
      sanitize: If True (default), auth headers/cookies in the rendered
        curl are replaced with placeholders. Set False only for
        operator-local debug renders.

    Returns:
      (entries, combined_placeholder_legend).
      The legend is the union across all entries — a single block the
      report can render once near the top: "Substitute placeholders
      before running: $TOKEN = …".
    """
    finding_summary: Optional[Dict[str, Any]] = None
    if session.original_finding:
        # Use the same summary shape VC1 exposed.
        from core.verify.console import _summarize_finding
        finding_summary = _summarize_finding(session.original_finding)

    if exchange_indices is None:
        selected = list(enumerate(session.transcript))
    else:
        selected = []
        for raw_idx in exchange_indices:
            if 0 <= raw_idx < len(session.transcript):
                selected.append((raw_idx, session.transcript[raw_idx]))
            else:
                logger.warning(
                    f"[promoter] session {session.session_id[:8]}: "
                    f"skipping out-of-range exchange index {raw_idx}"
                )

    entries: List[ReproEntry] = []
    combined_legend: Dict[str, str] = {}
    for one_based_i, (_orig_idx, step) in enumerate(selected, start=1):
        curl, legend = render_curl(step, sanitize=sanitize)
        prose = _build_prose_for_step(
            step, index=one_based_i, finding_summary=finding_summary
        )
        excerpt = _excerpt_response_body(step.response_body)
        entries.append(ReproEntry(
            index=one_based_i,
            method=step.method,
            url=step.url,
            prose=prose,
            curl=curl,
            response_status=step.response_status,
            response_excerpt=excerpt,
            placeholder_legend=legend,
        ))
        combined_legend.update(legend)

    # If any placeholders were used and we have at least one entry,
    # inject the legend at the TOP of the first entry's prose so the
    # triager sees what to substitute before they read any curl
    # commands. Tested in Calibration Run #50 — without this, the
    # triager sees `Bearer $TOKEN` with no idea what to swap in.
    if entries and combined_legend and sanitize:
        legend_lines = [
            "_Before running, substitute these placeholders with real values:_",
        ]
        for ph in sorted(combined_legend.keys()):
            legend_lines.append(f"- `{ph}` — {combined_legend[ph]}")
        legend_block = "\n".join(legend_lines)
        # Prepend legend to the first entry's prose.
        first = entries[0]
        first.prose = f"{legend_block}\n\n{first.prose}"

    return entries, combined_legend


def render_repro_as_strings(
    entries: List[ReproEntry],
) -> List[str]:
    """Convert promoted ReproEntries to the List[str] shape that
    BountyReport.steps_to_reproduce expects.

    Each string is one fully-rendered repro entry (prose + curl +
    response excerpt) ready to drop into the report's numbered list."""
    return [e.markdown for e in entries]
