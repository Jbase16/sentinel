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

import hashlib
import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from core.ghost.flow import FlowStep
from core.verify.console import VerificationSession

logger = logging.getLogger(__name__)


# ─────────────────────── sanitization ───────────────────────


# Header names whose values we ALWAYS treat as secret regardless of
# whether they came from the persona binding. Operators sometimes
# include auth via per-request headers — those still need sanitizing.
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-csrf-token", "x-xsrf-token",
    "x-auth-token", "x-api-key", "x-session-token", "proxy-authorization",
}

_SECRET_NAMES = frozenset({
    "authorization", "proxyauthorization", "cookie", "setcookie", "password",
    "passwd", "secret", "clientsecret", "apikey", "xapikey", "token", "authtoken",
    "accesstoken", "refreshtoken", "idtoken", "session", "sessionid", "sessiontoken",
    "sid", "csrf", "csrftoken", "xcsrftoken", "xsrf", "xsrftoken", "xxsrftoken",
    "credential", "credentials", "bearertoken",
})
_PLACEHOLDER = re.compile(r"\$[A-Z][A-Z0-9_]*\Z")
_SECRET_NAME_PATTERN = (
    r"(?:proxy[-_ ]?authorization|authorization|set[-_ ]?cookie|cookie|password|passwd|"
    r"(?:client[-_]?)?secret|(?:x[-_]?)?api[-_]?key|(?:access|refresh|id|auth|bearer)[-_]?token|"
    r"session(?:[-_]?(?:id|token))?|sid|(?:x[-_]?)?(?:csrf|xsrf)(?:[-_]?token)?|"
    r"token|credentials?)"
)
_SECRET_PAIR = re.compile(
    rf"(?i)(?<![\w-])(?P<key>{_SECRET_NAME_PATTERN})(?P<sep>[\"']?\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^&;\s,}\]<>`]+)"
)
_AUTH_VALUE = re.compile(r"(?i)\b(Bearer|Basic)\s+([^\s\"'`,;<>]+)")
_COOKIE_LINE = re.compile(r"(?im)\b((?:set-)?cookie\s*:\s*)([^\r\n]+)")
_MEDIA_VALUE = re.compile(
    r"(?:application/(?:json|xml|x-www-form-urlencoded|octet-stream|problem\+json|vnd\.api\+json|\*)"
    r"|text/(?:plain|html|xml|csv|\*)|multipart/form-data|\*/\*)"
    r"(?:\s*;\s*(?:charset=(?:utf-8|us-ascii|iso-8859-1)|q=(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?)))*",
    re.IGNORECASE,
)


def _secret_name(name: str) -> bool:
    return not _PLACEHOLDER.fullmatch(name) and re.sub(r"[^a-z0-9]", "", name.lower()) in _SECRET_NAMES


def _safe_media_header(name: str, value: str) -> bool:
    return name.lower() in {"accept", "content-type"} and all(
        _MEDIA_VALUE.fullmatch(part.strip()) is not None for part in value.split(",")
    )


class ArtifactSanitizer:
    """In-memory credential redaction shared by both candidate artifact shapes.

    Captures and credential values never enter this object's repr or a durable
    export. Only length/hash deny-checks may be retained in an owned workbench;
    these also redact reflected credentials when the workbench is reopened.
    No method dispatches a request or mutates a capture.
    """

    __slots__ = ("_values", "_secret_fingerprints")

    def __init__(
        self,
        records: Iterable[Any] = (),
        *,
        sensitive_values: Iterable[str] = (),
        secret_fingerprints: Iterable[Tuple[int, str]] = (),
        redact_response_values: bool = False,
    ) -> None:
        self._values: set[str] = set()
        self._secret_fingerprints: set[Tuple[int, str]] = set()
        for length, digest in secret_fingerprints:
            if (
                isinstance(length, bool) or not isinstance(length, int) or length < 1
                or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("Artifact credential fingerprint is invalid")
            self._secret_fingerprints.add((length, digest))
        for value in sensitive_values:
            self._remember(value)
            if isinstance(value, str):
                self._collect_text(value)
        for record in records:
            if isinstance(record, Mapping):
                self._collect_value(record)
                if redact_response_values:
                    self._collect_response_values(record.get("response_body", ""))
                continue
            for name in ("headers", "response_headers"):
                self._collect_headers(getattr(record, name, {}) or {})
            for value in (getattr(record, "cookies_after_step", {}) or {}).values():
                self._remember(value)
            self._collect_url(str(getattr(record, "url", "")))
            for name in ("request_body", "response_body"):
                self._collect_text(str(getattr(record, name, "") or ""))
            if redact_response_values:
                self._collect_response_values(getattr(record, "response_body", "") or "")
            self._collect_value(getattr(record, "params", {}) or {})

    def __repr__(self) -> str:
        return "ArtifactSanitizer(credentials=<redacted>)"

    def __reduce_ex__(self, protocol: int) -> Any:
        raise TypeError("Artifact credentials cannot be serialized")

    def _remember(self, value: Any) -> None:
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            return
        raw = str(value)
        if not raw or _PLACEHOLDER.fullmatch(raw):
            return
        variants = {
            raw, quote(raw, safe=""), quote_plus(raw, safe=""),
            json.dumps(raw, ensure_ascii=True)[1:-1],
        }
        self._values.update(variants | {
            re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), item)
            for item in variants
        })

    def _collect_headers(self, headers: Mapping[str, Any]) -> None:
        for name, value in headers.items():
            name, value = str(name).lower(), str(value)
            if _safe_media_header(name, value):
                continue
            if name in {"cookie", "set-cookie"}:
                parts = value.split(";") if name == "cookie" else value.split(";", 1)[:1]
                for part in parts:
                    self._remember(part.split("=", 1)[-1].strip())
            elif name in {"authorization", "proxy-authorization"}:
                self._remember(value.split(" ", 1)[-1].strip())
            else:
                self._remember(value)
                self._collect_text(value)

    def _collect_url(self, value: str) -> None:
        try:
            parts = urlsplit(value)
        except ValueError:
            return
        self._remember(parts.username or "")
        self._remember(parts.password or "")
        for name, item in parse_qsl(parts.query, keep_blank_values=True):
            if _secret_name(name):
                self._remember(item)

    def _collect_value(self, value: Any) -> None:
        if isinstance(value, Mapping):
            for name, item in value.items():
                key = str(name).lower()
                if key in {"headers", "request_headers", "response_headers"} and isinstance(item, Mapping):
                    self._collect_headers(item)
                elif key in {"cookies", "cookies_after_step", "persona_cookies"} and isinstance(item, Mapping):
                    for cookie in item.values():
                        self._remember(cookie)
                elif _secret_name(key):
                    self._remember(item)
                    if isinstance(item, str):
                        self._collect_text(item)
                elif key in {"url", "target_url"} and isinstance(item, str):
                    self._collect_url(item)
                elif isinstance(item, str):
                    self._collect_text(item)
                else:
                    self._collect_value(item)
        elif isinstance(value, (tuple, list)):
            for item in value:
                self._collect_value(item)

    def _collect_text(self, value: str) -> None:
        for match in _AUTH_VALUE.finditer(value):
            self._remember(match.group(2))
        for match in _SECRET_PAIR.finditer(value):
            raw = match.group("value").strip("\"'")
            if not (
                "authorization" in match.group("key").lower()
                and raw.lower() in {"bearer", "basic"}
            ):
                self._remember(raw)
        if "=" in value and "\n" not in value:
            for name, item in parse_qsl(value, keep_blank_values=True):
                if _secret_name(name):
                    self._remember(item)
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return
        if isinstance(parsed, (dict, list)):
            self._collect_value(parsed)

    def _collect_response_values(self, value: Any) -> None:
        """Draft recipes retain response shapes, never protected response data."""
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                self._remember(value)
                return
            if isinstance(parsed, str):
                self._remember(parsed)
                return
            self._collect_response_values(parsed)
        elif isinstance(value, Mapping):
            for item in value.values():
                self._collect_response_values(item)
        elif isinstance(value, (tuple, list)):
            for item in value:
                self._collect_response_values(item)

    def fingerprints(self) -> Tuple[Tuple[int, str], ...]:
        return tuple(sorted(self._secret_fingerprints | {
            (len(value), hashlib.sha256(value.encode("utf-8")).hexdigest())
            for value in self._values
        }))

    @staticmethod
    def _fingerprint_spans(value: str, fingerprints: Iterable[Tuple[int, str]]) -> list[Tuple[int, int]]:
        by_length: Dict[int, set[str]] = {}
        for length, digest in fingerprints:
            if length <= len(value):
                by_length.setdefault(length, set()).add(digest)
        spans = []
        for length, digests in by_length.items():
            for start in range(len(value) - length + 1):
                if hashlib.sha256(value[start:start + length].encode("utf-8")).hexdigest() in digests:
                    spans.append((start, start + length))
        return spans

    def contains_secret(self, value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(self.contains_secret(str(key)) or self.contains_secret(item) for key, item in value.items())
        if isinstance(value, (tuple, list)):
            return any(self.contains_secret(item) for item in value)
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            return False
        text = str(value)
        return any(item in text for item in self._values) or bool(
            self._fingerprint_spans(text, self._secret_fingerprints)
        )

    def text(self, value: str) -> str:
        result = str(value)
        spans = self._fingerprint_spans(result, self._secret_fingerprints)
        for secret in self._values:
            start = result.find(secret)
            while start >= 0:
                spans.append((start, start + len(secret)))
                start = result.find(secret, start + 1)
        if spans:
            merged: list[Tuple[int, int]] = []
            for start, end in sorted(spans):
                if merged and start < merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                else:
                    merged.append((start, end))
            for start, end in reversed(merged):
                result = result[:start] + "$REDACTED" + result[end:]
        result = _AUTH_VALUE.sub(
            lambda match: f"{match.group(1)} " + (
                "$CREDENTIALS_B64" if match.group(1).lower() == "basic" else "$TOKEN"
            ), result,
        )
        result = _COOKIE_LINE.sub(lambda match: match.group(1) + _sanitize_cookie_value(match.group(2)), result)

        def redact_pair(match: re.Match[str]) -> str:
            current = match.group("value")
            wrapper = current[0] if current.startswith(("\"", "'")) else ""
            raw = current.strip("\"'")
            if raw.lower() in {"bearer", "basic"}:
                return match.group(0)
            replacement = raw if _PLACEHOLDER.fullmatch(raw) else "$REDACTED"
            return match.group("key") + match.group("sep") + wrapper + replacement + wrapper

        return _SECRET_PAIR.sub(redact_pair, result)

    def value(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            result = {}
            for key, item in value.items():
                safe_key = self.text(str(key))
                if safe_key in result:
                    raise ValueError("Artifact field names collide after sanitization")
                result[safe_key] = "$REDACTED" if _secret_name(str(key)) else self.value(item)
            return result
        if isinstance(value, (tuple, list)):
            return [self.value(item) for item in value]
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and self.contains_secret(value):
            return "$REDACTED"
        return value

    def headers(self, headers: Mapping[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        sanitized, legend = sanitize_headers(headers)
        result = {}
        for name, value in sanitized.items():
            safe_name = self.text(name)
            if safe_name in result:
                raise ValueError("Artifact header names collide after sanitization")
            if name == "cookie" or name in _AUTH_HEADER_NAMES:
                result[safe_name] = self.text(value)
            elif _safe_media_header(name, value):
                result[safe_name] = self.text(value)
            else:
                result[safe_name] = "$REDACTED"
        return result, self.value(legend)

    def url(self, value: str) -> str:
        try:
            parts = urlsplit(value)
        except ValueError:
            raise ValueError("Artifact URL is invalid") from None
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError("Artifact URL must use HTTP(S)")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Artifact URL must not contain credentials")
        query = urlencode([
            (self.text(name), "$VALUE")
            for name, _value in parse_qsl(parts.query, keep_blank_values=True)
        ], safe="$")
        return urlunsplit((parts.scheme.lower(), self.text(parts.netloc), self.text(parts.path), query, ""))

    def body(self, value: str) -> str:
        if not value:
            return value
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return self.text(value)
        sanitized = self.value(parsed)
        return value if parsed == sanitized else json.dumps(sanitized, sort_keys=True, ensure_ascii=True)


def _placeholder_for(header_name: str, value: str) -> str:
    """Choose an operator-readable placeholder for `header_name`.

    The placeholder tells the triager what KIND of value they need to
    substitute, not the actual value. Examples:
        Authorization: Bearer ... → $TOKEN
        X-API-Key: ...            → $API_KEY
        Cookie: sid=...; csrf=... → handled by _sanitize_cookie_value
    """
    name = header_name.lower()
    if name in {"authorization", "proxy-authorization"}:
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
            out_parts.append("$REDACTED")
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


def render_curl(
    step: FlowStep,
    sanitize: bool = True,
    *,
    sanitizer: Optional[ArtifactSanitizer] = None,
) -> Tuple[str, Dict[str, str]]:
    """Render `step` as a multi-line curl command. Returns (curl, legend).

    The curl is produced as:
        curl -X METHOD \\
          -H 'Header1: Value1' \\
          -H 'Header2: Value2' \\
          -d 'body' \\
          'URL'

    `sanitize=True` sanitizes the entire request with placeholders;
    `sanitize=False` returns the raw captured values (operator's local
    debugging only).
    """
    if sanitize:
        sanitizer = sanitizer or ArtifactSanitizer((step,))
        sanitized_headers, legend = sanitizer.headers(step.headers)
        method = sanitizer.text(step.method)
        body = sanitizer.body(step.request_body)
        url = sanitizer.url(step.url)
    else:
        sanitized_headers = {str(k).lower(): str(v) for k, v in step.headers.items()}
        legend = {}
        method, body, url = step.method, step.request_body, step.url

    lines = [f"curl -X {shlex.quote(method)}"]
    for k, v in sorted(sanitized_headers.items()):
        # shlex.quote handles single-quoted escapes; we wrap manually
        # so the formatting stays consistent line-to-line.
        header_line = f"{k}: {v}"
        lines.append(f"  -H {shlex.quote(header_line)}")
    if body:
        lines.append(f"  -d {shlex.quote(body)}")
    lines.append(f"  {shlex.quote(url)}")
    rendered = " \\\n".join(lines)
    if sanitize and sanitizer is not None and sanitizer.contains_secret((rendered, legend)):
        raise ValueError("Artifact credential redaction is incomplete")
    return rendered, legend


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

    # First-step prose used to reference internal Sentinel labels
    # ("to reproduce the IDOR confirmation (payload: admin↔jim)") —
    # that voice leaks into PT2's submission output. The operator
    # narrates the bug in the impact/summary sections of the
    # SubmissionCandidate render; the steps themselves stay action-only.
    # Keeping this stub here so we remember the intentional removal.
    _ = (index, finding_summary)

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
      sanitize: If True (default), credential values throughout the rendered
        entries are replaced with placeholders. Set False only for
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
                    "[promoter] skipping out-of-range exchange index"
                )

    sanitizer = ArtifactSanitizer(
        session.transcript,
        sensitive_values=(
            *session.persona_headers.values(),
            *session.persona_cookies.values(),
        ),
    ) if sanitize else None
    entries: List[ReproEntry] = []
    combined_legend: Dict[str, str] = {}
    for one_based_i, (_orig_idx, step) in enumerate(selected, start=1):
        curl, legend = render_curl(step, sanitize=sanitize, sanitizer=sanitizer)
        prose = _build_prose_for_step(
            step, index=one_based_i, finding_summary=finding_summary
        )
        if sanitizer is not None:
            prose = sanitizer.text(prose)
            excerpt = _excerpt_response_body(sanitizer.body(step.response_body))
        else:
            excerpt = _excerpt_response_body(step.response_body)
        entries.append(ReproEntry(
            index=one_based_i,
            method=sanitizer.text(step.method) if sanitizer is not None else step.method,
            url=sanitizer.url(step.url) if sanitizer is not None else step.url,
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

    if sanitizer is not None and sanitizer.contains_secret([
        {
            "method": entry.method, "url": entry.url, "markdown": entry.markdown,
            "response_excerpt": entry.response_excerpt, "legend": entry.placeholder_legend,
        }
        for entry in entries
    ]):
        raise ValueError("Artifact credential redaction is incomplete")
    return entries, combined_legend


def render_repro_as_strings(
    entries: List[ReproEntry],
) -> List[str]:
    """Convert promoted ReproEntries to the List[str] shape that
    BountyReport.steps_to_reproduce expects.

    Each string is one fully-rendered repro entry (prose + curl +
    response excerpt) ready to drop into the report's numbered list."""
    return [e.markdown for e in entries]
