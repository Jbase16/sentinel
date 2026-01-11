from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple

from core.mimic.models import Route


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

# Heuristics (fast, dependency-minimal):
# - fetch("..."), axios.get("..."), xhr.open("GET","..."), $.ajax({url:"..."})
# - string routes: "/api/...", "/v1/...", "/graphql", "https://example.com/api/..."
_FETCH_RE = re.compile(
    r"""
    (?:
        \bfetch\s*\(\s*
        (?P<q1>["'`])(?P<url1>[^"'`]{1,500})(?P=q1)
    )
    """,
    re.VERBOSE,
)

_AXIOS_RE = re.compile(
    r"""
    \baxios\.(?P<verb>get|post|put|patch|delete|request)\s*\(\s*
    (?P<q1>["'`])(?P<url1>[^"'`]{1,500})(?P=q1)
    """,
    re.VERBOSE | re.IGNORECASE,
)

_XHR_OPEN_RE = re.compile(
    r"""
    \.open\s*\(\s*
    (?P<qv>["'`])(?P<verb>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)(?P=qv)\s*,\s*
    (?P<qu>["'`])(?P<url>[^"'`]{1,500})(?P=qu)
    """,
    re.VERBOSE,
)

_AJAX_OBJ_URL_RE = re.compile(
    r"""
    \bajax\s*\(\s*\{[^}]*?\burl\s*:\s*(?P<q>["'`])(?P<url>[^"'`]{1,500})(?P=q)
    """,
    re.VERBOSE | re.IGNORECASE | re.DOTALL,
)

# General string route patterns (lower confidence)
_ROUTE_STRING_RE = re.compile(
    r"""
    (?P<q>["'`])
    (?P<route>
        (?:https?://[^"'`\s]{4,500})|
        (?:/[^"'`\s]{1,500})
    )
    (?P=q)
    """,
    re.VERBOSE,
)

# "Hidden" routes (common patterns: internal, admin, debug, dev endpoints)
_HIDDEN_HINT_RE = re.compile(r"(?:/admin\b|/internal\b|/debug\b|/dev\b|/private\b|/graphql\b)", re.IGNORECASE)


def _evidence_from_match(text: str, start: int, end: int) -> Dict:
    snippet = text[max(0, start - 40): min(len(text), end + 40)]
    return {"start": start, "end": end, "snippet": snippet}


def mine_routes(asset_id: str, text: str) -> List[Route]:
    routes: List[Route] = []
    seen = set()

    def add(route: str, method: Optional[str], confidence: int, start: int, end: int) -> None:
        key = (route, method or "")
        if key in seen:
            return
        seen.add(key)
        hidden = bool(_HIDDEN_HINT_RE.search(route))
        routes.append(
            Route(
                route=route,
                method=(method.upper() if method else None),
                confidence=confidence,
                hidden=hidden,
                evidence=_evidence_from_match(text, start, end),
            )
        )

    for m in _FETCH_RE.finditer(text):
        route = m.group("url1")
        add(route, None, 70, m.start(), m.end())

    for m in _AXIOS_RE.finditer(text):
        verb = (m.group("verb") or "").upper()
        method = verb.upper() if verb.upper() in _HTTP_METHODS else None
        route = m.group("url1")
        add(route, method, 75, m.start(), m.end())

    for m in _XHR_OPEN_RE.finditer(text):
        verb = m.group("verb").upper()
        route = m.group("url")
        add(route, verb, 80, m.start(), m.end())

    for m in _AJAX_OBJ_URL_RE.finditer(text):
        route = m.group("url")
        add(route, None, 65, m.start(), m.end())

    # Low-confidence sweep for route-ish strings
    for m in _ROUTE_STRING_RE.finditer(text):
        route = m.group("route")
        # avoid junk like "//# sourceMappingURL="
        if "sourcemappingurl" in route.lower():
            continue
        # keep it sane
        if len(route) < 2:
            continue
        add(route, None, 35, m.start(), m.end())

    # Promote "hidden" ones to higher confidence signal
    promoted: List[Route] = []
    for r in routes:
        if r.hidden and r.confidence < 60:
            promoted.append(Route(route=r.route, method=r.method, confidence=60, hidden=True, evidence=r.evidence))
        else:
            promoted.append(r)

    return promoted
