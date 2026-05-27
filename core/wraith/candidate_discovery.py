"""
core/wraith/candidate_discovery.py

Phase 3 step 3 — bridge from recon to verify_phase.

The verify phase's built-in `_SEED_PROBES` is hand-curated for Juice-Shop-
shaped paths (`/rest/products/search`, `/rest/basket/{N}`, …). Against a
real H1 target with its own URL space, the seed list catches nothing —
there's no `/rest/products/search` on gitlab.com.

This module bridges the gap. It:
  1. CRAWLS the target with the existing `core/web/HttpCrawler` (the
     orphaned infrastructure under core/web/ that was built but never
     wired). Same battle-tested code, accessed via thin adapter classes
     so we don't drag in the full WebOrchestrator pipeline.
  2. CLASSIFIES each discovered URL into zero-or-more
     `(url, label, vuln_class)` probe candidates. Classification is
     content-aware: a `/search?url=...&q=...` URL spawns BOTH an SQLi
     probe (on `q`) AND an open-redirect probe (on `url`).
  3. RETURNS those candidates in the exact tuple shape `verify_phase`
     consumes, so they UNION naturally with `_SEED_PROBES`.

Scope authority: the `scope_filter(url)->bool` callable passed to
`discover_candidates()` is THE authority. The crawler also uses it via
the adapter (fail-closed on exception). Same callable verify_phase uses
for its own scope gate — single source of truth, no drift.

Determinism: same target+filter → same candidates. The classifier is
pure; the crawler is BFS with sorted enqueuing.
"""
from __future__ import annotations

import logging
from typing import Callable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

logger = logging.getLogger(__name__)


# ────────────────────────── classification hints ───────────────────────────
#
# These mirror the hint sets the verifier already uses internally
# (vuln_verifier._URL_PARAM_HINTS for SSRF). Keeping them HERE in the
# discovery layer (vs. importing from the verifier) is intentional: this
# module decides "what KIND of probe a URL deserves"; the verifier decides
# "how to actually confirm" each probe class. Two responsibilities, two
# locations.

# Query-param names that strongly suggest the value will be FETCHED or
# REDIRECTED-TO by the server → both open_redirect AND ssrf candidates.
_URL_LIKE_PARAMS = {
    "url", "href", "redirect", "redirecturl", "next", "target",
    "src", "source", "dest", "destination", "endpoint", "host",
    "fetch", "load", "image", "icon", "proxy", "callback", "return",
    "returnurl", "returnto", "goto", "link", "uri", "resource", "to",
}

# Query-param names that suggest the value will be USED AS A FILE PATH
# → path traversal candidates.
_FILE_LIKE_PARAMS = {
    "file", "filename", "filepath", "path", "page", "doc", "document",
    "include", "template", "view", "load", "page_name", "name",
    "asset", "static", "download",
}


def _is_id_segment(seg: str) -> bool:
    """A path segment is ID-shaped if it's purely numeric or UUID-shaped.

    This mirrors `VulnVerifier._inject_path_segment`'s detection so we
    only emit IDOR candidates for URLs the verifier can actually mutate.
    """
    if not seg:
        return False
    if seg.isdigit():
        return True
    # UUID: 32-char hex (no dashes) or 36-char dashed
    if len(seg) in (32, 36) and all(c in "0123456789abcdefABCDEF-" for c in seg):
        return True
    return False


def classify_url(url: str) -> List[Tuple[str, str, str]]:
    """Pure function — given one URL, return all probe candidates it implies.

    Returns a list of `(url, label, vuln_class)` tuples in the EXACT shape
    `verify_phase.seed_candidates()` already produces. Empty list means
    "this URL has nothing the verifier can chew on" (no query params, no
    ID segment).

    A URL can yield MULTIPLE candidates — that's the whole point of doing
    this in the discovery layer rather than letting verify_phase do
    single-class probing per URL.
    """
    out: List[Tuple[str, str, str]] = []
    try:
        parsed = urlparse(url)
    except Exception:
        return out
    if not parsed.scheme or not parsed.netloc:
        return out

    host = parsed.netloc
    params = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
    has_query = bool(params)

    # 1. Any URL with at least one query param is a SQLi candidate.
    #    The verifier walks each param; we don't have to enumerate here.
    if has_query:
        out.append((url, f"disc-sqli@{host}{parsed.path}", "sqli"))

    # 2. URL-shaped params → open_redirect + ssrf. Two distinct classes
    #    because the confirmation logic differs (Location header vs.
    #    fetched-canary body marker).
    url_params = [p for p in params if p.lower().strip("_-[]") in _URL_LIKE_PARAMS]
    if url_params:
        out.append((url, f"disc-redirect@{host}{parsed.path}", "open_redirect"))
        out.append((url, f"disc-ssrf@{host}{parsed.path}", "ssrf"))

    # 3. File/path-shaped params → path_traversal.
    file_params = [p for p in params if p.lower().strip("_-[]") in _FILE_LIKE_PARAMS]
    if file_params:
        out.append((url, f"disc-traversal@{host}{parsed.path}", "path_traversal"))

    # 4. Numeric / UUID terminal path segment → IDOR. The verifier's
    #    _inject_path_segment walks the LAST id-shaped segment, so we
    #    require the terminal segment specifically.
    path_parts = [p for p in (parsed.path or "/").split("/") if p]
    if path_parts and _is_id_segment(path_parts[-1]):
        out.append((url, f"disc-idor@{host}{parsed.path}", "idor"))

    return out


def classify_urls(
    urls: List[str],
    scope_filter: Optional[Callable[[str], bool]] = None,
    max_candidates: int = 200,
) -> List[Tuple[str, str, str]]:
    """Run `classify_url` over a batch with dedup + scope + cap.

    Dedup is on the (url, vuln_class) pair — same URL classified under
    different vuln classes is intentional (a redirect-shaped query URL
    is BOTH a redirect probe AND an SQLi probe; we want both probes).
    """
    seen: set[Tuple[str, str]] = set()
    out: List[Tuple[str, str, str]] = []
    for u in urls:
        if scope_filter is not None:
            try:
                if not scope_filter(u):
                    continue
            except Exception:
                # Fail-closed: same authority semantics as verify_phase's
                # own scope gate. An exception is NOT-IN-SCOPE.
                continue
        for cand in classify_url(u):
            key = (cand[0], cand[2])
            if key in seen:
                continue
            seen.add(key)
            out.append(cand)
            if len(out) >= max_candidates:
                return out
    return out


# ──────────────────────────── crawler adapters ─────────────────────────────
#
# The core/web/HttpCrawler is the existing battle-tested crawler. It expects
# an ExecutionPolicy (sync http_get + assert_url_allowed) and an EventBus.
# We don't need the full WebOrchestrator's mutation/evidence pipeline — we
# just want URL discovery. So we provide MINIMAL adapters:
#
#   _ScopeOnlyPolicy: http_get via a regular httpx client, scope check via
#     the caller's scope_filter callable (fail-closed).
#   _NullEventBus: drops all events (we don't emit during discovery).
#
# This keeps the discovery surface dependency-light while still reusing
# the crawler's HTML parsing, BFS, and SurfaceRegistry dedup.


class _NullEventBus:
    """Drops all events. Discovery doesn't need event emission — the
    verifier emits its own findings, and we don't care about WEB_*
    telemetry here."""

    def emit(self, event):  # noqa: D401
        return


class _ScopeOnlyPolicy:
    """Minimal `ExecutionPolicy` adapter for HttpCrawler.

    Two responsibilities:
      * `assert_url_allowed`: delegate to the caller's scope_filter. Fail
        CLOSED on exceptions (consistent with verify_phase's own gate).
      * `http_get`: ordinary httpx GET with a small timeout.

    Deliberately does NOT touch authentication, cookies, custom headers,
    or rate limits. Discovery is anonymous + best-effort; auth-gated
    pages will simply return 401/403 and yield no links to follow.
    """

    def __init__(
        self,
        scope_filter: Optional[Callable[[str], bool]],
        timeout: float = 10.0,
        user_agent: str = "SentinelForge/discovery",
    ):
        self._scope_filter = scope_filter
        self._timeout = timeout
        self._ua = user_agent

    def assert_url_allowed(self, mission, url: str) -> None:
        if self._scope_filter is None:
            return  # No filter → all URLs allowed (caller's choice).
        try:
            allowed = bool(self._scope_filter(url))
        except Exception:
            from core.web.contracts.errors import ScopeViolation
            raise ScopeViolation(f"scope filter raised on {url!r}; fail-closed")
        if not allowed:
            from core.web.contracts.errors import ScopeViolation
            raise ScopeViolation(f"url {url!r} out of scope")

    def http_get(self, mission, ctx, url: str, headers=None):
        # HttpCrawler is sync, so we use a sync httpx client here. The
        # caller of `discover_candidates()` runs the whole crawl inside
        # an executor thread so this doesn't block the asyncio loop.
        import httpx

        req_headers = {"User-Agent": self._ua}
        if headers:
            req_headers.update(headers)
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=True) as client:
                resp = client.get(url, headers=req_headers)
        except Exception as e:
            # Return a synthetic (502, {}, b"") tuple — the crawler
            # tolerates non-200 bodies (just gets no links to parse).
            logger.debug(
                f"[discovery] http_get failed on {url!r}: {type(e).__name__}: {e}"
            )
            return (502, {}, b"")
        return (resp.status_code, {k: v for k, v in resp.headers.items()}, resp.content)


def _build_mission(target_url: str, *, max_depth: int, max_pages: int):
    """Build the WebMission the HttpCrawler needs from a bare target URL.

    `WebMission` is a Pydantic model with mission/scan/session IDs typed
    as `SentinelId` wrappers (BaseModel(value=str) with a regex constraint:
    lowercase [a-z0-9][a-z0-9\\-_:]{7,127}). uuid4().hex is 32 lowercase
    hex chars — fits the regex; we wrap it in the proper ID models.

    `allowed_origins` is required and seeded from the target's origin so
    the crawler's own origin-constraint check keeps us on-host.
    """
    import uuid
    from core.web.contracts.ids import MissionId, ScanId, SessionId
    from core.web.contracts.models import WebMission

    parsed = urlparse(target_url if "://" in target_url else "http://" + target_url)
    if not parsed.netloc:
        raise ValueError(f"target lacks a host: {target_url!r}")
    origin = f"{parsed.scheme}://{parsed.netloc}"

    return WebMission(
        mission_id=MissionId(value=uuid.uuid4().hex),
        scan_id=ScanId(value=uuid.uuid4().hex),
        session_id=SessionId(value=uuid.uuid4().hex),
        origin=origin,  # type: ignore[arg-type]
        allowed_origins=[origin],
        max_depth=max_depth,
        max_pages=max_pages,
    )


def _build_context():
    """Minimal WebContext for the crawler. Anonymous principal."""
    from core.web.context import WebContext
    from core.web.contracts.ids import PrincipalId

    return WebContext(principal_id=PrincipalId(value="discovery-anon-principal"))


# ──────────────────────────── async top-level ──────────────────────────────


async def discover_candidates(
    target: str,
    scope_filter: Optional[Callable[[str], bool]] = None,
    *,
    max_depth: int = 2,
    max_pages: int = 50,
    max_candidates: int = 200,
    timeout: float = 10.0,
) -> List[Tuple[str, str, str]]:
    """Crawl `target`, classify discovered URLs, return verify_phase tuples.

    Returns `(url, label, vuln_class)` tuples ready for verify_phase's probe
    loop. Empty list on any failure — discovery is BEST EFFORT and must never
    raise (the verify phase will still run seed-based probes).

    Runs the sync HttpCrawler inside an executor thread so it doesn't
    block the asyncio event loop. The thread completes when the crawl
    does (bounded by max_depth/max_pages/scope).
    """
    import asyncio

    def _do_crawl() -> List[str]:
        # Imports inside the executor to keep import overhead off the
        # async path when discovery is disabled.
        from core.web.crawler import HttpCrawler
        from core.web.surface_registry import SurfaceRegistry

        try:
            mission = _build_mission(target, max_depth=max_depth, max_pages=max_pages)
        except Exception as e:
            logger.warning(
                f"[discovery] mission build failed for {target!r}: "
                f"{type(e).__name__}: {e}"
            )
            return []
        ctx = _build_context()
        policy = _ScopeOnlyPolicy(scope_filter=scope_filter, timeout=timeout)
        bus = _NullEventBus()
        registry = SurfaceRegistry()
        crawler = HttpCrawler(policy=policy, bus=bus)  # type: ignore[arg-type]

        try:
            crawler.crawl(mission, ctx, registry)
        except Exception as e:
            # Even on crawl failure, we may have partial registry data
            # — surface whatever we got rather than empty-out.
            logger.warning(
                f"[discovery] crawl aborted on {target!r}: "
                f"{type(e).__name__}: {e}"
            )

        urls, _assets, endpoints = registry.snapshot()
        # Also collect URLs off endpoint candidates — forms, JS-discovered
        # endpoints etc. contribute here even when no `<a href>` linked them.
        all_urls = list(urls)
        for e in endpoints:
            try:
                all_urls.append(str(e.url))
            except Exception:
                continue
        # Dedup while preserving order (stable across runs).
        seen = set()
        out = []
        for u in all_urls:
            if u in seen:
                continue
            seen.add(u)
            out.append(u)
        return out

    try:
        loop = asyncio.get_running_loop()
        urls = await loop.run_in_executor(None, _do_crawl)
    except Exception as e:
        logger.warning(
            f"[discovery] executor wrap failed: {type(e).__name__}: {e}"
        )
        return []

    candidates = classify_urls(urls, scope_filter=scope_filter, max_candidates=max_candidates)
    logger.info(
        f"[discovery] {target!r} → {len(urls)} URL(s) discovered → "
        f"{len(candidates)} probe candidate(s)"
    )
    return candidates
