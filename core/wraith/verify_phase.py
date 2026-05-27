"""
core/wraith/verify_phase.py

Phase 3 active-verification phase (Run #26).

After recon completes, this phase probes a curated set of well-known
parameterized endpoints on each in-scope host using the fixed VulnVerifier.
Confirmations are returned as finding dicts ready for FindingsStore.bulk_add.

Design choices:
  - SEED-based candidate generation (not crawl-based — yet). A short list of
    classic injection / IDOR / redirect / traversal probe paths covers the
    common cases without depending on a crawler. Crawler-driven discovery
    is the next layer (Phase 3 step 3).
  - SCOPE-respecting. The caller passes a scope_filter callable (typically
    bound to the scan's ScopeContext.registry); out-of-scope candidates are
    dropped before any probe goes out — same authority the scan uses for tools.
  - BUDGET-bounded. max_hosts × len(_SEED_PROBES) × per_probe_budget caps
    the absolute number of HTTP requests this phase can emit.
  - FAULT-isolated. A probe error on one candidate logs + continues; one
    bad target never kills the whole phase.
  - DETERMINISTIC. Same targets+filter → same candidates → testable.

Auth-gated classes (IDOR, multi-principal) are deferred to a follow-up
that wires personas/credentials in. SQLi / PathTraversal / OpenRedirect /
GENERIC all work unauthenticated and are covered here.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# (path, label, vuln_class) — paths chosen because they're either RFC-common
# parameterized API shapes or specifically present on calibration targets
# (e.g. /rest/products/search for OWASP Juice Shop). The `sentinel_probe`
# query value is a benign sentinel so logs on the target identify our probes.
#
# IDOR probes use path-segment numeric IDs because VulnVerifier._confirm_idor
# enumerates the LAST numeric/UUID segment via _inject_path_segment — so the
# bare /N at the end is what triggers it. With an authenticated persona,
# these probes test horizontal-IDOR (can identity X see identity Y's object).
_SEED_PROBES: List[Tuple[str, str, str]] = [
    ("/?q=sentinel_probe",                       "root-q",                 "sqli"),
    ("/?id=1",                                   "root-id",                "sqli"),
    ("/?search=sentinel_probe",                  "root-search",            "sqli"),
    ("/search?q=sentinel_probe",                 "search-q",               "sqli"),
    ("/api/search?q=sentinel_probe",             "api-search",             "sqli"),
    ("/api/products?q=sentinel_probe",           "api-products",           "sqli"),
    ("/api/products/search?q=sentinel_probe",    "api-products-search",    "sqli"),
    ("/rest/products/search?q=sentinel_probe",   "rest-products-search",   "sqli"),
    ("/rest/products?q=sentinel_probe",          "rest-products",          "sqli"),
    ("/rest/user?id=1",                          "rest-user-id",           "sqli"),
    ("/users?id=1",                              "users-id",               "sqli"),
    ("/redirect?url=http://evil.example.com",    "redirect-url",           "open_redirect"),
    ("/login?next=http://evil.example.com",      "login-next",             "open_redirect"),
    ("/?file=../../../etc/passwd",               "file-traversal",         "path_traversal"),
    # IDOR path-segment shapes — only meaningful with an authenticated persona.
    # Juice Shop /rest/basket/{N} is the canonical IDOR case (any logged-in
    # user can access any basket by ID).
    ("/rest/basket/1",                           "rest-basket-id",         "idor"),
    ("/api/users/1",                             "api-users-id",           "idor"),
    ("/api/orders/1",                            "api-orders-id",          "idor"),
    ("/api/profile/1",                           "api-profile-id",         "idor"),
]


def _base_for(target: str) -> Optional[str]:
    """Normalize a target into a scheme+netloc base, or None if unusable."""
    if not target:
        return None
    s = target.strip()
    parsed = urlparse(s if "://" in s else "http://" + s)
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def seed_candidates(
    targets: Iterable[str],
    scope_filter: Optional[Callable[[str], bool]] = None,
    max_hosts: int = 5,
) -> List[Tuple[str, str, str]]:
    """Build deterministic (url, label, vuln_class) candidates from targets.

    Each unique host gets the full _SEED_PROBES set, optionally filtered by
    a scope_filter(url) -> bool callable. Order is stable (input order for
    hosts, fixed for probes) so tests can pin output.
    """
    out: List[Tuple[str, str, str]] = []
    seen: set[str] = set()
    for target in targets:
        base = _base_for(target)
        if not base or base in seen:
            continue
        if len(seen) >= max_hosts:
            break
        seen.add(base)
        for path, label, vc in _SEED_PROBES:
            url = base + path
            if scope_filter is not None:
                try:
                    if not scope_filter(url):
                        continue
                except Exception:
                    # An exception in the scope filter is treated as
                    # NOT-IN-SCOPE (fail closed) — never probe a URL we
                    # couldn't authoritatively confirm in-scope.
                    continue
            out.append((url, label, vc))
    return out


async def run_verify_phase(
    session,
    targets: Iterable[str],
    scope_filter: Optional[Callable[[str], bool]] = None,
    personas: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    per_probe_budget: int = 4,
    max_candidates: int = 60,
    max_hosts: int = 5,
) -> List[Dict[str, Any]]:
    """Run VulnVerifier against seed candidates; return finding dicts.

    The returned dicts are shaped to match what FindingsStore.bulk_add()
    consumes so the caller can persist them in one call.

    Persona handling (Run #26 step 3):
      - If `personas` is given, each is authenticated (best-effort; failures
        fall back to anonymous probing for that persona) and used as a
        distinct identity context. Probes for each candidate run once per
        identity, with that identity's headers/cookies. This is what makes
        IDOR + authenticated-SQLi reachable.
      - Without `personas`, a single anonymous identity is used (the `headers`
        and `cookies` args, defaulting to empty).
      - Findings record which persona triggered confirmation
        (`metadata.persona`) so the report/AI can attribute correctly.
    """
    from core.web.contracts.enums import VulnerabilityClass
    from core.wraith.mutation_engine import MutationEngine
    from core.wraith.vuln_verifier import VulnVerifier

    candidates = seed_candidates(targets, scope_filter=scope_filter, max_hosts=max_hosts)[:max_candidates]
    if not candidates:
        logger.info("[verify_phase] no in-scope candidates; skipping")
        return []

    vc_map = {
        "sqli": VulnerabilityClass.SQLI,
        "xss": VulnerabilityClass.XSS,
        "idor": VulnerabilityClass.IDOR,
        "ssrf": VulnerabilityClass.SSRF,
        "path_traversal": VulnerabilityClass.PATH_TRAVERSAL,
        "open_redirect": VulnerabilityClass.OPEN_REDIRECT,
        "generic": VulnerabilityClass.GENERIC,
    }

    # Build identity contexts. List of (name, headers, cookies) tuples.
    identity_contexts: List[Tuple[str, Dict[str, str], Dict[str, str]]] = []
    if personas:
        from core.wraith.persona_auth import authenticate_persona
        for p in personas:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "anon")
            try:
                p_headers, p_cookies = await authenticate_persona(p)
            except Exception as e:
                logger.warning(
                    f"[verify_phase] persona {name!r} auth failed: "
                    f"{type(e).__name__}: {e} — falling back to anonymous for this identity"
                )
                p_headers, p_cookies = {}, {}
            identity_contexts.append((name, p_headers, p_cookies))
    if not identity_contexts:
        identity_contexts.append(("anonymous", headers or {}, cookies or {}))

    verifier = VulnVerifier(session)
    engine = MutationEngine()
    confirmed: List[Dict[str, Any]] = []
    probes_total = 0

    logger.info(
        f"[verify_phase] probing {len(candidates)} candidate(s) "
        f"with {len(identity_contexts)} identity context(s)"
    )
    try:
        for identity_name, id_headers, id_cookies in identity_contexts:
            authed = bool(id_headers) or bool(id_cookies)
            for url, label, vc_name in candidates:
                vc = vc_map.get(vc_name, VulnerabilityClass.GENERIC)
                # IDOR probes only make sense authenticated — skip unauthenticated
                # IDOR probes (would just confirm "logged-out user can't see basket").
                if vc_name == "idor" and not authed:
                    continue
                try:
                    results, probes = await verifier.verify_finding(
                        engine=engine,
                        finding={},
                        url=url,
                        vuln_class=vc,
                        headers=id_headers,
                        cookies=id_cookies,
                        budget=per_probe_budget,
                    )
                    probes_total += int(probes or 0)
                except Exception as e:
                    logger.warning(
                        f"[verify_phase] {label} probe errored on {url} "
                        f"(persona={identity_name!r}): {type(e).__name__}: {e}"
                    )
                    continue
                for confidence, evidence, payload, kind in results or []:
                    evidence_str = evidence if isinstance(evidence, str) else str(evidence)
                    finding_id = (
                        f"verified-{kind.lower()}-"
                        f"{abs(hash((url, payload, identity_name))) % 1_000_000}"
                    )
                    confirmed.append({
                        "id": finding_id,
                        "type": f"{kind} (active verification)",
                        "severity": "HIGH",
                        "tool": "vuln_verifier",
                        "target": url,
                        "message": (
                            f"{kind} confirmed on {url} as persona={identity_name!r} "
                            f"(confidence={float(confidence):.2f}, payload={payload!r})"
                        ),
                        "proof": evidence_str[:500],
                        "tags": ["verified", "active_test", label,
                                 f"persona:{identity_name}"],
                        "families": ["confirmed_vuln"],
                        "metadata": {
                            "vuln_class": kind,
                            "confidence": float(confidence),
                            "payload": payload,
                            "probe_label": label,
                            "probes_sent": int(probes or 0),
                            "persona": identity_name,
                            "authenticated": authed,
                        },
                    })
                    logger.info(
                        f"[verify_phase] CONFIRMED {kind} on {url} "
                        f"as persona={identity_name!r} "
                        f"via payload={payload!r} (conf={confidence})"
                    )
    finally:
        close = getattr(engine, "close", None)
        if callable(close):
            try:
                await close()
            except Exception:
                pass

    logger.info(
        f"[verify_phase] complete: {len(confirmed)} confirmed across "
        f"{len(candidates)} candidates × {len(identity_contexts)} identity "
        f"context(s) ({probes_total} probes total)"
    )
    return confirmed
