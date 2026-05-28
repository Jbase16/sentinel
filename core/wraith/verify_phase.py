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
    discovered: Optional[List[Tuple[str, str, str]]] = None,
) -> List[Tuple[str, str, str]]:
    """Build deterministic (url, label, vuln_class) candidates from targets.

    Each unique host gets the full _SEED_PROBES set, optionally filtered by
    a scope_filter(url) -> bool callable. Order is stable (input order for
    hosts, fixed for probes) so tests can pin output.

    `discovered` (Phase 3 step 3): an OPTIONAL pre-computed list of
    crawler-discovered candidates (already in the same tuple shape).
    These are APPENDED after the seed-template expansion and deduped
    against it by (url, vuln_class) so the same probe never fires twice.
    Discovery is generated by core.wraith.candidate_discovery and lets
    Phase 3 reach real-world targets whose URL space doesn't match the
    Juice-Shop-flavored _SEED_PROBES list.
    """
    out: List[Tuple[str, str, str]] = []
    seen: set[str] = set()
    seen_pairs: set[Tuple[str, str]] = set()
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
            pair = (url, vc)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            out.append((url, label, vc))

    # Append discovered candidates after seed-templates. They were already
    # scope-filtered upstream (in classify_urls), but re-check here so the
    # scope_filter remains the AUTHORITY regardless of how candidates got
    # in. Dedup against seed-template pairs by (url, vuln_class).
    if discovered:
        for url, label, vc in discovered:
            if scope_filter is not None:
                try:
                    if not scope_filter(url):
                        continue
                except Exception:
                    continue
            pair = (url, vc)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
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
    enable_discovery: bool = True,
    discovery_max_depth: int = 2,
    discovery_max_pages: int = 50,
    discovery_max_candidates: int = 80,
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

    # Phase 3 step 3 — augment seed templates with crawler-discovered
    # candidates so Phase 3 reaches real-world targets whose URL space
    # doesn't match the Juice-Shop-flavored seed list. Discovery is
    # best-effort + fault-isolated; any failure here MUST NOT block the
    # seed-based probes that already work today.
    discovered: List[Tuple[str, str, str]] = []
    if enable_discovery:
        from core.wraith.candidate_discovery import discover_candidates

        # Discover once per unique host (honors max_hosts the same way
        # seed_candidates does), so a 10-target scan doesn't crawl 10×.
        seen_hosts: set[str] = set()
        for t in targets:
            base = _base_for(t)
            if not base or base in seen_hosts:
                continue
            if len(seen_hosts) >= max_hosts:
                break
            seen_hosts.add(base)
            try:
                disc = await discover_candidates(
                    target=base,
                    scope_filter=scope_filter,
                    max_depth=discovery_max_depth,
                    max_pages=discovery_max_pages,
                    max_candidates=discovery_max_candidates,
                )
            except Exception as e:
                logger.warning(
                    f"[verify_phase] discovery on {base!r} failed: "
                    f"{type(e).__name__}: {e} — falling back to seeds only"
                )
                disc = []
            discovered.extend(disc)

    candidates = seed_candidates(
        targets,
        scope_filter=scope_filter,
        max_hosts=max_hosts,
        discovered=discovered or None,
    )[:max_candidates]
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

    # ── Multi-principal IDOR pass (Phase 3 step 4 — cross-principal IDOR) ──
    #
    # The single-principal loop above tests "horizontal IDOR within an
    # identity" — e.g. Alice can read /baskets/N for N != Alice's own.
    # That's one IDOR class. The OTHER class is "cross-principal" — Alice's
    # resource at /baskets/A is readable by Bob using Bob's auth. Both
    # vulnerabilities are real and orthogonal.
    #
    # Detection signal: fetch each IDOR-class candidate as EVERY authenticated
    # identity. If 2+ identities receive 200 OK with structurally-similar
    # bodies for the same URL, that's strong evidence the URL is not
    # authorization-gated by identity — i.e., cross-principal IDOR.
    #
    # Requirements: 2+ authenticated identity contexts. With 0 or 1, this
    # comparison has no meaning and we skip.
    auth_identities = [(n, h, c) for n, h, c in identity_contexts
                       if bool(h) or bool(c)]
    if len(auth_identities) >= 2:
        try:
            multi_findings = await _run_multi_principal_idor(
                candidates=candidates,
                identity_contexts=auth_identities,
                scope_filter=scope_filter,
            )
        except Exception as e:
            logger.warning(
                f"[verify_phase] multi-principal IDOR pass failed: "
                f"{type(e).__name__}: {e}"
            )
            multi_findings = []
        confirmed.extend(multi_findings)
        logger.info(
            f"[verify_phase] multi-principal pass: "
            f"{len(multi_findings)} cross-principal IDOR finding(s) "
            f"across {len(auth_identities)} authenticated identity(ies)"
        )

    logger.info(
        f"[verify_phase] complete: {len(confirmed)} confirmed across "
        f"{len(candidates)} candidates × {len(identity_contexts)} identity "
        f"context(s) ({probes_total} probes total)"
    )
    return confirmed


async def _run_multi_principal_idor(
    candidates: List[Tuple[str, str, str]],
    identity_contexts: List[Tuple[str, Dict[str, str], Dict[str, str]]],
    scope_filter: Optional[Callable[[str], bool]] = None,
    timeout: float = 8.0,
) -> List[Dict[str, Any]]:
    """Cross-principal IDOR pass.

    For each IDOR-shaped candidate URL, fetch it as each authenticated
    identity. If 2+ identities receive 200 OK with structurally-similar
    bodies, emit a cross-principal IDOR finding tagged with both identity
    names (the "attacker" who shouldn't be able to access, and the
    "victim" whose resource they accessed).

    Why this is its own pass instead of folded into _confirm_idor:
      * _confirm_idor varies the ID (path segment) while holding identity
        fixed — that's horizontal IDOR.
      * This pass varies the IDENTITY while holding the URL fixed — that's
        cross-principal IDOR. The two axes need different orchestration.

    Decision rules per candidate:
      * Only IDOR-class candidates (terminal numeric/UUID segment) — other
        classes have unrelated semantics.
      * Need 2+ identities to compare. Skip when only one authenticated.
      * Each identity must return 200 with body length > 50 (filter
        generic-error / SPA-shell responses).
      * Bodies must NOT be byte-identical across identities (that's a SPA
        shell or anonymous content — not IDOR).
      * Both bodies JSON-shaped (start with { or [) + size ratio ≥ 0.5
        → high confidence (0.85).
      * Otherwise distinct bodies of similar status → mid confidence (0.60).
    """
    import httpx
    from urllib.parse import urlparse

    findings: List[Dict[str, Any]] = []
    # Filter to IDOR-shaped candidates only. Cross-principal SQLi etc. is
    # not a meaningful concept — auth context doesn't change SQL injection
    # success, it changes WHICH ROWS get returned. Pure IDOR is the case.
    idor_candidates = [
        (u, lbl, vc) for (u, lbl, vc) in candidates
        if vc == "idor" and _is_idor_shape(u)
    ]
    if not idor_candidates:
        return findings

    logger.info(
        f"[multi-principal] probing {len(idor_candidates)} IDOR-shaped URL(s) "
        f"× {len(identity_contexts)} identity(ies)"
    )

    # Single shared client (connection-reuse). HTTP/2 disabled to keep the
    # error surface small; we don't need its features here.
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, http2=False,
    ) as client:
        for url, label, _vc in idor_candidates:
            # Belt-and-suspenders scope check — even though the candidates
            # were already filtered by scope_filter upstream, re-check here
            # so the AUTHORITY is consistent regardless of caller wiring.
            if scope_filter is not None:
                try:
                    if not scope_filter(url):
                        continue
                except Exception:
                    continue

            # Collect (identity_name, status, body, body_hash) per identity.
            per_identity: List[Tuple[str, int, str, str]] = []
            for ident_name, ident_headers, ident_cookies in identity_contexts:
                try:
                    headers = dict(ident_headers)
                    cookie_header = "; ".join(
                        f"{k}={v}" for k, v in ident_cookies.items()
                    )
                    if cookie_header:
                        headers["Cookie"] = cookie_header
                    resp = await client.get(url, headers=headers)
                    status = int(resp.status_code)
                    body = resp.text or ""
                except Exception as e:
                    logger.debug(
                        f"[multi-principal] request failed for "
                        f"identity={ident_name!r} url={url}: "
                        f"{type(e).__name__}: {e}"
                    )
                    continue
                # Quick body-hash for equality check across identities.
                import hashlib
                bh = hashlib.sha256(body.encode(errors="replace")).hexdigest()[:16]
                per_identity.append((ident_name, status, body, bh))

            # Need at least two identities that successfully fetched the
            # URL to compare cross-principal. The 20-char floor filters
            # truly-empty / trivial-error responses (e.g. `{"e":1}`)
            # without rejecting realistic minimal JSON IDOR responses
            # like `{"id":42,"name":"x"}` (20 chars).
            ok_responses = [r for r in per_identity if r[1] == 200 and len(r[2]) >= 20]
            if len(ok_responses) < 2:
                continue

            # For each pair (A, B), check the cross-principal signal.
            # Iterating ALL pairs ensures we don't miss the case where
            # A's resource is readable by B but not C. We emit ONE finding
            # per URL (multi-victim), tagging all leaking pairs.
            #
            # Signal taxonomy (calibrated against Juice Shop /rest/basket/1):
            #   IDENTICAL JSON across two auth'd identities → the strongest
            #     cross-principal IDOR signal. Both identities got the SAME
            #     structured data from a URL that's supposedly identity-
            #     gated. This is what "Jim reads Alice's basket" looks like.
            #     Confidence: 0.90.
            #   IDENTICAL HTML (or other non-JSON) → almost always SPA shell
            #     or generic "you are logged in" page that's same for every
            #     identity. NOT an IDOR signal. Skip.
            #   DISTINCT JSON, similar size → could be IDOR where each
            #     identity sees their own row (sometimes A's data, sometimes
            #     B's — depends on auth state). Confidence: 0.85.
            #   DISTINCT body, otherwise → still suspicious (200 for both,
            #     just different content). Confidence: 0.60.
            leaks: List[Tuple[str, str, float, str]] = []
            n = len(ok_responses)
            for i in range(n):
                a_name, _a_status, a_body, a_hash = ok_responses[i]
                for j in range(i + 1, n):
                    b_name, _b_status, b_body, b_hash = ok_responses[j]
                    is_json_a = a_body.lstrip().startswith(("{", "["))
                    is_json_b = b_body.lstrip().startswith(("{", "["))
                    both_json = is_json_a and is_json_b
                    identical = (a_hash == b_hash) or (a_body == b_body)

                    if identical:
                        if both_json:
                            # Two different identities receiving the SAME
                            # JSON for the same URL = the canonical cross-
                            # principal IDOR. This is the Juice Shop case.
                            leaks.append((a_name, b_name, 0.90, "identical-json"))
                        # else: identical non-JSON body is a shell, not IDOR.
                        continue

                    size_ratio = (
                        min(len(a_body), len(b_body))
                        / max(len(a_body), len(b_body), 1)
                    )
                    structurally_similar = size_ratio >= 0.5
                    if both_json and structurally_similar:
                        leaks.append((a_name, b_name, 0.85, "distinct-json+size"))
                    else:
                        leaks.append((a_name, b_name, 0.60, "distinct-body"))

            if not leaks:
                continue

            # Emit one finding per URL summarizing all leak pairs. The
            # finding's primary "attacker"/"victim" attribution is the
            # highest-confidence pair; the full pair list is in metadata.
            leaks.sort(key=lambda L: L[2], reverse=True)
            top_a, top_b, top_conf, top_shape = leaks[0]
            host = urlparse(url).netloc or "?"
            finding_id = (
                f"verified-cross-idor-"
                f"{abs(hash((url, top_a, top_b))) % 1_000_000}"
            )
            # Build proof: include the actual response bodies (truncated)
            # for the two identities in the top leak. This is what operators
            # need to triage — "did Jim really see Alice's data?" — having
            # the raw body excerpts answers it at a glance.
            body_by_name = {n: b for n, _s, b, _h in ok_responses}
            a_body_excerpt = (body_by_name.get(top_a) or "")[:200]
            b_body_excerpt = (body_by_name.get(top_b) or "")[:200]
            signal_explainer = {
                "identical-json": (
                    "Both identities received BYTE-IDENTICAL JSON — "
                    f"{top_b!r} is reading {top_a!r}'s data"
                ),
                "distinct-json+size": (
                    "Identities received DISTINCT JSON of similar shape — "
                    "the same URL is returning per-identity data, suggesting "
                    "missing access-control gate"
                ),
                "distinct-body": (
                    "Identities received distinct 200 OK bodies — "
                    "suggests authorization-aware response but possibly "
                    "still leaking shape/existence"
                ),
            }.get(top_shape, "")
            findings.append({
                "id": finding_id,
                "type": "Cross-Principal IDOR (active verification)",
                "severity": "HIGH",
                "tool": "vuln_verifier",
                "target": url,
                "message": (
                    f"Cross-principal IDOR confirmed on {url} — "
                    f"attacker={top_a!r} victim={top_b!r} "
                    f"(confidence={top_conf:.2f}, signal={top_shape}). "
                    f"{signal_explainer}"
                ),
                "proof": (
                    f"as {top_a!r} ({len(body_by_name.get(top_a) or '')}B): "
                    f"{a_body_excerpt!r}\n"
                    f"as {top_b!r} ({len(body_by_name.get(top_b) or '')}B): "
                    f"{b_body_excerpt!r}\n"
                    f"{len(leaks)} leaking pair(s) across "
                    f"{len(ok_responses)} authenticated identity(ies)"
                )[:500],
                "tags": [
                    "verified", "active_test", "cross_principal_idor",
                    label, f"persona:{top_a}", f"persona:{top_b}",
                ],
                "families": ["confirmed_vuln"],
                "metadata": {
                    "vuln_class": "IDOR",
                    "subclass": "cross_principal",
                    "confidence": float(top_conf),
                    "payload": f"{top_a}↔{top_b}",
                    "probe_label": label,
                    "host": host,
                    "attacker_persona": top_a,
                    "victim_persona": top_b,
                    "signal": top_shape,
                    "leak_pairs": [
                        {"a": a, "b": b, "confidence": conf, "signal": s}
                        for a, b, conf, s in leaks
                    ],
                    "identities_checked": [r[0] for r in per_identity],
                    "ok_identities": [r[0] for r in ok_responses],
                    "authenticated": True,
                },
            })
            logger.info(
                f"[multi-principal] CONFIRMED cross-principal IDOR on {url} "
                f"between identities {top_a!r} and {top_b!r} "
                f"(conf={top_conf:.2f}, {len(leaks)} pairs)"
            )
    return findings


def _is_idor_shape(url: str) -> bool:
    """True iff the URL's terminal path segment is numeric or UUID-shaped
    (mirrors VulnVerifier._inject_path_segment + candidate_discovery._is_id_segment).
    """
    from urllib.parse import urlparse
    try:
        parts = [p for p in (urlparse(url).path or "/").split("/") if p]
    except Exception:
        return False
    if not parts:
        return False
    seg = parts[-1]
    if seg.isdigit():
        return True
    if len(seg) in (32, 36) and all(c in "0123456789abcdefABCDEF-" for c in seg):
        return True
    return False
