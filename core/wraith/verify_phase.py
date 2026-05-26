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
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    per_probe_budget: int = 4,
    max_candidates: int = 60,
    max_hosts: int = 5,
) -> List[Dict[str, Any]]:
    """Run VulnVerifier against seed candidates; return finding dicts.

    The returned dicts are shaped to match what FindingsStore.bulk_add()
    consumes so the caller can persist them in one call.
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

    verifier = VulnVerifier(session)
    engine = MutationEngine()
    confirmed: List[Dict[str, Any]] = []
    probes_total = 0

    logger.info(f"[verify_phase] probing {len(candidates)} candidates")
    try:
        for url, label, vc_name in candidates:
            vc = vc_map.get(vc_name, VulnerabilityClass.GENERIC)
            try:
                results, probes = await verifier.verify_finding(
                    engine=engine,
                    finding={},
                    url=url,
                    vuln_class=vc,
                    headers=headers or {},
                    cookies=cookies or {},
                    budget=per_probe_budget,
                )
                probes_total += int(probes or 0)
            except Exception as e:
                logger.warning(
                    f"[verify_phase] {label} probe errored on {url}: "
                    f"{type(e).__name__}: {e}"
                )
                continue
            for confidence, evidence, payload, kind in results or []:
                evidence_str = evidence if isinstance(evidence, str) else str(evidence)
                finding_id = f"verified-{kind.lower()}-{abs(hash((url, payload))) % 1_000_000}"
                confirmed.append({
                    "id": finding_id,
                    "type": f"{kind} (active verification)",
                    "severity": "HIGH",
                    "tool": "vuln_verifier",
                    "target": url,
                    "message": (
                        f"{kind} confirmed on {url} "
                        f"(confidence={float(confidence):.2f}, payload={payload!r})"
                    ),
                    "proof": evidence_str[:500],
                    "tags": ["verified", "active_test", label],
                    "families": ["confirmed_vuln"],
                    "metadata": {
                        "vuln_class": kind,
                        "confidence": float(confidence),
                        "payload": payload,
                        "probe_label": label,
                        "probes_sent": int(probes or 0),
                    },
                })
                logger.info(
                    f"[verify_phase] CONFIRMED {kind} on {url} "
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
        f"{len(candidates)} candidates ({probes_total} probes total)"
    )
    return confirmed
