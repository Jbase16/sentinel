"""
core/wraith/bola_replay.py

Capture-driven BOLA orchestrator — the generalizable engine that turns a pair of
recorded authenticated sessions (attacker + victim) into confirmed cross-tenant
BOLA findings, with NO target-specific code.

The algorithm is identical for every target — Yelp GraphQL, Whatnot GraphQL, any
REST API:

    1. Parse both captures. Auto-detect each persona's OWNED object ids
       (id-shaped values that recur across their own requests).
    2. Find the attacker's OBJECT-SCOPED operations — requests carrying an owned
       id (in a GraphQL variable or a REST path/query).
    3. For each, drive a THREE-way replay through the live transport:
         victim-baseline   — the op as the victim, with the victim's id
                              (yields the victim's private response → the markers)
         attacker-baseline — the op as the attacker, with the attacker's id
                              (the honest control: strips markers that are generic
                              or that the attacker already knows)
         attack            — the op as the attacker, with the VICTIM's id swapped in
    4. Confirm the only honest way (reusing core/wraith/bola.py): the attack is 2xx
       AND carries a victim-private marker that is absent from the attacker's own
       baseline. A bare 200, or one echoing only the attacker's own data, is NOT a
       finding.

The Yelp business ids / operation names are INPUTS, never hardcoded. Feed it two
captures and a transport; it does the rest.

The replay transport is injectable (`ReplayTransport`). Production drives the
authenticated SND / BOLA-Lab browser window (real session + CSRF + passes bot
protection); tests inject a mock. This module never places traffic itself.
"""
from __future__ import annotations

import json as _json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple

from core.wraith.bola import BolaFinding, _contains

logger = logging.getLogger(__name__)

# An id-shaped value: base64url-ish (Yelp's 22-char enc ids), long digit runs, or UUID.
_ID_SHAPE = re.compile(
    r"^(?:[A-Za-z0-9_-]{16,40}|\d{6,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
# Key names that strongly signal "this value is an object id".
_ID_KEY = re.compile(r"(?:^|_)(?:id|encid)$|id$|business|biz|owner|entity|account", re.I)

# Request headers we never replay: the browser owns them (fetch() silently drops
# "forbidden" header names anyway), and Cookie is supplied by credentials:'include'.
# Everything else — crucially the CSRF token header — is replayed verbatim.
_FORBIDDEN_REPLAY_HEADERS = frozenset({
    "host", "content-length", "connection", "cookie", "cookie2", "origin", "referer",
    "accept-encoding", "accept-charset", "date", "dnt", "expect", "keep-alive", "te",
    "trailer", "transfer-encoding", "upgrade", "via",
})


# ─────────────────────────── capture model ───────────────────────────


@dataclass
class ReplayRequest:
    """A concrete request to place through the live transport."""
    method: str
    url: str
    body: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    max_response_chars: Optional[int] = None


@dataclass
class ReplayResponse:
    status: int
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_truncated: bool = False


@dataclass
class ObjectScopedOp:
    """An attacker request that carries an owned id and is therefore a swap
    candidate. `kind` is 'graphql' (id lives in a variable) or 'rest' (id lives
    in the URL)."""
    kind: str
    label: str                    # operationName, or the URL path template
    method: str
    url: str
    op_payload: Optional[Dict[str, Any]] = None   # graphql: the single operation dict
    raw_body: Optional[str] = None                # rest / fallback
    id_where: str = ""            # human note: where the id was found
    headers: Dict[str, str] = field(default_factory=dict)   # captured request headers (CSRF, etc.)


class ReplayTransport(Protocol):
    """Places a request as a given persona and returns the response. The impl owns
    the authenticated session (a browser window per persona, an httpx client, …)."""
    async def send(self, persona: str, req: ReplayRequest) -> ReplayResponse: ...


# ─────────────────────────── parsing ───────────────────────────


def parse_capture(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize the BOLA-Lab jsonl records (url / request_body / response_body /
    type). Keeps only first-party (relative or same-site) API calls, drops the
    third-party analytics/ads/CDN noise."""
    out = []
    for r in records:
        u = r.get("url", "") or ""
        # First-party = relative URL (same-origin XHR) or an explicit yelp-family host.
        host = re.sub(r"^https?://", "", u).split("/")[0] if "://" in u else ""
        if host and "yelp.com" not in host and "." in host:
            continue  # third-party absolute URL
        out.append(r)
    return out


def _iter_gql_ops(rec: Dict[str, Any]):
    """Yield each operation dict from a /gql/batch request record."""
    rb = rec.get("request_body")
    if not rb or rb == "[Binary/FormData]" or not isinstance(rb, str):
        return
    try:
        payload = _json.loads(rb)
    except Exception:
        return
    for it in (payload if isinstance(payload, list) else [payload]):
        if isinstance(it, dict) and (it.get("operationName") or it.get("variables")):
            yield it


def extract_owned_ids(records: List[Dict[str, Any]], *, top: int = 5) -> List[str]:
    """Auto-detect a persona's owned object ids: id-shaped values that recur across
    their OWN requests (weighted toward id-ish variable keys). Returns them ranked,
    most-owned first. Generalizable — no target-specific ids."""
    weight: Dict[str, float] = {}

    def note(key: str, val: Any):
        if isinstance(val, str) and _ID_SHAPE.match(val):
            w = 2.0 if _ID_KEY.search(key or "") else 1.0
            weight[val] = weight.get(val, 0.0) + w

    def walk(o: Any, key: str = ""):
        if isinstance(o, dict):
            for k, v in o.items():
                note(k, v)
                walk(v, k)
        elif isinstance(o, list):
            for v in o:
                walk(v, key)

    for rec in records:
        for op in _iter_gql_ops(rec):
            walk(op.get("variables", {}) or {})
        # REST: ids sitting in the path (…/api/{id}/…)
        for seg in re.sub(r"^https?://[^/]+", "", rec.get("url", "") or "").split("/"):
            note("path", seg)
    return [i for i, _ in sorted(weight.items(), key=lambda kv: -kv[1])[:top]]


def _id_key_values(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Map each id-ish GraphQL variable key → {id-shaped value: count} for a persona."""
    from collections import Counter, defaultdict
    kv: Dict[str, Counter] = defaultdict(Counter)

    def walk(o: Any):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and _ID_SHAPE.match(v) and _ID_KEY.search(k):
                    kv[k][v] += 1
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    for rec in records:
        for op in _iter_gql_ops(rec):
            walk(op.get("variables", {}) or {})
    return {k: dict(c) for k, c in kv.items()}


def detect_swap_pairs(
    attacker_records: List[Dict[str, Any]], victim_records: List[Dict[str, Any]],
) -> List[Tuple[str, str, str]]:
    """The robust, generalizable owned-id detector: an object id is the value of a
    variable key that carries an id in BOTH captures but DIFFERS between them — i.e.
    the per-tenant field. Returns (key, attacker_value, victim_value), most-used
    first. Ignores ids that are identical across personas (global/shared) or that
    appear for only one persona (session/device noise) — which is what defeated the
    naive frequency heuristic."""
    a = _id_key_values(attacker_records)
    v = _id_key_values(victim_records)
    ranked: List[Tuple[int, str, str, str]] = []
    for key, avals in a.items():
        if key not in v:
            continue
        av = max(avals, key=avals.get)
        vv = max(v[key], key=v[key].get)
        if av != vv:
            ranked.append((sum(avals.values()), key, av, vv))
    ranked.sort(reverse=True)
    return [(k, av, vv) for _, k, av, vv in ranked]


def find_object_scoped_ops(
    records: List[Dict[str, Any]], attacker_id: str, *, max_ops: int = 64
) -> List[ObjectScopedOp]:
    """The attacker requests that carry `attacker_id` (and are therefore swap
    candidates). Deduped by operation label."""
    ops: List[ObjectScopedOp] = []
    seen: set = set()
    for rec in records:
        url = rec.get("url", "") or ""
        hdrs = _record_headers(rec)
        # GraphQL: id in a variable
        for op in _iter_gql_ops(rec):
            if attacker_id in _json.dumps(op.get("variables", {}) or {}):
                name = op.get("operationName") or "?"
                if name in seen:
                    continue
                seen.add(name)
                ops.append(ObjectScopedOp(
                    kind="graphql", label=name, method="POST", url=url,
                    op_payload=op, id_where="graphql variable", headers=hdrs))
        # REST: id in the path/query
        if attacker_id in url:
            path = re.sub(r"^https?://[^/]+", "", url).split("?")[0]
            tmpl = path.replace(attacker_id, "{id}")
            if tmpl in seen:
                continue
            seen.add(tmpl)
            ops.append(ObjectScopedOp(
                kind="rest", label=tmpl,
                method="POST" if rec.get("request_body") not in (None, "", "[Binary/FormData]") else "GET",
                url=url, raw_body=(rec.get("request_body") if isinstance(rec.get("request_body"), str) else None),
                id_where="url path/query", headers=hdrs))
        if len(ops) >= max_ops:
            break
    return ops


# ─────────────────────────── swap ───────────────────────────


def _deep_swap(obj: Any, old: str, new: str) -> Any:
    """Return a copy of `obj` with every string value equal to `old` replaced by
    `new` (exact-value swap on leaves — safe), plus substring swap inside longer
    strings that embed the id."""
    if isinstance(obj, str):
        return new if obj == old else obj.replace(old, new)
    if isinstance(obj, dict):
        return {k: _deep_swap(v, old, new) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_swap(v, old, new) for v in obj]
    return obj


def _record_headers(rec: Dict[str, Any]) -> Dict[str, str]:
    """Pull request headers off a capture record, once the Lab records them. Accepts
    either a {name: value} dict or a [{name, value}] list; empty until the Lab adds
    header capture."""
    h = rec.get("request_headers") or rec.get("headers") or {}
    if isinstance(h, list):
        out: Dict[str, str] = {}
        for it in h:
            if isinstance(it, dict):
                n = it.get("name") or it.get("key")
                if n is not None:
                    out[str(n)] = str(it.get("value", ""))
        return out
    if isinstance(h, dict):
        return {str(k): str(v) for k, v in h.items()}
    return {}


def _clean_headers(headers: Dict[str, str], *, default_content_type: Optional[str] = None) -> Dict[str, str]:
    """Drop browser-owned/forbidden headers (fetch would reject them) while keeping
    everything meaningful — above all the CSRF token — and ensure a content-type."""
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk in _FORBIDDEN_REPLAY_HEADERS or lk.startswith(("sec-", "proxy-")):
            continue
        out[str(k)] = str(v)
    if default_content_type and not any(k.lower() == "content-type" for k in out):
        out["content-type"] = default_content_type
    return out


def build_request(op: ObjectScopedOp, use_id: str, attacker_id: str) -> ReplayRequest:
    """Build a concrete replay request for `op`, with `attacker_id` swapped to
    `use_id`. When use_id == attacker_id this is the unmodified (baseline) request.
    Captured request headers (CSRF, etc.) ride along verbatim, minus the swapped id."""
    if op.kind == "graphql" and op.op_payload is not None:
        swapped = _deep_swap(op.op_payload, attacker_id, use_id)
        return ReplayRequest(
            method="POST", url=op.url, body=_json.dumps([swapped]),
            headers=_clean_headers(_deep_swap(op.headers, attacker_id, use_id),
                                   default_content_type="application/json"))
    # REST
    return ReplayRequest(
        method=op.method,
        url=op.url.replace(attacker_id, use_id),
        body=(op.raw_body.replace(attacker_id, use_id) if op.raw_body else None),
        headers=_clean_headers(_deep_swap(op.headers, attacker_id, use_id)))


# ─────────────────────────── marker extraction + diff ───────────────────────────


_TOKEN = re.compile(r'"([^"\\]{4,80})"|(\b\d{4,}\b)')


def extract_victim_markers(victim_body: str, attacker_body: str, *, exclude: set) -> List[str]:
    """Victim-private markers = contentful tokens present in the victim's own
    response but ABSENT from the attacker's own baseline (so they're genuinely the
    victim's data, not generic UI chrome), minus the ids we already swapped.

    This is the honesty gate: a marker the attacker's baseline also contains proves
    nothing, and neither does the swapped id itself."""
    a = attacker_body.replace(" ", "")
    markers: List[str] = []
    seen: set = set()
    for m in _TOKEN.finditer(victim_body or ""):
        tok = m.group(1) or m.group(2)
        if not tok or tok in seen or tok in exclude:
            continue
        # skip obvious non-identifying chrome (keys, enums, urls, booleans)
        if tok.lower() in ("true", "false", "null") or tok.startswith(("http", "/", "biz.")):
            continue
        if tok.replace(" ", "") in a:
            continue  # attacker's baseline has it too → generic, not victim-private
        seen.add(tok)
        markers.append(tok)
        if len(markers) >= 40:
            break
    return markers


@dataclass
class OpVerdict:
    op: str
    verdict: str          # "BOLA_CONFIRMED" | "DENIED" | "NO_CROSS_READ" | "AMBIGUOUS" | "ERROR"
    detail: str = ""
    finding: Optional[BolaFinding] = None


def is_denied_response(resp: ReplayResponse) -> bool:
    """Return whether a replay response represents an authorization denial."""
    if resp.status in (401, 403):
        return True
    b = resp.body.lower()
    return any(k in b for k in ("not authorized", "forbidden", "permission denied",
                                "access denied", "unauthorized", "not permitted"))


async def _classify(
    op: ObjectScopedOp, attacker: str, victim: str, attacker_id: str, victim_id: str,
    transport: ReplayTransport, victim_op: Optional[ObjectScopedOp] = None,
) -> OpVerdict:
    # 1. victim baseline — the op pointed at the victim's object, sent AS the victim
    #    (swap attacker_id → victim_id so it references the victim's object) → the
    #    victim's own legitimate view, from which we mine the private markers.
    if victim_op is None:
        victim_request = build_request(op, victim_id, attacker_id)
    else:
        # A paired capture carries the victim persona's own CSRF/auth headers.
        # Use that operation unmodified instead of transplanting attacker-session
        # headers into the victim baseline.
        victim_request = build_request(victim_op, victim_id, victim_id)
    victim_base = await transport.send(victim, victim_request)
    # 2. attacker baseline — the op as the attacker, unmodified → attacker data + shape.
    atk_base = await transport.send(attacker, build_request(op, attacker_id, attacker_id))
    if victim_base.body_truncated or atk_base.body_truncated:
        return OpVerdict(
            op.label,
            "AMBIGUOUS",
            "baseline response exceeded the bounded replay limit",
        )
    # 3. the attack — attacker session, victim's id swapped in.
    attack = await transport.send(attacker, build_request(op, victim_id, attacker_id))

    if attack.body_truncated:
        return OpVerdict(
            op.label,
            "AMBIGUOUS",
            "counterfactual response exceeded the bounded replay limit",
        )

    if not (200 <= attack.status < 300):
        return OpVerdict(op.label, "DENIED", f"attack HTTP {attack.status}")
    if is_denied_response(attack):
        return OpVerdict(op.label, "DENIED", "attack returned an authorization error")

    markers = extract_victim_markers(victim_base.body, atk_base.body,
                                     exclude={attacker_id, victim_id})
    if not markers:
        return OpVerdict(op.label, "AMBIGUOUS",
                         "no victim-private marker isolable (victim baseline empty or "
                         "indistinguishable from attacker baseline)")
    leaked = [m for m in markers if _contains(attack.body, m)]
    if not leaked:
        # 2xx but only the attacker's own data / nothing of the victim's.
        return OpVerdict(op.label, "NO_CROSS_READ",
                         "attack 2xx but carried no victim-private marker")
    ref = f"{op.method} {op.url} [{op.label}]"
    finding = BolaFinding(
        object_ref=ref, method=op.method, leaked=leaked[:8], victim=victim_id,
        evidence=(f"HTTP {attack.status}; attacker session '{attacker}' sent op {op.label!r} with "
                  f"victim id {victim_id!r} ({op.id_where}) and the response carried victim-private "
                  f"marker(s) absent from the attacker's own baseline: {leaked[:8]}"))
    return OpVerdict(op.label, "BOLA_CONFIRMED", "cross-tenant read confirmed", finding)


async def classify_operation(
    op: ObjectScopedOp,
    attacker: str,
    victim: str,
    attacker_id: str,
    victim_id: str,
    transport: ReplayTransport,
    *,
    victim_op: Optional[ObjectScopedOp] = None,
) -> OpVerdict:
    """Run the established three-leg BOLA oracle for one selected operation.

    The public wrapper lets controlled schedulers select exactly one operation
    while keeping this module's existing marker-diff verdict authoritative.
    """
    return await _classify(
        op,
        attacker,
        victim,
        attacker_id,
        victim_id,
        transport,
        victim_op=victim_op,
    )


async def hunt(
    attacker_records: List[Dict[str, Any]],
    victim_records: List[Dict[str, Any]],
    *,
    transport: ReplayTransport,
    attacker_persona: str = "attacker",
    victim_persona: str = "victim",
    attacker_id: Optional[str] = None,
    victim_id: Optional[str] = None,
    max_ops: int = 64,
) -> Tuple[List[BolaFinding], List[OpVerdict]]:
    """Run the full capture→detect→swap→diff BOLA hunt. Auto-detects the primary
    owned id for each persona when not supplied. Returns (confirmed findings, all
    per-op verdicts). Best-effort: a transport error on one op never aborts the run."""
    attacker_records = parse_capture(attacker_records)
    victim_records = parse_capture(victim_records)

    if not (attacker_id and victim_id):
        # Primary: pair by the per-tenant field (robust). Fallback: frequency ranking.
        pairs = detect_swap_pairs(attacker_records, victim_records)
        if pairs:
            _key, av, vv = pairs[0]
            attacker_id = attacker_id or av
            victim_id = victim_id or vv
            logger.info("[bola_replay] swap pair on %r: %s <-> %s", _key, av, vv)
        else:
            if not attacker_id:
                ai = extract_owned_ids(attacker_records)
                attacker_id = ai[0] if ai else None
            if not victim_id:
                vi = extract_owned_ids(victim_records)
                victim_id = next((i for i in vi if i != attacker_id), (vi[0] if vi else None))
    if not attacker_id or not victim_id:
        logger.warning("[bola_replay] could not resolve attacker/victim owned ids "
                       "(attacker=%r victim=%r) — nothing to test", attacker_id, victim_id)
        return [], []
    logger.info("[bola_replay] attacker_id=%s victim_id=%s", attacker_id, victim_id)

    ops = find_object_scoped_ops(attacker_records, attacker_id, max_ops=max_ops)
    logger.info("[bola_replay] %d object-scoped operation(s) to test", len(ops))

    findings: List[BolaFinding] = []
    verdicts: List[OpVerdict] = []
    for op in ops:
        try:
            v = await classify_operation(op, attacker_persona, victim_persona,
                                         attacker_id, victim_id, transport)
        except Exception as e:
            v = OpVerdict(op.label, "ERROR", f"{type(e).__name__}: {e}")
        verdicts.append(v)
        if v.finding is not None:
            findings.append(v.finding)
            logger.info("[bola_replay] CONFIRMED BOLA via %s", op.label)
    return findings, verdicts


# ─────────────────────────── production transport ───────────────────────────


class SNDReplayTransport:
    """Production `ReplayTransport`: drives the authenticated SND / BOLA-Lab browser
    window over the existing WebSocket bridge. `persona` selects that persona's
    logged-in window (the Swift node routes it); the window executes the request
    with its own live session + CSRF token and returns {status, headers, body}.
    Being a real browser is also why it sails past DataDome — no impersonation
    needed on the replay path.

    Swift side to implement: a `"replay"` command that runs the request via
    `fetch()` (credentials:'include') inside the named persona's WKWebView and
    replies `{status, headers, body}`.
    """

    def __init__(self, *, timeout: float = 30.0):
        self.timeout = timeout

    async def send(self, persona: str, req: ReplayRequest) -> ReplayResponse:
        import uuid
        from core.server.routers.driver import node_manager  # lazy: server-only dep

        result = await node_manager.send_command({
            "request_id": uuid.uuid4().hex,
            "command": "replay",
            "args": {"persona": persona, "method": req.method, "url": req.url,
                     "headers": req.headers, "body": req.body,
                     "max_response_chars": req.max_response_chars},
        }, timeout=self.timeout) or {}
        return ReplayResponse(
            status=int(result.get("status", 0) or 0),
            body=result.get("body", "") or "",
            headers=result.get("headers", {}) or {},
            body_truncated=bool(result.get("body_truncated")),
        )
