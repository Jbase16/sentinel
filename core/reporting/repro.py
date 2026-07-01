"""
core/reporting/repro.py

Turn a confirmed finding's STRUCTURED metadata into a submittable write-up.

The detection engines already capture exactly what happened — the chain hops with
per-hop evidence, the leaked victim markers, the injected field and the value the
server persisted, the invariant that was violated. The generic report path threw
all of that away and emitted "curl the homepage / no captured evidence". This
module reconstructs real reproduction steps, an evidence block, and class-specific
remediation from that metadata, so a verified finding reads like something a
program would accept.

`reproduction_for(finding)` returns None for finding classes it doesn't recognize
(the caller then falls back to the generic builder), so it never degrades a report
it can't improve.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Repro:
    steps: List[str] = field(default_factory=list)      # numbered reproduction
    evidence: List[str] = field(default_factory=list)   # evidence blocks
    remediation: str = ""
    confirmed: bool = False                             # actively verified → assertive language


def _curl(method: str, url: str, body: Optional[Dict[str, Any]] = None, *, token: str = "$TOKEN") -> str:
    parts = ["curl -s -i"]
    if method and method.upper() != "GET":
        parts.append(f"-X {method.upper()}")
    parts.append(f"-H 'Authorization: Bearer {token}'")
    if body is not None:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(body)}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


_REMEDIATION = {
    "mass_assignment":
        "Bind only an explicit allowlist of user-writable fields when creating or "
        "updating a record. Never let a request body set privilege/ownership "
        "attributes (`{field}`); derive them server-side.",
    "bola":
        "Enforce object-level authorization on every object access: verify the "
        "authenticated principal actually owns or is entitled to the requested "
        "object, not merely that they are authenticated. Do not rely on ids being "
        "unguessable.",
    "business_logic":
        "Validate and enforce the invariant server-side ('{invariant}'). Reject "
        "client-supplied values for `{field}` that violate it; derive server-owned "
        "values (pricing, balances) on the server, never from the request.",
    "chain_privilege_escalation":
        "Enforce server-side authorization for privileged operations independent of "
        "any client-assertable role, and reject client attempts to set role/"
        "privilege fields (mass assignment).",
    "chain_data_exposure":
        "Enforce object-level authorization so a freshly-registered, low-privilege "
        "account cannot read other users' objects by walking id spaces.",
    "chain_amplified_bola":
        "Two failures compound here: client-writable role (mass assignment) AND "
        "authorization checks that key only on role without object/tenant scoping. "
        "Fix both — make roles server-controlled, and authorize every object access "
        "against the caller's actual entitlement.",
}


def _fmt(template: str, meta: Dict[str, Any]) -> str:
    try:
        return template.format(field=meta.get("field", "the field"),
                               invariant=meta.get("invariant", "the invariant"))
    except Exception:
        return template


def _chain_repro(finding: Dict[str, Any], meta: Dict[str, Any]) -> Repro:
    hops = meta.get("hops") or []
    steps: List[str] = []
    evidence: List[str] = []
    for i, h in enumerate(hops, 1):
        label = h.get("label", "")
        steps.append(label)
        ev = h.get("evidence")
        if ev:
            evidence.append(f"Step {i} — {label}\n  verified: {ev}")
    kind = meta.get("kind", "")
    rem = _REMEDIATION.get(f"chain_{kind}", _REMEDIATION["chain_privilege_escalation"])
    goal = meta.get("goal")
    if goal:
        steps.append(f"Result: {goal}")
    return Repro(steps=steps, evidence=evidence, remediation=rem, confirmed=True)


def _bola_repro(finding: Dict[str, Any], meta: Dict[str, Any]) -> Repro:
    if meta.get("subtype") == "horizontal_enumeration":
        ep = meta.get("endpoint", finding.get("target", ""))
        steps = [
            "Authenticate as a single low-privilege user.",
            f"Enumerate object ids at `{ep}` across the range {meta.get('id_range', '')}.",
            f"Observe that {meta.get('accessed')} objects belonging to "
            f"{meta.get('distinct_owners')} DISTINCT owners (field "
            f"`{meta.get('owner_field')}`, e.g. owners {meta.get('sample_owners')}) are "
            f"readable — a whole population's private records, not just your own.",
            f"Reproduce with:\n\n    ```bash\n    {_curl('GET', ep.replace('{id}', '<N>'))}\n    ```",
        ]
        evidence = [f"{meta.get('accessed')} objects across {meta.get('distinct_owners')} "
                    f"distinct owners via {meta.get('endpoint')} (ids {meta.get('id_range')})"]
        return Repro(steps=steps, evidence=evidence, remediation=_REMEDIATION["bola"], confirmed=True)

    ref = meta.get("object_ref", finding.get("target", ""))
    method = meta.get("method", "GET")
    leaked = meta.get("leaked_markers") or []
    steps = [
        "Register/authenticate two separate low-privilege accounts: victim A and attacker B.",
        f"As victim A, own an object; as attacker B, request A's object: `{method} {ref}`.",
        f"Observe attacker B's response contains victim A's private data that B never "
        f"supplied: {leaked}.",
        f"Reproduce with (B's token):\n\n    ```bash\n    {_curl(method, ref)}\n    ```",
    ]
    evidence = [meta.get("evidence") or f"cross-principal read of {ref}; leaked {leaked}"]
    return Repro(steps=steps, evidence=evidence, remediation=_REMEDIATION["bola"], confirmed=True)


def _mass_assignment_repro(finding: Dict[str, Any], meta: Dict[str, Any]) -> Repro:
    fld, inj, base = meta.get("field"), meta.get("injected"), meta.get("baseline")
    url = finding.get("target", "")
    steps = [
        f"Register a new account, adding the privileged field to the request body: "
        f"`\"{fld}\": {json.dumps(inj)}`.",
        "Read the account back (own profile, or a directory/listing endpoint).",
        f"Observe the server persisted `{fld}={json.dumps(inj)}`, whereas a baseline "
        f"account created without it has `{fld}={json.dumps(base)}` — the field is "
        f"client-controlled at a privilege boundary.",
        f"Reproduce with:\n\n    ```bash\n    {_curl('POST', url, {fld: inj, '...': '...'}, token='')}\n    ```",
    ]
    evidence = [meta.get("evidence") or f"persisted {fld}={inj!r} (baseline {base!r})"]
    return Repro(steps=steps, evidence=evidence,
                 remediation=_fmt(_REMEDIATION["mass_assignment"], meta), confirmed=True)


def _business_logic_repro(finding: Dict[str, Any], meta: Dict[str, Any]) -> Repro:
    fld, viol = meta.get("field"), meta.get("violation")
    url = finding.get("target", "")
    steps = [
        f"Send a request to `{url}` with the invariant-violating value: "
        f"`\"{fld}\": {json.dumps(viol)}`.",
        f"Observe the server accepts (2xx) AND persists the value — the invariant "
        f"'{meta.get('invariant')}' is trusted from the client, not enforced.",
        f"Reproduce with:\n\n    ```bash\n    {_curl('PUT', url, {fld: viol})}\n    ```",
    ]
    evidence = [meta.get("evidence") or f"server persisted {fld}={viol!r}"]
    return Repro(steps=steps, evidence=evidence,
                 remediation=_fmt(_REMEDIATION["business_logic"], meta), confirmed=True)


def reproduction_for(finding: Dict[str, Any]) -> Optional[Repro]:
    """Build a real reproduction from a confirmed finding's structured metadata.
    Returns None for unrecognized classes (caller falls back to the generic path)."""
    meta = finding.get("metadata") or {}
    vc = meta.get("vuln_class")
    try:
        if vc == "exploit_chain":
            return _chain_repro(finding, meta)
        if vc == "bola":
            return _bola_repro(finding, meta)
        if vc == "mass_assignment":
            return _mass_assignment_repro(finding, meta)
        if vc == "business_logic":
            return _business_logic_repro(finding, meta)
    except Exception:
        return None
    return None
