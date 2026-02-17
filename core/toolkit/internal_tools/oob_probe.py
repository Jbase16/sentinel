from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlunparse

import httpx

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.execution_policy import build_policy_runtime, PolicyViolation
from core.wraith.mutation_engine import (
    EvidenceType,
    HttpMethod,
    MutationEngine,
    MutationPayload,
    MutationRequest,
    PayloadEncoding,
)
from core.wraith.oob_detector import (
    InteractshProvider,
    OOBEvidence,
    OOBManager,
    VulnerabilityClass,
)
from core.wraith.session_manager import AuthSessionManager
from core.wraith.waf_retry import get_or_create_waf_engine, waf_aware_raw_send


def _is_http_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _same_origin(a: str, b: str) -> bool:
    try:
        pa = urlparse(a)
        pb = urlparse(b)
        return pa.scheme == pb.scheme and pa.netloc == pb.netloc
    except Exception:
        return False


def _origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    return f"{scheme}://{netloc}"


def _strip_query_and_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


class WraithOOBProbeTool(InternalTool):
    """Out-of-band verification probes (SSRF/XXE/RCE/blind-SQLi/blind-XSS) using OOBManager."""

    MAX_PROBES = 10
    # SSRF-flavoured parameter hints
    SSRF_PARAM_HINTS = ("url", "next", "redirect", "return", "dest", "target", "callback", "uri", "path", "link", "src", "href")
    # Parameters likely to hit a backend query or template renderer
    INJECTION_PARAM_HINTS = ("q", "query", "search", "id", "uid", "name", "filter", "sort", "order", "file", "page", "template", "input", "data")
    # XXE-specific: endpoints that accept XML bodies
    XML_CONTENT_HINTS = ("xml", "soap", "wsdl", "rss", "feed", "import", "upload")

    # Vuln classes to attempt per parameter type
    SSRF_CLASSES = (VulnerabilityClass.SSRF,)
    INJECTION_CLASSES = (VulnerabilityClass.SQLi, VulnerabilityClass.RCE, VulnerabilityClass.XSS)

    @property
    def name(self) -> str:
        return "wraith_oob_probe"

    async def execute(
        self,
        target: str,
        context: InternalToolContext,
        queue: asyncio.Queue[str],
    ) -> List[Dict[str, Any]]:
        cfg = context.knowledge.get("oob")
        if not isinstance(cfg, dict):
            await self.log(queue, "No OOB provider configured (knowledge['oob'] missing). Skipping.")
            return []

        provider_name = str(cfg.get("provider") or "interactsh").strip().lower()
        if provider_name != "interactsh":
            await self.log(queue, f"Unsupported OOB provider '{provider_name}'. Only 'interactsh' is supported currently.")
            return []

        base_domain = str(cfg.get("base_domain") or "").strip()
        if not base_domain:
            await self.log(queue, "OOB config missing required 'base_domain'. Skipping.")
            return []

        api_url = str(cfg.get("api_url") or "https://interactsh.com").strip()
        poll_timeout_s = float(cfg.get("poll_timeout_s") or 25.0)
        poll_interval_s = float(cfg.get("poll_interval_s") or 2.0)
        poll_interval_s = max(0.5, poll_interval_s)
        max_poll_calls = max(1, int(poll_timeout_s / poll_interval_s) + 1)

        policy_runtime = build_policy_runtime(
            context=context,
            tool_name=self.name,
            target=target,
            default_rate_limit_ms=150,
            default_request_budget=max(30, self.MAX_PROBES * 6),
            default_retry_ceiling=2,
            default_external_budget=max(6, max_poll_calls + 2),
        )

        provider = InteractshProvider(base_domain=base_domain, api_url=api_url)
        manager = OOBManager(provider=provider)
        waf_engine = get_or_create_waf_engine(context.knowledge)

        base_origin = _origin(target)
        ssrf_candidates = self._collect_candidate_injection_points(
            base_origin, context.existing_findings, self.SSRF_PARAM_HINTS
        )
        injection_candidates = self._collect_candidate_injection_points(
            base_origin, context.existing_findings, self.INJECTION_PARAM_HINTS
        )

        if not ssrf_candidates and not injection_candidates:
            await self.log(queue, "No OOB-eligible injection points found in findings metadata; skipping.")
            return []

        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        session_bridge = await AuthSessionManager.from_knowledge(context.knowledge, base_url=target)
        if session_bridge is not None:
            auth = await session_bridge.get_baseline_auth()
            if auth is not None:
                headers = dict(auth.headers)
                cookies = dict(auth.cookies)
                await self.log(queue, f"Using baseline auth: {auth.redacted_summary()}")

        engine = MutationEngine(rate_limit_ms=150, policy_runtime=policy_runtime)
        try:
            probes_sent = 0

            # Phase A: SSRF probes on URL-like parameters
            for url, param, source_tool in ssrf_candidates[: self.MAX_PROBES // 2]:
                for vuln_class in self.SSRF_CLASSES:
                    if probes_sent >= self.MAX_PROBES:
                        break
                    payload_id = f"{url}|{param}|{vuln_class.value}"
                    interaction_id = manager.generate_interaction_id(payload_id)
                    manager.register_payload(
                        payload_id=payload_id,
                        interaction_id=interaction_id,
                        metadata={"url": url, "param": param, "vuln_class": vuln_class.value},
                    )

                    oob_payload = manager.create_oob_payload(
                        vuln_class=vuln_class,
                        interaction_id=interaction_id,
                        base_domain=base_domain,
                    )

                    canonical_url, params = self._canonicalize_url_params(url)
                    params[param] = oob_payload

                    await self.log(queue, f"Inject {vuln_class.value} canary: {canonical_url} param={param}")
                    req = MutationRequest(
                        url=canonical_url,
                        method=HttpMethod.GET,
                        headers=headers,
                        cookies=cookies,
                        query_params=params,
                        timeout=12.0,
                        payload=MutationPayload(
                            value=oob_payload,
                            encoding=PayloadEncoding.QUERY_PARAM,
                            param_name=param,
                            vuln_class=vuln_class.value.lower(),
                            description=f"{vuln_class.value} OOB canary",
                            expected_evidence=EvidenceType.OOB_TRIGGER,
                            tier_required=3,
                        ),
                    )
                    _, was_bypassed = await waf_aware_raw_send(
                        engine, req,
                        waf_engine=waf_engine,
                        vuln_class_hint=vuln_class.value.lower(),
                        queue=queue,
                        tool_label=self.name,
                    )
                    probes_sent += 1

            # Phase B: Injection-class probes (SQLi OOB, RCE OOB, blind XSS) on
            # search/query/id parameters
            for url, param, source_tool in injection_candidates[: self.MAX_PROBES // 2]:
                for vuln_class in self.INJECTION_CLASSES:
                    if probes_sent >= self.MAX_PROBES:
                        break
                    payload_id = f"{url}|{param}|{vuln_class.value}"
                    interaction_id = manager.generate_interaction_id(payload_id)
                    manager.register_payload(
                        payload_id=payload_id,
                        interaction_id=interaction_id,
                        metadata={"url": url, "param": param, "vuln_class": vuln_class.value},
                    )

                    oob_payload = manager.create_oob_payload(
                        vuln_class=vuln_class,
                        interaction_id=interaction_id,
                        base_domain=base_domain,
                    )

                    canonical_url, params = self._canonicalize_url_params(url)
                    params[param] = oob_payload

                    await self.log(queue, f"Inject {vuln_class.value} OOB canary: {canonical_url} param={param}")
                    req = MutationRequest(
                        url=canonical_url,
                        method=HttpMethod.GET,
                        headers=headers,
                        cookies=cookies,
                        query_params=params,
                        timeout=12.0,
                        payload=MutationPayload(
                            value=oob_payload,
                            encoding=PayloadEncoding.QUERY_PARAM,
                            param_name=param,
                            vuln_class=vuln_class.value.lower(),
                            description=f"{vuln_class.value} OOB canary",
                            expected_evidence=EvidenceType.OOB_TRIGGER,
                            tier_required=3,
                        ),
                    )
                    _, was_bypassed = await waf_aware_raw_send(
                        engine, req,
                        waf_engine=waf_engine,
                        vuln_class_hint=vuln_class.value.lower(),
                        queue=queue,
                        tool_label=self.name,
                    )
                    probes_sent += 1

            # Phase C: XXE probes — POST XML bodies to endpoints that hint at XML acceptance
            xxe_endpoints = self._collect_xxe_endpoints(base_origin, context.existing_findings)
            for url, source_tool in xxe_endpoints[:2]:
                if probes_sent >= self.MAX_PROBES:
                    break
                payload_id = f"{url}|body|xxe"
                interaction_id = manager.generate_interaction_id(payload_id)
                manager.register_payload(
                    payload_id=payload_id,
                    interaction_id=interaction_id,
                    metadata={"url": url, "param": "body", "vuln_class": "xxe"},
                )
                oob_payload = manager.create_oob_payload(
                    vuln_class=VulnerabilityClass.XXE,
                    interaction_id=interaction_id,
                    base_domain=base_domain,
                )
                xxe_headers = {**headers, "Content-Type": "application/xml"}
                await self.log(queue, f"Inject XXE canary (POST body): {url}")
                req = MutationRequest(
                    url=url,
                    method=HttpMethod.POST,
                    headers=xxe_headers,
                    cookies=cookies,
                    body=oob_payload,
                    timeout=12.0,
                    payload=MutationPayload(
                        value=oob_payload,
                        encoding=PayloadEncoding.RAW_BODY,
                        param_name="body",
                        vuln_class="xxe",
                        description="XXE OOB canary",
                        expected_evidence=EvidenceType.OOB_TRIGGER,
                        tier_required=3,
                    ),
                )
                _, was_bypassed = await waf_aware_raw_send(
                    engine, req,
                    waf_engine=waf_engine,
                    vuln_class_hint="xxe",
                    queue=queue,
                    tool_label=self.name,
                )
                probes_sent += 1

            await self.log(queue, f"Polling OOB provider (probes={probes_sent}, timeout={poll_timeout_s:.0f}s)...")
            try:
                async with httpx.AsyncClient(follow_redirects=True) as oob_client:
                    evidence = await manager.poll_interactions_async(
                        client=oob_client,
                        policy_runtime=policy_runtime,
                        timeout_s=poll_timeout_s,
                        interval_s=poll_interval_s,
                    )
            except PolicyViolation as exc:
                await self.log(queue, f"OOB polling blocked by policy: {exc}")
                return []

            if not evidence:
                await self.log(queue, f"No OOB interactions observed (probes_sent={probes_sent}).")
                return []

            out: List[Dict[str, Any]] = []
            for ev in evidence:
                reg_entry = manager.payload_registry.get(ev.payload_id, {})
                meta = reg_entry.get("metadata", {}) if isinstance(reg_entry, dict) else {}
                url = str(meta.get("url") or target)
                param = str(meta.get("param") or "unknown")
                vuln_class_str = str(meta.get("vuln_class") or "ssrf").lower()

                severity = "CRITICAL" if vuln_class_str in ("rce", "xxe") else "HIGH"

                finding = self.make_finding(
                    target=url,
                    finding_type=vuln_class_str,
                    severity=severity,
                    message=f"OOB callback observed for {vuln_class_str.upper()} probe on {url} (param='{param}')",
                    proof=str(ev.to_dict()),
                    confidence=0.95,
                    tags=["wraith", "oob", vuln_class_str, "confirmed"],
                    families=["vulnerability"],
                    metadata={
                        "oob": ev.to_dict(),
                        "payload_id": ev.payload_id,
                        "interaction_id": ev.interaction_id,
                        "provider": provider_name,
                        "base_domain": base_domain,
                        "vuln_class": vuln_class_str,
                    },
                )
                finding["confirmation_level"] = "confirmed"
                finding["capability_types"] = ["execution"]
                finding["details"] = {
                    "url": url,
                    "param": param,
                    "vuln_class": vuln_class_str,
                    "interaction_type": ev.interaction_type.value,
                    "source_ip": ev.source_ip,
                }
                out.append(finding)

            await self.log(queue, f"OOB probe complete (interactions={len(out)})")
            await self.log(queue, f"Policy metrics: {policy_runtime.metrics()}")
            return out
        finally:
            await engine.close()

    def _canonicalize_url_params(self, url: str) -> Tuple[str, Dict[str, str]]:
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        canonical_url = urlunparse(parsed._replace(query="", fragment=""))
        params = {str(k): str(v) for k, v in params.items() if v is not None}
        return canonical_url, params

    def _collect_candidate_injection_points(
        self,
        base_origin: str,
        findings: Sequence[Dict[str, Any]],
        param_hints: Tuple[str, ...],
    ) -> List[Tuple[str, str, str]]:
        scored: List[Tuple[int, str, str, str]] = []
        for f in findings:
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            url = meta.get("url") if isinstance(meta.get("url"), str) else None
            if not url or not _is_http_url(url):
                continue
            if not _same_origin(url, base_origin):
                continue

            parsed = urlparse(url)
            if not parsed.query:
                continue

            tool = str(f.get("tool") or "unknown")
            sev = str(f.get("severity") or "INFO").upper()
            score = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, 0)

            params = _unique_preserve_order([k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)])
            for param in params:
                p = (param or "").lower()
                if any(h in p for h in param_hints):
                    scored.append((score, url, param, tool))

        scored.sort(key=lambda t: (-t[0], t[1], t[2]))
        out: List[Tuple[str, str, str]] = []
        seen: Set[str] = set()
        for _, url, param, tool in scored:
            key = f"{_strip_query_and_fragment(url)}|{param}"
            if key in seen:
                continue
            seen.add(key)
            out.append((url, param, tool))
        return out

    def _collect_xxe_endpoints(
        self,
        base_origin: str,
        findings: Sequence[Dict[str, Any]],
    ) -> List[Tuple[str, str]]:
        """Find endpoints likely to accept XML bodies (for XXE probing)."""
        candidates: List[Tuple[int, str, str]] = []
        for f in findings:
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            url = meta.get("url") if isinstance(meta.get("url"), str) else None
            if not url or not _is_http_url(url):
                continue
            if not _same_origin(url, base_origin):
                continue

            tool = str(f.get("tool") or "unknown")
            sev = str(f.get("severity") or "INFO").upper()
            score = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, 0)

            # Check if URL path or content-type hints at XML acceptance
            url_lower = url.lower()
            content_type = str(meta.get("content_type") or meta.get("Content-Type") or "").lower()
            if any(h in url_lower for h in self.XML_CONTENT_HINTS) or "xml" in content_type:
                candidates.append((score, url, tool))

        candidates.sort(key=lambda t: (-t[0], t[1]))
        seen: Set[str] = set()
        out: List[Tuple[str, str]] = []
        for _, url, tool in candidates:
            stripped = _strip_query_and_fragment(url)
            if stripped in seen:
                continue
            seen.add(stripped)
            out.append((url, tool))
        return out
