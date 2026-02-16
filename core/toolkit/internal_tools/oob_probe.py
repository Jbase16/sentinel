from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlunparse

from core.toolkit.internal_tool import InternalTool, InternalToolContext
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
    """Out-of-band verification probes (SSRF/XXE/etc.) using OOBManager."""

    MAX_PROBES = 6
    PARAM_HINTS = ("url", "next", "redirect", "return", "dest", "target", "callback")

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

        provider = InteractshProvider(base_domain=base_domain, api_url=api_url)
        manager = OOBManager(provider=provider)

        base_origin = _origin(target)
        candidates = self._collect_candidate_injection_points(base_origin, context.existing_findings)
        if not candidates:
            await self.log(queue, "No SSRF-like injection points found in findings metadata; skipping.")
            return []

        engine = MutationEngine(rate_limit_ms=150)
        try:
            probes_sent = 0
            for url, param, source_tool in candidates[: self.MAX_PROBES]:
                payload_id = f"{url}|{param}|ssrf"
                interaction_id = manager.generate_interaction_id(payload_id)
                manager.register_payload(payload_id=payload_id, interaction_id=interaction_id, metadata={"url": url, "param": param})

                oob_payload = manager.create_oob_payload(
                    vuln_class=VulnerabilityClass.SSRF,
                    interaction_id=interaction_id,
                    base_domain=base_domain,
                )

                canonical_url, params = self._canonicalize_url_params(url)
                params[param] = oob_payload

                await self.log(queue, f"Inject SSRF canary: {canonical_url} param={param} (source={source_tool})")
                req = MutationRequest(
                    url=canonical_url,
                    method=HttpMethod.GET,
                    query_params=params,
                    timeout=12.0,
                    payload=MutationPayload(
                        value=oob_payload,
                        encoding=PayloadEncoding.QUERY_PARAM,
                        param_name=param,
                        vuln_class="ssrf",
                        description="SSRF OOB canary",
                        expected_evidence=EvidenceType.OOB_TRIGGER,
                        tier_required=3,
                    ),
                )
                _ = await engine.send(req)
                probes_sent += 1

            await self.log(queue, f"Polling OOB provider (timeout={poll_timeout_s:.0f}s)...")
            evidence: List[OOBEvidence] = await asyncio.to_thread(
                manager.poll_interactions,
                timeout_s=poll_timeout_s,
                interval_s=poll_interval_s,
            )

            if not evidence:
                await self.log(queue, f"No OOB interactions observed (probes_sent={probes_sent}).")
                return []

            out: List[Dict[str, Any]] = []
            for ev in evidence:
                meta = manager.payload_registry.get(ev.payload_id, {}).get("metadata", {})
                url = str(meta.get("url") or target)
                param = str(meta.get("param") or "unknown")

                finding = self.make_finding(
                    target=url,
                    finding_type="ssrf",
                    severity="HIGH",
                    message=f"OOB callback observed for SSRF probe on {url} (param='{param}')",
                    proof=str(ev.to_dict()),
                    confidence=0.95,
                    tags=["wraith", "oob", "ssrf", "confirmed"],
                    families=["vulnerability"],
                    metadata={
                        "oob": ev.to_dict(),
                        "payload_id": ev.payload_id,
                        "interaction_id": ev.interaction_id,
                        "provider": provider_name,
                        "base_domain": base_domain,
                    },
                )
                finding["confirmation_level"] = "confirmed"
                finding["capability_types"] = ["execution"]
                finding["details"] = {
                    "url": url,
                    "param": param,
                    "interaction_type": ev.interaction_type.value,
                    "source_ip": ev.source_ip,
                }
                out.append(finding)

            await self.log(queue, f"OOB probe complete (interactions={len(out)})")
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
                if any(h in p for h in self.PARAM_HINTS):
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
