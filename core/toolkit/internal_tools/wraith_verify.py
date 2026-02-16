from __future__ import annotations

import asyncio
import re
from dataclasses import replace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.mutation_engine import (
    ActionOutcome,
    EvidenceType,
    HttpMethod,
    MutationEngine,
    MutationPayload,
    sqli_payloads,
    xss_payloads,
)
from core.wraith.waf_bypass import VulnerabilityClass, WAFBypassEngine


_SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _strip_query_and_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


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


def _unique_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


class WraithVerifyTool(InternalTool):
    """Targeted payload verification using MutationEngine + response oracles.

    This tool consumes previously-discovered endpoints (from findings metadata)
    and performs bounded mutation testing on existing query parameters.
    """

    MAX_CANDIDATE_URLS = 16
    MAX_PARAMS_PER_URL = 3
    MAX_PAYLOADS_PER_PARAM = 3
    MAX_TOTAL_MUTATIONS = 30

    # Heuristic param allow-lists to avoid "spray and pray".
    SQLI_PARAM_HINTS = ("id", "uid", "user", "account", "page", "item", "product", "order")
    XSS_PARAM_HINTS = ("q", "query", "search", "s", "term", "redirect", "next", "return", "url")

    @property
    def name(self) -> str:
        return "wraith_verify"

    async def execute(
        self,
        target: str,
        context: InternalToolContext,
        queue: asyncio.Queue[str],
    ) -> List[Dict[str, Any]]:
        await self.log(queue, f"Starting verification (findings_in_context={len(context.existing_findings)})")

        base_target = target
        candidate_urls = self._collect_candidate_urls(base_target, context.existing_findings)
        if not candidate_urls:
            await self.log(queue, "No candidate URLs found in findings metadata; skipping.")
            return []

        # Keep tool bounded: do not allow unbounded request fan-out.
        engine = MutationEngine(rate_limit_ms=120)
        try:
            waf_engine = self._get_waf_engine(context.knowledge)

            findings_out: List[Dict[str, Any]] = []
            dedup: Set[str] = set()
            total_mutations = 0

            for url, source_tool, source_severity in candidate_urls[: self.MAX_CANDIDATE_URLS]:
                if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                    break

                parsed = urlparse(url)
                if not parsed.query:
                    continue

                params_in_url = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
                params = _unique_preserve_order(params_in_url)[: self.MAX_PARAMS_PER_URL]
                if not params:
                    continue

                for param in params:
                    if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                        break

                    for payload in self._payloads_for_param(param)[: self.MAX_PAYLOADS_PER_PARAM]:
                        if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                            break

                        await self.log(queue, f"Mutate {url} param={param} class={payload.vuln_class}")

                        response, outcome = await engine.mutate_and_analyze(
                            url=url,
                            payload=payload,
                            method=HttpMethod.GET,
                        )
                        total_mutations += 1

                        if outcome == ActionOutcome.BLOCKED and waf_engine is not None:
                            response, outcome, total_mutations = await self._attempt_waf_bypass(
                                engine=engine,
                                waf_engine=waf_engine,
                                url=url,
                                payload=payload,
                                blocked_response=response,
                                total_mutations=total_mutations,
                                queue=queue,
                            )

                        if outcome not in (ActionOutcome.SUCCESS, ActionOutcome.PARTIAL):
                            continue

                        if not response.evidence:
                            continue

                        max_conf = max(e.confidence for e in response.evidence)
                        confirmation = "confirmed" if max_conf >= 0.9 else ("probable" if max_conf >= 0.6 else "hypothesized")
                        severity = self._severity_for(payload, response.evidence, source_severity)

                        key = f"{_strip_query_and_fragment(url)}|{param}|{payload.vuln_class}"
                        if key in dedup:
                            continue
                        dedup.add(key)

                        evidence_summary = self._summarize_evidence(response.evidence)
                        proof = self._format_proof(payload, response.evidence, response.status_code, response.elapsed_ms)

                        finding = self.make_finding(
                            target=url,
                            finding_type=payload.vuln_class,
                            severity=severity,
                            message=(
                                f"{payload.vuln_class.upper()} evidence ({confirmation}) on {url} "
                                f"(param='{param}', source={source_tool})"
                            ),
                            proof=proof,
                            confidence=max_conf,
                            tags=["wraith", "verified", payload.vuln_class],
                            families=["vulnerability"],
                            metadata={
                                "source_tool": source_tool,
                                "source_severity": source_severity,
                                "url": url,
                                "param": param,
                                "vuln_class": payload.vuln_class,
                                "expected_evidence": payload.expected_evidence.value,
                                "outcome": outcome.value,
                                "evidence": [e.to_dict() for e in response.evidence],
                                "evidence_summary": evidence_summary,
                            },
                        )

                        # First-class fields used by Strategos + causal graph.
                        finding["confirmation_level"] = confirmation
                        finding["capability_types"] = ["execution"]
                        finding["details"] = {
                            "url": url,
                            "param": param,
                            "vuln_type": payload.vuln_class,
                            "source_tool": source_tool,
                        }

                        findings_out.append(finding)

            await self.log(queue, f"Completed verification (mutations_sent={total_mutations}, findings={len(findings_out)})")
            return findings_out
        finally:
            await engine.close()

    def _collect_candidate_urls(self, base_target: str, findings: Sequence[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
        """Extract candidate URLs from existing findings.

        Returns:
            List of tuples: (url, source_tool, source_severity)
        """
        base_url = _strip_query_and_fragment(base_target)
        urls_scored: List[Tuple[int, str, str, str]] = []

        for f in findings:
            tool = str(f.get("tool") or "unknown")
            severity = str(f.get("severity") or "INFO").upper()
            sev_score = _SEVERITY_SCORE.get(severity, 0)

            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            url = meta.get("url") if isinstance(meta.get("url"), str) else None
            if not url:
                details = f.get("details") if isinstance(f.get("details"), dict) else {}
                url = details.get("url") if isinstance(details.get("url"), str) else None

            if not url and isinstance(meta.get("path"), str) and str(meta.get("path")).startswith("/"):
                url = urljoin(base_url + "/", str(meta.get("path")).lstrip("/"))
            if not url and isinstance(f.get("message"), str):
                # Extract a path like "/api/users?id=1" from message/proof.
                m = re.search(r"(/[A-Za-z0-9_\\-\\./%]+\\?[A-Za-z0-9_\\-\\.%=&]+)", f.get("message") or "")
                if m:
                    url = urljoin(base_url + "/", m.group(1).lstrip("/"))

            if not url or not isinstance(url, str) or not _is_http_url(url):
                continue

            if not _same_origin(url, base_url):
                # Don't let this tool pivot to other hosts automatically.
                continue

            # Prefer URLs that already have parameters (verification targets).
            parsed = urlparse(url)
            if not parsed.query:
                continue

            urls_scored.append((sev_score, url, tool, severity))

        # Stable ordering: highest severity first, then lexicographic URL for determinism.
        urls_scored.sort(key=lambda t: (-t[0], t[1]))
        seen: Set[str] = set()
        out: List[Tuple[str, str, str]] = []
        for _, url, tool, severity in urls_scored:
            if url in seen:
                continue
            seen.add(url)
            out.append((url, tool, severity))
        return out

    def _payloads_for_param(self, param: str) -> List[MutationPayload]:
        """Generate a bounded payload set for a parameter."""
        p = (param or "").lower()

        payloads: List[MutationPayload] = []

        if any(hint in p for hint in self.SQLI_PARAM_HINTS):
            # Avoid slow time-based payloads by default; keep verification fast.
            payloads.extend([p for p in sqli_payloads(param) if "sleep" not in p.value.lower()][:2])

        if any(hint == p or hint in p for hint in self.XSS_PARAM_HINTS):
            payloads.extend(xss_payloads(param)[:2])

        # If the param doesn't match any heuristic, avoid noise.
        return payloads

    def _severity_for(self, payload: MutationPayload, evidence: List[Any], source_severity: str) -> str:
        """Classify severity for a verified finding."""
        max_conf = max(getattr(e, "confidence", 0.0) for e in evidence) if evidence else 0.0
        if payload.vuln_class == "sqli":
            # Error signatures with high confidence are high impact.
            if any(getattr(e, "type", None) == EvidenceType.ERROR_SIGNATURE for e in evidence) and max_conf >= 0.8:
                return "HIGH"
            if any(getattr(e, "type", None) == EvidenceType.TIME_ANOMALY for e in evidence) and max_conf >= 0.8:
                return "HIGH"
            return "MEDIUM"
        if payload.vuln_class == "xss":
            # Reflection is not full XSS execution, but it's still worth attention.
            return "MEDIUM" if max_conf >= 0.8 else "LOW"

        # Fall back to the upstream tool severity, but keep within known domain.
        sev = (source_severity or "INFO").upper()
        return sev if sev in _SEVERITY_SCORE else "INFO"

    def _summarize_evidence(self, evidence: Sequence[Any]) -> str:
        parts: List[str] = []
        for e in evidence[:4]:
            et = getattr(e, "type", None)
            desc = getattr(e, "description", "")
            conf = getattr(e, "confidence", 0.0)
            if et is None:
                continue
            parts.append(f"{et.value}:{conf:.2f} {desc}")
        return " | ".join(parts)

    def _format_proof(
        self,
        payload: MutationPayload,
        evidence: Sequence[Any],
        status_code: int,
        elapsed_ms: float,
    ) -> str:
        ev_lines: List[str] = []
        for e in evidence[:5]:
            et = getattr(e, "type", None)
            if et is None:
                continue
            snippet = getattr(e, "response_snippet", "") or ""
            snippet = snippet[:240]
            ev_lines.append(f"- {et.value} conf={getattr(e, 'confidence', 0.0):.2f} {getattr(e, 'description', '')}")
            if snippet:
                ev_lines.append(f"  snippet: {snippet}")
        ev_block = "\n".join(ev_lines).strip()
        return (
            f"payload: {payload.value}\n"
            f"param: {payload.param_name}\n"
            f"status: {status_code}\n"
            f"elapsed_ms: {elapsed_ms:.0f}\n"
            f"evidence:\n{ev_block}"
        ).strip()

    def _get_waf_engine(self, knowledge: Dict[str, Any]) -> Optional[WAFBypassEngine]:
        engine = knowledge.get("waf_bypass_engine")
        if isinstance(engine, WAFBypassEngine):
            return engine
        return None

    async def _attempt_waf_bypass(
        self,
        *,
        engine: MutationEngine,
        waf_engine: WAFBypassEngine,
        url: str,
        payload: MutationPayload,
        blocked_response: Any,
        total_mutations: int,
        queue: asyncio.Queue[str],
    ) -> Tuple[Any, ActionOutcome, int]:
        # Parse waf name from blocking evidence (MutationEngine attaches it in metadata).
        waf_name = None
        for ev in getattr(blocked_response, "evidence", []) or []:
            meta = getattr(ev, "metadata", {}) or {}
            if isinstance(meta, dict) and meta.get("waf"):
                waf_name = str(meta.get("waf"))
                break
        if not waf_name:
            return blocked_response, ActionOutcome.BLOCKED, total_mutations

        vuln_class = self._to_vuln_class(payload.vuln_class)
        if vuln_class is None:
            return blocked_response, ActionOutcome.BLOCKED, total_mutations

        technique = waf_engine.select_bypass_technique(waf_name, vuln_class)
        if technique is None:
            return blocked_response, ActionOutcome.BLOCKED, total_mutations

        transformed = waf_engine.apply_bypass_to_payload(payload.value, technique)
        bypass_payload = replace(payload, value=transformed, description=f"{payload.description} (bypass:{technique.id})")

        await self.log(queue, f"WAF({waf_name}) blocked; retrying with bypass={technique.id}")
        response2, outcome2 = await engine.mutate_and_analyze(url=url, payload=bypass_payload, method=HttpMethod.GET)
        total_mutations += 1

        # Treat "not blocked" as success signal for the bandit; evidence presence is a bonus.
        bypass_success = outcome2 != ActionOutcome.BLOCKED
        waf_engine.record_bypass_result(waf_name, technique.id, bypass_success)

        return response2, outcome2, total_mutations

    def _to_vuln_class(self, vuln_class: str) -> Optional[VulnerabilityClass]:
        v = (vuln_class or "").strip().lower()
        if v == "sqli":
            return VulnerabilityClass.SQLI
        if v == "xss":
            return VulnerabilityClass.XSS
        if v == "ssrf":
            return VulnerabilityClass.SSRF
        if v == "rce":
            return VulnerabilityClass.RCE
        return None

