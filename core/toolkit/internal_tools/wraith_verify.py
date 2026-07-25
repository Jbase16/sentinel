from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.execution_policy import build_policy_runtime
from core.wraith.mutation_engine import (
    ActionOutcome,
    EvidenceType,
    HttpMethod,
    MutationEngine,
    MutationPayload,
    PayloadEncoding,
    xss_payloads,
)
from core.wraith.session_manager import AuthSessionManager
from core.wraith.waf_bypass import VulnerabilityClass, WAFBypassEngine
from core.wraith.waf_retry import get_or_create_waf_engine, waf_aware_send


_SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Normalized vuln-class hints we know how to verify quickly.
_VERIFYABLE_VULN_HINTS = ("sqli", "xss")


def _origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    return f"{scheme}://{netloc}"


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


def _is_id_like_segment(segment: str) -> bool:
    seg = (segment or "").strip()
    if not seg:
        return False
    if seg.isdigit() and 1 <= len(seg) <= 12:
        return True
    if _UUID_RE.match(seg):
        return True
    # Common compact UUID (32 hex chars)
    if len(seg) == 32 and all(c in "0123456789abcdefABCDEF" for c in seg):
        return True
    return False


def _path_injection_template(url: str) -> Optional[Tuple[str, str]]:
    """
    Replace the last id-like path segment with {PAYLOAD}.

    Returns:
      (template_url, original_segment)
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None
    for i in range(len(parts) - 1, -1, -1):
        if _is_id_like_segment(parts[i]):
            original = parts[i]
            parts[i] = "{PAYLOAD}"
            new_path = "/" + "/".join(parts)
            template = urlunparse(parsed._replace(path=new_path, fragment=""))
            return template, original
    return None


class WraithVerifyTool(InternalTool):
    """Targeted payload verification using MutationEngine + response oracles.

    This tool consumes previously-discovered endpoints (from findings metadata)
    and performs bounded mutation testing on:
      - existing query parameters, and
      - id-like path segments (e.g., /api/users/123) via placeholder mutation.

    Safety:
      - Same-origin only (no pivoting).
      - Request fan-out is strictly bounded (MAX_* limits).
      - SQLi verification uses low-risk syntax probes by default (no extraction).
    """

    MAX_CANDIDATE_URLS = 16
    MAX_PARAMS_PER_URL = 3
    MAX_PAYLOADS_PER_PARAM = 3
    MAX_TOTAL_MUTATIONS = 30
    MAX_PATH_PAYLOADS_PER_URL = 2

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

        # Optional: baseline authenticated context for endpoints behind login.
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        session_bridge = await AuthSessionManager.from_knowledge(context.knowledge, base_url=base_target)
        if session_bridge is not None:
            auth = await session_bridge.get_baseline_auth()
            if auth is not None:
                headers = dict(auth.headers)
                cookies = dict(auth.cookies)
                await self.log(queue, f"Using baseline auth: {auth.redacted_summary()}")

        policy_runtime = build_policy_runtime(
            context=context,
            tool_name=self.name,
            target=target,
            default_rate_limit_ms=120,
            default_request_budget=max(40, self.MAX_TOTAL_MUTATIONS * 2),
            default_retry_ceiling=2,
        )
        # Keep tool bounded: do not allow unbounded request fan-out.
        engine = MutationEngine(rate_limit_ms=120, policy_runtime=policy_runtime)
        try:
            waf_engine: Optional[WAFBypassEngine] = get_or_create_waf_engine(context.knowledge)

            findings_out: List[Dict[str, Any]] = []
            dedup: Set[str] = set()
            total_mutations = 0

            for url, source_tool, source_severity, vuln_hints in candidate_urls[: self.MAX_CANDIDATE_URLS]:
                if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                    break

                parsed = urlparse(url)
                # Query param injection points (existing parameters only).
                params_in_url = [k for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
                params = _unique_preserve_order(params_in_url)[: self.MAX_PARAMS_PER_URL]

                for param in params:
                    if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                        break

                    payloads = self._payloads_for_param(param, vuln_hints=vuln_hints)[: self.MAX_PAYLOADS_PER_PARAM]
                    for payload in payloads:
                        if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                            break

                        await self.log(queue, f"Mutate {url} param={param} class={payload.vuln_class}")

                        response, outcome, was_bypassed = await waf_aware_send(
                            engine, url, payload,
                            method=HttpMethod.GET,
                            headers=headers,
                            cookies=cookies,
                            waf_engine=waf_engine,
                            queue=queue,
                            tool_label=self.name,
                        )
                        total_mutations += 1

                        self._maybe_emit_verified_finding(
                            findings_out=findings_out,
                            dedup=dedup,
                            source_tool=source_tool,
                            source_severity=source_severity,
                            url=url,
                            baseline_url=url,
                            param=param,
                            payload=payload,
                            response=response,
                            outcome=outcome,
                        )

                # Path-segment injection (only when an id-like segment exists).
                if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                    continue

                template_info = _path_injection_template(url)
                if template_info:
                    template_url, original_segment = template_info
                    path_payloads = self._payloads_for_path_segment(
                        original_segment=original_segment,
                        vuln_hints=vuln_hints,
                    )[: self.MAX_PATH_PAYLOADS_PER_URL]
                    for payload in path_payloads:
                        if total_mutations >= self.MAX_TOTAL_MUTATIONS:
                            break

                        param_label = f"path:{original_segment}"
                        await self.log(queue, f"Mutate {url} {param_label} class={payload.vuln_class}")

                        response, outcome, was_bypassed = await waf_aware_send(
                            engine, template_url, payload,
                            method=HttpMethod.GET,
                            headers=headers,
                            cookies=cookies,
                            baseline_url=url,
                            waf_engine=waf_engine,
                            queue=queue,
                            tool_label=self.name,
                        )
                        total_mutations += 1

                        self._maybe_emit_verified_finding(
                            findings_out=findings_out,
                            dedup=dedup,
                            source_tool=source_tool,
                            source_severity=source_severity,
                            url=template_url,
                            baseline_url=url,
                            param=param_label,
                            payload=payload,
                            response=response,
                            outcome=outcome,
                        )

            await self.log(queue, f"Completed verification (mutations_sent={total_mutations}, findings={len(findings_out)})")
            await self.log(queue, f"Policy metrics: {policy_runtime.metrics()}")
            return findings_out
        finally:
            await engine.close()

    def _collect_candidate_urls(
        self,
        base_target: str,
        findings: Sequence[Dict[str, Any]],
    ) -> List[Tuple[str, str, str, Set[str]]]:
        """Extract candidate URLs from existing findings.

        Returns:
            List of tuples: (url, source_tool, source_severity, vuln_hints)
        """
        base_origin = _origin(base_target)
        base_url_for_join = base_origin

        candidates: Dict[str, Dict[str, Any]] = {}

        for f in findings:
            tool = str(f.get("tool") or "unknown")
            severity = str(f.get("severity") or "INFO").upper()
            sev_score = _SEVERITY_SCORE.get(severity, 0)
            vuln_hints = self._infer_vuln_hints(f)

            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            url = meta.get("url") if isinstance(meta.get("url"), str) else None
            if not url:
                details = f.get("details") if isinstance(f.get("details"), dict) else {}
                url = details.get("url") if isinstance(details.get("url"), str) else None

            if not url and isinstance(meta.get("path"), str) and str(meta.get("path")).startswith("/"):
                url = urljoin(base_url_for_join + "/", str(meta.get("path")).lstrip("/"))
            if not url and isinstance(f.get("message"), str):
                # Extract a path like "/api/users?id=1" from message/proof.
                m = re.search(r"(/[A-Za-z0-9_\\-\\./%]+(?:\\?[A-Za-z0-9_\\-\\.%=&]+)?)", f.get("message") or "")
                if m:
                    url = urljoin(base_url_for_join + "/", m.group(1).lstrip("/"))

            if not url or not isinstance(url, str) or not _is_http_url(url):
                continue

            if not _same_origin(url, base_origin):
                # Don't let this tool pivot to other hosts automatically.
                continue

            # Require an injection surface (query params or id-like path segment).
            parsed = urlparse(url)
            has_query = bool(parsed.query)
            has_path_id = _path_injection_template(url) is not None
            # Only consider path-id mutation when we have a strong SQLi hint. Otherwise
            # we'd spray syntax probes at REST resources that are unlikely to parse input.
            if not has_query and not ("sqli" in vuln_hints and has_path_id):
                continue

            entry = candidates.get(url)
            if entry is None:
                candidates[url] = {
                    "score": sev_score,
                    "tool": tool,
                    "severity": severity,
                    "hints": set(vuln_hints),
                }
                continue

            # Merge hints; keep the highest-severity source attribution.
            entry["hints"].update(vuln_hints)
            if sev_score > int(entry.get("score", 0)):
                entry["score"] = sev_score
                entry["tool"] = tool
                entry["severity"] = severity

        scored: List[Tuple[int, str]] = []
        for url, meta in candidates.items():
            scored.append((int(meta.get("score", 0)), url))

        # Stable ordering: highest severity first, then lexicographic URL for determinism.
        scored.sort(key=lambda t: (-t[0], t[1]))

        out: List[Tuple[str, str, str, Set[str]]] = []
        for _, url in scored:
            meta = candidates[url]
            hints = meta.get("hints") if isinstance(meta.get("hints"), set) else set()
            out.append((url, str(meta.get("tool") or "unknown"), str(meta.get("severity") or "INFO"), hints))
        return out

    def _infer_vuln_hints(self, finding: Dict[str, Any]) -> Set[str]:
        """Infer likely vulnerability classes from a T1 finding.

        This is intentionally conservative: hints only influence which payload
        families we attempt, not the breadth of endpoints we touch.
        """
        hints: Set[str] = set()

        # Tags are the most reliable signal (nuclei templates commonly include sqli/xss tags).
        tags = finding.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        if isinstance(tags, list):
            for t in tags:
                norm = str(t).strip().lower()
                if not norm:
                    continue
                if norm in ("sqli", "sql", "sql-injection", "sql_injection", "sqlinjection"):
                    hints.add("sqli")
                if norm in ("xss", "reflected-xss", "reflected_xss", "stored-xss", "stored_xss"):
                    hints.add("xss")

        # Fall back to finding type/message/template identifiers.
        ftype = str(finding.get("type") or "").lower()
        if "xss" in ftype:
            hints.add("xss")
        if "sql" in ftype and ("inject" in ftype or "sqli" in ftype):
            hints.add("sqli")

        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        template_id = str(meta.get("template_id") or meta.get("templateID") or "").lower()
        if template_id:
            if "xss" in template_id:
                hints.add("xss")
            if "sqli" in template_id or ("sql" in template_id and "inject" in template_id):
                hints.add("sqli")

        # Only return hints we can actually verify in this tool.
        return {h for h in hints if h in _VERIFYABLE_VULN_HINTS}

    def _sqli_query_payloads(self, param: str) -> List[MutationPayload]:
        # Low-risk syntax probes: confirm via ERROR_SIGNATURE oracle.
        return [
            MutationPayload(
                value="'",
                encoding=PayloadEncoding.QUERY_PARAM,
                param_name=param,
                vuln_class="sqli",
                description="SQLi syntax probe (single quote)",
                expected_evidence=EvidenceType.ERROR_SIGNATURE,
                tier_required=2,
            ),
            MutationPayload(
                value="\"",
                encoding=PayloadEncoding.QUERY_PARAM,
                param_name=param,
                vuln_class="sqli",
                description="SQLi syntax probe (double quote)",
                expected_evidence=EvidenceType.ERROR_SIGNATURE,
                tier_required=2,
            ),
            MutationPayload(
                value="')--",
                encoding=PayloadEncoding.QUERY_PARAM,
                param_name=param,
                vuln_class="sqli",
                description="SQLi syntax probe (quote + comment)",
                expected_evidence=EvidenceType.ERROR_SIGNATURE,
                tier_required=2,
            ),
        ]

    def _payloads_for_param(self, param: str, *, vuln_hints: Set[str]) -> List[MutationPayload]:
        """Generate a bounded payload set for a parameter."""
        p = (param or "").lower()

        payloads: List[MutationPayload] = []

        want_sqli = "sqli" in vuln_hints or any(hint in p for hint in self.SQLI_PARAM_HINTS)
        want_xss = "xss" in vuln_hints or any(hint == p or hint in p for hint in self.XSS_PARAM_HINTS)

        if want_sqli:
            payloads.extend(self._sqli_query_payloads(param))
        if want_xss:
            payloads.extend(xss_payloads(param)[:2])

        return payloads

    def _payloads_for_path_segment(self, *, original_segment: str, vuln_hints: Set[str]) -> List[MutationPayload]:
        # Path mutation is only useful for SQLi-style parsing bugs; keep it narrow.
        if "sqli" not in vuln_hints:
            return []

        seg = (original_segment or "").strip()
        if not seg:
            return []

        # URL-encode quotes in path segments to keep the URL valid.
        return [
            MutationPayload(
                value=f"{seg}%27",
                encoding=PayloadEncoding.PATH_SEGMENT,
                param_name="path",
                vuln_class="sqli",
                description="Path-segment SQLi probe (%27)",
                expected_evidence=EvidenceType.ERROR_SIGNATURE,
                tier_required=2,
            ),
            MutationPayload(
                value=f"{seg}%22",
                encoding=PayloadEncoding.PATH_SEGMENT,
                param_name="path",
                vuln_class="sqli",
                description="Path-segment SQLi probe (%22)",
                expected_evidence=EvidenceType.ERROR_SIGNATURE,
                tier_required=2,
            ),
        ]

    def _maybe_emit_verified_finding(
        self,
        *,
        findings_out: List[Dict[str, Any]],
        dedup: Set[str],
        source_tool: str,
        source_severity: str,
        url: str,
        baseline_url: str,
        param: str,
        payload: MutationPayload,
        response: Any,
        outcome: ActionOutcome,
    ) -> None:
        if outcome not in (ActionOutcome.SUCCESS, ActionOutcome.PARTIAL):
            return

        evidence = getattr(response, "evidence", None) or []
        if not evidence:
            return

        max_conf = max(getattr(e, "confidence", 0.0) for e in evidence) if evidence else 0.0
        confirmation = "confirmed" if max_conf >= 0.9 else ("probable" if max_conf >= 0.6 else "hypothesized")
        severity = self._severity_for(payload, evidence, source_severity)

        key = f"{_strip_query_and_fragment(baseline_url)}|{param}|{payload.vuln_class}"
        if key in dedup:
            return
        dedup.add(key)

        evidence_summary = self._summarize_evidence(evidence)
        status_code = int(getattr(response, "status_code", 0) or 0)
        elapsed_ms = float(getattr(response, "elapsed_ms", 0.0) or 0.0)
        proof = self._format_proof(payload, evidence, status_code, elapsed_ms)

        finding = self.make_finding(
            target=baseline_url,
            finding_type=payload.vuln_class,
            severity=severity,
            message=(
                f"{payload.vuln_class.upper()} evidence ({confirmation}) on {baseline_url} "
                f"(param='{param}', source={source_tool})"
            ),
            proof=proof,
            confidence=max_conf,
            tags=["wraith", "verified", payload.vuln_class],
            families=["vulnerability"],
            metadata={
                "source_tool": source_tool,
                "source_severity": source_severity,
                "url": baseline_url,
                "mutated_url": str(getattr(response, "url", "") or ""),
                "verification_url": url,
                "param": param,
                "vuln_class": payload.vuln_class,
                "expected_evidence": payload.expected_evidence.value,
                "outcome": outcome.value,
                "evidence": [e.to_dict() for e in evidence],
                "evidence_summary": evidence_summary,
            },
        )

        # First-class fields used by Strategos + causal graph.
        finding["confirmation_level"] = confirmation
        finding["capability_types"] = ["execution"]
        finding["details"] = {
            "url": baseline_url,
            "param": param,
            "vuln_type": payload.vuln_class,
            "source_tool": source_tool,
        }

        findings_out.append(finding)

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

