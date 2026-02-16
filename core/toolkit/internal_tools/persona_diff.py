from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.execution_policy import build_policy_runtime
from core.wraith.mutation_engine import HttpMethod, MutationRequest
from core.wraith.personas import (
    DifferentialAnalyzer,
    Persona,
    PersonaManager,
)
from core.wraith.session_manager import AuthSessionManager, parse_personas_config


_SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


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


class WraithPersonaDiffTool(InternalTool):
    """Differential auth testing across personas (IDOR/Auth Bypass/etc.)."""

    MAX_TARGET_URLS = 12

    @property
    def name(self) -> str:
        return "wraith_persona_diff"

    async def execute(
        self,
        target: str,
        context: InternalToolContext,
        queue: asyncio.Queue[str],
    ) -> List[Dict[str, Any]]:
        personas_cfg = context.knowledge.get("personas")
        if not isinstance(personas_cfg, list) or not personas_cfg:
            await self.log(queue, "No personas configured (knowledge['personas'] missing). Skipping.")
            return []

        base_url = self._origin(target)
        # Pre-auth/login once per scan (loads persisted sessions, replays login flows as needed).
        session_bridge = await AuthSessionManager.from_knowledge(context.knowledge, base_url=target)
        if session_bridge is not None and session_bridge.personas:
            personas = list(session_bridge.personas)
        else:
            personas, _ = parse_personas_config(base_url, personas_cfg)
        if not personas:
            await self.log(queue, "Personas config present but invalid/empty after parsing. Skipping.")
            return []

        requested_baseline = str(context.knowledge.get("persona_baseline") or "Admin")
        baseline_persona = requested_baseline
        available_names = {p.name for p in personas}
        if baseline_persona not in available_names:
            admin_name = next(
                (p.name for p in personas if str(getattr(p.persona_type, "value", "")).lower() == "admin"),
                None,
            )
            baseline_persona = admin_name or next(
                (p.name for p in personas if str(getattr(p.persona_type, "value", "")).lower() != "anonymous"),
                requested_baseline,
            )
            await self.log(queue, f"Baseline persona '{requested_baseline}' not found; using '{baseline_persona}'")

        policy_runtime = build_policy_runtime(
            context=context,
            tool_name=self.name,
            target=target,
            default_rate_limit_ms=120,
            default_request_budget=max(30, self.MAX_TARGET_URLS * max(2, len(personas))),
            default_retry_ceiling=2,
        )

        mgr = PersonaManager(personas=personas, policy_runtime=policy_runtime)
        await self.log(queue, f"Initializing personas (count={len(personas)}, baseline={baseline_persona})")

        ok = await mgr.initialize()
        if not ok:
            await self.log(queue, "One or more personas failed to authenticate; continuing with available sessions.")

        try:
            analyzer = DifferentialAnalyzer(manager=mgr, baseline_persona=baseline_persona, skip_anonymous=False)

            candidate_urls = self._collect_candidate_urls(target, context.existing_findings)[: self.MAX_TARGET_URLS]
            if not candidate_urls:
                await self.log(queue, "No candidate URLs found in findings metadata; skipping.")
                return []

            out: List[Dict[str, Any]] = []
            dedup: Set[str] = set()

            for url, source_tool in candidate_urls:
                await self.log(queue, f"Diff replay: {url} (source={source_tool})")
                req = MutationRequest(
                    url=url,
                    method=HttpMethod.GET,
                    headers={"Accept": "application/json"},
                    timeout=12.0,
                )

                findings = await analyzer.analyze(req)
                for df in findings:
                    issue_type = df.issue_type.value
                    key = f"{issue_type}|{url}|{df.test_persona}|{df.baseline_persona}"
                    if key in dedup:
                        continue
                    dedup.add(key)

                    conf = float(df.confidence or 0.0)
                    confirmation = "confirmed" if conf >= 0.9 else ("probable" if conf >= 0.6 else "hypothesized")
                    severity = str(df.severity or "medium").upper()
                    if severity not in _SEVERITY_SCORE:
                        severity = "MEDIUM"

                    finding = self.make_finding(
                        target=url,
                        finding_type=issue_type,
                        severity=severity,
                        message=df.description or f"{issue_type} detected on {url}",
                        proof=df.response_diff.description,
                        confidence=conf,
                        tags=["wraith", "persona", issue_type],
                        families=["access-control"],
                        metadata={
                            "source_tool": source_tool,
                            "url": url,
                            "baseline_persona": df.baseline_persona,
                            "test_persona": df.test_persona,
                            "response_diff": df.response_diff.description,
                            "evidence": [e.to_dict() for e in df.evidence],
                            "remediation": df.remediation,
                        },
                    )
                    finding["confirmation_level"] = confirmation
                    finding["capability_types"] = ["access"]
                    finding["details"] = {
                        "url": url,
                        "method": df.method,
                        "issue_type": issue_type,
                        "baseline_persona": df.baseline_persona,
                        "test_persona": df.test_persona,
                    }
                    out.append(finding)

            await self.log(queue, f"Persona diff complete (findings={len(out)})")
            await self.log(queue, f"Policy metrics: {policy_runtime.metrics()}")
            return out
        finally:
            await mgr.close()

    def _origin(self, target: str) -> str:
        parsed = urlparse(target)
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc
        return f"{scheme}://{netloc}"

    def _collect_candidate_urls(self, base_target: str, findings: Sequence[Dict[str, Any]]) -> List[Tuple[str, str]]:
        base_url = self._origin(base_target)
        scored: List[Tuple[int, str, str]] = []
        for f in findings:
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            url = meta.get("url") if isinstance(meta.get("url"), str) else None
            if not url or not _is_http_url(url):
                continue
            if not _same_origin(url, base_url):
                continue
            status = meta.get("status")
            if isinstance(status, int) and status >= 400:
                continue

            tool = str(f.get("tool") or "unknown")
            severity = str(f.get("severity") or "INFO").upper()
            score = _SEVERITY_SCORE.get(severity, 0)
            # Prefer API-like endpoints.
            if "/api" in url or "graphql" in url:
                score += 1

            scored.append((score, url, tool))

        scored.sort(key=lambda t: (-t[0], t[1]))
        urls = _unique_preserve_order([u for _, u, _ in scored])
        # Preserve the associated source tool by re-looking up (stable ordering).
        out: List[Tuple[str, str]] = []
        for url in urls:
            tool = next((tool for _, u, tool in scored if u == url), "unknown")
            out.append((url, tool))
        return out
