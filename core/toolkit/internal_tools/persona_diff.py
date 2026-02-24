from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.execution_policy import build_policy_runtime
from core.wraith.mutation_engine import HttpMethod, MutationRequest
from core.wraith.personas import PersonaManager
from core.wraith.auth_diff_scanner import AuthDiffScanner


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
        scanner = AuthDiffScanner(context.session)
        if not await scanner.initialize():
            await self.log(queue, "AuthDiffScanner failed to initialize. Skipping.")
            return []

        try:
            candidate_urls = self._collect_candidate_urls(target, context.existing_findings)[: self.MAX_TARGET_URLS]
            if not candidate_urls:
                await self.log(queue, "No candidate URLs found in findings metadata; skipping.")
                return []

            out: List[Dict[str, Any]] = []
            dedup: Set[str] = set()

            for url, source_tool in candidate_urls:
                await self.log(queue, f"Diff replay: {url} (source={source_tool})")
                # The scanner handles logging the finding directly to the central session,
                # but we will also process it for the tool return queue just in case.
                findings = await scanner.scan_endpoint(url, method="GET")
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
            return out
        finally:
            await scanner.close()

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
