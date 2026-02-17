"""
API Discovery Tool (T1_PROBE)

Discovers API endpoints via multiple strategies:
1. Lazarus shadow client — reads JS-extracted API routes from Ghost Protocol
2. Common path probing — tries well-known API paths (/api/, /swagger.json, /graphql, etc.)
3. OpenAPI/Swagger parsing — if a spec is found, extracts all endpoints with methods + parameters
4. Existing findings mining — harvests URLs from T0/T1 tool outputs

Outputs INFO-severity findings for each discovered endpoint so downstream tools
(wraith_verify, wraith_persona_diff, wraith_oob_probe) have targets to fuzz.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from core.toolkit.internal_tool import InternalTool, InternalToolContext
from core.wraith.execution_policy import build_policy_runtime, PolicyViolation

logger = logging.getLogger(__name__)

# Well-known API discovery paths, grouped by priority.
# Higher priority = more commonly used, more likely to exist.
_COMMON_API_PATHS: List[Tuple[str, str]] = [
    # OpenAPI / Swagger specs (highest value — full endpoint catalog)
    ("/swagger.json", "GET"),
    ("/openapi.json", "GET"),
    ("/swagger/v1/swagger.json", "GET"),
    ("/api-docs", "GET"),
    ("/v1/swagger.json", "GET"),
    ("/v2/swagger.json", "GET"),
    ("/api/swagger.json", "GET"),
    ("/api/openapi.json", "GET"),
    ("/.well-known/openapi.yaml", "GET"),
    # GraphQL introspection
    ("/graphql", "POST"),
    ("/api/graphql", "POST"),
    ("/v1/graphql", "POST"),
    # Common API roots
    ("/api/", "GET"),
    ("/api/v1/", "GET"),
    ("/api/v2/", "GET"),
    ("/api/v3/", "GET"),
    ("/rest/", "GET"),
    # Debug / admin (often misconfigured)
    ("/actuator", "GET"),
    ("/actuator/health", "GET"),
    ("/_debug", "GET"),
    ("/debug/vars", "GET"),
    ("/server-info", "GET"),
    ("/server-status", "GET"),
    ("/.env", "GET"),
    ("/wp-json/", "GET"),
    ("/wp-json/wp/v2/users", "GET"),
]

# GraphQL introspection query
_GRAPHQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { queryType { name } mutationType { name } types { name fields { name } } } }"
})

# Status codes that indicate "something is there"
_INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


class APIDiscovererTool(InternalTool):
    """Discover API endpoints via path probing, spec parsing, and Lazarus shadow clients."""

    MAX_PATH_PROBES = 20
    MAX_OPENAPI_ENDPOINTS = 50
    REQUEST_TIMEOUT = 10.0

    @property
    def name(self) -> str:
        return "api_discoverer"

    async def execute(
        self,
        target: str,
        context: InternalToolContext,
        queue: asyncio.Queue[str],
    ) -> List[Dict[str, Any]]:
        base_url = self._base_url(target)
        await self.log(queue, f"Starting API discovery on {base_url}")

        policy_runtime = build_policy_runtime(
            context=context,
            tool_name=self.name,
            target=target,
            default_rate_limit_ms=100,
            default_request_budget=self.MAX_PATH_PROBES + 10,
            default_retry_ceiling=1,
        )

        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        try:
            from core.wraith.session_manager import AuthSessionManager
            session_bridge = await AuthSessionManager.from_knowledge(context.knowledge, base_url=target)
            if session_bridge is not None:
                auth = await session_bridge.get_baseline_auth()
                if auth is not None:
                    headers = dict(auth.headers)
                    cookies = dict(auth.cookies)
                    await self.log(queue, f"Using baseline auth: {auth.redacted_summary()}")
        except Exception:
            pass  # Auth is optional for discovery

        all_findings: List[Dict[str, Any]] = []
        dedup: Set[str] = set()

        # Strategy 1: Lazarus shadow clients (JS-extracted routes)
        lazarus_findings = self._harvest_lazarus_routes(context.knowledge, base_url, dedup)
        all_findings.extend(lazarus_findings)
        if lazarus_findings:
            await self.log(queue, f"Lazarus shadow client: {len(lazarus_findings)} routes")

        # Strategy 2: Mine existing findings for undiscovered endpoints
        mined_findings = self._mine_existing_findings(context.existing_findings, base_url, dedup)
        all_findings.extend(mined_findings)
        if mined_findings:
            await self.log(queue, f"Findings mining: {len(mined_findings)} endpoints")

        # Strategy 3: Active path probing
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.REQUEST_TIMEOUT,
            verify=False,
            headers={**headers, "User-Agent": "Mozilla/5.0 (compatible; SentinelForge/1.0)"},
            cookies=cookies,
        ) as client:
            probed = 0
            spec_url: Optional[str] = None

            for path, method in _COMMON_API_PATHS[:self.MAX_PATH_PROBES]:
                probe_url = urljoin(base_url, path)
                dedup_key = f"{method}|{self._normalize_path(probe_url)}"
                if dedup_key in dedup:
                    continue

                try:
                    if method == "POST" and "graphql" in path:
                        resp = await client.post(
                            probe_url,
                            content=_GRAPHQL_INTROSPECTION,
                            headers={"Content-Type": "application/json"},
                        )
                    else:
                        resp = await client.get(probe_url)

                    probed += 1
                    status = resp.status_code

                    if status not in _INTERESTING_STATUS:
                        continue

                    dedup.add(dedup_key)
                    content_type = resp.headers.get("content-type", "")

                    # Check if we found a Swagger/OpenAPI spec
                    is_spec = False
                    if ("swagger" in path or "openapi" in path) and status == 200:
                        if "json" in content_type or "yaml" in content_type:
                            is_spec = True
                            spec_url = probe_url

                    # GraphQL introspection success
                    is_graphql = False
                    if "graphql" in path and status == 200:
                        try:
                            body = resp.json()
                            if "data" in body and "__schema" in (body.get("data") or {}):
                                is_graphql = True
                        except Exception:
                            pass

                    severity = "MEDIUM" if (is_spec or is_graphql or status in (401, 403)) else "INFO"
                    tags = ["wraith", "discovery", "api"]
                    if is_spec:
                        tags.append("openapi_spec")
                    if is_graphql:
                        tags.append("graphql")
                    if status in (401, 403):
                        tags.append("auth_required")

                    finding = self.make_finding(
                        target=probe_url,
                        finding_type="api_endpoint",
                        severity=severity,
                        message=f"API endpoint discovered: {method} {path} (status={status})",
                        proof=f"HTTP {status} {content_type[:60]}",
                        confidence=0.7 if status == 200 else 0.5,
                        tags=tags,
                        families=["discovery"],
                        metadata={
                            "url": probe_url,
                            "method": method,
                            "path": path,
                            "status": status,
                            "content_type": content_type[:100],
                            "source": "path_probe",
                            "is_spec": is_spec,
                            "is_graphql": is_graphql,
                        },
                    )
                    finding["details"] = {
                        "url": probe_url,
                        "method": method,
                        "status": status,
                    }
                    all_findings.append(finding)

                    await self.log(queue, f"Found: {method} {path} → {status}")

                except (httpx.TimeoutException, httpx.ConnectError):
                    probed += 1
                    continue
                except PolicyViolation as exc:
                    await self.log(queue, f"Policy blocked probe: {exc}")
                    break
                except Exception as exc:
                    logger.debug(f"[api_discoverer] Probe failed {path}: {exc}")
                    probed += 1
                    continue

            # Strategy 4: Parse OpenAPI/Swagger spec if found
            if spec_url:
                await self.log(queue, f"Parsing OpenAPI spec from {spec_url}")
                spec_findings = await self._parse_openapi_spec(client, spec_url, base_url, dedup)
                all_findings.extend(spec_findings)
                await self.log(queue, f"OpenAPI spec: {len(spec_findings)} endpoints extracted")

        await self.log(queue, f"API discovery complete (total={len(all_findings)}, probed={probed})")
        return all_findings

    def _base_url(self, target: str) -> str:
        parsed = urlparse(target)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _normalize_path(self, url: str) -> str:
        parsed = urlparse(url)
        path = (parsed.path or "/").rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def _harvest_lazarus_routes(
        self,
        knowledge: Dict[str, Any],
        base_url: str,
        dedup: Set[str],
    ) -> List[Dict[str, Any]]:
        """Extract API routes from Lazarus shadow clients stored in knowledge."""
        findings: List[Dict[str, Any]] = []

        # Shadow clients may be stored directly or via LazarusEngine reference
        shadow_clients = knowledge.get("shadow_clients") or {}
        if not isinstance(shadow_clients, dict):
            return findings

        for code_hash, client_spec in shadow_clients.items():
            if not isinstance(client_spec, dict):
                continue
            endpoints = client_spec.get("endpoints") or []
            for ep in endpoints:
                if not isinstance(ep, dict):
                    continue
                method = str(ep.get("method") or "GET").upper()
                path = str(ep.get("path") or "")
                if not path:
                    continue

                full_url = ep.get("full_url") or urljoin(base_url, path)
                dedup_key = f"{method}|{self._normalize_path(full_url)}"
                if dedup_key in dedup:
                    continue
                dedup.add(dedup_key)

                attack_vectors = ep.get("attack_vectors") or []
                tags = ["wraith", "discovery", "lazarus", "js_extracted"]

                finding = self.make_finding(
                    target=full_url,
                    finding_type="api_endpoint",
                    severity="INFO",
                    message=f"JS-extracted API route: {method} {path}",
                    proof=f"Source: {ep.get('source', 'unknown')} | Vectors: {len(attack_vectors)}",
                    confidence=0.6,
                    tags=tags,
                    families=["discovery"],
                    metadata={
                        "url": full_url,
                        "method": method,
                        "path": path,
                        "source": "lazarus",
                        "js_source": ep.get("source"),
                        "attack_vectors": attack_vectors,
                        "code_hash": code_hash[:16],
                    },
                )
                finding["details"] = {"url": full_url, "method": method}
                findings.append(finding)

        return findings

    def _mine_existing_findings(
        self,
        findings: Sequence[Dict[str, Any]],
        base_url: str,
        dedup: Set[str],
    ) -> List[Dict[str, Any]]:
        """Extract API-like endpoints from existing T0/T1 findings that haven't been cataloged."""
        out: List[Dict[str, Any]] = []
        base_origin = self._base_url(base_url)

        api_patterns = re.compile(r"/(api|rest|v[0-9]+|graphql|internal|admin|debug|_)", re.IGNORECASE)

        for f in findings:
            meta = f.get("metadata") if isinstance(f.get("metadata"), dict) else {}
            url = meta.get("url") if isinstance(meta.get("url"), str) else None
            if not url:
                continue
            try:
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    continue
                url_origin = f"{parsed.scheme}://{parsed.netloc}"
                if url_origin != base_origin:
                    continue
            except Exception:
                continue

            path = parsed.path or "/"
            if not api_patterns.search(path):
                continue

            method = str(meta.get("method") or "GET").upper()
            dedup_key = f"{method}|{self._normalize_path(url)}"
            if dedup_key in dedup:
                continue
            dedup.add(dedup_key)

            status = meta.get("status")
            source_tool = str(f.get("tool") or "unknown")

            finding = self.make_finding(
                target=url,
                finding_type="api_endpoint",
                severity="INFO",
                message=f"API endpoint from {source_tool}: {method} {path}",
                proof=f"Discovered by {source_tool}" + (f" (status={status})" if status else ""),
                confidence=0.5,
                tags=["wraith", "discovery", "mined"],
                families=["discovery"],
                metadata={
                    "url": url,
                    "method": method,
                    "path": path,
                    "status": status,
                    "source": "findings_mining",
                    "source_tool": source_tool,
                },
            )
            finding["details"] = {"url": url, "method": method}
            out.append(finding)

        return out

    async def _parse_openapi_spec(
        self,
        client: httpx.AsyncClient,
        spec_url: str,
        base_url: str,
        dedup: Set[str],
    ) -> List[Dict[str, Any]]:
        """Fetch and parse an OpenAPI/Swagger spec, extracting all endpoints."""
        findings: List[Dict[str, Any]] = []
        try:
            resp = await client.get(spec_url)
            if resp.status_code != 200:
                return findings

            spec = resp.json()
        except Exception as exc:
            logger.debug(f"[api_discoverer] Failed to parse spec from {spec_url}: {exc}")
            return findings

        # Determine base path from spec
        spec_base = base_url
        if "basePath" in spec:  # Swagger 2.0
            spec_base = urljoin(base_url, spec["basePath"])
        elif "servers" in spec:  # OpenAPI 3.x
            servers = spec.get("servers") or []
            if servers and isinstance(servers[0], dict):
                server_url = servers[0].get("url", "")
                if server_url.startswith("/"):
                    spec_base = urljoin(base_url, server_url)
                elif server_url.startswith("http"):
                    spec_base = server_url

        paths = spec.get("paths") or {}
        count = 0
        for path, methods in paths.items():
            if not isinstance(methods, dict) or count >= self.MAX_OPENAPI_ENDPOINTS:
                break

            for method, operation in methods.items():
                method_upper = method.upper()
                if method_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    continue
                if count >= self.MAX_OPENAPI_ENDPOINTS:
                    break

                full_url = urljoin(spec_base.rstrip("/") + "/", path.lstrip("/"))
                dedup_key = f"{method_upper}|{self._normalize_path(full_url)}"
                if dedup_key in dedup:
                    continue
                dedup.add(dedup_key)

                # Extract parameters
                params = []
                if isinstance(operation, dict):
                    for p in (operation.get("parameters") or []):
                        if isinstance(p, dict):
                            params.append({
                                "name": p.get("name"),
                                "in": p.get("in"),
                                "required": p.get("required", False),
                            })

                summary = ""
                if isinstance(operation, dict):
                    summary = str(operation.get("summary") or operation.get("description") or "")[:120]

                tags = ["wraith", "discovery", "openapi_spec"]
                # Flag potentially interesting endpoints
                auth_required = False
                if isinstance(operation, dict) and operation.get("security"):
                    auth_required = True
                    tags.append("auth_required")

                finding = self.make_finding(
                    target=full_url,
                    finding_type="api_endpoint",
                    severity="INFO",
                    message=f"OpenAPI: {method_upper} {path}" + (f" — {summary}" if summary else ""),
                    proof=f"From spec at {spec_url} | Params: {len(params)}",
                    confidence=0.9,
                    tags=tags,
                    families=["discovery"],
                    metadata={
                        "url": full_url,
                        "method": method_upper,
                        "path": path,
                        "source": "openapi_spec",
                        "spec_url": spec_url,
                        "parameters": params,
                        "summary": summary,
                        "auth_required": auth_required,
                    },
                )
                finding["details"] = {
                    "url": full_url,
                    "method": method_upper,
                    "parameters": params,
                }
                findings.append(finding)
                count += 1

        return findings
