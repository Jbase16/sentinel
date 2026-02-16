import asyncio

import pytest

from core.toolkit.internal_tool import InternalToolContext
from core.toolkit.internal_tools.wraith_verify import WraithVerifyTool
from core.wraith.mutation_engine import (
    ActionOutcome,
    Evidence,
    EvidenceType,
    MutationResponse,
)


class _FakeMutationEngine:
    def __init__(self, rate_limit_ms: int = 0):
        self.calls = []

    async def mutate_and_analyze(self, *, url, payload, method, headers=None, cookies=None, baseline_url=None, **kwargs):
        self.calls.append(
            {
                "url": url,
                "payload": payload,
                "method": method,
                "headers": headers,
                "cookies": cookies,
                "baseline_url": baseline_url,
            }
        )

        final_url = url
        if isinstance(url, str) and "{PAYLOAD}" in url:
            final_url = url.replace("{PAYLOAD}", str(payload.value))

        resp = MutationResponse(
            status_code=200,
            headers={},
            body="SQL syntax MySQL",
            body_length=14,
            elapsed_ms=12.0,
            url=final_url,
        )
        resp.evidence = [
            Evidence(
                type=EvidenceType.ERROR_SIGNATURE,
                description="SQL error detected: MySQL syntax error (mysql)",
                confidence=0.85,
                payload_used=str(payload.value),
                response_snippet="SQL syntax",
                metadata={"db_type": "mysql"},
            )
        ]
        resp.outcome = ActionOutcome.SUCCESS
        return resp, ActionOutcome.SUCCESS

    async def close(self):
        return None


@pytest.mark.anyio
async def test_wraith_verify_confirms_sqli_on_query_param(monkeypatch):
    monkeypatch.setattr("core.toolkit.internal_tools.wraith_verify.MutationEngine", _FakeMutationEngine)

    tool = WraithVerifyTool()
    ctx = InternalToolContext(
        target="https://example.com",
        scan_id="scan-1",
        session_id="sess-1",
        existing_findings=[
            {
                "tool": "nuclei_mutating",
                "severity": "HIGH",
                "tags": ["nuclei", "sqli"],
                "metadata": {"url": "https://example.com/api/users?id=1", "template_id": "sqli-template"},
            }
        ],
        knowledge={},
        mode="bounty",
    )

    q: asyncio.Queue[str] = asyncio.Queue()
    findings = await tool.execute("https://example.com", ctx, q)
    assert len(findings) == 1
    assert findings[0]["type"] == "sqli"
    assert findings[0]["metadata"]["verified"] is True
    assert findings[0]["metadata"]["url"] == "https://example.com/api/users?id=1"


@pytest.mark.anyio
async def test_wraith_verify_confirms_sqli_on_path_segment(monkeypatch):
    monkeypatch.setattr("core.toolkit.internal_tools.wraith_verify.MutationEngine", _FakeMutationEngine)

    tool = WraithVerifyTool()
    ctx = InternalToolContext(
        target="https://example.com",
        scan_id="scan-2",
        session_id="sess-2",
        existing_findings=[
            {
                "tool": "nuclei_mutating",
                "severity": "HIGH",
                "tags": ["nuclei", "sqli"],
                "metadata": {"url": "https://example.com/api/users/123", "template_id": "sqli-template"},
            }
        ],
        knowledge={},
        mode="bounty",
    )

    q: asyncio.Queue[str] = asyncio.Queue()
    findings = await tool.execute("https://example.com", ctx, q)
    assert len(findings) == 1
    assert findings[0]["type"] == "sqli"
    assert findings[0]["metadata"]["url"] == "https://example.com/api/users/123"
    assert findings[0]["metadata"]["verification_url"].endswith("/api/users/{PAYLOAD}")

