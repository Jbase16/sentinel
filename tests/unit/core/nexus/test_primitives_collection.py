import pytest

from core.aegis.nexus.primitives import (
    PrimitiveCollector,
    PrimitiveType,
    collect_primitives,
)


def test_collector_maps_findings_to_primitives():
    collector = PrimitiveCollector(safe_mode=False)
    findings = [
        {
            "id": "f-open-redirect",
            "type": "open redirect",
            "target": "https://example.com",
            "message": "Open redirect via next parameter",
            "severity": "medium",
            "tool": "nikto",
        },
        {
            "id": "f-idor",
            "type": "idor",
            "target": "https://example.com",
            "message": "Potential insecure direct object reference",
            "severity": "high",
            "tool": "nikto",
        },
    ]

    inventory = collector.collect(findings, "example.com")
    primitive_types = {primitive.type for primitive in inventory.primitives}

    assert PrimitiveType.OPEN_REDIRECT in primitive_types
    assert PrimitiveType.IDOR_PATTERN in primitive_types
    assert len(inventory.primitives) == 2


def test_collector_safe_mode_blocks_high_risk_primitives():
    collector = PrimitiveCollector(safe_mode=True)
    findings = [
        {
            "id": "f-deser",
            "type": "deserialization",
            "target": "https://example.com",
            "message": "Insecure deserialization endpoint",
            "severity": "high",
            "tool": "nikto",
        }
    ]

    inventory = collector.collect(findings, "example.com")
    assert inventory.primitives == []


@pytest.mark.asyncio
async def test_collect_primitives_helper_accepts_supplied_findings():
    findings = [
        {
            "id": "f-cors",
            "type": "cors",
            "target": "https://example.com",
            "message": "Access-Control-Allow-Origin: * with credentials",
            "severity": "medium",
            "tool": "httpx",
        }
    ]

    primitives = await collect_primitives(
        "example.com",
        findings=findings,
        safe_mode=False,
    )
    assert len(primitives) == 1
    assert primitives[0].type == PrimitiveType.WEAK_CORS
