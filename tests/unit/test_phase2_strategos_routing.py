import pytest

from core.contracts.schemas import InsightActionType, InsightPayload
from core.scheduler.strategos import ScanContext, Strategos


@pytest.mark.anyio
async def test_generate_insight_routes_confirmed_access_to_confirmed_exposure():
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")

    insight = await strategos._generate_insights_from_finding(
        {
            "id": "f-1",
            "type": "credential_dump",
            "target": "https://example.com",
            "confirmation_level": "confirmed",
            "capability_types": ["access"],
            "base_score": 9.5,
        }
    )

    assert insight is not None
    assert insight.action_type == InsightActionType.CONFIRMED_EXPOSURE
    assert insight.confidence == pytest.approx(0.95)
    assert insight.priority == 0


@pytest.mark.anyio
async def test_generate_insight_deprioritizes_hypothesized_execution():
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")

    insight = await strategos._generate_insights_from_finding(
        {
            "id": "f-2",
            "type": "ssrf",
            "target": "https://example.com",
            "confirmation_level": "hypothesized",
            "capability_types": ["execution"],
            "base_score": 9.2,
        }
    )

    assert insight is not None
    assert insight.action_type == InsightActionType.CONFIRMED_VULN
    assert insight.confidence == pytest.approx(0.40)
    assert insight.priority == 2


@pytest.mark.anyio
async def test_confirmed_exposure_handler_updates_knowledge():
    strategos = Strategos()
    strategos.context = ScanContext(target="https://example.com")

    insight = InsightPayload(
        insight_id="insight-1",
        scan_id=strategos.context.scan_id,
        action_type=InsightActionType.CONFIRMED_EXPOSURE,
        confidence=0.95,
        target="https://example.com",
        summary="Confirmed Access Capability: credential_dump at https://example.com",
        details={"finding_type": "credential_dump"},
        source_tool="test",
        priority=0,
    )

    await strategos._handle_confirmed_exposure(insight)

    assert "confirmed_exposures" in strategos.context.knowledge
    assert len(strategos.context.knowledge["confirmed_exposures"]) == 1
    entry = strategos.context.knowledge["confirmed_exposures"][0]
    assert entry["target"] == "https://example.com"
    assert entry["finding_type"] == "credential_dump"
