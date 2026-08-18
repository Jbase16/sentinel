from __future__ import annotations

from typing import Any

import pytest

from core.cortex.arbitration import ArbitrationEngine
from core.cortex.policy import Verdict
from core.cortex.tool_execution_admission import CanonicalToolSelectionPolicy
from core.scheduler.decisions import DecisionPoint, DecisionType


def _context(**overrides: Any) -> dict[str, Any]:
    value = {
        "phase_index": 2,
        "knowledge": {"tags": []},
        "active_tools": 0,
        "max_concurrent": 3,
    }
    value.update(overrides)
    return value


def _tool(**overrides: Any) -> dict[str, Any]:
    value = {
        "phase": 1,
        "gates": [],
        "resource_cost": 1,
    }
    value.update(overrides)
    return value


@pytest.fixture()
def legacy_cal() -> ArbitrationEngine:
    engine = ArbitrationEngine()
    policies = engine.load_cal_file("assets/laws/constitution.cal")
    assert [policy.name for policy in policies] == [
        "CAL:PassiveBeforeActive",
        "CAL:EvidenceGates",
        "CAL:ResourceAwareness",
    ]
    return engine


def _legacy_allows(engine: ArbitrationEngine, context: Any, tool: Any) -> tuple[bool, str]:
    if isinstance(context, dict):
        review_context: Any = {**context, "tool": tool}
    else:
        review_context = context
    decision = DecisionPoint.create(
        DecisionType.TOOL_SELECTION,
        chosen="fixture-tool",
        reason="CAL equivalence fixture",
        context=review_context,
    )
    judgment = engine.review(decision, review_context)
    return judgment.verdict != Verdict.VETO, judgment.reason


@pytest.mark.parametrize(
    ("context", "tool", "expected_allowed", "expected_policy"),
    [
        pytest.param(
            _context(phase_index=0),
            _tool(phase=2),
            False,
            "PassiveBeforeActive",
            id="passive-before-active-deny",
        ),
        pytest.param(
            _context(phase_index=1),
            _tool(phase=1),
            True,
            None,
            id="passive-before-active-allow",
        ),
        pytest.param(
            _context(knowledge={"tags": ["protocol:http"]}),
            _tool(gates=["protocol:http", "auth:session"]),
            False,
            "EvidenceGates",
            id="evidence-gates-deny",
        ),
        pytest.param(
            _context(knowledge={"tags": ["protocol:http", "auth:session"]}),
            _tool(gates=["auth:session", "protocol:http"]),
            True,
            None,
            id="evidence-gates-allow",
        ),
        pytest.param(
            _context(active_tools=2, max_concurrent=3),
            _tool(resource_cost=2),
            False,
            "ResourceAwareness",
            id="resource-awareness-deny",
        ),
        pytest.param(
            _context(active_tools=1, max_concurrent=3),
            _tool(resource_cost=2),
            True,
            None,
            id="resource-awareness-allow-at-limit",
        ),
    ],
)
def test_typed_policy_matches_cal_laws(
    legacy_cal: ArbitrationEngine,
    context: Any,
    tool: Any,
    expected_allowed: bool,
    expected_policy: str | None,
) -> None:
    old_allowed, old_reason = _legacy_allows(legacy_cal, context, tool)
    typed = CanonicalToolSelectionPolicy().evaluate(context, tool)

    assert old_allowed is expected_allowed
    assert typed.allowed is expected_allowed
    assert old_allowed is typed.allowed
    if expected_policy is not None:
        assert expected_policy in old_reason
        assert expected_policy in typed.reason


@pytest.mark.parametrize(
    ("context", "tool"),
    [
        pytest.param(None, _tool(), id="non-dict-context-none"),
        pytest.param([], _tool(), id="non-dict-context-list"),
        pytest.param(_context(), None, id="non-dict-tool-none"),
        pytest.param(_context(), [], id="non-dict-tool-list"),
        pytest.param(_context(phase_index="0"), _tool(), id="malformed-passive-phase"),
        pytest.param(
            _context(knowledge={"tags": "protocol:http"}),
            _tool(),
            id="malformed-evidence-tags",
        ),
        pytest.param(
            _context(),
            _tool(gates="protocol:http"),
            id="malformed-evidence-gates",
        ),
        pytest.param(
            _context(max_concurrent=None),
            _tool(),
            id="malformed-resource-limit",
        ),
        pytest.param(
            _context(),
            _tool(resource_cost="1"),
            id="malformed-resource-cost",
        ),
        pytest.param(
            {"phase_index": 2, "active_tools": 0, "max_concurrent": 3},
            _tool(),
            id="malformed-missing-knowledge",
        ),
    ],
)
def test_cal_and_typed_policy_fail_closed_on_malformed_input(
    legacy_cal: ArbitrationEngine,
    context: Any,
    tool: Any,
) -> None:
    old_allowed, _ = _legacy_allows(legacy_cal, context, tool)
    typed = CanonicalToolSelectionPolicy().evaluate(context, tool)

    assert old_allowed is False
    assert typed.allowed is False
    assert old_allowed is typed.allowed
