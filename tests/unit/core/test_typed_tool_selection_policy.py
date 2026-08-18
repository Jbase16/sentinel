from __future__ import annotations

from typing import Any

import pytest

from core.cortex.tool_execution_admission import CanonicalToolSelectionPolicy


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


# Recorded by the live legacy-vs-typed equivalence proof in DB-R1-WO18
# (commit 5e6e422). The legacy runtime is intentionally absent after WO19.
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
def test_typed_policy_preserves_recorded_cal_outcomes(
    context: Any,
    tool: Any,
    expected_allowed: bool,
    expected_policy: str | None,
) -> None:
    decision = CanonicalToolSelectionPolicy().evaluate(context, tool)

    assert decision.allowed is expected_allowed
    if expected_policy is not None:
        assert expected_policy in decision.reason


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
def test_typed_policy_fails_closed_on_recorded_malformed_inputs(
    context: Any,
    tool: Any,
) -> None:
    decision = CanonicalToolSelectionPolicy().evaluate(context, tool)

    assert decision.allowed is False
    assert decision.reason.startswith("TypedToolPolicyInput:")
