from pathlib import Path

import pytest

from core.cortex.execution_policy import DENIED_STATUS, ExecutionPolicy, PolicyExecutor
from core.cortex.tool_execution_admission import (
    CanonicalToolExecutionAdmission,
    ToolExecutionProposal,
    ToolProposalAdmissionDenied,
    ToolPolicySnapshot,
)


@pytest.mark.asyncio
async def test_proposals_require_one_bounded_policy_executor_claim():
    local_target = "http://127.0.0.1:39871"
    requests = []

    async def mock_transport(method, url, body=None, **_kwargs):
        requests.append((method, url, body))
        return 200, {"findings": []}

    proposal = ToolExecutionProposal.build(
        source="ai_action_dispatcher",
        tool="nmap",
        args=("-sV",),
        target=local_target,
        reason="operator approved local-lab service inventory",
    )

    passive = CanonicalToolExecutionAdmission(
        executor=PolicyExecutor(
            mock_transport,
            ExecutionPolicy(
                "passive",
                scope_filter=lambda url: url == local_target,
            ),
        ),
        allowed_tools={"nmap"},
        safe_tools=set(),
    )
    with pytest.raises(ToolProposalAdmissionDenied, match="AUTHZ_PROBE"):
        passive.claim(proposal)
    assert requests == []

    lab = CanonicalToolExecutionAdmission(
        executor=PolicyExecutor(
            mock_transport,
            ExecutionPolicy(
                "lab",
                scope_filter=lambda url: url == local_target,
            ),
        ),
        allowed_tools={"nmap"},
        safe_tools=set(),
    )
    status, response = await lab.execute_claimed(proposal, None)
    assert status == DENIED_STATUS
    assert response["_policy_denied"] == "proposal_execution_claim_unavailable"
    assert requests == []

    claim = lab.claim(proposal)
    assert claim.max_requests == 1
    status, response = await lab.execute_claimed(proposal, claim)
    assert status == 200
    assert response == {"findings": []}
    assert requests == [
        (
            "EXECUTE",
            local_target,
            {
                "proposal_ref": proposal.proposal_ref,
                "source": "ai_action_dispatcher",
                "tool": "nmap",
                "args": ["-sV"],
            },
        )
    ]

    replay_status, _ = await lab.execute_claimed(proposal, claim)
    assert replay_status == DENIED_STATUS
    assert len(requests) == 1


def test_ai_and_strategos_share_the_canonical_router_adapter():
    source = Path("core/server/routers/scans.py").read_text()
    assert "CanonicalToolExecutionAdmission" in source
    assert 'source="ai_action_dispatcher"' in source
    assert 'source: str = "strategos"' in source
    assert source.count("admit_and_execute(proposal)") == 1


def test_strategos_proposals_require_a_passing_typed_policy_snapshot():
    local_target = "http://127.0.0.1:39871"

    async def mock_transport(method, url, body=None, **_kwargs):
        raise AssertionError("claim admission must not touch transport")

    admission = CanonicalToolExecutionAdmission(
        executor=PolicyExecutor(
            mock_transport,
            ExecutionPolicy("lab", scope_filter=lambda url: url == local_target),
        ),
        allowed_tools={"nmap"},
        safe_tools=set(),
    )

    missing_snapshot = ToolExecutionProposal.build(
        source="strategos",
        tool="nmap",
        args=(),
        target=local_target,
        reason="typed policy admission fixture",
    )
    with pytest.raises(ToolProposalAdmissionDenied, match="malformed scheduling policy snapshot"):
        admission.claim(missing_snapshot)

    blocked_snapshot = ToolPolicySnapshot.from_inputs(
        {
            "phase_index": 0,
            "knowledge": {"tags": []},
            "active_tools": 0,
            "max_concurrent": 3,
        },
        {"phase": 3, "gates": [], "resource_cost": 1},
    )
    blocked = ToolExecutionProposal.build(
        source="strategos",
        tool="nmap",
        args=(),
        target=local_target,
        reason="typed policy admission fixture",
        policy_snapshot=blocked_snapshot,
    )
    with pytest.raises(ToolProposalAdmissionDenied, match="PassiveBeforeActive"):
        admission.claim(blocked)

    passing_snapshot = ToolPolicySnapshot.from_inputs(
        {
            "phase_index": 3,
            "knowledge": {"tags": []},
            "active_tools": 0,
            "max_concurrent": 3,
        },
        {"phase": 3, "gates": [], "resource_cost": 1},
    )
    passing = ToolExecutionProposal.build(
        source="strategos",
        tool="nmap",
        args=(),
        target=local_target,
        reason="typed policy admission fixture",
        policy_snapshot=passing_snapshot,
    )
    assert admission.claim(passing).max_requests == 1
