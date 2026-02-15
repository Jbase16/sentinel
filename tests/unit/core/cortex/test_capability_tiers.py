from core.cortex.capability_tiers import CapabilityGate, CapabilityTier, ExecutionMode


def test_dry_run_does_not_consume_budget() -> None:
    gate = CapabilityGate(mode=ExecutionMode.RESEARCH)
    target = "https://example.test"
    gate.add_scope_target(target)

    budget_before = gate.get_budget(target)
    assert budget_before.remaining_tokens == 100
    assert budget_before.actions_taken == 0

    result = gate.evaluate_tool(target, "nikto", dry_run=True)
    assert result.approved is True
    assert result.budget_cost == 1

    budget_after = gate.get_budget(target)
    assert budget_after.remaining_tokens == 100
    assert budget_after.actions_taken == 0


def test_real_evaluation_consumes_budget() -> None:
    gate = CapabilityGate(mode=ExecutionMode.RESEARCH)
    target = "https://example.test"
    gate.add_scope_target(target)

    result = gate.evaluate_tool(target, "nikto")
    assert result.approved is True
    assert result.budget_cost == 1

    budget = gate.get_budget(target)
    assert budget.remaining_tokens == 99
    assert budget.actions_taken == 1
    assert budget.actions_by_tier[CapabilityTier.T2a_SAFE_VERIFY] == 1


def test_nuclei_mutating_blocked_in_research_mode() -> None:
    gate = CapabilityGate(mode=ExecutionMode.RESEARCH)
    target = "https://example.test"
    gate.add_scope_target(target)

    result = gate.evaluate_tool(target, "nuclei_mutating", dry_run=True)
    assert result.approved is False
    assert "not allowed in research mode" in result.reason


def test_nuclei_safe_allowed_in_research_mode() -> None:
    gate = CapabilityGate(mode=ExecutionMode.RESEARCH)
    target = "https://example.test"
    gate.add_scope_target(target)

    result = gate.evaluate_tool(target, "nuclei_safe", dry_run=True)
    assert result.approved is True
    assert result.budget_cost == 1


def test_nuclei_mutating_allowed_in_bounty_without_operator_approval() -> None:
    gate = CapabilityGate(mode=ExecutionMode.BOUNTY)
    target = "https://example.test"
    gate.add_scope_target(target)

    result = gate.evaluate_tool(target, "nuclei_mutating", dry_run=True)
    assert result.approved is True
    assert result.budget_cost == 5
    assert result.requires_operator_approval is False


def test_t3_allowed_in_bounty_without_operator_approval() -> None:
    gate = CapabilityGate(mode=ExecutionMode.BOUNTY)
    target = "https://example.test"
    gate.add_scope_target(target)

    result = gate.evaluate_tool(target, "rce_proof", dry_run=True)
    assert result.approved is True
    assert result.budget_cost == 10
    assert result.requires_operator_approval is False


def test_t4_allowed_in_bounty_without_operator_approval() -> None:
    gate = CapabilityGate(mode=ExecutionMode.BOUNTY)
    target = "https://example.test"
    gate.add_scope_target(target)

    result = gate.evaluate_tool(target, "data_exfil", dry_run=True)
    assert result.approved is True
    assert result.budget_cost == 20
    assert result.requires_operator_approval is False


def test_reset_target_budget_reinitializes_budget_lifecycle() -> None:
    gate = CapabilityGate(mode=ExecutionMode.RESEARCH)
    target = "https://example.test"
    gate.add_scope_target(target)

    gate.evaluate(target, CapabilityTier.T2a_SAFE_VERIFY)
    before_reset = gate.get_budget(target)
    assert before_reset.remaining_tokens == 99
    assert before_reset.actions_taken == 1

    gate.reset_target_budget(target)
    after_reset = gate.get_budget(target)
    assert after_reset.remaining_tokens == 100
    assert after_reset.actions_taken == 0
