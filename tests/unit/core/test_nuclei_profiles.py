from core.scheduler.registry import ToolRegistry as StrategosToolRegistry
from core.toolkit.registry import get_tool_command


def test_nuclei_profiles_use_expected_severity_sets() -> None:
    safe_cmd, _ = get_tool_command("nuclei_safe", "https://example.test")
    mutating_cmd, _ = get_tool_command("nuclei_mutating", "https://example.test")
    legacy_cmd, _ = get_tool_command("nuclei", "https://example.test")

    safe_idx = safe_cmd.index("-severity")
    mutating_idx = mutating_cmd.index("-severity")
    legacy_idx = legacy_cmd.index("-severity")

    assert safe_cmd[safe_idx + 1] == "low"
    assert mutating_cmd[mutating_idx + 1] == "medium,high,critical"
    assert legacy_cmd[legacy_idx + 1] == "low"


def test_strategos_metadata_uses_split_nuclei_profiles() -> None:
    metadata = StrategosToolRegistry.METADATA

    assert "nuclei_safe" in metadata
    assert "nuclei_mutating" in metadata
    assert "nuclei" not in metadata
