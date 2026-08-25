"""Source contracts for the native ordinary-Scan Family-C profile."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "ui" / "Sources" / "Models" / "SharedModels.swift"
CLIENT = ROOT / "ui" / "Sources" / "Services" / "SentinelAPIClient.swift"
SCAN = ROOT / "ui" / "Sources" / "Views" / "Scan" / "ScanControlView.swift"
SCHEME = (
    ROOT
    / "ui"
    / "SentinelForge.xcodeproj"
    / "xcshareddata"
    / "xcschemes"
    / "SentinelForge-Acceptance.xcscheme"
)


def test_native_model_carries_bounded_role_profile() -> None:
    source = MODELS.read_text(encoding="utf-8")

    assert 'case roleMonotonicity = "role_monotonicity"' in source
    assert 'case behavioralPhaseOnly = "behavioral_phase_only"' in source
    assert "public let roleMonotonicityJSON: String?" in source


def test_native_client_serializes_role_object_and_completion() -> None:
    source = CLIENT.read_text(encoding="utf-8")
    start = source.index("if let behavioralOneClick")
    end = source.index('body["behavioral_one_click"] = profile', start)
    block = source[start:end]

    assert '"completion": behavioralOneClick.completion.rawValue' in block
    assert "JSONSerialization.jsonObject(with: data)" in block
    assert 'profile["role_monotonicity"] = roleObject' in block


def test_role_profile_requires_both_workflows_and_stops_after_behavior() -> None:
    source = SCAN.read_text(encoding="utf-8")
    profile = source.index("if behavioralProfileMode == .roleMonotonicity")
    bounded = source.index("completion: .behavioralPhaseOnly", profile)
    role_json = source.index("roleMonotonicityJSON: roleJSON", bounded)
    workflows = source.index("private var requiredBehavioralWorkflows")
    controlled = source.index("Self.controlledBehavioralWorkflow", workflows)
    role = source.index("Self.roleMonotonicityWorkflow", controlled)
    eligibility = source.index("requiredBehavioralWorkflows.allSatisfy", role)

    assert profile < bounded < role_json < workflows < controlled < role < eligibility


def test_acceptance_scheme_enables_all_role_execution_gates() -> None:
    source = SCHEME.read_text(encoding="utf-8")

    for gate in (
        "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK",
        "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM",
        "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE",
        "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION",
    ):
        start = source.index(f'key = "{gate}"')
        end = source.index("</EnvironmentVariable>", start)
        assert 'value = "1"' in source[start:end]
        assert 'isEnabled = "YES"' in source[start:end]
