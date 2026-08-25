"""Safety contracts for the isolated visual-acceptance launch profile."""

from pathlib import Path
from xml.etree import ElementTree

import yaml


ROOT = Path(__file__).resolve().parents[2]
PROJECT_SPEC = ROOT / "ui" / "project.yml"
SCHEMES = ROOT / "ui" / "SentinelForge.xcodeproj" / "xcshareddata" / "xcschemes"

REQUIRED_ACCEPTANCE_ENV = {
    "SENTINEL_ACCEPTANCE_MODE": "1",
    "SENTINEL_API_PORT": "8766",
    "SENTINEL_CA_BUNDLE": (
        "../sentinel-visual-acceptance-lab/var/caddy/caddy/pki/authorities/"
        "local/root.crt"
    ),
    "SENTINELFORGE_BEHAVIOR_PRIMARY": "1",
    "SENTINELFORGE_BEHAVIOR_INTERACTION_ACQUISITION": "1",
    "SENTINELFORGE_BEHAVIOR_INTERACTION_RENDER": "1",
    "SENTINELFORGE_BEHAVIOR_INTERACTION_ADAPTIVE": "1",
    "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_ONE_CLICK": "1",
    "SENTINELFORGE_BEHAVIOR_ROLE_MONOTONICITY_EXECUTION_CLAIM": "1",
    "SENTINELFORGE_BEHAVIOR_ROLE_MEMBERSHIP_LIFECYCLE": "1",
    "SENTINELFORGE_BEHAVIOR_ROLE_PROTECTED_EFFECT_EXECUTION": "1",
}
ACTIVE_BEHAVIOR_ENV = {
    name
    for name in REQUIRED_ACCEPTANCE_ENV
    if name.startswith("SENTINELFORGE_BEHAVIOR_")
}


def _scheme_environment(name: str) -> dict[str, str]:
    root = ElementTree.parse(SCHEMES / f"{name}.xcscheme").getroot()
    return {
        item.attrib["key"]: item.attrib["value"]
        for item in root.findall("./LaunchAction/EnvironmentVariables/EnvironmentVariable")
        if item.attrib.get("isEnabled") == "YES"
    }


def test_acceptance_project_spec_matches_committed_scheme() -> None:
    spec = yaml.safe_load(PROJECT_SPEC.read_text(encoding="utf-8"))
    spec_environment = spec["schemes"]["SentinelForge-Acceptance"]["run"][
        "environmentVariables"
    ]
    scheme_environment = _scheme_environment("SentinelForge-Acceptance")

    assert REQUIRED_ACCEPTANCE_ENV.items() <= spec_environment.items()
    assert REQUIRED_ACCEPTANCE_ENV.items() <= scheme_environment.items()
    assert spec_environment == scheme_environment


def test_standard_scheme_does_not_grant_behavioral_execution_authority() -> None:
    assert ACTIVE_BEHAVIOR_ENV.isdisjoint(_scheme_environment("SentinelForge"))


def test_acceptance_scheme_keeps_tls_verification_enabled() -> None:
    environment = _scheme_environment("SentinelForge-Acceptance")

    assert environment.get("SENTINEL_TLS_VERIFY", "true").lower() != "false"
