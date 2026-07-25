import pytest

from core.base.config import (
    CapabilityModelConfig,
    SentinelConfig,
    StorageConfig,
    get_config,
    set_config,
)
from core.data.risk import RiskEngine


@pytest.fixture(autouse=True)
def _restore_global_config():
    original = get_config()
    yield
    set_config(original)


def _set_test_config(tmp_path, capability_model: CapabilityModelConfig | None = None) -> None:
    config = SentinelConfig(
        storage=StorageConfig(base_dir=tmp_path),
        capability_model=capability_model or CapabilityModelConfig(),
    )
    set_config(config)


def test_time_to_impact_scoring():
    engine = RiskEngine()
    cases = [
        ("confirmed", ["access"], 10.0),
        ("confirmed", ["execution"], 9.0),
        ("confirmed", ["information"], 8.0),
        ("probable", ["execution"], 6.0),
        ("probable", ["information"], 5.0),
        ("hypothesized", ["execution"], 3.0),
        ("hypothesized", ["information"], 2.0),
    ]
    for confirmation, capabilities, expected in cases:
        score = engine._compute_time_to_impact(confirmation, capabilities)
        assert score == expected


def test_three_axis_composite_formula(tmp_path):
    _set_test_config(tmp_path)
    engine = RiskEngine()
    issue = {
        "confirmation_level": "confirmed",
        "capability_types": ["access"],
        "enablement_score": 5.0,
        "enablement_class": "credential_exposure",
    }
    scores = engine.compute_three_axis_priority(issue)

    expected = 0.40 * 10.0 + 0.30 * 5.0 + 0.30 * 9.0
    assert scores["priority_composite"] == round(expected, 2)


def test_three_axis_missing_metadata(tmp_path):
    _set_test_config(tmp_path)
    engine = RiskEngine()
    issue = {
        "confirmation_level": "confirmed",
        "capability_types": ["execution"],
    }
    scores = engine.compute_three_axis_priority(issue)
    assert scores["uncertainty_reduction"] == 0.0
    assert scores["effort_eliminated"] == 2.0
    assert scores["time_to_impact"] == 9.0


def test_three_axis_is_read_only(tmp_path):
    _set_test_config(tmp_path)
    engine = RiskEngine()
    original_scores = dict(engine._scores)
    signal_fired = []
    engine.scores_changed.connect(lambda: signal_fired.append(True))

    engine.compute_three_axis_priority(
        {
            "confirmation_level": "confirmed",
            "capability_types": ["access"],
        }
    )

    assert engine._scores == original_scores
    assert len(signal_fired) == 0


def test_end_to_end_credentials_outrank_hypothesized_ssrf(tmp_path):
    _set_test_config(tmp_path, capability_model=CapabilityModelConfig(three_axis_enabled=True))
    engine = RiskEngine()

    issue_a = {
        "confirmation_level": "confirmed",
        "capability_types": ["access"],
        "enablement_score": 4.0,
        "enablement_class": "credential_exposure",
    }
    issue_b = {
        "confirmation_level": "hypothesized",
        "capability_types": ["execution"],
        "enablement_score": 0.0,
        "enablement_class": "partial_info",
    }

    a_scores = engine.compute_three_axis_priority(issue_a)
    b_scores = engine.compute_three_axis_priority(issue_b)

    assert a_scores["priority_composite"] == 7.9
    assert b_scores["priority_composite"] == 1.8
    assert a_scores["priority_composite"] > (b_scores["priority_composite"] * 4.0)
