from pathlib import Path

import pytest

from core.base.config import (
    CapabilityModelConfig,
    SentinelConfig,
    StorageConfig,
    get_config,
    set_config,
)
from core.cortex.causal_graph import _get_effort_eliminated_table


@pytest.fixture(autouse=True)
def _restore_global_config():
    original = get_config()
    yield
    set_config(original)


def test_capability_model_config_defaults():
    config = CapabilityModelConfig()
    assert config.three_axis_enabled is False
    assert config.time_to_impact_weight == 0.40
    assert config.uncertainty_reduction_weight == 0.30
    assert config.effort_eliminated_weight == 0.30
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.0


def test_capability_model_config_yaml(tmp_path):
    yaml_file = tmp_path / "capability.yaml"
    yaml_file.write_text(
        "effort_eliminated:\n"
        "  credential_exposure: 9.5\n"
        "  source_code: 7.5\n",
        encoding="utf-8",
    )
    config = CapabilityModelConfig.from_env_and_yaml(yaml_file)
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.5
    assert config.effort_eliminated_by_capability["source_code"] == 7.5


def test_capability_model_config_env_override(monkeypatch, tmp_path):
    yaml_file = tmp_path / "capability.yaml"
    yaml_file.write_text("time_to_impact_weight: 0.50\n", encoding="utf-8")

    monkeypatch.setenv("SENTINEL_CM_TTI_WEIGHT", "0.35")
    monkeypatch.setenv("SENTINEL_CM_UR_WEIGHT", "0.35")
    monkeypatch.setenv("SENTINEL_CM_EE_WEIGHT", "0.30")

    config = CapabilityModelConfig.from_env_and_yaml(yaml_file)
    assert config.time_to_impact_weight == 0.35
    assert config.uncertainty_reduction_weight == 0.35
    assert config.effort_eliminated_weight == 0.30


def test_capability_model_config_weight_validation(monkeypatch):
    monkeypatch.setenv("SENTINEL_CM_TTI_WEIGHT", "0.50")
    monkeypatch.setenv("SENTINEL_CM_UR_WEIGHT", "0.50")
    monkeypatch.setenv("SENTINEL_CM_EE_WEIGHT", "0.50")
    with pytest.raises(ValueError, match="must sum to 1.0"):
        CapabilityModelConfig.from_env_and_yaml()


def test_capability_model_config_missing_yaml():
    config = CapabilityModelConfig.from_env_and_yaml(Path("/nonexistent.yaml"))
    assert config.three_axis_enabled is False
    assert config.effort_eliminated_by_capability["credential_exposure"] == 9.0


def test_causal_graph_reads_config_effort(tmp_path):
    custom_cm = CapabilityModelConfig(
        effort_eliminated_by_capability={
            "credential_exposure": 5.0,
            "source_code": 7.0,
            "topology": 6.0,
            "confirmed_injection": 4.0,
            "stack_disclosure": 3.0,
            "port_disclosure": 2.0,
            "partial_info": 1.0,
        }
    )
    test_config = SentinelConfig(
        storage=StorageConfig(base_dir=tmp_path),
        capability_model=custom_cm,
    )
    set_config(test_config)

    table = _get_effort_eliminated_table()
    assert table["credential_exposure"] == 5.0
    assert table["partial_info"] == 1.0


def test_effort_table_fallback(monkeypatch):
    def _raise_config_error():
        raise RuntimeError("config unavailable")

    monkeypatch.setattr("core.base.config.get_config", _raise_config_error)
    table = _get_effort_eliminated_table()
    assert table["credential_exposure"] == 9.0
    assert table["partial_info"] == 2.0
