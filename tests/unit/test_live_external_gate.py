"""The manual external scan probe must refuse default execution before HTTP."""

import runpy
from pathlib import Path

import pytest
import requests


def test_scan_flow_script_requires_explicit_live_opt_in(monkeypatch):
    monkeypatch.delenv("SENTINEL_RUN_LIVE", raising=False)

    def unexpected_post(*args, **kwargs):
        pytest.fail("external scan POST attempted without opt-in")

    monkeypatch.setattr(requests, "post", unexpected_post)
    script = Path(__file__).resolve().parents[1] / "integration" / "test_scan_flow.py"
    with pytest.raises(SystemExit, match="SENTINEL_RUN_LIVE=1"):
        runpy.run_path(str(script), run_name="__main__")
