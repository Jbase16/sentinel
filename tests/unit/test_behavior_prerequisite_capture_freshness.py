from dataclasses import replace

import pytest

from core.behavior.prerequisite_capture_freshness import (
    GraphBoundCaptureFreshnessBinding,
    GraphBoundCaptureFreshnessDenied,
)

ORIGIN = "https://api.example.test"


def _records(*, object_id: str, token: str, status: int = 200):
    return [
        {
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows",
            "request_body": '{"name":"owned"}',
            "response_status": 201,
            "response_body": (
                f'{{"id":"{object_id}","token":"{token}"}}'
            ),
        },
        {
            "method": "POST",
            "url": f"{ORIGIN}/api/workflows/{object_id}/export",
            "request_body": f'{{"token":"{token}"}}',
            "response_status": status,
            "response_body": '{"exported":true}',
        },
    ]


def _binding(**overrides):
    values = {
        "prior_source_records": _records(
            object_id="prior-source-object",
            token="prior-source-token",
        ),
        "prior_peer_records": _records(
            object_id="prior-peer-object",
            token="prior-peer-token",
        ),
        "current_source_records": _records(
            object_id="current-source-object",
            token="current-source-token",
        ),
        "current_peer_records": _records(
            object_id="current-peer-object",
            token="current-peer-token",
        ),
        "target_origin": ORIGIN,
        "source_world_id": "source-persona",
        "peer_world_id": "peer-persona",
    }
    values.update(overrides)
    return GraphBoundCaptureFreshnessBinding.build(**values).bind_selection(
        prior_selection={"family": "omission", "terminal": "export"},
        current_selection={"family": "omission", "terminal": "export"},
    )


def test_dynamic_values_may_rotate_while_structure_is_revalidated():
    binding = _binding()

    assert binding.current_capture_revalidated is True
    assert binding.selection_revalidated is True
    assert binding.prior_source_snapshot_ref == (
        binding.current_source_snapshot_ref
    )
    assert binding.prior_peer_snapshot_ref == binding.current_peer_snapshot_ref
    assert binding.prior_source_artifact_ref != (
        binding.current_source_capture_ref
    )
    assert binding.prior_peer_artifact_ref != binding.current_peer_capture_ref
    assert binding.target_requests_sent == 0
    assert binding.backend_dispatch_authority is False
    assert binding.promotion_authority is False
    assert binding.finding_authority is False
    assert binding.retry_authority is False

    encoded = str(binding.to_dict())
    assert "prior-source-token" not in encoded
    assert "current-source-token" not in encoded
    assert "prior-source-object" not in encoded
    assert "current-source-object" not in encoded


def test_response_state_drift_is_refused():
    with pytest.raises(
        GraphBoundCaptureFreshnessDenied,
        match="graph_bound_prior_capture_is_stale",
    ):
        _binding(
            current_source_records=_records(
                object_id="current-source-object",
                token="current-source-token",
                status=409,
            )
        )


def test_capture_origin_drift_is_refused():
    current = _records(
        object_id="current-source-object",
        token="current-source-token",
    )
    current[0] = {**current[0], "url": "https://other.example/api/workflows"}

    with pytest.raises(
        GraphBoundCaptureFreshnessDenied,
        match="graph_bound_current_source_capture_origin_mismatch",
    ):
        _binding(current_source_records=current)


def test_binding_identity_rejects_tampering():
    binding = _binding()

    with pytest.raises(
        ValueError,
        match="graph-bound capture freshness binding is invalid",
    ):
        replace(binding, source_record_count=binding.source_record_count + 1)


def test_changed_current_selection_is_refused():
    binding = _binding()

    with pytest.raises(
        GraphBoundCaptureFreshnessDenied,
        match="graph_bound_prior_capture_selection_is_stale",
    ):
        binding.bind_selection(
            prior_selection={"family": "omission", "terminal": "export"},
            current_selection={"family": "reordering", "terminal": "export"},
        )
