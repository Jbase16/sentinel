"""
Unit tests for Project MIMIC (The Shape Shifter).
Migrated from tests/verification/verify_mimic_miner.py and inferencer.py
"""
import pytest
from unittest.mock import MagicMock
from core.sentient.mimic.route_miner import RouteMiner
from core.sentient.mimic.model_inferencer import ModelInferencer
from core.sentient.mimic.types import DataType

@pytest.fixture
def miner():
    return RouteMiner()

def test_route_clustering(miner):
    """Verify that multiple IDs cluster to {id}."""
    
    # Dataset 1: User IDs
    urls_ids = ["/users/1", "/users/2", "/users/999", "/users/1024"]
    for url in urls_ids:
        ep = miner.ingest("GET", url)
        assert ep.path_template == "/users/{id}"
        
    # Dataset 2: UUIDs
    urls_uuids = [
        "/files/550e8400-e29b-41d4-a716-446655440000",
        "/files/123e4567-e89b-12d3-a456-426614174000"
    ]
    for url in urls_uuids:
        ep = miner.ingest("GET", url)
        assert ep.path_template == "/files/{id}"

def test_mixed_templates(miner):
    """Verify literal vs parameter distinction."""
    
    # Literal
    ep = miner.ingest("GET", "/users/profile")
    assert ep.path_template == "/users/profile"
    
    # Mixed
    ep = miner.ingest("GET", "/users/1/details")
    assert ep.path_template == "/users/{id}/details"

def test_model_inference_simple():
    """Verify basic JSON schema inference."""
    payload = {
        "id": 123,
        "name": "Alice",
        "is_admin": False
    }
    schema = ModelInferencer.infer(payload)
    
    assert schema.type == DataType.OBJECT
    assert schema.properties["id"].type == DataType.INTEGER
    assert schema.properties["name"].type == DataType.STRING
    assert schema.properties["is_admin"].type == DataType.BOOLEAN

def test_model_inference_nested():
    """Verify nested object and array inference."""
    payload = {
        "user": {
            "id": 1,
            "roles": ["admin", "editor"],
            "settings": {
                "theme": "dark"
            }
        }
    }
    schema = ModelInferencer.infer(payload)
    
    user = schema.properties["user"]
    assert user.type == DataType.OBJECT
    
    roles = user.properties["roles"]
    assert roles.type == DataType.ARRAY
    assert roles.items.type == DataType.STRING
    
    settings = user.properties["settings"]
    assert settings.properties["theme"].type == DataType.STRING
