"""
Test Policy Management REST API

Tests the full lifecycle: upload → list → get → delete
"""

import pytest
import asyncio
from core.data.db import Database


@pytest.fixture
async def db():
    """Initialize database for testing."""
    db = Database.instance()
    await db.init()
    return db


@pytest.mark.asyncio
async def test_policy_crud_lifecycle(db):
    """Test complete CRUD lifecycle for policies."""

    # 1. Create a policy
    policy_name = "test_block_localhost"
    cal_source = """
    Law BlockLocalhost {
        Claim: "Localhost scans forbidden"
        When: context.target == "localhost"
        Then: DENY "Cannot scan localhost"
    }
    """

    policy_id = await db.save_policy(
        name=policy_name,
        cal_source=cal_source,
        enabled=True
    )

    assert policy_id > 0
    print(f"✓ Created policy with ID {policy_id}")

    # 2. Retrieve the policy
    policy = await db.get_policy_by_name(policy_name)
    assert policy is not None
    assert policy["name"] == policy_name
    assert policy["enabled"] is True
    assert "BlockLocalhost" in policy["cal_source"]
    print(f"✓ Retrieved policy: {policy['name']}")

    # 3. List all policies
    policies = await db.list_policies()
    assert len(policies) >= 1
    assert any(p["name"] == policy_name for p in policies)
    print(f"✓ Listed {len(policies)} policies")

    # 4. Update the policy
    updated = await db.update_policy(policy_name, enabled=False)
    assert updated is True

    policy = await db.get_policy_by_name(policy_name)
    assert policy["enabled"] is False
    print(f"✓ Updated policy (disabled)")

    # 5. Delete the policy
    deleted = await db.delete_policy(policy_name)
    assert deleted is True

    policy = await db.get_policy_by_name(policy_name)
    assert policy is None
    print(f"✓ Deleted policy")


@pytest.mark.asyncio
async def test_policy_uniqueness(db):
    """Test that duplicate policy names are rejected."""

    policy_name = "test_duplicate"
    cal_source = "Law Test { When: true Then: ALLOW \"ok\" }"

    # Create first policy
    await db.save_policy(policy_name, cal_source)

    # Attempt to create duplicate
    with pytest.raises(Exception):  # Should raise integrity error
        await db.save_policy(policy_name, cal_source)

    # Cleanup
    await db.delete_policy(policy_name)
    print(f"✓ Uniqueness constraint enforced")


@pytest.mark.asyncio
async def test_policy_loading_into_arbitrator(db):
    """Test that policies can be loaded from DB into ArbitrationEngine."""

    from core.cortex.arbitration import ArbitrationEngine

    # Create test policy in database
    policy_name = "test_load"
    cal_source = """
    Law TestLoad {
        When: context.test == "yes"
        Then: DENY "Test blocked"
    }
    """

    await db.save_policy(policy_name, cal_source, enabled=True)

    # Load into arbitrator
    arbitrator = ArbitrationEngine()
    policies = await db.list_policies()

    loaded_count = 0
    for policy in policies:
        if policy["enabled"]:
            loaded = arbitrator.load_cal_policy(policy["cal_source"])
            loaded_count += len(loaded)

    assert loaded_count > 0

    # Verify policy is registered
    policy_names = arbitrator.list_policies()
    assert "CAL:TestLoad" in policy_names

    # Cleanup
    await db.delete_policy(policy_name)
    print(f"✓ Loaded {loaded_count} policies into arbitrator")


@pytest.mark.asyncio
async def test_policy_update_partial(db):
    """Test that partial updates work correctly."""

    policy_name = "test_partial"
    cal_source_v1 = "Law V1 { When: true Then: ALLOW \"v1\" }"
    cal_source_v2 = "Law V2 { When: true Then: ALLOW \"v2\" }"

    # Create policy
    await db.save_policy(policy_name, cal_source_v1, enabled=True)

    # Update only source
    await db.update_policy(policy_name, cal_source=cal_source_v2)
    policy = await db.get_policy_by_name(policy_name)
    assert "V2" in policy["cal_source"]
    assert policy["enabled"] is True  # Should remain True

    # Update only enabled status
    await db.update_policy(policy_name, enabled=False)
    policy = await db.get_policy_by_name(policy_name)
    assert policy["enabled"] is False
    assert "V2" in policy["cal_source"]  # Source unchanged

    # Cleanup
    await db.delete_policy(policy_name)
    print(f"✓ Partial updates work correctly")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
