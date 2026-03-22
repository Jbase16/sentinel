"""
Verification Script for Project MIMIC Integration.

Tests the MimicSession pipeline: asset ingestion -> route mining -> event emission.
"""
import asyncio
from unittest.mock import MagicMock, call
from core.base.sequence import GlobalSequenceAuthority
from core.mimic.models import Asset, sha256_bytes
from core.mimic.session import MimicSession


def run_test():
    print("MIMIC Integration Test (core.mimic pipeline)")

    # 0. Initialize sequence authority (bypasses DB for testing)
    GlobalSequenceAuthority.reset_for_testing()
    GlobalSequenceAuthority.initialize_for_testing(start=1)

    # 1. Setup mock EventBus
    bus = MagicMock()

    session = MimicSession(
        scan_id="test-integration",
        bus=bus,
    )

    # 2. Create a synthetic JS asset with known routes
    js_content = b'''
    fetch("/api/users")
    axios.post("/api/orders")
    fetch("/admin/settings")
    const key = "AKIAIOSFODNN7EXAMPLE"
    '''

    asset = Asset(
        asset_id="test-asset-001",
        url="https://example.com/app.js",
        content_type="application/javascript",
        size_bytes=len(js_content),
        sha256=sha256_bytes(js_content),
        content=js_content,
    )

    # 3. Ingest the asset
    asyncio.run(session.ingest_asset(asset=asset))

    # 4. Verify routes were discovered
    assert "/api/users" in session.routes, f"Missing /api/users in {session.routes}"
    assert "/api/orders" in session.routes, f"Missing /api/orders in {session.routes}"
    print("  Routes discovered: OK")

    # 5. Verify hidden routes were flagged
    assert "/admin/settings" in session.hidden_routes, f"Missing hidden /admin/settings"
    print("  Hidden routes flagged: OK")

    # 6. Verify secrets were detected
    assert len(session.secrets) > 0, "No secrets detected"
    assert any(s.secret_type == "aws_access_key_id" for s in session.secrets)
    print("  Secrets detected: OK")

    # 7. Verify events were emitted
    assert bus.emit.call_count > 0, "No events emitted"
    event_types = [c.args[0].type for c in bus.emit.call_args_list]
    print(f"  Events emitted: {len(event_types)}")

    # 8. Finalize and check summary
    summary = session.finalize()
    assert summary.assets_analyzed == 1
    assert summary.routes_found >= 2
    assert summary.hidden_routes_found >= 1
    assert summary.secrets_found >= 1
    print(f"  Summary: {summary.assets_analyzed} assets, "
          f"{summary.routes_found} routes, "
          f"{summary.hidden_routes_found} hidden, "
          f"{summary.secrets_found} secrets")

    # 9. Shutdown
    session.shutdown()
    assert len(session.assets) == 0, "Assets not cleared after shutdown"
    print("  Shutdown: OK")

    print("\nMIMIC Integration: all checks passed")


if __name__ == "__main__":
    run_test()
