"""
Unit tests for CRONUS module - Temporal Mining for Zombie Endpoints.

These tests verify the core functionality of:
- TimeMachine: Archive querying and sitemap parsing
- SitemapDiffer: Set comparison and diff generation
- ZombieHunter: Response classification and probe handling
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from core.sentient.cronus import (
    # TimeMachine
    TimeMachine,
    SnapshotQuery,
    SnapshotResult,
    ArchiveSource,
    create_time_machine,
    # SitemapDiffer
    SitemapDiffer,
    DiffReport,
    Endpoint,
    EndpointStatus,
    create_sitemap_differ,
    # ZombieHunter
    ZombieHunter,
    ZombieProbe,
    ZombieReport,
    ActiveStatus,
    create_zombie_hunter,
)


# ============================================================================
# TimeMachine Tests
# ============================================================================

class TestTimeMachine:
    """Tests for TimeMachine archive querying."""

    def test_create_time_machine(self):
        """Test factory function creates TimeMachine with defaults."""
        machine = create_time_machine()
        assert machine.safe_mode is True
        assert machine.query_count == 0

    def test_create_time_machine_unsafe(self):
        """Test factory function creates TimeMachine with safe_mode=False."""
        machine = create_time_machine(safe_mode=False)
        assert machine.safe_mode is False

    def test_statistics_initial(self):
        """Test initial statistics are correct."""
        machine = TimeMachine()
        stats = machine.get_statistics()
        assert stats["query_count"] == 0
        assert stats["last_query_time"] is None
        assert stats["safe_mode"] is True
        assert stats["cache_size"] == 0

    def test_safe_mode_blocks_query(self):
        """Test safe mode blocks query execution."""
        machine = TimeMachine(safe_mode=True)
        query = SnapshotQuery(
            target="example.com",
            timestamp_start=datetime(2023, 1, 1),
            timestamp_end=datetime(2023, 12, 31),
        )
        with pytest.raises(ValueError, match="SAFE_MODE"):
            machine.query(query)

    def test_safe_mode_blocks_custom_archives(self):
        """Test safe mode blocks non-standard archives."""
        machine = TimeMachine(safe_mode=True)
        query = SnapshotQuery(
            target="example.com",
            timestamp_start=datetime(2023, 1, 1),
            timestamp_end=datetime(2023, 12, 31),
            sources=[ArchiveSource.ALIEN_VAULT],
        )
        with pytest.raises(ValueError, match="SAFE_MODE"):
            machine.query(query)


class TestSnapshotQuery:
    """Tests for SnapshotQuery dataclass."""

    def test_valid_query(self):
        """Test valid query creation."""
        query = SnapshotQuery(
            target="example.com",
            timestamp_start=datetime(2023, 1, 1),
            timestamp_end=datetime(2023, 12, 31),
        )
        assert query.target == "example.com"
        assert len(query.sources) == 1
        assert query.sources[0] == ArchiveSource.WAYBACK_MACHINE

    def test_query_to_dict(self):
        """Test query serialization."""
        query = SnapshotQuery(
            target="example.com",
            timestamp_start=datetime(2023, 1, 1),
            timestamp_end=datetime(2023, 12, 31),
        )
        data = query.to_dict()
        assert data["target"] == "example.com"
        assert "timestamp_start" in data
        assert "timestamp_end" in data
        assert data["sources"] == ["wayback_machine"]

    def test_invalid_timestamp_range(self):
        """Test validation rejects invalid timestamp range."""
        with pytest.raises(ValueError, match="timestamp_start must be before"):
            SnapshotQuery(
                target="example.com",
                timestamp_start=datetime(2023, 12, 31),
                timestamp_end=datetime(2023, 1, 1),
            )

    def test_max_results_limit(self):
        """Test validation rejects excessive max_results."""
        with pytest.raises(ValueError, match="max_results cannot exceed 1000"):
            SnapshotQuery(
                target="example.com",
                timestamp_start=datetime(2023, 1, 1),
                timestamp_end=datetime(2023, 12, 31),
                max_results=2000,
            )


class TestSnapshotResult:
    """Tests for SnapshotResult dataclass."""

    def test_result_creation(self):
        """Test result creation."""
        result = SnapshotResult(
            source=ArchiveSource.WAYBACK_MACHINE,
            timestamp=datetime(2023, 6, 15),
            url="https://example.com/api/v1",
            content_type="text/html",
            status_code=200,
            content="<html>...</html>",
            size_bytes=1234,
        )
        assert result.source == ArchiveSource.WAYBACK_MACHINE
        assert result.status_code == 200

    def test_result_to_dict(self):
        """Test result serialization."""
        result = SnapshotResult(
            source=ArchiveSource.WAYBACK_MACHINE,
            timestamp=datetime(2023, 6, 15),
            url="https://example.com/api/v1",
            content_type="text/html",
            status_code=200,
            content="<html>test</html>",
            size_bytes=100,
        )
        data = result.to_dict()
        assert data["source"] == "wayback_machine"
        assert data["url"] == "https://example.com/api/v1"


class TestTimeMachineParsing:
    """Tests for TimeMachine sitemap parsing."""

    def test_parse_empty_content(self):
        """Test parsing returns empty for None content."""
        machine = TimeMachine()
        result = SnapshotResult(
            source=ArchiveSource.WAYBACK_MACHINE,
            timestamp=datetime(2023, 6, 15),
            url="https://example.com",
            content_type="text/html",
            status_code=200,
            content=None,
            size_bytes=0,
        )
        endpoints = machine.parse_sitemap(result)
        assert endpoints == []

    def test_parse_html_links(self):
        """Test parsing extracts links from HTML."""
        machine = TimeMachine()
        html_content = '''
        <html>
            <body>
                <a href="/api/v1/users">Users</a>
                <a href="/api/v1/orders">Orders</a>
                <a href="https://example.com/api/v1/products">Products</a>
            </body>
        </html>
        '''
        result = SnapshotResult(
            source=ArchiveSource.WAYBACK_MACHINE,
            timestamp=datetime(2023, 6, 15),
            url="https://example.com",
            content_type="text/html",
            status_code=200,
            content=html_content,
            size_bytes=len(html_content),
        )
        endpoints = machine.parse_sitemap(result)
        assert "/api/v1/users" in endpoints
        assert "/api/v1/orders" in endpoints

    def test_parse_api_paths_from_js(self):
        """Test parsing extracts API paths from JavaScript."""
        machine = TimeMachine()
        js_content = '''
        const API_BASE = '/api/v2';
        fetch('/api/v1/deprecated-endpoint');
        axios.get("/v3/new-endpoint");
        '''
        result = SnapshotResult(
            source=ArchiveSource.WAYBACK_MACHINE,
            timestamp=datetime(2023, 6, 15),
            url="https://example.com",
            content_type="application/javascript",
            status_code=200,
            content=js_content,
            size_bytes=len(js_content),
        )
        endpoints = machine.parse_sitemap(result)
        assert "/api/v1/deprecated-endpoint" in endpoints


# ============================================================================
# SitemapDiffer Tests
# ============================================================================

class TestSitemapDiffer:
    """Tests for SitemapDiffer comparison logic."""

    def test_create_differ(self):
        """Test factory function creates SitemapDiffer."""
        differ = create_sitemap_differ()
        assert differ.safe_mode is True
        assert differ.comparison_count == 0

    def test_compare_empty_sitemaps(self):
        """Test comparing empty sitemaps."""
        differ = SitemapDiffer(safe_mode=False)
        report = differ.compare_sets([], [], "https://example.com")
        assert report.target == "https://example.com"
        assert len(report.deleted) == 0
        assert len(report.stable) == 0
        assert len(report.added) == 0

    def test_compare_finds_deleted(self):
        """Test comparison finds deleted endpoints."""
        differ = SitemapDiffer(safe_mode=False)
        old = [
            Endpoint("/api/v1/old"),
            Endpoint("/api/v1/stable"),
        ]
        new = [
            Endpoint("/api/v1/stable"),
        ]
        report = differ.compare_sets(old, new, "https://example.com")

        assert len(report.deleted) == 1
        assert report.deleted[0].path == "/api/v1/old"
        assert len(report.stable) == 1
        assert report.stable[0].path == "/api/v1/stable"

    def test_compare_finds_added(self):
        """Test comparison finds added endpoints."""
        differ = SitemapDiffer(safe_mode=False)
        old = [
            Endpoint("/api/v1/existing"),
        ]
        new = [
            Endpoint("/api/v1/existing"),
            Endpoint("/api/v2/new"),
        ]
        report = differ.compare_sets(old, new, "https://example.com")

        assert len(report.added) == 1
        assert report.added[0].path == "/api/v2/new"

    def test_compare_detects_modified(self):
        """Test comparison detects modified endpoints."""
        differ = SitemapDiffer(safe_mode=False)
        old = [
            Endpoint("/api/v1/users", parameters=["id"]),
        ]
        new = [
            Endpoint("/api/v1/users", parameters=["id", "filter"]),
        ]
        report = differ.compare_sets(old, new, "https://example.com")

        assert len(report.modified) == 1
        assert report.modified[0].path == "/api/v1/users"

    def test_get_deleted_paths(self):
        """Test get_deleted_paths helper."""
        differ = SitemapDiffer(safe_mode=False)
        old = [
            Endpoint("/api/old1"),
            Endpoint("/api/old2"),
            Endpoint("/api/stable"),
        ]
        new = [
            Endpoint("/api/stable"),
        ]
        deleted = differ.get_deleted_paths(old, new)

        assert len(deleted) == 2
        paths = [ep.path for ep in deleted]
        assert "/api/old1" in paths
        assert "/api/old2" in paths

    def test_get_stable_paths(self):
        """Test get_stable_paths helper."""
        differ = SitemapDiffer(safe_mode=False)
        old = [
            Endpoint("/api/a"),
            Endpoint("/api/b"),
        ]
        new = [
            Endpoint("/api/b"),
            Endpoint("/api/c"),
        ]
        stable = differ.get_stable_paths(old, new)

        assert len(stable) == 1
        assert stable[0].path == "/api/b"

    def test_safe_mode_blocks_http(self):
        """Test safe mode blocks HTTP targets."""
        differ = SitemapDiffer(safe_mode=True)
        with pytest.raises(ValueError, match="SAFE_MODE"):
            differ.compare_sets([], [], "http://insecure.com")


class TestEndpoint:
    """Tests for Endpoint dataclass."""

    def test_endpoint_normalization(self):
        """Test endpoint path normalization."""
        ep = Endpoint("api/v1/users")
        assert ep.path == "/api/v1/users"

    def test_endpoint_signature(self):
        """Test endpoint signature generation."""
        ep = Endpoint("/api/v1/users", method="POST")
        assert ep.signature == "POST:/api/v1/users"

    def test_endpoint_to_dict(self):
        """Test endpoint serialization."""
        ep = Endpoint("/api/v1/users", method="GET", parameters=["id"])
        data = ep.to_dict()
        assert data["path"] == "/api/v1/users"
        assert data["method"] == "GET"
        assert data["parameters"] == ["id"]


class TestConfidenceCalculation:
    """Tests for confidence score calculation."""

    def test_confidence_empty_sitemaps(self):
        """Test confidence is 0 for empty sitemaps."""
        differ = SitemapDiffer(safe_mode=False)
        confidence = differ.calculate_confidence(0, 0, 0.0)
        assert confidence == 0.0

    def test_confidence_one_empty(self):
        """Test confidence is low when one side is empty."""
        differ = SitemapDiffer(safe_mode=False)
        confidence = differ.calculate_confidence(10, 0, 0.0)
        assert confidence == 0.2

    def test_confidence_high_overlap(self):
        """Test confidence is high with high overlap."""
        differ = SitemapDiffer(safe_mode=False)
        confidence = differ.calculate_confidence(100, 100, 0.9)
        assert confidence > 0.8

    def test_confidence_clamped(self):
        """Test confidence is clamped to [0, 1]."""
        differ = SitemapDiffer(safe_mode=False)
        confidence = differ.calculate_confidence(1000, 1000, 1.0)
        assert 0.0 <= confidence <= 1.0


# ============================================================================
# ZombieHunter Tests
# ============================================================================

class TestZombieHunter:
    """Tests for ZombieHunter probing logic."""

    def test_create_hunter(self):
        """Test factory function creates ZombieHunter."""
        hunter = create_zombie_hunter()
        assert hunter.safe_mode is True
        assert hunter.hunt_count == 0

    def test_statistics_initial(self):
        """Test initial statistics are correct."""
        hunter = ZombieHunter()
        stats = hunter.get_statistics()
        assert stats["hunt_count"] == 0
        assert stats["safe_mode"] is True
        assert stats["max_concurrent"] == 5
        assert stats["rate_limit"] == 5

    def test_safe_mode_blocks_hunt(self):
        """Test safe mode blocks hunting."""
        hunter = ZombieHunter(safe_mode=True)
        with pytest.raises(ValueError, match="SAFE_MODE"):
            asyncio.run(hunter.hunt([], "https://example.com"))


class TestResponseClassification:
    """Tests for HTTP response classification."""

    def test_classify_200_confirmed(self):
        """Test 200 response is CONFIRMED."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(200, 100)
        assert status == ActiveStatus.CONFIRMED
        assert confidence == 1.0

    def test_classify_201_confirmed(self):
        """Test 201 response is CONFIRMED."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(201, 100)
        assert status == ActiveStatus.CONFIRMED

    def test_classify_301_confirmed(self):
        """Test 301 redirect is CONFIRMED (endpoint exists)."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(301, 100)
        assert status == ActiveStatus.CONFIRMED

    def test_classify_401_denied(self):
        """Test 401 response is DENIED."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(401, 100)
        assert status == ActiveStatus.DENIED

    def test_classify_403_denied(self):
        """Test 403 response is DENIED."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(403, 100)
        assert status == ActiveStatus.DENIED

    def test_classify_404_dead(self):
        """Test 404 response is DEAD."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(404, 100)
        assert status == ActiveStatus.DEAD

    def test_classify_410_dead(self):
        """Test 410 Gone response is DEAD."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(410, 100)
        assert status == ActiveStatus.DEAD

    def test_classify_405_confirmed(self):
        """Test 405 Method Not Allowed is CONFIRMED (endpoint exists)."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(405, 100)
        assert status == ActiveStatus.CONFIRMED

    def test_classify_500_error(self):
        """Test 500 response is ERROR."""
        hunter = ZombieHunter()
        status, confidence = hunter.classify_response(500, 100)
        assert status == ActiveStatus.ERROR

    def test_confidence_decreases_with_slow_response(self):
        """Test confidence decreases for slow responses."""
        hunter = ZombieHunter()
        _, fast_confidence = hunter.classify_response(200, 100)
        _, slow_confidence = hunter.classify_response(200, 3000)
        assert fast_confidence > slow_confidence


class TestZombieProbe:
    """Tests for ZombieProbe dataclass."""

    def test_probe_is_zombie_confirmed(self):
        """Test is_zombie for CONFIRMED status."""
        ep = Endpoint("/api/v1/test")
        probe = ZombieProbe(
            endpoint=ep,
            status=ActiveStatus.CONFIRMED,
            status_code=200,
        )
        assert probe.is_zombie is True

    def test_probe_is_zombie_denied(self):
        """Test is_zombie for DENIED status."""
        ep = Endpoint("/api/v1/test")
        probe = ZombieProbe(
            endpoint=ep,
            status=ActiveStatus.DENIED,
            status_code=403,
        )
        assert probe.is_zombie is True

    def test_probe_is_not_zombie_dead(self):
        """Test is_zombie for DEAD status."""
        ep = Endpoint("/api/v1/test")
        probe = ZombieProbe(
            endpoint=ep,
            status=ActiveStatus.DEAD,
            status_code=404,
        )
        assert probe.is_zombie is False

    def test_probe_to_dict(self):
        """Test probe serialization."""
        ep = Endpoint("/api/v1/test")
        probe = ZombieProbe(
            endpoint=ep,
            status=ActiveStatus.CONFIRMED,
            status_code=200,
            response_time_ms=150,
            confidence=0.95,
        )
        data = probe.to_dict()
        assert data["status"] == "confirmed"
        assert data["status_code"] == 200
        assert data["response_time_ms"] == 150


class TestZombieReport:
    """Tests for ZombieReport dataclass."""

    def test_report_zombie_count(self):
        """Test zombie_count calculation."""
        report = ZombieReport(target="example.com")
        report.confirmed = 3
        report.denied = 2
        report.dead = 5
        assert report.zombie_count == 5  # confirmed + denied

    def test_report_zombie_rate(self):
        """Test zombie_rate calculation."""
        report = ZombieReport(target="example.com")
        report.total_probed = 10
        report.confirmed = 3
        report.denied = 2
        assert report.zombie_rate == 50.0  # 5/10 * 100

    def test_report_zombie_rate_zero_probed(self):
        """Test zombie_rate with zero probed."""
        report = ZombieReport(target="example.com")
        assert report.zombie_rate == 0.0

    def test_report_to_dict(self):
        """Test report serialization."""
        report = ZombieReport(
            target="example.com",
            total_probed=10,
            confirmed=3,
            denied=2,
            dead=4,
            inconclusive=1,
        )
        data = report.to_dict()
        assert data["target"] == "example.com"
        assert data["summary"]["zombie_count"] == 5
        assert data["summary"]["zombie_rate_percent"] == 50.0


class TestActiveStatus:
    """Tests for ActiveStatus enum."""

    def test_status_values(self):
        """Test ActiveStatus values are correct."""
        assert ActiveStatus.CONFIRMED.value == "confirmed"
        assert ActiveStatus.DENIED.value == "denied"
        assert ActiveStatus.DEAD.value == "dead"
        assert ActiveStatus.ERROR.value == "error"
        assert ActiveStatus.TIMEOUT.value == "timeout"


# ============================================================================
# Integration Tests (Data Flow)
# ============================================================================

class TestCronusDataFlow:
    """Tests for CRONUS data flow between components."""

    def test_differ_report_provides_zombie_candidates(self):
        """Test DiffReport.get_zombie_candidates returns deleted endpoints."""
        differ = SitemapDiffer(safe_mode=False)
        old = [
            Endpoint("/api/v1/old-endpoint"),
            Endpoint("/api/v1/stable"),
        ]
        new = [
            Endpoint("/api/v1/stable"),
        ]
        report = differ.compare_sets(old, new, "https://example.com")
        zombies = report.get_zombie_candidates()

        assert len(zombies) == 1
        assert zombies[0].path == "/api/v1/old-endpoint"

    def test_endpoint_status_enum(self):
        """Test EndpointStatus enum values."""
        assert EndpointStatus.DELETED.value == "deleted"
        assert EndpointStatus.STABLE.value == "stable"
        assert EndpointStatus.MODIFIED.value == "modified"
        assert EndpointStatus.ADDED.value == "added"

    def test_archive_source_enum(self):
        """Test ArchiveSource enum values."""
        assert ArchiveSource.WAYBACK_MACHINE.value == "wayback_machine"
        assert ArchiveSource.COMMON_CRAWL.value == "common_crawl"
        assert ArchiveSource.ALIEN_VAULT.value == "alien_vault"
        assert ArchiveSource.VIRUS_TOTAL.value == "virus_total"


# ============================================================================
# Replay Tests
# ============================================================================

class TestReplayFunctionality:
    """Tests for replay/replayability features."""

    def test_differ_replay(self):
        """Test SitemapDiffer replay reconstructs report."""
        differ = SitemapDiffer(safe_mode=False)

        # Create original report
        old = [Endpoint("/api/old")]
        new = [Endpoint("/api/new")]
        original = differ.compare_sets(old, new, "https://example.com")

        # Serialize and replay
        data = original.to_dict()
        replayed = differ.replay(data)

        assert replayed.target == original.target
        assert len(replayed.deleted) == len(original.deleted)
        assert len(replayed.added) == len(original.added)

    def test_hunter_replay(self):
        """Test ZombieHunter replay reconstructs report."""
        hunter = ZombieHunter()

        # Create mock report data
        report_data = {
            "target": "https://example.com",
            "summary": {
                "total_probed": 3,
                "confirmed": 1,
                "denied": 1,
                "dead": 1,
                "inconclusive": 0,
            },
            "probes": [
                {
                    "endpoint": {"path": "/api/v1/test", "method": "GET", "parameters": []},
                    "status": "confirmed",
                    "status_code": 200,
                    "response_time_ms": 100,
                    "confidence": 1.0,
                    "probed_at": datetime.utcnow().isoformat(),
                    "error_message": None,
                }
            ],
            "started_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
        }

        replayed = hunter.replay(report_data)

        assert replayed.target == "https://example.com"
        assert replayed.confirmed == 1
        assert len(replayed.probes) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
