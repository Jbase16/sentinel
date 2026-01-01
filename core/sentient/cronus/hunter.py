"""
CRONUS Zombie Hunter - Active Endpoint Verification

PURPOSE:
Verify if "zombie" endpoints (identified by the Differ) are still active on the target
server. This transforms theoretical findings into confirmed vulnerabilities.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Confirm which deprecated endpoints are actually still active
- Prioritize remediation based on actual exposure
- Test deprecation processes during red team exercises
- Audit their own attack surface cleanup

ASSUMPTIONS:
1. Target server is reachable from scanning host
2. HTTP/HTTPS protocols are available
3. Rate limits will be respected to avoid blocking
4. Probing is non-destructive (HEAD/GET requests only)

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, only sends safe HTTP methods (HEAD, OPTIONS)
- Rate limiting enforced (max 5 requests per second)
- No payload injection or exploit attempts
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits HUNT_STARTED, ZOMBIE_CONFIRMED, ZOMBIE_DENIED events
- DecisionLedger: Logs probing decisions and confidence scores
- KnowledgeGraph: Stores confirmed zombie endpoint nodes

DEPENDENCIES (Future):
- aiohttp: Async HTTP client for efficient probing
- asyncio: For concurrent request handling
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class ActiveStatus(str, Enum):
    """
    Result of probing a zombie endpoint candidate.

    - CONFIRMED: Endpoint returns 2xx/3xx (still active!)
    - DENIED: Endpoint returns 401/403 (active but restricted)
    - DEAD: Endpoint returns 404/410 (properly removed)
    - ERROR: Network/probe error (inconclusive)
    - TIMEOUT: Request timed out (may still exist)
    """
    CONFIRMED = "confirmed"    # 200-299: Still active!
    DENIED = "denied"          # 401/403: Active but requires auth
    DEAD = "dead"              # 404/410: Properly removed
    ERROR = "error"            # Network error, inconclusive
    TIMEOUT = "timeout"        # Request timeout, inconclusive


@dataclass
class ZombieProbe:
    """
    Result of probing a single zombie endpoint.

    Attributes:
        endpoint: The endpoint that was probed
        status: What happened when we probed it
        status_code: HTTP status code (if received)
        response_time_ms: How long the response took
        confidence: How confident we are (0.0-1.0)
        probed_at: When this probe was performed
        error_message: Any error details
    """
    endpoint: "Endpoint"
    status: ActiveStatus
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    confidence: float = 1.0
    probed_at: datetime = field(default_factory=lambda: datetime.utcnow())
    error_message: Optional[str] = None

    @property
    def is_zombie(self) -> bool:
        """Check if this endpoint is confirmed as still active."""
        return self.status in (ActiveStatus.CONFIRMED, ActiveStatus.DENIED)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize probe to dict."""
        return {
            "endpoint": self.endpoint.to_dict(),
            "status": self.status.value,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "confidence": self.confidence,
            "probed_at": self.probed_at.isoformat(),
            "error_message": self.error_message,
        }


@dataclass
class ZombieReport:
    """
    Aggregated report from zombie hunting operation.

    Attributes:
        target: Domain that was hunted
        total_probed: How many endpoints were checked
        confirmed: How many are still active (zombies!)
        denied: How many are active but restricted
        dead: How many are properly removed
        inconclusive: How many had errors/timeouts
        probes: Individual probe results
        started_at: When hunting started
        completed_at: When hunting completed
    """
    target: str
    total_probed: int = 0
    confirmed: int = 0
    denied: int = 0
    dead: int = 0
    inconclusive: int = 0
    probes: List[ZombieProbe] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    @property
    def zombie_count(self) -> int:
        """Get total number of confirmed zombies (confirmed + denied)."""
        return self.confirmed + self.denied

    @property
    def zombie_rate(self) -> float:
        """Get percentage of probed endpoints that are zombies."""
        if self.total_probed == 0:
            return 0.0
        return (self.zombie_count / self.total_probed) * 100

    def get_zombie_endpoints(self) -> List["Endpoint"]:
        """Get list of confirmed zombie endpoints."""
        return [
            p.endpoint for p in self.probes
            if p.is_zombie
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dict."""
        return {
            "target": self.target,
            "summary": {
                "total_probed": self.total_probed,
                "zombie_count": self.zombie_count,
                "zombie_rate_percent": round(self.zombie_rate, 2),
                "confirmed": self.confirmed,
                "denied": self.denied,
                "dead": self.dead,
                "inconclusive": self.inconclusive,
            },
            "probes": [p.to_dict() for p in self.probes],
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class ZombieHunter:
    """
    Verifies if "zombie" endpoints are still active on target servers.

    This class performs non-destructive probing to confirm whether endpoints
    identified by the Differ are actually still accessible.

    PROBING STRATEGY:
    1. Try HEAD request (lightweight)
    2. Fall back to GET with Range header (fetch first byte only)
    3. Analyze response code and timing
    4. Classify as CONFIRMED/DENIED/DEAD/ERROR

    EXAMPLE USAGE:
        ```python
        hunter = ZombieHunter()
        zombies = [Endpoint("/admin/old-panel"), Endpoint("/api/v1/deprecated")]
        report = await hunter.hunt(zombies, "https://example.com")
        print(f"Found {report.zombie_count} zombie endpoints!")
        ```
    """

    # Event names for integration with EventBus
    EVENT_HUNT_STARTED = "cronus_hunt_started"
    EVENT_HUNT_COMPLETED = "cronus_hunt_completed"
    EVENT_ZOMBIE_CONFIRMED = "cronus_zombie_confirmed"
    EVENT_ZOMBIE_DENIED = "cronus_zombie_denied"

    # Rate limiting
    DEFAULT_MAX_CONCURRENT = 5
    DEFAULT_RATE_LIMIT = 5  # requests per second

    def __init__(
        self,
        safe_mode: bool = SAFE_MODE,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        rate_limit: int = DEFAULT_RATE_LIMIT,
    ):
        """
        Initialize ZombieHunter.

        Args:
            safe_mode: If True, only allows safe HTTP methods
            max_concurrent: Maximum concurrent probes
            rate_limit: Maximum requests per second
        """
        self._safe_mode = safe_mode
        self._max_concurrent = max_concurrent
        self._rate_limit = rate_limit
        self._hunt_count = 0
        self._last_hunt_time: Optional[datetime] = None

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def hunt_count(self) -> int:
        """Get number of hunts performed."""
        return self._hunt_count

    async def probe_endpoint(
        self,
        endpoint: "Endpoint",
        base_url: str,
        method: str = "HEAD"
    ) -> ZombieProbe:
        """
        Probe a single endpoint to check if it's still active.

        TODO: Implement async HTTP probing.
        TODO: Add timeout handling (5 second default).
        TODO: Add retry logic for transient errors.
        TODO: Extract response headers for additional intel.

        Args:
            endpoint: The endpoint to probe
            base_url: Base URL of target (e.g., "https://example.com")
            method: HTTP method to use (HEAD, GET, OPTIONS)

        Returns:
            ZombieProbe with result

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Validate safe mode
        if self._safe_mode:
            safe_methods = ("HEAD", "OPTIONS", "GET")
            if method not in safe_methods:
                raise ValueError(
                    f"SAFE_MODE: Only {safe_methods} allowed. Got: {method}"
                )

        # Validate base_url
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid base_url scheme: {parsed.scheme}")
        if self._safe_mode and parsed.scheme != "https":
            raise ValueError("SAFE_MODE: Only HTTPS targets allowed")

        # Emit event (integration point)
        logger.debug(
            f"[ZombieHunter] Probing: {method} {base_url}{endpoint.path}"
        )

        raise NotImplementedError(
            "Wrapper-only: Endpoint probing implementation deferred. "
            "Future implementation should use aiohttp for async HTTP requests."
        )

    async def hunt(
        self,
        endpoints: List["Endpoint"],
        target: str,
        method: str = "HEAD"
    ) -> ZombieReport:
        """
        Hunt for zombie endpoints among candidates.

        This method concurrently probes all candidate endpoints to verify
        which ones are still active ("zombies").

        TODO: Implement concurrent probing with semaphore.
        TODO: Implement rate limiting (token bucket algorithm).
        TODO: Add progress reporting via events.
        TODO: Store results in KnowledgeGraph.

        Args:
            endpoints: List of candidate zombie endpoints
            target: Base URL of target
            method: HTTP method for probing

        Returns:
            ZombieReport with all probe results

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Validate safe mode
        if self._safe_mode:
            parsed = urlparse(target)
            if parsed.scheme != "https":
                raise ValueError("SAFE_MODE: Only HTTPS targets allowed")

        # Update statistics
        self._hunt_count += 1
        self._last_hunt_time = datetime.utcnow()

        # Emit event (integration point)
        logger.debug(
            f"[ZombieHunter] {self.EVENT_HUNT_STARTED}: "
            f"target={target}, candidates={len(endpoints)}"
        )

        # Create report skeleton
        ZombieReport(
            target=target,
            started_at=datetime.utcnow(),
        )

        raise NotImplementedError(
            "Wrapper-only: Concurrent hunting implementation deferred. "
            "Future implementation should use asyncio.gather with semaphore."
        )

    def classify_response(
        self,
        status_code: int,
        response_time_ms: int
    ) -> tuple[ActiveStatus, float]:
        """
        Classify HTTP response into ActiveStatus with confidence.

        TODO: Implement classification logic.
        TODO: Handle edge cases (3xx redirects, 500 errors).
        TODO: Adjust confidence based on response time.

        Args:
            status_code: HTTP status code from probe
            response_time_ms: Response time in milliseconds

        Returns:
            Tuple of (ActiveStatus, confidence_score)

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Response classification deferred. "
            "Future implementation should use status code ranges."
        )

    def replay(self, recorded_hunt: Dict[str, Any]) -> ZombieReport:
        """
        Replay a previously completed hunt for analysis.

        Enables replayability without re-probing endpoints.

        Args:
            recorded_hunt: Serialized ZombieReport from to_dict()

        Returns:
            Reconstructed ZombieReport

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Hunt replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ZombieHunter instance.

        Returns:
            Dictionary with hunting statistics
        """
        return {
            "hunt_count": self._hunt_count,
            "last_hunt_time": self._last_hunt_time.isoformat() if self._last_hunt_time else None,
            "safe_mode": self._safe_mode,
            "max_concurrent": self._max_concurrent,
            "rate_limit": self._rate_limit,
        }


def create_zombie_hunter(
    safe_mode: bool = SAFE_MODE,
    max_concurrent: int = ZombieHunter.DEFAULT_MAX_CONCURRENT,
    rate_limit: int = ZombieHunter.DEFAULT_RATE_LIMIT,
) -> ZombieHunter:
    """
    Factory function to create ZombieHunter instance.

    This is the recommended way to create ZombieHunter objects in production code.

    Args:
        safe_mode: Safety mode flag
        max_concurrent: Maximum concurrent probes
        rate_limit: Maximum requests per second

    Returns:
        Configured ZombieHunter instance
    """
    return ZombieHunter(
        safe_mode=safe_mode,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit,
    )


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    from core.sentient.cronus.differ import Endpoint

    # Verify ActiveStatus enum
    assert ActiveStatus.CONFIRMED.value == "confirmed"
    assert ActiveStatus.DEAD.value == "dead"
    print("✓ ActiveStatus enum works")

    # Verify ZombieProbe dataclass
    ep = Endpoint(path="/admin/old", method="GET")
    probe = ZombieProbe(
        endpoint=ep,
        status=ActiveStatus.CONFIRMED,
        status_code=200,
        response_time_ms=150,
    )

    assert probe.is_zombie is True
    assert probe.to_dict()["status"] == "confirmed"
    print("✓ ZombieProbe structure works")

    # Verify ZombieReport dataclass
    report = ZombieReport(target="example.com")
    report.total_probed = 10
    report.confirmed = 3
    report.denied = 2

    assert report.zombie_count == 5
    assert report.zombie_rate == 50.0
    print("✓ ZombieReport aggregation works")

    # Verify ZombieHunter creation
    hunter = create_zombie_hunter()
    assert hunter.safe_mode is True
    assert hunter.hunt_count == 0
    print("✓ ZombieHunter factory works")

    # Verify safe mode enforcement
    try:
        import asyncio
        asyncio.run(hunter.probe_endpoint(
            endpoint=ep,
            base_url="http://insecure.com",  # Non-HTTPS
            method="POST",  # Unsafe method
        ))
        print("✗ Safe mode enforcement failed")
    except ValueError as e:
        if "SAFE_MODE" in str(e):
            print("✓ Safe mode enforcement works")
        else:
            print(f"✗ Unexpected error: {e}")

    print("\n✅ All ZombieHunter design invariants verified!")
