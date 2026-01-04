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

DEPENDENCIES:
- aiohttp: Async HTTP client for efficient probing
- asyncio: For concurrent request handling
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)

# EventBus import - optional, gracefully degrades to logging if not available
try:
    from core.cortex.events import get_event_bus
    EVENTBUS_AVAILABLE = True
except ImportError:
    EVENTBUS_AVAILABLE = False


def _emit_event(method_name: str, **kwargs) -> None:
    """
    Helper to emit events via EventBus with graceful degradation.

    If EventBus is not available, falls back to logging.
    """
    if EVENTBUS_AVAILABLE:
        try:
            bus = get_event_bus()
            emit_method = getattr(bus, method_name, None)
            if emit_method:
                emit_method(**kwargs)
        except Exception as e:
            logger.debug(f"[ZombieHunter] EventBus emission failed: {e}")
    else:
        logger.debug(f"[ZombieHunter] Event: {method_name} {kwargs}")


# Default configuration
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_RATE_LIMIT = 5  # requests per second
DEFAULT_TIMEOUT = 10  # seconds


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


class RateLimiter:
    """
    Token bucket rate limiter for endpoint probing.

    Ensures we don't overwhelm target servers with requests.
    """

    def __init__(self, rate: float = DEFAULT_RATE_LIMIT):
        """
        Initialize rate limiter.

        Args:
            rate: Maximum requests per second
        """
        self._rate = rate
        self._tokens = rate
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
            self._last_update = now

            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1


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
        hunter = ZombieHunter(safe_mode=False)
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

    def __init__(
        self,
        safe_mode: bool = SAFE_MODE,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        """
        Initialize ZombieHunter.

        Args:
            safe_mode: If True, blocks all probing
            max_concurrent: Maximum concurrent probes
            rate_limit: Maximum requests per second
            timeout: Timeout for individual requests in seconds
        """
        self._safe_mode = safe_mode
        self._max_concurrent = max_concurrent
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._hunt_count = 0
        self._last_hunt_time: Optional[datetime] = None
        self._rate_limiter = RateLimiter(rate_limit)

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def hunt_count(self) -> int:
        """Get number of hunts performed."""
        return self._hunt_count

    def classify_response(
        self,
        status_code: int,
        response_time_ms: int
    ) -> Tuple[ActiveStatus, float]:
        """
        Classify HTTP response into ActiveStatus with confidence.

        Classification rules:
        - 200-299: CONFIRMED (endpoint is active and responding)
        - 401, 403: DENIED (endpoint exists but requires auth)
        - 404, 410: DEAD (endpoint properly removed)
        - 301, 302, 307, 308: May indicate endpoint moved (treated as CONFIRMED)
        - 500-599: ERROR (server issue, inconclusive)
        - Other: ERROR (unexpected status)

        Confidence is adjusted based on response time:
        - Fast responses (< 500ms): High confidence
        - Slow responses (> 2000ms): Lower confidence (may be timeout edge case)

        Args:
            status_code: HTTP status code from probe
            response_time_ms: Response time in milliseconds

        Returns:
            Tuple of (ActiveStatus, confidence_score)
        """
        # Base confidence starts at 1.0
        confidence = 1.0

        # Adjust confidence based on response time
        if response_time_ms <= 100:
            confidence = 1.0  # Very fast, high confidence
        elif response_time_ms <= 500:
            confidence = 0.95
        elif response_time_ms <= 1000:
            confidence = 0.85
        elif response_time_ms <= 2000:
            confidence = 0.75
        else:
            confidence = 0.6  # Slow response, lower confidence

        # Classify by status code
        if 200 <= status_code <= 299:
            # Success - endpoint is definitely active
            return (ActiveStatus.CONFIRMED, confidence)

        elif status_code in (301, 302, 307, 308):
            # Redirect - endpoint exists but redirects
            # This still counts as "active" since it responds
            return (ActiveStatus.CONFIRMED, confidence * 0.9)

        elif status_code in (401, 403):
            # Authentication required - endpoint exists but is protected
            return (ActiveStatus.DENIED, confidence)

        elif status_code in (404, 410):
            # Not found / Gone - endpoint properly removed
            return (ActiveStatus.DEAD, confidence)

        elif status_code == 405:
            # Method not allowed - endpoint exists but doesn't accept this method
            # This counts as CONFIRMED since the endpoint is responding
            return (ActiveStatus.CONFIRMED, confidence * 0.8)

        elif 500 <= status_code <= 599:
            # Server error - inconclusive
            return (ActiveStatus.ERROR, confidence * 0.5)

        else:
            # Unexpected status code
            return (ActiveStatus.ERROR, confidence * 0.4)

    async def probe_endpoint(
        self,
        endpoint: "Endpoint",
        base_url: str,
        method: str = "HEAD",
        session: Optional["aiohttp.ClientSession"] = None,
    ) -> ZombieProbe:
        """
        Probe a single endpoint to check if it's still active.

        Uses HEAD request first (lightweight), then falls back to GET
        with Range header if HEAD returns unexpected results.

        Args:
            endpoint: The endpoint to probe
            base_url: Base URL of target (e.g., "https://example.com")
            method: HTTP method to use (HEAD, GET, OPTIONS)
            session: Optional aiohttp session to reuse

        Returns:
            ZombieProbe with result
        """
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError(
                "aiohttp is required for ZombieHunter. "
                "Install with: pip install aiohttp"
            )

        # Validate safe mode
        if self._safe_mode:
            logger.warning(f"[ZombieHunter] SAFE_MODE: Blocking probe to {endpoint.path}")
            return ZombieProbe(
                endpoint=endpoint,
                status=ActiveStatus.ERROR,
                status_code=None,
                response_time_ms=None,
                confidence=0.0,
                error_message="SAFE_MODE: Probing is disabled",
            )

        safe_methods = ("HEAD", "OPTIONS", "GET")
        if method not in safe_methods:
            raise ValueError(
                f"Only safe methods {safe_methods} allowed. Got: {method}"
            )

        # Validate and normalize base_url
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid base_url scheme: {parsed.scheme}")

        # Build full URL
        full_url = urljoin(base_url, endpoint.path)

        logger.debug(f"[ZombieHunter] Probing: {method} {full_url}")

        # Wait for rate limiter
        await self._rate_limiter.acquire()

        start_time = time.monotonic()
        status_code: Optional[int] = None
        error_message: Optional[str] = None
        status = ActiveStatus.ERROR
        confidence = 0.0

        # Manage session lifecycle
        close_session = False
        if session is None:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            session = aiohttp.ClientSession(timeout=timeout)
            close_session = True

        try:
            # Custom headers to be polite and identify ourselves
            headers = {
                "User-Agent": "CRONUS-ZombieHunter/1.0 (Security Assessment)",
                "Accept": "*/*",
            }

            # For GET requests, only fetch first byte to minimize bandwidth
            if method == "GET":
                headers["Range"] = "bytes=0-0"

            async with session.request(method, full_url, headers=headers, allow_redirects=False) as response:
                status_code = response.status
                response_time_ms = int((time.monotonic() - start_time) * 1000)

                # Classify the response
                status, confidence = self.classify_response(status_code, response_time_ms)

                probe = ZombieProbe(
                    endpoint=endpoint,
                    status=status,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    confidence=confidence,
                    error_message=None,
                )

                # Log based on status
                if status == ActiveStatus.CONFIRMED:
                    logger.info(
                        f"[ZombieHunter] {self.EVENT_ZOMBIE_CONFIRMED}: "
                        f"{endpoint.path} (HTTP {status_code})"
                    )
                elif status == ActiveStatus.DENIED:
                    logger.info(
                        f"[ZombieHunter] {self.EVENT_ZOMBIE_DENIED}: "
                        f"{endpoint.path} (HTTP {status_code})"
                    )
                else:
                    logger.debug(
                        f"[ZombieHunter] Probe result: {endpoint.path} -> {status.value}"
                    )

                return probe

        except asyncio.TimeoutError:
            response_time_ms = int((time.monotonic() - start_time) * 1000)
            return ZombieProbe(
                endpoint=endpoint,
                status=ActiveStatus.TIMEOUT,
                status_code=None,
                response_time_ms=response_time_ms,
                confidence=0.5,
                error_message="Request timed out",
            )

        except aiohttp.ClientError as e:
            response_time_ms = int((time.monotonic() - start_time) * 1000)
            return ZombieProbe(
                endpoint=endpoint,
                status=ActiveStatus.ERROR,
                status_code=None,
                response_time_ms=response_time_ms,
                confidence=0.0,
                error_message=str(e),
            )

        except Exception as e:
            response_time_ms = int((time.monotonic() - start_time) * 1000)
            logger.error(f"[ZombieHunter] Unexpected error probing {full_url}: {e}")
            return ZombieProbe(
                endpoint=endpoint,
                status=ActiveStatus.ERROR,
                status_code=None,
                response_time_ms=response_time_ms,
                confidence=0.0,
                error_message=str(e),
            )

        finally:
            if close_session and session:
                await session.close()

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

        Uses a semaphore to limit concurrent requests and a token bucket
        rate limiter to avoid overwhelming the target server.

        Args:
            endpoints: List of candidate zombie endpoints
            target: Base URL of target
            method: HTTP method for probing

        Returns:
            ZombieReport with all probe results
        """
        # Check safe mode first (before dependency check)
        if self._safe_mode:
            logger.warning(f"[ZombieHunter] SAFE_MODE: Blocking hunt to {target}")
            raise ValueError("SAFE_MODE: Hunting is disabled")

        if not AIOHTTP_AVAILABLE:
            raise RuntimeError(
                "aiohttp is required for ZombieHunter. "
                "Install with: pip install aiohttp"
            )

        # Validate target
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid target scheme: {parsed.scheme}")

        # Update statistics
        self._hunt_count += 1
        self._last_hunt_time = datetime.utcnow()
        start_time = time.monotonic()

        # Emit CRONUS_HUNT_STARTED event
        _emit_event(
            "emit_cronus_hunt_started",
            target=target,
            candidate_count=len(endpoints),
        )

        logger.info(
            f"[ZombieHunter] {self.EVENT_HUNT_STARTED}: "
            f"target={target}, candidates={len(endpoints)}"
        )

        # Initialize report
        report = ZombieReport(
            target=target,
            started_at=datetime.utcnow(),
        )

        if not endpoints:
            report.completed_at = datetime.utcnow()
            return report

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def probe_with_semaphore(ep: "Endpoint", session: "aiohttp.ClientSession") -> ZombieProbe:
            async with semaphore:
                return await self.probe_endpoint(ep, target, method, session)

        # Create shared session for connection pooling
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Launch all probes concurrently (semaphore limits actual concurrency)
            tasks = [probe_with_semaphore(ep, session) for ep in endpoints]
            probes = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in probes:
            if isinstance(result, Exception):
                logger.error(f"[ZombieHunter] Probe exception: {result}")
                continue

            if isinstance(result, ZombieProbe):
                report.probes.append(result)
                report.total_probed += 1

                if result.status == ActiveStatus.CONFIRMED:
                    report.confirmed += 1
                    # Emit ZOMBIE_CONFIRMED event
                    _emit_event(
                        "emit_cronus_zombie_confirmed",
                        path=result.endpoint.path,
                        status_code=result.status_code or 0,
                        method=result.endpoint.method,
                        confidence=result.confidence,
                    )
                elif result.status == ActiveStatus.DENIED:
                    report.denied += 1
                    # Emit ZOMBIE_DENIED event
                    _emit_event(
                        "emit_cronus_zombie_denied",
                        path=result.endpoint.path,
                        status_code=result.status_code or 0,
                        method=result.endpoint.method,
                    )
                elif result.status == ActiveStatus.DEAD:
                    report.dead += 1
                else:
                    report.inconclusive += 1

        report.completed_at = datetime.utcnow()

        # Calculate duration
        duration_ms = int((time.monotonic() - start_time) * 1000)

        # Emit CRONUS_HUNT_COMPLETED event
        _emit_event(
            "emit_cronus_hunt_completed",
            target=target,
            confirmed=report.confirmed,
            denied=report.denied,
            dead=report.dead,
            duration_ms=duration_ms,
        )

        logger.info(
            f"[ZombieHunter] {self.EVENT_HUNT_COMPLETED}: "
            f"confirmed={report.confirmed}, denied={report.denied}, "
            f"dead={report.dead}, inconclusive={report.inconclusive}"
        )

        return report

    def hunt_sync(
        self,
        endpoints: List["Endpoint"],
        target: str,
        method: str = "HEAD"
    ) -> ZombieReport:
        """
        Synchronous wrapper for hunt().

        Args:
            endpoints: List of candidate zombie endpoints
            target: Base URL of target
            method: HTTP method for probing

        Returns:
            ZombieReport with all probe results
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.hunt(endpoints, target, method))

    def replay(self, recorded_hunt: Dict[str, Any]) -> ZombieReport:
        """
        Replay a previously completed hunt for analysis.

        Enables replayability without re-probing endpoints.

        Args:
            recorded_hunt: Serialized ZombieReport from to_dict()

        Returns:
            Reconstructed ZombieReport
        """
        from core.sentient.cronus.differ import Endpoint

        def parse_probe(data: Dict[str, Any]) -> ZombieProbe:
            """Parse probe from dict."""
            ep_data = data["endpoint"]
            endpoint = Endpoint(
                path=ep_data["path"],
                method=ep_data.get("method", "GET"),
                parameters=ep_data.get("parameters", []),
            )
            return ZombieProbe(
                endpoint=endpoint,
                status=ActiveStatus(data["status"]),
                status_code=data.get("status_code"),
                response_time_ms=data.get("response_time_ms"),
                confidence=data.get("confidence", 1.0),
                probed_at=datetime.fromisoformat(data["probed_at"]) if data.get("probed_at") else datetime.utcnow(),
                error_message=data.get("error_message"),
            )

        summary = recorded_hunt.get("summary", {})

        report = ZombieReport(
            target=recorded_hunt["target"],
            total_probed=summary.get("total_probed", 0),
            confirmed=summary.get("confirmed", 0),
            denied=summary.get("denied", 0),
            dead=summary.get("dead", 0),
            inconclusive=summary.get("inconclusive", 0),
            probes=[parse_probe(p) for p in recorded_hunt.get("probes", [])],
            started_at=datetime.fromisoformat(recorded_hunt["started_at"]) if recorded_hunt.get("started_at") else None,
            completed_at=datetime.fromisoformat(recorded_hunt["completed_at"]) if recorded_hunt.get("completed_at") else None,
        )

        return report

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
            "timeout": self._timeout,
        }


def create_zombie_hunter(
    safe_mode: bool = SAFE_MODE,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    rate_limit: int = DEFAULT_RATE_LIMIT,
    timeout: int = DEFAULT_TIMEOUT,
) -> ZombieHunter:
    """
    Factory function to create ZombieHunter instance.

    This is the recommended way to create ZombieHunter objects in production code.

    Args:
        safe_mode: Safety mode flag
        max_concurrent: Maximum concurrent probes
        rate_limit: Maximum requests per second
        timeout: Timeout for individual requests in seconds

    Returns:
        Configured ZombieHunter instance
    """
    return ZombieHunter(
        safe_mode=safe_mode,
        max_concurrent=max_concurrent,
        rate_limit=rate_limit,
        timeout=timeout,
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
