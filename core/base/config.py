"""Module config: inline documentation for /Users/jason/Developer/sentinelforge/core/base/config.py."""
#
# PURPOSE:
# This file defines all configuration settings for the entire application.
# Think of it as the "control panel" where you can adjust how Sentinel behaves
# without changing code throughout the system.
#
# KEY CONCEPTS:
# 1. Dataclasses: Python's way of creating simple data containers (like structs)
# 2. Environment Variables: Settings read from the system (e.g., SENTINEL_DEBUG=true)
# 3. Security Defaults: Safe settings by default, can be tightened for production
# 4. Singleton Pattern: One global config shared across the entire application
#
# WHY CONFIGURATION MATTERS:
# - Local dev needs different settings than production (ports, auth, etc.)
# - Secrets should come from environment, not hardcoded in files
# - Changing a setting in one place (here) affects the whole system
#
# AI Engine Configuration

import os
import secrets
import logging
import re
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field
from enum import Enum

class AIProvider(str, Enum):
    """Supported AI Providers."""
    OLLAMA = "ollama"
    OPENAI = "openai"
    MOCK = "mock"

@dataclass(frozen=True)
class AIConfig:
    """Class AIConfig."""
    provider: str = "ollama"
    ollama_url: str = "http://localhost:11434"
    model: str = "sentinel-9b-god-tier"
    fallback_enabled: bool = True
    request_timeout: float = 300.0
    max_concurrent_requests: int = 2

# Security & Access Control Configuration
# Controls who can access the API and what operations are allowed.
# These defaults are permissive for local development - tighten for production.


@dataclass(frozen=True)
class SecurityConfig:
    # Randomly generated secret token for API authentication
    # secrets.token_urlsafe creates a cryptographically random string (32 bytes = strong)
    # Each time the app starts, it gets a new token unless you set SENTINEL_API_TOKEN
    """Class SecurityConfig."""
    api_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))

    # Which websites can connect to our API (prevents random sites from accessing it)
    # 127.0.0.1 and localhost both mean "this computer only"
    # Port wildcards are only allowed for loopback in development mode.
    allowed_origins: tuple = ("http://127.0.0.1:*", "http://localhost:*", "tauri://localhost")

    # Should users need to authenticate before using the API?
    # False = anyone on localhost can use it (convenient for development)
    # True = must provide api_token with each request (enable for production)
    # Note: Boot interlock still prevents network-exposed + no-auth configurations
    require_auth: bool = False

    # Can users run terminal commands through the UI?
    # True = yes (convenient but potentially dangerous if exposed remotely)
    # False = no terminal access (safer for untrusted environments)
    terminal_enabled: bool = True

    # Does terminal access require authentication even if require_auth is False?
    # False = terminal follows require_auth setting (convenient for local dev)
    # True = terminal always requires token regardless of require_auth
    # Note: Boot interlock still prevents network-exposed + no-auth configurations
    terminal_require_auth: bool = False

    # Can users copy/paste through the terminal interface?
    # True = clipboard works (UX improvement), False = disabled (extra security)
    clipboard_enabled: bool = True

    # Rate limiting: Maximum API requests per minute (prevents abuse/accidents)
    # 600 = 10 requests per second (generous for local dev)
    rate_limit_requests_per_minute: int = 600

    # Rate limiting specifically for AI requests (these are expensive/slow)
    # 60 = 1 request per second (AI processing is the bottleneck)
    rate_limit_ai_per_minute: int = 60


# ============================================================================
# File Storage Configuration
# ============================================================================
# Defines where data is stored on disk (databases, scan results, reports).

@dataclass(frozen=True)
class StorageConfig:
    # Base directory for all Sentinel data (~ means your home folder)
    # Example: /Users/yourname/.sentinelforge/ on Mac
    # Keeps all data organized in one hidden folder
    """Class StorageConfig."""
    base_dir: Path = field(default_factory=lambda: Path.home() / ".sentinelforge")

    # Name of the SQLite database file (stores findings, sessions, evidence metadata)
    db_name: str = "sentinel.db"

    # Subdirectory name for raw evidence (tool outputs, screenshots, pcaps)
    evidence_dir: str = "evidence"

    # Subdirectory name for generated reports (PDFs, JSON exports)
    reports_dir: str = "reports"

    # Maximum size of a single piece of evidence (prevents filling disk)
    # 100 MB is enough for most tool outputs but prevents huge files
    max_evidence_size_mb: int = 100

    # Property: Computed path to the database file
    # @property makes this look like a regular attribute but it's calculated dynamically
    @property
    def db_path(self) -> Path:
        """Function db_path."""
        return self.base_dir / self.db_name  # / operator joins paths (OS-independent)

    # Property: Computed path to the evidence directory
    @property
    def evidence_path(self) -> Path:
        """Function evidence_path."""
        return self.base_dir / self.evidence_dir

    # Property: Computed path to the reports directory
    @property
    def reports_path(self) -> Path:
        """Function reports_path."""
        return self.base_dir / self.reports_dir


# ============================================================================
# Scanning & Tool Execution Configuration
# ============================================================================
# Controls how security tools are executed and what safety limits are applied.

@dataclass(frozen=True)
class ScanConfig:
    # How many security tools can run at the same time (parallelization)
    # 2 = balanced (doesn't overload system, still reasonably fast)
    # Higher = faster scans but more resource usage
    """Class ScanConfig."""
    max_concurrent_tools: int = 2

    # How long to wait for a single tool to finish before killing it (in seconds)
    # 300 seconds = 5 minutes (some scans like nmap can take a while)
    tool_timeout_seconds: int = 300

    # Maximum number of results one tool can return (prevents memory exhaustion)
    # 1000 findings is enough for most scans, more likely means noise/errors
    max_findings_per_tool: int = 1000

    # Should "safe" tools run automatically without asking permission?
    # True = reconnaissance tools auto-run (faster workflow)
    # False = every tool requires manual approval (safer but slower)
    auto_approve_safe_tools: bool = True

    # List of "safe" tools that can run without approval
    # These are passive reconnaissance tools that just gather public information
    # (httpx checks what website responds, subfinder finds subdomains from DNS, etc.)
    safe_tools: tuple = ("httpx", "dnsx", "subfinder", "whois")

    # List of "restricted" tools that require explicit human approval
    # These are active/intrusive tools that could trigger alerts or cause damage
    # (nmap sends probe packets, sqlmap tests for SQL injection, etc.)
    # Also includes system tools (brew, pip) that could modify the environment
    restricted_tools: tuple = ("nmap", "nikto", "nuclei", "gobuster", "feroxbuster", "sqlmap", "masscan", "brew", "pip")


# ============================================================================
# Logging Configuration
# ============================================================================
# Controls what gets logged and where logs are stored (for debugging/auditing).

@dataclass(frozen=True)
class LogConfig:
    # Log level: How verbose should logging be?
    # DEBUG = everything (very noisy, use for troubleshooting)
    # INFO = important events (default, good balance)
    # WARNING = only potential problems
    # ERROR = only actual failures
    """Class LogConfig."""
    level: str = "INFO"

    # Log message format template (Python's logging format string)
    # %(asctime)s = timestamp when event occurred
    # %(levelname)s = severity (INFO, WARNING, ERROR, etc.)
    # %(name)s = which module logged this (e.g., "core.ai.ai_engine")
    # %(message)s = the actual log message
    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # Should logs be written to a file? (in addition to console output)
    # True = yes, keep a permanent log file (useful for reviewing past scans)
    # False = only print to console (logs disappear when program closes)
    file_enabled: bool = True

    # Directory for log files (inside base_dir)
    # Each scan creates its own log file: {target}-{date}.log
    # System-wide logs go to system.log
    log_dir: str = "logs"

    # Name of the system log file (for non-scan events like startup/shutdown)
    system_log_name: str = "system.log"

    # Maximum size of system.log before rotation (in megabytes)
    max_file_size_mb: int = 10

    # How many old system.log files to keep after rotation
    backup_count: int = 5


# ============================================================================
# Ghost Module Configuration (Lazarus, Proxy)
# ============================================================================
# Controls the JS de-obfuscation and proxy intercept behavior.

@dataclass(frozen=True)
class GhostConfig:
    # Minimum JS file size to consider for de-obfuscation (bytes)
    """Class GhostConfig."""
    min_js_size: int = 500

    # Maximum JS file size to process (bytes) - larger files skipped for performance
    max_js_size: int = 100_000

    # Maximum characters to send to LLM for de-obfuscation context
    max_context_chars: int = 2000

    # Known library hashes to skip (jQuery, React, etc.)
    skip_library_hashes: tuple = ()


# ============================================================================
# NEXUS/OMEGA Module Configuration
# ============================================================================
# Controls the advanced security analysis modules for threat discovery.

@dataclass(frozen=True)
class CronusConfig:
    """Temporal mining configuration (CRONUS - The Archaeologist).

    CRONUS discovers "zombie endpoints" - deprecated routes that are still
    active on the backend but no longer documented. This configuration controls
    how aggressively we probe historical archives and verify endpoints.

    Safety:
    - All CRONUS operations require safe_mode=False to execute
    - Rate limiting prevents overwhelming target servers
    - Probe requests are designed to be non-disruptive
    """
    # Safety flag: When True, blocks all historical queries and endpoint probing
    # True = safe mode (no network requests to archives or targets)
    # False = operational mode (enabled for authorized testing)
    safe_mode: bool = True

    # Maximum number of snapshots to retrieve per archive source
    # Prevents overwhelming the archive APIs with massive result sets
    max_snapshots_per_source: int = 100

    # Maximum number of endpoints to probe concurrently
    # Higher = faster verification but more server load
    # Lower = slower but gentler on target infrastructure
    max_concurrent_probes: int = 5

    # Rate limit for zombie endpoint probing (requests per second)
    # 5 = conservative, prevents triggering rate limits or WAF alerts
    # Archive APIs (Wayback, CommonCrawl) may have their own limits
    probe_rate_limit: int = 5

    # Which archive sources to query (reduces API load if disabled)
    enable_wayback_machine: bool = True
    enable_commoncrawl: bool = True
    enable_alienvault: bool = True

    # Timeout for individual probe requests (seconds)
    probe_timeout: int = 10

    # Whether to cache query results locally
    cache_enabled: bool = True


@dataclass(frozen=True)
class MimicConfig:
    """Source reconstruction configuration (MIMIC - The Source Reconstructor).

    MIMIC downloads and analyzes frontend JavaScript bundles to discover
    hidden routes and hardcoded secrets. This configuration controls asset
    downloading behavior and analysis limits.

    Safety:
    - All MIMIC operations require safe_mode=False to execute
    - Asset size limits prevent downloading massive files
    - Secrets are automatically redacted in logs and reports
    """
    # Safety flag: When True, blocks all asset downloads and parsing
    # True = safe mode (no network requests to download assets)
    # False = operational mode (enabled for authorized testing)
    safe_mode: bool = True

    # Maximum size of a single asset file to download (megabytes)
    # 50 MB = reasonable limit (most bundles are < 10 MB)
    # Larger files are skipped to prevent filling disk storage
    max_asset_size_mb: int = 50

    # Maximum number of assets to download concurrently
    # 10 = balanced (fast but doesn't overwhelm network)
    max_download_concurrent: int = 10

    # Rate limit for asset downloads (requests per second)
    # 20 = generous for static asset retrieval
    download_rate_limit: int = 20

    # Whether to respect robots.txt when discovering assets
    respect_robots_txt: bool = True

    # Whether to download source maps (.map files) for better analysis
    # Source maps can be large but provide much better code comprehension
    fetch_source_maps: bool = True

    # Maximum cache age before re-downloading assets (hours)
    cache_ttl_hours: int = 24

    # Which asset types to download
    download_javascript: bool = True
    download_css: bool = True
    download_images: bool = False  # Images are rarely useful for analysis


@dataclass(frozen=True)
class NexusConfig:
    """Logic chaining configuration (NEXUS - The Chain Reactor).

    NEXUS chains low-severity findings into high-impact exploit paths.
    This configuration controls the pathfinding algorithm and execution
    safety limits.

    Safety:
    - Chain execution is ALWAYS blocked unless explicitly enabled
    - Chain calculation is safe (just planning, no exploitation)
    - Chains require approval tokens before execution
    """
    # Safety flag: When True, blocks all chain planning and execution
    # True = safe mode (no chain calculation or execution)
    # False = operational mode (chain planning allowed)
    safe_mode: bool = True

    # Maximum depth of an exploit chain (number of steps)
    # 5 = reasonable limit (deeper chains are less reliable)
    # Longer chains have exponentially lower success probability
    max_chain_depth: int = 5

    # Maximum number of chains to calculate per goal state
    # 10 = provides options without overwhelming the user
    max_chains_per_goal: int = 10

    # Whether chain execution is allowed (EXTREMELY DANGEROUS)
    # False = planning only (chains calculated but not executed)
    # True = execution enabled (requires approval_token per chain)
    # This should NEVER be True in automated environments
    enable_chain_execution: bool = False

    # Minimum reliability score for a primitive to be used in chains
    # 0.0 = allow all primitives (more false positives)
    # 1.0 = only certain primitives (may miss valid chains)
    min_primitive_reliability: float = 0.5

    # Whether to use the KnowledgeGraph for primitive correlation
    use_knowledge_graph: bool = True

    # Maximum execution time for a single chain step (seconds)
    step_timeout_seconds: int = 60

    # Chain goals to prioritize (empty = all goals)
    priority_goals: tuple = ()


@dataclass(frozen=True)
class OmegaConfig:
    """Integration manager configuration (OMEGA - The Orchestrator).

    OMEGA coordinates all three pillars (CRONUS, MIMIC, NEXUS) for
    comprehensive security analysis. This configuration controls which
    modules are enabled and how results are aggregated.

    Safety:
    - Individual module safe_modes are respected
    - OMEGA itself requires safe_mode=False to run
    - Results are aggregated without executing exploit chains
    """
    # Safety flag: When True, blocks all OMEGA orchestration
    # True = safe mode (no module coordination)
    # False = operational mode (coordinates enabled modules)
    safe_mode: bool = True

    # Which pillars to enable (can run subsets independently)
    enable_cronus: bool = True
    enable_mimic: bool = True
    enable_nexus: bool = True

    # Maximum duration for a complete OMEGA analysis (seconds)
    # 3600 = 1 hour (comprehensive analysis can take time)
    max_duration_seconds: int = 3600

    # Whether to generate a unified risk score across all pillars
    calculate_combined_risk: bool = True

    # Minimum confidence threshold for including findings in results
    min_confidence_threshold: float = 0.3

    # Whether to persist intermediate results for analysis
    persist_intermediate_results: bool = True

    # Maximum number of zombie endpoints to investigate (CRONUS)
    max_zombie_endpoints: int = 50

    # Maximum number of hidden routes to investigate (MIMIC)
    max_hidden_routes: int = 50

    # Maximum number of exploit chains to calculate (NEXUS)
    max_exploit_chains: int = 10


# ============================================================================
# Master Configuration Container
# ============================================================================
# Combines all configuration sections into one cohesive structure.

@dataclass  # Not frozen because we need __post_init__ to create directories
class SentinelConfig:
    # AI engine settings (which model, timeouts, etc.)
    """Class SentinelConfig."""
    ai: AIConfig = field(default_factory=AIConfig)

    # Security/access control settings (authentication, rate limiting, etc.)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    # File storage settings (where to save data)
    storage: StorageConfig = field(default_factory=StorageConfig)

    # Scanning behavior settings (tool restrictions, timeouts, etc.)
    scan: ScanConfig = field(default_factory=ScanConfig)

    # Logging behavior settings (verbosity, file rotation, etc.)
    log: LogConfig = field(default_factory=LogConfig)

    # Ghost module settings (Lazarus JS de-obfuscation, proxy)
    ghost: GhostConfig = field(default_factory=GhostConfig)

    # CRONUS module settings (temporal mining for zombie endpoints)
    cronus: CronusConfig = field(default_factory=CronusConfig)

    # MIMIC module settings (source reconstruction for hidden routes)
    mimic: MimicConfig = field(default_factory=MimicConfig)

    # NEXUS module settings (logic chaining for exploit paths)
    nexus: NexusConfig = field(default_factory=NexusConfig)

    # OMEGA module settings (orchestration of all three pillars)
    omega: OmegaConfig = field(default_factory=OmegaConfig)

    # Debug mode: enables extra logging and development features
    # False = production mode (clean output, fast)
    # True = debug mode (verbose logging, extra checks)
    debug: bool = False

    # IP address the API server should listen on
    # 127.0.0.1 = only accessible from this computer (secure default)
    # 0.0.0.0 = accessible from network (risky, only use if you know what you're doing)
    api_host: str = "127.0.0.1"

    # Port number the API server should listen on
    # 8765 = our chosen default port (arbitrary, not used by other common services)
    api_port: int = 8765

    # Special method that runs automatically after __init__ completes
    # Used to create necessary directories before the app starts using them
    def __post_init__(self):
        # Create storage directories if they don't exist
        # parents=True means "create parent directories too if needed"
        # exist_ok=True means "don't error if the directory already exists"
        """Function __post_init__."""
        self.storage.base_dir.mkdir(parents=True, exist_ok=True)
        self.storage.evidence_path.mkdir(parents=True, exist_ok=True)
        self.storage.reports_path.mkdir(parents=True, exist_ok=True)

        # Write the API token to a discoverable file so UI clients can authenticate
        # This solves the "Auth Singularity" - backend generates token, UI discovers it
        self._write_token_file()

    def _write_token_file(self) -> None:
        """
        Write the current API token to ~/.sentinelforge/api_token.

        This enables the Swift UI to discover the token that the Python backend
        generated at startup. The file is chmod 0600 (owner read/write only).

        Security: Token changes each restart, limiting exposure window.
        """
        token_path = self.storage.base_dir / "api_token"
        try:
            token_path.write_text(self.security.api_token)
            token_path.chmod(0o600)
            logging.getLogger(__name__).info(f"[Config] API token written to {token_path}")
        except OSError as e:
            logging.getLogger(__name__).warning(f"[Config] Failed to write token file: {e}")

    # Class method: builds a SentinelConfig by reading environment variables
    # @classmethod means this is called on the class itself (SentinelConfig.from_env())
    # not on an instance. Think of it as a factory function.
    # Returns a fully configured SentinelConfig object with settings from the environment
    @classmethod
    def from_env(cls) -> "SentinelConfig":
        # Build AI config from environment variables
        # os.getenv("VAR_NAME", "default") reads an environment variable, uses default if not set
        # This allows users to customize settings without editing code
        """Function from_env."""
        ai = AIConfig(
            provider=os.getenv("SENTINEL_AI_PROVIDER", "ollama"),
            # AI Config - defaults to Sentinel Brain (local fine-tuned model on port 8009)
            ollama_url=os.getenv("SENTINEL_OLLAMA_URL", "http://localhost:11434"),
            model=os.getenv("SENTINEL_AI_MODEL", "sentinel-9b-god-tier"),
            # Convert "true"/"false" string to actual Python boolean
            fallback_enabled=os.getenv("SENTINEL_AI_FALLBACK", "true").lower() == "true",
            # Convert string to float for timeout (env vars are always strings)
            request_timeout=float(os.getenv("SENTINEL_AI_TIMEOUT", "300")),
            # Convert string to integer for concurrent requests
            max_concurrent_requests=int(os.getenv("SENTINEL_AI_MAX_CONCURRENT", "2")),
        )

        # Get API token from environment, generate random one if not provided
        token = os.getenv("SENTINEL_API_TOKEN")
        # Conditional branch.
        if not token:
            # No token provided, generate a cryptographically secure random token
            token = secrets.token_urlsafe(32)

        # Parse allowed origins (comma-separated list from environment)
        origins_str = os.getenv("SENTINEL_ALLOWED_ORIGINS", "")
        # Split "http://a.com,http://b.com" into tuple ("http://a.com", "http://b.com")
        # If empty, use localhost defaults
        origins = tuple(origins_str.split(",")) if origins_str else ("http://127.0.0.1:*", "http://localhost:*")

        security = SecurityConfig(
            api_token=token,
            allowed_origins=origins,
            require_auth=os.getenv("SENTINEL_REQUIRE_AUTH", "false").lower() == "true",
            terminal_enabled=os.getenv("SENTINEL_TERMINAL_ENABLED", "true").lower() == "true",
            terminal_require_auth=os.getenv("SENTINEL_TERMINAL_REQUIRE_AUTH", "false").lower() == "true",
            clipboard_enabled=os.getenv("SENTINEL_CLIPBOARD_ENABLED", "true").lower() == "true",
            rate_limit_requests_per_minute=int(os.getenv("SENTINEL_RATE_LIMIT", "600")),
            rate_limit_ai_per_minute=int(os.getenv("SENTINEL_AI_RATE_LIMIT", "60")),
        )

        base_dir = Path(os.getenv("SENTINEL_DATA_DIR", str(Path.home() / ".sentinelforge")))
        storage = StorageConfig(base_dir=base_dir)

        scan = ScanConfig(
            max_concurrent_tools=int(os.getenv("SENTINEL_MAX_CONCURRENT_TOOLS", "2")),
            tool_timeout_seconds=int(os.getenv("SENTINEL_TOOL_TIMEOUT", "300")),
        )

        log = LogConfig(
            level=os.getenv("SENTINEL_LOG_LEVEL", "INFO"),
        )

        # Ghost config (minimal configuration needed)
        ghost = GhostConfig()  # Use defaults

        # CRONUS config (temporal mining)
        cronus = CronusConfig(
            safe_mode=os.getenv("SENTINEL_CRONUS_SAFE_MODE", "true").lower() == "true",
            max_snapshots_per_source=int(os.getenv("SENTINEL_CRONUS_MAX_SNAPSHOTS", "100")),
            max_concurrent_probes=int(os.getenv("SENTINEL_CRONUS_MAX_PROBES", "5")),
            probe_rate_limit=int(os.getenv("SENTINEL_CRONUS_RATE_LIMIT", "5")),
            enable_wayback_machine=os.getenv("SENTINEL_CRONUS_WAYBACK", "true").lower() == "true",
            enable_commoncrawl=os.getenv("SENTINEL_CRONUS_COMMONCRAWL", "true").lower() == "true",
            enable_alienvault=os.getenv("SENTINEL_CRONUS_ALIENVAULT", "true").lower() == "true",
            probe_timeout=int(os.getenv("SENTINEL_CRONUS_TIMEOUT", "10")),
            cache_enabled=os.getenv("SENTINEL_CRONUS_CACHE", "true").lower() == "true",
        )

        # MIMIC config (source reconstruction)
        mimic = MimicConfig(
            safe_mode=os.getenv("SENTINEL_MIMIC_SAFE_MODE", "true").lower() == "true",
            max_asset_size_mb=int(os.getenv("SENTINEL_MIMIC_MAX_ASSET_SIZE", "50")),
            max_download_concurrent=int(os.getenv("SENTINEL_MIMIC_MAX_CONCURRENT", "10")),
            download_rate_limit=int(os.getenv("SENTINEL_MIMIC_RATE_LIMIT", "20")),
            respect_robots_txt=os.getenv("SENTINEL_MIMIC_ROBOTS_TXT", "true").lower() == "true",
            fetch_source_maps=os.getenv("SENTINEL_MIMIC_SOURCE_MAPS", "true").lower() == "true",
            cache_ttl_hours=int(os.getenv("SENTINEL_MIMIC_CACHE_TTL", "24")),
            download_javascript=os.getenv("SENTINEL_MIMIC_DOWNLOAD_JS", "true").lower() == "true",
            download_css=os.getenv("SENTINEL_MIMIC_DOWNLOAD_CSS", "true").lower() == "true",
            download_images=os.getenv("SENTINEL_MIMIC_DOWNLOAD_IMAGES", "false").lower() == "true",
        )

        # NEXUS config (logic chaining)
        nexus = NexusConfig(
            safe_mode=os.getenv("SENTINEL_NEXUS_SAFE_MODE", "true").lower() == "true",
            max_chain_depth=int(os.getenv("SENTINEL_NEXUS_MAX_DEPTH", "5")),
            max_chains_per_goal=int(os.getenv("SENTINEL_NEXUS_MAX_CHAINS", "10")),
            enable_chain_execution=os.getenv("SENTINEL_NEXUS_ENABLE_EXECUTION", "false").lower() == "true",
            min_primitive_reliability=float(os.getenv("SENTINEL_NEXUS_MIN_RELIABILITY", "0.5")),
            use_knowledge_graph=os.getenv("SENTINEL_NEXUS_USE_KG", "true").lower() == "true",
            step_timeout_seconds=int(os.getenv("SENTINEL_NEXUS_STEP_TIMEOUT", "60")),
        )

        # OMEGA config (integration manager)
        omega = OmegaConfig(
            safe_mode=os.getenv("SENTINEL_OMEGA_SAFE_MODE", "true").lower() == "true",
            enable_cronus=os.getenv("SENTINEL_OMEGA_ENABLE_CRONUS", "true").lower() == "true",
            enable_mimic=os.getenv("SENTINEL_OMEGA_ENABLE_MIMIC", "true").lower() == "true",
            enable_nexus=os.getenv("SENTINEL_OMEGA_ENABLE_NEXUS", "true").lower() == "true",
            max_duration_seconds=int(os.getenv("SENTINEL_OMEGA_MAX_DURATION", "3600")),
            calculate_combined_risk=os.getenv("SENTINEL_OMEGA_COMBINED_RISK", "true").lower() == "true",
            min_confidence_threshold=float(os.getenv("SENTINEL_OMEGA_MIN_CONFIDENCE", "0.3")),
            persist_intermediate_results=os.getenv("SENTINEL_OMEGA_PERSIST_RESULTS", "true").lower() == "true",
            max_zombie_endpoints=int(os.getenv("SENTINEL_OMEGA_MAX_ZOMBIES", "50")),
            max_hidden_routes=int(os.getenv("SENTINEL_OMEGA_MAX_ROUTES", "50")),
            max_exploit_chains=int(os.getenv("SENTINEL_OMEGA_MAX_CHAINS", "10")),
        )

        return cls(
            ai=ai,
            security=security,
            storage=storage,
            scan=scan,
            log=log,
            ghost=ghost,
            cronus=cronus,
            mimic=mimic,
            nexus=nexus,
            omega=omega,
            debug=os.getenv("SENTINEL_DEBUG", "false").lower() == "true",
            api_host=os.getenv("SENTINEL_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("SENTINEL_API_PORT", "8765")),
        )


# ============================================================================
# Security Validation Helpers
# ============================================================================
# These functions validate configuration for security issues BEFORE startup.


# Addresses that are considered "safe" (loopback-only, not exposed to network)
LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "localhost", "::1"})


def is_network_exposed(api_host: str) -> bool:
    """
    Check if the API host is exposed to the network (non-loopback).

    Args:
        api_host: The configured API host address

    Returns:
        True if the host is exposed to network (e.g., 0.0.0.0), False if loopback-only
    """
    return api_host.lower() not in LOOPBACK_ADDRESSES


@dataclass(frozen=True)
class OriginAssessment:
    """Structured assessment of a CORS origin pattern."""
    raw: str
    scheme: Optional[str]
    host: Optional[str]
    port: Optional[str]
    path: str
    parse_ok: bool
    has_wildcard: bool
    literal_wildcard: bool
    host_has_wildcard: bool
    port_has_wildcard: bool
    path_has_wildcard: bool
    is_loopback: bool


class OriginValidator:
    """
    Strict origin pinning validator.

    Port wildcards are only allowed for loopback hosts in development mode.
    """

    _ORIGIN_PATTERN = re.compile(
        r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<authority>[^/]+)(?P<path>/.*)?$"
    )
    _AUTHORITY_PATTERN = re.compile(r"^(?P<host>\[[^\]]+\]|[^:]+)(?::(?P<port>\*|\d+))?$")

    @staticmethod
    def assess(origin: str) -> OriginAssessment:
        candidate = origin.strip()
        has_wildcard = "*" in candidate
        literal_wildcard = candidate == "*"

        if literal_wildcard:
            return OriginAssessment(
                raw=origin,
                scheme=None,
                host=None,
                port=None,
                path="",
                parse_ok=False,
                has_wildcard=True,
                literal_wildcard=True,
                host_has_wildcard=False,
                port_has_wildcard=False,
                path_has_wildcard=False,
                is_loopback=False,
            )

        match = OriginValidator._ORIGIN_PATTERN.match(candidate)
        if not match:
            return OriginAssessment(
                raw=origin,
                scheme=None,
                host=None,
                port=None,
                path="",
                parse_ok=False,
                has_wildcard=has_wildcard,
                literal_wildcard=False,
                host_has_wildcard=False,
                port_has_wildcard=False,
                path_has_wildcard=False,
                is_loopback=False,
            )

        scheme = match.group("scheme")
        authority = match.group("authority")
        path = match.group("path") or ""

        auth_match = OriginValidator._AUTHORITY_PATTERN.match(authority)
        if not auth_match:
            return OriginAssessment(
                raw=origin,
                scheme=scheme,
                host=None,
                port=None,
                path=path,
                parse_ok=False,
                has_wildcard=has_wildcard,
                literal_wildcard=False,
                host_has_wildcard=False,
                port_has_wildcard=False,
                path_has_wildcard="*" in path,
                is_loopback=False,
            )

        host = auth_match.group("host") or ""
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        port = auth_match.group("port")

        host_has_wildcard = "*" in host
        port_has_wildcard = port == "*"
        path_has_wildcard = "*" in path
        is_loopback = host.lower() in LOOPBACK_ADDRESSES

        return OriginAssessment(
            raw=origin,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            parse_ok=True,
            has_wildcard=has_wildcard,
            literal_wildcard=False,
            host_has_wildcard=host_has_wildcard,
            port_has_wildcard=port_has_wildcard,
            path_has_wildcard=path_has_wildcard,
            is_loopback=is_loopback,
        )

    @staticmethod
    def enforce_config_guard(config: "SentinelConfig") -> None:
        from core.errors import CriticalSecurityBreach

        for origin in config.security.allowed_origins:
            assessment = OriginValidator.assess(origin)
            if not assessment.has_wildcard:
                continue

            if assessment.literal_wildcard:
                raise CriticalSecurityBreach(
                    "Wildcard CORS origin '*' is forbidden under strict origin pinning.",
                    remediation=(
                        "Pin explicit origins:\n"
                        "  1. Example: SENTINEL_ALLOWED_ORIGINS=http://127.0.0.1:8000\n"
                        "  2. Use comma-separated origins for multiple entries"
                    ),
                    details={"origin": origin},
                )

            if not assessment.parse_ok:
                raise CriticalSecurityBreach(
                    "Unparseable CORS origin contains a wildcard.",
                    remediation=(
                        "Ensure origins match scheme://host[:port] (no wildcards), "
                        "or use a localhost port wildcard only in development mode."
                    ),
                    details={"origin": origin},
                )

            if assessment.host_has_wildcard:
                raise CriticalSecurityBreach(
                    "Wildcard hostnames are forbidden under strict origin pinning.",
                    remediation=(
                        "Pin explicit hostnames:\n"
                        "  1. Example: SENTINEL_ALLOWED_ORIGINS=https://app.example.com:443\n"
                        "  2. Avoid '*' in the host component"
                    ),
                    details={"origin": origin},
                )

            if assessment.path_has_wildcard:
                raise CriticalSecurityBreach(
                    "Wildcard paths are forbidden in CORS origins.",
                    remediation=(
                        "Remove path wildcards and pin the exact origin "
                        "(scheme + host + port)."
                    ),
                    details={"origin": origin},
                )

            if assessment.port_has_wildcard:
                if assessment.is_loopback:
                    # Allow loopback wildcards in all modes for developer convenience
                    continue

                raise CriticalSecurityBreach(
                    "Network origins may not use port wildcards.",
                    remediation=(
                        "Pin explicit ports for network origins:\n"
                        "  1. Example: https://app.example.com:443\n"
                        "  2. Remove :* from allowed origins"
                    ),
                    details={"origin": origin},
                )

            raise CriticalSecurityBreach(
                "Wildcard CORS origin pattern detected.",
                remediation="Remove wildcards from allowed origins.",
                details={"origin": origin},
            )


class SecurityInterlock:
    """
    Fail-closed security interlock for startup invariants.

    This runs before the API binds to a port and halts on unsafe settings.
    """

    @staticmethod
    def verify_safe_boot(config: "SentinelConfig") -> None:
        """Enforce startup invariants that must never be violated."""
        SecurityInterlock._enforce_network_interlock(config)
        SecurityInterlock._enforce_cors_interlock(config)

    @staticmethod
    def _enforce_network_interlock(config: "SentinelConfig") -> None:
        from core.errors import CriticalSecurityBreach

        is_exposed = is_network_exposed(config.api_host)
        is_naked = not config.security.require_auth

        if is_exposed and is_naked:
            raise CriticalSecurityBreach(
                "SentinelForge cannot be exposed to the network without an Auth Shield.",
                remediation=(
                    "Choose one of these options:\n"
                    "  1. Enable authentication: SENTINEL_REQUIRE_AUTH=true\n"
                    "  2. Restrict to localhost: SENTINEL_API_HOST=127.0.0.1\n"
                    "  3. Both (recommended for production)"
                ),
                details={
                    "api_host": config.api_host,
                    "require_auth": config.security.require_auth,
                    "terminal_enabled": config.security.terminal_enabled,
                    "terminal_require_auth": config.security.terminal_require_auth,
                },
            )

    @staticmethod
    def _enforce_cors_interlock(config: "SentinelConfig") -> None:
        OriginValidator.enforce_config_guard(config)


def validate_security_posture(config: "SentinelConfig") -> None:
    """
    Validate that the configuration doesn't create a security vulnerability.

    This is a compatibility wrapper for the SecurityInterlock guardrails.

    Args:
        config: The SentinelConfig to validate

    Raises:
        CriticalSecurityBreach: If the configuration is insecure

    Security Matrix:
        | api_host      | require_auth | Result        |
        |---------------|--------------|---------------|
        | 127.0.0.1     | False        | OK (local) |
        | 127.0.0.1     | True         | OK         |
        | 0.0.0.0       | True         | OK (auth)  |
        | 0.0.0.0       | False        | BLOCKED    |
    """
    SecurityInterlock.verify_safe_boot(config)


def get_sensitive_endpoints() -> tuple:
    """
    Return the list of endpoints that should ALWAYS require authentication
    when the system is exposed to the network, regardless of require_auth setting.

    These endpoints provide dangerous capabilities:
    - /ws/pty: Full terminal access (command execution)
    - /forge/*: Exploit compilation and execution
    - /tools/install: Can install arbitrary packages
    - /tools/uninstall: Can remove security tools
    - /mission/start: Can launch security scans against targets
    """
    return (
        "/ws/pty",
        "/forge/compile",
        "/forge/execute",
        "/tools/install",
        "/tools/uninstall",
        "/mission/start",
    )


# ============================================================================
# Global Configuration Singleton
# ============================================================================
# These functions provide access to the one shared configuration instance.

# Private module variable holding the singleton config (starts as None)
_config: Optional[SentinelConfig] = None


def get_config() -> SentinelConfig:
    """
    Get the global configuration instance.

    Singleton pattern: only creates the config once, then reuses it.
    This ensures all parts of the application use the same settings.

    Returns:
        The shared SentinelConfig instance (creates it if it doesn't exist yet)
    """
    global _config  # Access the module-level _config variable
    # Conditional branch.
    if _config is None:
        # First time being called - load config from environment
        _config = SentinelConfig.from_env()
    return _config


def set_config(config: SentinelConfig) -> None:
    """
    Replace the global configuration (mainly used for testing).

    In production, config comes from environment variables.
    In tests, we might want to inject a specific config.

    Args:
        config: The SentinelConfig instance to use globally
    """
    global _config  # Modify the module-level _config variable
    _config = config


def setup_logging(config: Optional[SentinelConfig] = None) -> None:
    """
    Configure Python's logging system based on our settings.

    Sets up console logging and system.log for app-wide events.
    Per-scan logs are handled separately by ScanSession.
    Call this once at application startup.

    Args:
        config: Optional config to use (defaults to global config)
    """
    # Use provided config or get the global one
    cfg = config or get_config()

    # Start with a console handler (prints logs to terminal)
    handlers: List[logging.Handler] = [logging.StreamHandler()]

    # If file logging is enabled, write system-wide logs to logs/system.log
    if cfg.log.file_enabled:
        from logging.handlers import RotatingFileHandler

        # Create logs directory if it doesn't exist
        log_dir = cfg.storage.base_dir / cfg.log.log_dir
        log_dir.mkdir(parents=True, exist_ok=True)

        # System log for non-scan events (startup, shutdown, config errors)
        system_log_path = log_dir / cfg.log.system_log_name
        file_handler = RotatingFileHandler(
            system_log_path,
            maxBytes=cfg.log.max_file_size_mb * 1024 * 1024,  # Convert MB to bytes
            backupCount=cfg.log.backup_count,  # How many old files to keep
        )
        handlers.append(file_handler)

    # Configure Python's logging system with our settings
    logging.basicConfig(
        level=getattr(logging, cfg.log.level.upper()),  # Convert "INFO" string to logging.INFO constant
        format=cfg.log.format,  # How log messages should look
        handlers=handlers,  # Where logs go (console and/or file)
        force=True,  # Replace any existing logging configuration
    )


# ============================================================================
# Legacy Compatibility Aliases (DEPRECATED)
# ============================================================================
# Do NOT use these in new code. Use get_config() instead.
# _cfg = get_config()
# AI_PROVIDER = _cfg.ai.provider
# OLLAMA_URL = _cfg.ai.ollama_url
# AI_MODEL = _cfg.ai.model
# AI_FALLBACK_ENABLED = _cfg.ai.fallback_enabled

# Compatibility Alias
AppConfig = SentinelConfig
