# ============================================================================
# core/base/config.py
# Application Configuration Management
# ============================================================================
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
# ============================================================================

from __future__ import annotations

import os
import secrets
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


# ============================================================================
# AI Engine Configuration
# ============================================================================
# Controls how the AI brain (Large Language Model) operates.
# Sentinel uses local AI models running on your machine for security analysis.

@dataclass(frozen=True)  # frozen=True makes this immutable (can't be changed after creation)
class AIConfig:
    # Which AI provider to use (we use "ollama" for local LLM hosting)
    provider: str = "ollama"
    
    # Where the local AI server is running (localhost means "this computer")
    # Port 11434 is Ollama's default port for serving AI models
    ollama_url: str = "http://localhost:11434"
    
    # Which AI model to load (our fine-tuned security analysis model)
    # "sentinel-9b-god-tier" is a custom 9-billion parameter model trained for security
    model: str = "sentinel-9b-god-tier"
    
    # If AI fails, should we fall back to rule-based analysis? (safer but less smart)
    fallback_enabled: bool = True
    
    # How long to wait for AI response before giving up (in seconds)
    # 300 seconds = 5 minutes (analysis can be slow on complex outputs)
    request_timeout: float = 300.0
    
    # How many AI requests can run at the same time (prevents overloading the GPU)
    max_concurrent_requests: int = 2
    
    # Maximum text length the AI can process at once (in tokens, roughly words)
    # 8000 tokens ≈ 6000 words of context
    max_context_tokens: int = 8000


# ============================================================================
# Security & Access Control Configuration
# ============================================================================
# Controls who can access the API and what operations are allowed.
# These defaults are permissive for local development - tighten for production.

@dataclass(frozen=True)
class SecurityConfig:
    # Randomly generated secret token for API authentication
    # secrets.token_urlsafe creates a cryptographically random string (32 bytes = strong)
    # Each time the app starts, it gets a new token unless you set SENTINEL_API_TOKEN
    api_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    
    # Which websites can connect to our API (prevents random sites from accessing it)
    # 127.0.0.1 and localhost both mean "this computer only"
    # The * means any port (8000, 8080, etc.)
    allowed_origins: tuple = ("http://127.0.0.1:*", "http://localhost:*", "tauri://localhost")
    
    # Should users need to authenticate before using the API?
    # False = anyone on localhost can use it (fine for single-user local dev)
    # True = must provide api_token with each request (better for production)
    require_auth: bool = False
    
    # Can users run terminal commands through the UI?
    # True = yes (convenient but potentially dangerous if exposed remotely)
    # False = no terminal access (safer for untrusted environments)
    terminal_enabled: bool = True
    
    # Does terminal access require authentication even if require_auth is False?
    # Currently False for dev convenience, should be True in production
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
        return self.base_dir / self.db_name  # / operator joins paths (OS-independent)
    
    # Property: Computed path to the evidence directory
    @property
    def evidence_path(self) -> Path:
        return self.base_dir / self.evidence_dir
    
    # Property: Computed path to the reports directory
    @property
    def reports_path(self) -> Path:
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
    
    # Name of the log file (stored in the base_dir)
    file_name: str = "sentinel.log"
    
    # Maximum size of a single log file before rotation (in megabytes)
    # When file hits 10 MB, it gets renamed to sentinel.log.1 and a new file starts
    max_file_size_mb: int = 10
    
    # How many old log files to keep after rotation
    # 5 = keep 5 old files (total ~50 MB of logs: 10 MB × 5 = 50 MB)
    # Oldest file gets deleted when we exceed this limit
    backup_count: int = 5


# ============================================================================
# Master Configuration Container
# ============================================================================
# Combines all configuration sections into one cohesive structure.

@dataclass  # Not frozen because we need __post_init__ to create directories
class SentinelConfig:
    # AI engine settings (which model, timeouts, etc.)
    ai: AIConfig = field(default_factory=AIConfig)
    
    # Security/access control settings (authentication, rate limiting, etc.)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # File storage settings (where to save data)
    storage: StorageConfig = field(default_factory=StorageConfig)
    
    # Scanning behavior settings (tool restrictions, timeouts, etc.)
    scan: ScanConfig = field(default_factory=ScanConfig)
    
    # Logging behavior settings (verbosity, file rotation, etc.)
    log: LogConfig = field(default_factory=LogConfig)
    
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
        self.storage.base_dir.mkdir(parents=True, exist_ok=True)
        self.storage.evidence_path.mkdir(parents=True, exist_ok=True)
        self.storage.reports_path.mkdir(parents=True, exist_ok=True)
    
    # Class method: builds a SentinelConfig by reading environment variables
    # @classmethod means this is called on the class itself (SentinelConfig.from_env())
    # not on an instance. Think of it as a factory function.
    # Returns a fully configured SentinelConfig object with settings from the environment
    @classmethod
    def from_env(cls) -> "SentinelConfig":
        # Build AI config from environment variables
        # os.getenv("VAR_NAME", "default") reads an environment variable, uses default if not set
        # This allows users to customize settings without editing code
        ai = AIConfig(
            provider=os.getenv("SENTINEL_AI_PROVIDER", "ollama"),
            # AI Config - defaults to Sentinel Brain (local fine-tuned model on port 8009)
            ollama_url=os.getenv("SENTINEL_OLLAMA_URL", "http://localhost:8009"),
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
        
        return cls(
            ai=ai,
            security=security,
            storage=storage,
            scan=scan,
            log=log,
            debug=os.getenv("SENTINEL_DEBUG", "false").lower() == "true",
            api_host=os.getenv("SENTINEL_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("SENTINEL_API_PORT", "8765")),
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
    
    Sets up console and file logging with rotation.
    Call this once at application startup.
    
    Args:
        config: Optional config to use (defaults to global config)
    """
    # Use provided config or get the global one
    cfg = config or get_config()
    
    # Start with a console handler (prints logs to terminal)
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    
    # If file logging is enabled, add a rotating file handler
    if cfg.log.file_enabled:
        from logging.handlers import RotatingFileHandler
        log_path = cfg.storage.base_dir / cfg.log.file_name
        # RotatingFileHandler automatically creates new files when size limit is hit
        file_handler = RotatingFileHandler(
            log_path,
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
# Legacy Compatibility Aliases
# ============================================================================
# These provide backward compatibility with old code that imported config values directly.
# Example: Old code did "from core.config import OLLAMA_URL"
# New code should use "get_config().ai.ollama_url" instead.
#
# We must evaluate these to actual values (not return property objects) because
# module-level properties don't work like class properties in Python.

_cfg = get_config()  # Get the singleton config
AI_PROVIDER = _cfg.ai.provider  # Extract provider string for old imports
OLLAMA_URL = _cfg.ai.ollama_url  # Extract URL for old imports
AI_MODEL = _cfg.ai.model  # Extract model name for old imports
AI_FALLBACK_ENABLED = _cfg.ai.fallback_enabled  # Extract fallback flag for old imports