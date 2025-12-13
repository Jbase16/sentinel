# core/config.py
# Production-grade configuration management with security defaults

from __future__ import annotations

import os
import secrets
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AIConfig:
    provider: str = "ollama"
    ollama_url: str = "http://localhost:11434"
    model: str = "llama3:latest"
    fallback_enabled: bool = True
    request_timeout: float = 300.0
    max_concurrent_requests: int = 2
    max_context_tokens: int = 8000


@dataclass(frozen=True)
class SecurityConfig:
    api_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    allowed_origins: tuple = ("http://127.0.0.1:*", "http://localhost:*", "tauri://localhost")
    require_auth: bool = False # Defaulting to False for local dev/demo ease, can be enabled via env
    terminal_enabled: bool = True
    terminal_require_auth: bool = False # Default False for dev
    clipboard_enabled: bool = True
    rate_limit_requests_per_minute: int = 600 # Higher for dev
    rate_limit_ai_per_minute: int = 60


@dataclass(frozen=True)
class StorageConfig:
    base_dir: Path = field(default_factory=lambda: Path.home() / ".sentinelforge")
    db_name: str = "sentinel.db"
    evidence_dir: str = "evidence"
    reports_dir: str = "reports"
    max_evidence_size_mb: int = 100
    
    @property
    def db_path(self) -> Path:
        return self.base_dir / self.db_name
    
    @property
    def evidence_path(self) -> Path:
        return self.base_dir / self.evidence_dir
    
    @property
    def reports_path(self) -> Path:
        return self.base_dir / self.reports_dir


@dataclass(frozen=True)
class ScanConfig:
    max_concurrent_tools: int = 2
    tool_timeout_seconds: int = 300
    max_findings_per_tool: int = 1000
    auto_approve_safe_tools: bool = True
    safe_tools: tuple = ("httpx", "dnsx", "subfinder", "whois")
    restricted_tools: tuple = ("nmap", "nikto", "nuclei", "gobuster", "feroxbuster", "sqlmap", "masscan", "brew", "pip")


@dataclass(frozen=True)
class LogConfig:
    level: str = "INFO"
    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    file_enabled: bool = True
    file_name: str = "sentinel.log"
    max_file_size_mb: int = 10
    backup_count: int = 5


@dataclass
class SentinelConfig:
    ai: AIConfig = field(default_factory=AIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    log: LogConfig = field(default_factory=LogConfig)
    debug: bool = False
    api_host: str = "127.0.0.1"
    api_port: int = 8765
    
    def __post_init__(self):
        self.storage.base_dir.mkdir(parents=True, exist_ok=True)
        self.storage.evidence_path.mkdir(parents=True, exist_ok=True)
        self.storage.reports_path.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_env(cls) -> "SentinelConfig":
        ai = AIConfig(
            provider=os.getenv("SENTINEL_AI_PROVIDER", "ollama"),
            # AI Config - defaults to Sentinel Brain (local fine-tuned model)
            ollama_url=os.getenv("SENTINEL_OLLAMA_URL", "http://localhost:8009"),
            model=os.getenv("SENTINEL_AI_MODEL", "llama3:latest"),
            fallback_enabled=os.getenv("SENTINEL_AI_FALLBACK", "true").lower() == "true",
            request_timeout=float(os.getenv("SENTINEL_AI_TIMEOUT", "300")),
            max_concurrent_requests=int(os.getenv("SENTINEL_AI_MAX_CONCURRENT", "2")),
        )
        
        token = os.getenv("SENTINEL_API_TOKEN")
        if not token:
            token = secrets.token_urlsafe(32)
        
        origins_str = os.getenv("SENTINEL_ALLOWED_ORIGINS", "")
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


_config: Optional[SentinelConfig] = None


def get_config() -> SentinelConfig:
    global _config
    if _config is None:
        _config = SentinelConfig.from_env()
    return _config


def set_config(config: SentinelConfig) -> None:
    global _config
    _config = config


def setup_logging(config: Optional[SentinelConfig] = None) -> None:
    cfg = config or get_config()
    
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    
    if cfg.log.file_enabled:
        from logging.handlers import RotatingFileHandler
        log_path = cfg.storage.base_dir / cfg.log.file_name
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=cfg.log.max_file_size_mb * 1024 * 1024,
            backupCount=cfg.log.backup_count,
        )
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=getattr(logging, cfg.log.level.upper()),
        format=cfg.log.format,
        handlers=handlers,
        force=True,
    )


# Legacy compatibility aliases
# Legacy compatibility aliases
# We must evaluate these to values, not return property objects, because module-level properties don't work like class properties.
_cfg = get_config()
AI_PROVIDER = _cfg.ai.provider
OLLAMA_URL = _cfg.ai.ollama_url
AI_MODEL = _cfg.ai.model
AI_FALLBACK_ENABLED = _cfg.ai.fallback_enabled