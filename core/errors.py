"""Module errors: inline documentation for /Users/jason/Developer/sentinelforge/core/errors.py."""
#
from enum import Enum
from typing import Dict, Any, Optional, List
# PURPOSE:
# Provides a structured error taxonomy for SentinelForge with error codes,
# typed exceptions, and consistent error handling across the codebase.
#
# WHY STRUCTURED ERRORS:
# - Makes debugging easier (error codes are searchable)
# - Enables better error handling in UI (can show specific messages)
# - Supports monitoring/alerting (can track error rates by type)
# - Provides audit trail (errors are categorized and logged consistently)
#
# ERROR CODE FORMAT:
# - SCAN_XXX: Scan-related errors
# - TOOL_XXX: Tool execution errors
# - AI_XXX: AI/LLM errors
# - DB_XXX: Database errors
# - AUTH_XXX: Authentication/authorization errors
# - IPC_XXX: Inter-process communication errors
# - CONFIG_XXX: Configuration errors
#
# USAGE:
#   from core.errors import SentinelError, ErrorCode
#
#   raise SentinelError(
#       ErrorCode.SCAN_ALREADY_RUNNING,
#       "Cannot start scan while another is active",
#       details={"active_target": "example.com"}
#   )
#
class ErrorCode(Enum):
    # Scan Errors
    SCAN_ALREADY_RUNNING = "SCAN_001"
    SCAN_TARGET_INVALID = "SCAN_002"
    SCAN_TIMEOUT = "SCAN_003"
    SCAN_CANCELLED = "SCAN_004"
    SCAN_SESSION_NOT_FOUND = "SCAN_005"
    SCAN_NO_TOOLS_AVAILABLE = "SCAN_006"

    # Tool Errors
    TOOL_NOT_INSTALLED = "TOOL_001"
    TOOL_EXEC_FAILED = "TOOL_002"
    TOOL_TIMEOUT = "TOOL_003"
    TOOL_OUTPUT_PARSE_ERROR = "TOOL_004"
    TOOL_BINARY_NOT_FOUND = "TOOL_005"
    TOOL_PERMISSION_DENIED = "TOOL_006"

    # AI Errors
    AI_OFFLINE = "AI_001"
    AI_TIMEOUT = "AI_002"
    AI_INVALID_RESPONSE = "AI_003"
    AI_JSON_PARSE_ERROR = "AI_004"
    AI_MODEL_NOT_FOUND = "AI_005"
    AI_RATE_LIMIT_EXCEEDED = "AI_006"

    # Database Errors
    DB_CONNECTION_FAILED = "DB_001"
    DB_LOCK_TIMEOUT = "DB_002"
    DB_QUERY_FAILED = "DB_003"
    DB_INIT_FAILED = "DB_004"
    DB_TRANSACTION_FAILED = "DB_005"

    # Auth Errors
    AUTH_TOKEN_INVALID = "AUTH_001"
    AUTH_TOKEN_MISSING = "AUTH_002"
    AUTH_PERMISSION_DENIED = "AUTH_003"
    AUTH_RATE_LIMIT_EXCEEDED = "AUTH_004"

    # IPC Errors
    IPC_CONNECTION_FAILED = "IPC_001"
    IPC_TIMEOUT = "IPC_002"
    IPC_PROTOCOL_ERROR = "IPC_003"
    IPC_VERSION_MISMATCH = "IPC_004"

    # Config Errors
    CONFIG_INVALID = "CONFIG_001"
    CONFIG_MISSING_REQUIRED = "CONFIG_002"
    CONFIG_FILE_NOT_FOUND = "CONFIG_003"
    CONFIG_PARSE_ERROR = "CONFIG_004"

    # Session Errors
    SESSION_NOT_FOUND = "SESSION_001"
    SESSION_ALREADY_EXISTS = "SESSION_002"
    SESSION_INVALID_STATE = "SESSION_003"

    # Event Errors
    EVENT_STORE_FULL = "EVENT_001"
    EVENT_SERIALIZATION_FAILED = "EVENT_002"
    EVENT_SUBSCRIBER_ERROR = "EVENT_003"

    # System Errors
    SYSTEM_INTERNAL_ERROR = "SYSTEM_001"
    SYSTEM_RESOURCE_EXHAUSTED = "SYSTEM_002"
    SYSTEM_NOT_IMPLEMENTED = "SYSTEM_003"


class SentinelError(Exception):
    """
    Base exception class for SentinelForge with structured error information.
    
    This exception provides:
    - Error code (for programmatic handling)
    - Human-readable message
    - Optional details dictionary (for context)
    - HTTP status code mapping (for API responses)
    
    Attributes:
        code: ErrorCode enum value (e.g., "SCAN_001")
        message: Human-readable error message
        details: Optional dictionary with additional context
        http_status: Suggested HTTP status code for API responses
    """
    
    # Map error codes to HTTP status codes
    HTTP_STATUS_MAP: Dict[ErrorCode, int] = {
        # Scan errors
        ErrorCode.SCAN_ALREADY_RUNNING: 409,  # Conflict
        ErrorCode.SCAN_TARGET_INVALID: 400,   # Bad Request
        ErrorCode.SCAN_TIMEOUT: 408,          # Request Timeout
        ErrorCode.SCAN_CANCELLED: 499,        # Client Closed Request
        ErrorCode.SCAN_SESSION_NOT_FOUND: 404, # Not Found
        ErrorCode.SCAN_NO_TOOLS_AVAILABLE: 503, # Service Unavailable
        
        # Tool errors
        ErrorCode.TOOL_NOT_INSTALLED: 503,    # Service Unavailable
        ErrorCode.TOOL_EXEC_FAILED: 500,      # Internal Server Error
        ErrorCode.TOOL_TIMEOUT: 408,          # Request Timeout
        ErrorCode.TOOL_OUTPUT_PARSE_ERROR: 500,
        ErrorCode.TOOL_BINARY_NOT_FOUND: 503,
        ErrorCode.TOOL_PERMISSION_DENIED: 403, # Forbidden
        
        # AI errors
        ErrorCode.AI_OFFLINE: 503,            # Service Unavailable
        ErrorCode.AI_TIMEOUT: 408,            # Request Timeout
        ErrorCode.AI_INVALID_RESPONSE: 500,
        ErrorCode.AI_JSON_PARSE_ERROR: 500,
        ErrorCode.AI_MODEL_NOT_FOUND: 404,
        ErrorCode.AI_RATE_LIMIT_EXCEEDED: 429, # Too Many Requests
        
        # Database errors
        ErrorCode.DB_CONNECTION_FAILED: 503,
        ErrorCode.DB_LOCK_TIMEOUT: 503,
        ErrorCode.DB_QUERY_FAILED: 500,
        ErrorCode.DB_INIT_FAILED: 500,
        ErrorCode.DB_TRANSACTION_FAILED: 500,
        
        # Auth errors
        ErrorCode.AUTH_TOKEN_INVALID: 401,    # Unauthorized
        ErrorCode.AUTH_TOKEN_MISSING: 401,
        ErrorCode.AUTH_PERMISSION_DENIED: 403, # Forbidden
        ErrorCode.AUTH_RATE_LIMIT_EXCEEDED: 429,
        
        # IPC errors
        ErrorCode.IPC_CONNECTION_FAILED: 503,
        ErrorCode.IPC_TIMEOUT: 408,
        ErrorCode.IPC_PROTOCOL_ERROR: 400,
        ErrorCode.IPC_VERSION_MISMATCH: 400,
        
        # Config errors
        ErrorCode.CONFIG_INVALID: 500,
        ErrorCode.CONFIG_MISSING_REQUIRED: 500,
        ErrorCode.CONFIG_FILE_NOT_FOUND: 500,
        ErrorCode.CONFIG_PARSE_ERROR: 500,
        
        # Session errors
        ErrorCode.SESSION_NOT_FOUND: 404,
        ErrorCode.SESSION_ALREADY_EXISTS: 409,
        ErrorCode.SESSION_INVALID_STATE: 400,
        
        # Event errors
        ErrorCode.EVENT_STORE_FULL: 503,
        ErrorCode.EVENT_SERIALIZATION_FAILED: 500,
        ErrorCode.EVENT_SUBSCRIBER_ERROR: 500,
        
        # System errors
        ErrorCode.SYSTEM_INTERNAL_ERROR: 500,
        ErrorCode.SYSTEM_RESOURCE_EXHAUSTED: 503,
        ErrorCode.SYSTEM_NOT_IMPLEMENTED: 501, # Not Implemented
    }
    
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        http_status: Optional[int] = None
    ):
        """
        Initialize a SentinelError.
        
        Args:
            code: ErrorCode enum value
            message: Human-readable error message
            details: Optional dictionary with additional context
            http_status: Optional HTTP status code (defaults to mapped value)
        """
        self.code = code
        self.message = message
        self.details = details or {}
        self.http_status = http_status or self.HTTP_STATUS_MAP.get(code, 500)
        
        # Build exception message with code for easy debugging
        super().__init__(f"[{code.value}] {message}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert error to dictionary for JSON serialization.
        
        Returns:
            Dictionary with code, message, details, and http_status
        """
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
            "http_status": self.http_status
        }
    
    def to_json(self) -> str:
        """
        Serialize error to JSON string.
        
        Returns:
            JSON string representation of the error
        """
        import json
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SentinelError":
        """
        Deserialize error from dictionary.
        
        Args:
            data: Dictionary with code, message, details, http_status
            
        Returns:
            SentinelError instance
        """
        code = ErrorCode(data["code"])
        message = data["message"]
        details = data.get("details", {})
        http_status = data.get("http_status")
        return cls(code, message, details, http_status)


# ============================================================================
# Convenience Functions
# ============================================================================

def handle_error(error: Exception, context: Optional[str] = None) -> SentinelError:
    """
    Convert a generic exception to a SentinelError.
    
    Useful for catching unexpected exceptions and wrapping them in structured errors.
    
    Args:
        error: The original exception
        context: Optional context string (e.g., "while processing tool output")
        
    Returns:
        SentinelError with appropriate code and message
    """
    if isinstance(error, SentinelError):
        return error
    
    # Try to map common exception types to error codes
    error_type = type(error).__name__
    
    if "Timeout" in error_type or "timeout" in str(error).lower():
        code = ErrorCode.SYSTEM_INTERNAL_ERROR  # Generic timeout
    elif "Permission" in error_type or "permission" in str(error).lower():
        code = ErrorCode.TOOL_PERMISSION_DENIED
    elif "Connection" in error_type or "connection" in str(error).lower():
        code = ErrorCode.IPC_CONNECTION_FAILED
    else:
        code = ErrorCode.SYSTEM_INTERNAL_ERROR
    
    message = str(error)
    if context:
        message = f"{context}: {message}"
    
    return SentinelError(
        code=code,
        message=message,
        details={
            "original_type": error_type,
            "original_message": str(error)
        }
    )


# ============================================================================
# Module-Level Exports
# ============================================================================

__all__ = ["ErrorCode", "SentinelError", "handle_error"]

