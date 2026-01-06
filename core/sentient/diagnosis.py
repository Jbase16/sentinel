"""
core/sentient/diagnosis.py
The Diagnostic Cortex.
Responsible for classifying failures into actionable categories.
"""
import logging
from enum import Enum, auto
from typing import Optional, Type, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class ErrorType(str, Enum):
    """
    Categorization of failure modes for decision making.
    """
    TRANSIENT = "transient"       # Network blip, timeout -> RETRY
    PERMANENT = "permanent"       # 404, Schema error -> SKIP
    WAF_BLOCK = "waf_block"       # 403, Cloudflare -> ROTATE/COOL
    RESOURCE = "resource"         # Disk full, Memory limit -> ABORT/GC
    UNKNOWN = "unknown"           # Unhandled -> LOG & ABORT

@dataclass
class Diagnosis:
    type: ErrorType
    confidence: float
    reason: str
    recommendation: str

class ErrorClassifier:
    """
    Expert system for failure analysis.
    """
    
    def __init__(self):
        # Maps exception strings/types to error categories
        # TODO: Load this from a configurable policy file
        pass

    def diagnose(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Diagnosis:
        """
        Analyze an exception and return a diagnosis.
        """
        err_str = str(error).lower()
        err_type = type(error).__name__
        
        # 1. WAF / Auth Blocks
        if "403" in err_str or "forbidden" in err_str or "captcha" in err_str:
             return Diagnosis(
                 ErrorType.WAF_BLOCK, 
                 0.9, 
                 "Likely WAF blocking or Auth failure",
                 "ROTATE_PROXY_OR_COOLDOWN"
             )

        # 2. Transient Network Issues
        # Check string OR type
        if ("timeout" in err_str or "connection reset" in err_str or "econnrefused" in err_str or
            isinstance(error, (ConnectionError, TimeoutError, OSError))):
            
            # Refine OSError: only if connection related (not file not found)
            if isinstance(error, FileNotFoundError):
                 pass # Fall through to default or permanent
            else:
                return Diagnosis(
                    ErrorType.TRANSIENT,
                    0.8,
                    f"Network instability detected ({err_type})",
                    "RETRY_WITH_BACKOFF"
                )

        # 3. Permanent Logic Errors
        if isinstance(error, (KeyError, ValueError, TypeError, AttributeError)):
             # Unless it's a known flaky library error, logic bugs are permanent
             return Diagnosis(
                 ErrorType.PERMANENT,
                 1.0,
                 f"Internal Logic Error: {err_type}",
                 "FAIL_TASK"
             )
        
        # 4. Resource Issues
        if "disk" in err_str or "memory" in err_str or "resource exhausted" in err_str:
             return Diagnosis(
                 ErrorType.RESOURCE,
                 0.9,
                 "System Resource Limit Hit",
                 "ABORT_SCAN"
             )

        # Default
        return Diagnosis(
            ErrorType.UNKNOWN,
            0.1,
            f"Unhandled Exception: {err_type} - {err_str}",
            "FAIL_TASK"
        )
