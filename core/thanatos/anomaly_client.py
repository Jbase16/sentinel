"""
core/thanatos/anomaly_client.py

Purpose:
    Defines the structural interfaces for the Anomaly Client (Raw Socket).
    This module is responsible for transmitting "Heretic" states that
    standard libraries (httpx, requests) would reject or normalize.

Safety:
    Wrapper-only. No real socket connections. No packet transmission.
    Guarded by SAFE_MODE.

Integration:
    - Ontology Breaker: Source of payloads.
    - EventBus: Emits 'DESYNC_DETECTED', 'PANIC_DETECTED'.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol, Tuple

from core.thanatos.ontology_breaker import HereticRequest

SAFE_MODE: bool = True

@dataclass(frozen=True)
class AnomalyResponse:
    """Represents the raw, potentially malformed response from the server."""
    raw_bytes: bytes
    status_code: Optional[int]
    is_desync: bool
    connection_state: str  # "CLOSED", "HUNG", "RESET"

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("Wrapper-only: implementation deferred")

class RawSocketHandler(Protocol):
    """Interface for low-level async socket operations."""
    
    async def connect(self, host: str, port: int, safe: bool = True) -> Any:
        ...
    
    async def send_raw(self, data: bytes) -> None:
        ...

    async def read_until_close(self) -> bytes:
        ...

class AnomalyClientService:
    """
    Main Service entry point for the Anomaly Client.
    """

    def __init__(self):
        if not SAFE_MODE:
            # Circuit breaker logic would live here
            raise RuntimeError("AnomalyClientService initiated in unsafe mode (Not Implemented)")

    async def transmit_heretic(self, request: HereticRequest) -> AnomalyResponse:
        """
        Transmit a heretic request via raw sockets.
        """
        raise NotImplementedError("Wrapper-only: implementation deferred")

    async def replay(self, artifact: Dict[str, Any]) -> None:
        """Replay a packet capture (PCAP) artifact."""
        raise NotImplementedError("Wrapper-only: replay deferred")
