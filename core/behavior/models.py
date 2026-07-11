"""Stable, redacted contracts for passive behavioral observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class NormalizedExchange:
    """One HTTP exchange with all raw values removed.

    The hashes let later relational analysis detect concrete differences without
    retaining credentials, identifiers, or response content.  ``action_id`` and
    ``state_id`` are structural fingerprints: changing only a password, token, or
    object value must not manufacture a new operation or response shape.
    """

    source_id: str
    world_id: str
    action_id: str
    state_id: str
    method: str
    origin: str
    path_template: str
    query_keys: Tuple[str, ...]
    request_header_names: Tuple[str, ...]
    response_header_names: Tuple[str, ...]
    request_content_type: Optional[str]
    response_content_type: Optional[str]
    request_shape: Dict[str, Any]
    response_status: int
    response_shape: Dict[str, Any]
    cookie_names: Tuple[str, ...]
    request_body_hash: Optional[str]
    response_body_hash: Optional[str]
    request_truncated: bool = False
    response_truncated: bool = False

    def action_descriptor(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "origin": self.origin,
            "path_template": self.path_template,
            "query_keys": list(self.query_keys),
            "request_header_names": list(self.request_header_names),
            "request_content_type": self.request_content_type,
            "request_shape": self.request_shape,
        }

    def state_descriptor(self) -> Dict[str, Any]:
        return {
            "status": self.response_status,
            "response_header_names": list(self.response_header_names),
            "response_content_type": self.response_content_type,
            "response_shape": self.response_shape,
            "cookie_names": list(self.cookie_names),
            "response_truncated": self.response_truncated,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe redacted representation."""
        return {
            "source_id": self.source_id,
            "world_id": self.world_id,
            "action_id": self.action_id,
            "state_id": self.state_id,
            **self.action_descriptor(),
            **self.state_descriptor(),
            "response_status": self.response_status,
            "request_body_hash": self.request_body_hash,
            "response_body_hash": self.response_body_hash,
            "request_truncated": self.request_truncated,
        }
