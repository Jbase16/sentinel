from __future__ import annotations

import re
from pydantic import BaseModel, Field, field_validator

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-_:]{7,127}$")


class SentinelId(BaseModel):
    """
    Strong-ish ID wrapper to prevent 'random string soup' from leaking into
    persistence and events.

    Format: lowercase, starts with [a-z0-9], then [a-z0-9-_:], length 8..128.
    """
    value: str = Field(..., description="Opaque identifier")

    @field_validator("value")
    @classmethod
    def validate_id(cls, v: str) -> str:
        v2 = v.strip()
        if not _ID_RE.match(v2):
            raise ValueError(f"Invalid id format: {v2!r}")
        return v2

    def __str__(self) -> str:
        return self.value


class MissionId(SentinelId):
    pass


class SessionId(SentinelId):
    pass


class ScanId(SentinelId):
    pass


class FindingId(SentinelId):
    pass


class ArtifactId(SentinelId):
    pass


class PrincipalId(SentinelId):
    pass


class RequestId(SentinelId):
    pass
