from __future__ import annotations

from pydantic import BaseModel, Field

from .contracts.models import WebMission


class WebMissionFactory(BaseModel):
    """
    Factory that constructs WebMission from existing Sentinel scan/session objects.
    Keep it deterministic and policy-first.
    """
    default_max_depth: int = Field(default=4, ge=0, le=20)
    default_max_pages: int = Field(default=500, ge=1, le=20000)
    default_exploit_ceiling: int = Field(default=1000, ge=0, le=200000)

    def build(self, mission: WebMission) -> WebMission:
        # This exists mostly to provide a stable extension point (env overrides, config, etc.)
        # Do not mutate IDs here.
        return mission
