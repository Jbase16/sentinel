from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, Optional

from ..contracts.models import HttpExchange, WebMission
from ..contracts.ids import FindingId


class ReplayStore(Protocol):
    def write_text(self, relative_path: str, content: str) -> str: ...


@dataclass
class ReplayGenerator:
    """
    Generates deterministic replay script content. Agent implements script body,
    but the interface is stable and evidence contract expects replay_script_path.
    """
    store: ReplayStore

    def generate(self, mission: WebMission, finding_id: FindingId, exchanges: List[HttpExchange]) -> str:
        # Agent implements:
        # - python script that replays exchanges via ExecutionPolicy adapter OR raw httpx
        # - validates expected delta assertions
        relative = f"replays/{finding_id}.py"
        content = (
            "# Auto-generated Sentinel replay script\n"
            "# Contract: deterministic reproduction of EvidenceBundle request_sequence\n"
            "raise SystemExit('ReplayGenerator not implemented')\n"
        )
        return self.store.write_text(relative, content)
