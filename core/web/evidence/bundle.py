from __future__ import annotations

from dataclasses import dataclass
from typing import List, Protocol, Optional

from ..contracts.models import EvidenceBundle, HttpExchange, ArtifactRef, BaselineSignature, DeltaVector, WebMission
from ..contracts.ids import FindingId, PrincipalId
from ..contracts.enums import VulnerabilityClass


class ArtifactStore(Protocol):
    def put_bytes(self, kind: str, data: bytes, suggested_name: str) -> ArtifactRef: ...
    def put_path(self, kind: str, path: str) -> ArtifactRef: ...


@dataclass
class EvidenceBuilder:
    """
    Builds the EvidenceBundle contract. Does not decide confirmation—only packages evidence.
    """
    artifact_store: ArtifactStore

    def build(
        self,
        mission: WebMission,
        finding_id: FindingId,
        principal_id: PrincipalId,
        vuln_class: VulnerabilityClass,
        title: str,
        summary: str,
        request_sequence: List[HttpExchange],
        baseline: Optional[BaselineSignature],
        delta: Optional[DeltaVector],
        artifacts: List[ArtifactRef],
        replay_script_path: Optional[str],
    ) -> EvidenceBundle:
        return EvidenceBundle(
            finding_id=finding_id,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            vuln_class=vuln_class,
            title=title,
            summary=summary,
            principal_id=principal_id,
            affected_principals=[],
            request_sequence=request_sequence,
            baseline=baseline,
            delta=delta,
            artifacts=artifacts,
            replay_script_path=replay_script_path,
        )
