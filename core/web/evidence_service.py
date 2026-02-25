import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

from .contracts.ids import FindingId, ArtifactId
from .contracts.models import EvidenceBundle, WebMission, ParamSpec, HttpExchange, ArtifactRef
from .contracts.enums import VulnerabilityClass
from .contracts.events import EventEnvelope, EventType, WebEvidenceBundleCreatedPayload, WebFindingConfirmedPayload
from .context import WebContext
from .transport import BaselineHandle, MutationResult, SentinelEventBus

logger = logging.getLogger(__name__)


class ReplayGenerator:
    """Generates a deterministic local replay python script."""
    def generate(self, finding_id: FindingId, mutation_exchange: HttpExchange, evidence_path: Path) -> Path:
        script_dir = evidence_path.parent.parent / "replays"
        script_dir.mkdir(parents=True, exist_ok=True)
        script_path = script_dir / f"{finding_id.value}.py"
        
        method = mutation_exchange.method.value if isinstance(mutation_exchange.method, str) else mutation_exchange.method.value
        url = str(mutation_exchange.url)
        headers = mutation_exchange.request_headers
        body_b64 = mutation_exchange.request_body_b64
        
        script = f"""#!/usr/bin/env python3
import httpx
import base64
import sys

# Deterministic Replay Script for {finding_id.value}

def main():
    target_url = {repr(url)}
    headers = {repr(headers)}
    method = {repr(method)}
    body_b64 = {repr(body_b64)}
    
    content = base64.b64decode(body_b64) if body_b64 else None
    
    print(f"[*] Replaying {{method}} {{target_url}}")
    client = httpx.Client(verify=False, follow_redirects=True)
    try:
        req = client.build_request(method, target_url, headers=headers, content=content)
        resp = client.send(req)
        print(f"[+] Status: {{resp.status_code}}")
        # In a real replay, you'd assert against the delta or canary here.
        # This V1 stub exits clean if network succeeds.
    except Exception as e:
        print(f"[-] Replay failed: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    main()
"""
        script_path.write_text(script)
        script_path.chmod(0o755)
        return script_path


class EvidenceBuilder:
    """Builds and persists EvidenceBundle components."""
    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = artifacts_dir
        
    def build(
        self,
        mission: WebMission,
        ctx: WebContext,
        vuln_class: VulnerabilityClass,
        param_spec: Optional[ParamSpec],
        handle: BaselineHandle,
        mutation: MutationResult,
        title: str,
        summary: str,
        affected_principals: Optional[List[PrincipalId]] = None,
        confidence: float = 0.9
    ) -> EvidenceBundle:
        
        # 1. Deterministic Hash ID
        normalized_url = handle.baseline_id.split("|")[2] # Extract from baseline key string
        param_name = param_spec.name if param_spec else "noparam"
        seed = f"{mission.mission_id.value}|{ctx.principal_id.value}|{vuln_class.value}|{normalized_url}|{param_name}"
        finding_id_str = "f-" + hashlib.sha256(seed.encode()).hexdigest()[:16]
        finding_id = FindingId(value=finding_id_str)
        
        evidence_dir = self.artifacts_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = evidence_dir / f"{finding_id_str}.json"
        
        # 2. Replay Automation
        replay_gen = ReplayGenerator()
        script_path = replay_gen.generate(finding_id, mutation.exchange, bundle_path)
        
        artifacts = [
            ArtifactRef(
                artifact_id=ArtifactId(value=f"art-{finding_id_str}-replay"),
                kind="replay_script",
                path=str(script_path)
            )
        ]
        
        bundle = EvidenceBundle(
            finding_id=finding_id,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=ctx.principal_id,
            affected_principals=affected_principals or [],
            vuln_class=vuln_class,
            title=title,
            summary=summary,
            request_sequence=[handle.exchange, mutation.exchange],
            baseline=handle.signature,
            delta=mutation.delta,
            vulnerable_param=param_spec,
            artifacts=artifacts,
            replay_script_path=str(script_path),
            notes=["Auto-generated Evidence Bundle"]
        )
        
        # Dump to disk
        bundle_path.write_text(json.dumps(bundle.model_dump(mode="json"), indent=2))
        
        return bundle


class EvidenceService:
    """
    Coordinates evidence generation and global event emission for confirmed findings.
    Keeps orchestrator clean.
    """
    def __init__(self, bus: SentinelEventBus, artifacts_dir: str):
        self.bus = bus
        self.builder = EvidenceBuilder(Path(artifacts_dir))
        
    def confirm(
        self,
        mission: WebMission,
        ctx: WebContext,
        vuln_class: VulnerabilityClass,
        param_spec: Optional[ParamSpec],
        handle: BaselineHandle,
        mutation: MutationResult,
        title: str,
        summary: str,
        affected_principals: Optional[List[PrincipalId]] = None,
        confidence: float = 0.9
    ) -> EvidenceBundle:
        
        bundle = self.builder.build(
            mission=mission,
            ctx=ctx,
            vuln_class=vuln_class,
            param_spec=param_spec,
            handle=handle,
            mutation=mutation,
            title=title,
            summary=summary,
            affected_principals=affected_principals,
            confidence=confidence
        )
        
        # Event 1: Bundle Created
        self.bus.emit(EventEnvelope(
            event_type=EventType.WEB_EVIDENCE_BUNDLE_CREATED,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=ctx.principal_id,
            payload=WebEvidenceBundleCreatedPayload(
                finding_id=bundle.finding_id,
                bundle=bundle.model_dump(mode="json")
            ).model_dump(mode="json")
        ))
        
        # Event 2: Finding Confirmed
        self.bus.emit(EventEnvelope(
            event_type=EventType.WEB_FINDING_CONFIRMED,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=ctx.principal_id,
            payload=WebFindingConfirmedPayload(
                finding_id=bundle.finding_id,
                vuln_class=vuln_class,
                title=title,
                target_url=mutation.exchange.url, # type: ignore
                severity=mutation.delta.severity,
                confidence=confidence,
                evidence_ready=True
            ).model_dump(mode="json")
        ))
        
        return bundle
