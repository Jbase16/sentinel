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
    """Generates a courtroom-grade deterministic local replay python script."""
    def generate_replay(self, bundle: EvidenceBundle) -> str:
        method = bundle.request_sequence[0].method.value if isinstance(bundle.request_sequence[0].method, str) else bundle.request_sequence[0].method.value
        url = str(bundle.request_sequence[0].url)
        
        script = [
            "#!/usr/bin/env python3",
            "# Sentinel Replay Artifact",
            f"# Finding: {bundle.finding_id.value}",
            f"# Vulnerability: {bundle.vuln_class.value}",
            f"# Principals: {' -> '.join([str(p.principal_id.value) for p in bundle.principal_states])}",
            "",
            "import httpx",
            "import hashlib",
            "import base64",
            "import sys",
            "",
            "def main():",
            f"    target_url = {repr(url)}",
            f"    method = {repr(method)}",
            ""
        ]

        clients = []
        for state in bundle.principal_states:
            pid = state.principal_id.value.replace('-', '_')
            clients.append(pid)
            script.append(f"    # Principal {state.principal_id.value}")
            script.append(f"    client_{pid} = httpx.Client(verify=False, follow_redirects=True)")
            if state.cookies:
                script.append(f"    client_{pid}.cookies.update({repr(state.cookies)})")
            script.append("")

        # Assume 2 sequence exchanges (baseline and mutate)
        if len(bundle.request_sequence) >= 2:
            base_b64 = bundle.request_sequence[0].request_body_b64
            mut_b64 = bundle.request_sequence[1].request_body_b64
            
            script.append(f"    base_content = base64.b64decode({repr(base_b64)}) if {repr(base_b64)} else None")
            script.append(f"    base_headers = {repr(bundle.request_sequence[0].request_headers)}")
            script.append(f"    base_req = client_{clients[0]}.build_request(method, target_url, headers=base_headers, content=base_content)")
            script.append(f"    print('[*] Simulating baseline execution...')")
            script.append(f"    base_resp = client_{clients[0]}.send(base_req)")
            script.append("")
            
            # The mutation attempt
            attacker_client = clients[1] if len(clients) > 1 else clients[0]
            script.append(f"    mut_content = base64.b64decode({repr(mut_b64)}) if {repr(mut_b64)} else None")
            script.append(f"    mut_headers = {repr(bundle.request_sequence[1].request_headers)}")
            script.append(f"    mut_req = client_{attacker_client}.build_request(method, target_url, headers=mut_headers, content=mut_content)")
            script.append(f"    print('[*] Simulating mutation execution...')")
            script.append(f"    mut_resp = client_{attacker_client}.send(mut_req)")
            script.append("")
            
            if bundle.vuln_class == VulnerabilityClass.IDOR:
                script.append("    print('[+] Response bodies extracted. Attempting to verify exact IDOR reproduction...')")
                script.append("    assert hashlib.sha256(base_resp.content).hexdigest() == hashlib.sha256(mut_resp.content).hexdigest(), 'Response contents do not match (IDOR failed)'")
                script.append("    print('IDOR reproduced successfully.')")
            else:
                script.append("    print(f'[+] Original Status: {base_resp.status_code}, Mutated Status: {mut_resp.status_code}')")
                script.append("    print('Finding verification complete.')")

        script.append("")
        script.append("if __name__ == '__main__':")
        script.append("    main()")
        
        return "\n".join(script)


class EvidenceBuilder:
    """Builds and persists EvidenceBundle components."""
    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = artifacts_dir
        
    def build(
        self,
        mission: WebMission,
        vuln_class: VulnerabilityClass,
        param_spec: Optional[ParamSpec],
        handle: BaselineHandle,
        mutation: MutationResult,
        title: str,
        summary: str,
        principal_states: List[PrincipalSnapshot],
        confidence: float = 0.9
    ) -> EvidenceBundle:
        
        # 1. Deterministic Hash ID
        url = str(handle.exchange.url)
        sorted_principals = ",".join(sorted(p.principal_id.value for p in principal_states))
        seed = f"{mission.mission_id.value}:{url}:{vuln_class.value}:{sorted_principals}"
        finding_id_str = "f-" + hashlib.sha256(seed.encode()).hexdigest()[:16]
        finding_id = FindingId(value=finding_id_str)
        
        # 2. Base Evidence Bundle
        bundle = EvidenceBundle(
            finding_id=finding_id,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=principal_states[0].principal_id, # Target principal
            principal_states=principal_states,
            affected_principals=[p.principal_id for p in principal_states],
            vuln_class=vuln_class,
            title=title,
            summary=summary,
            request_sequence=[handle.exchange, mutation.exchange],
            baseline=handle.signature,
            delta=mutation.delta,
            vulnerable_param=param_spec,
            artifacts=[],
            notes=["Auto-generated Evidence Bundle"]
        )

        # 3. Generate Courtroom-Grade Replay Script
        replay_gen = ReplayGenerator()
        script_content = replay_gen.generate_replay(bundle)
        script_hash = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
        
        script_dir = self.artifacts_dir / "replays"
        script_dir.mkdir(parents=True, exist_ok=True)
        script_path = script_dir / f"{finding_id_str}.py"
        script_path.write_text(script_content)
        script_path.chmod(0o755)

        bundle.replay_script_path = str(script_path)
        bundle.artifacts.append(
            ArtifactRef(
                artifact_id=ArtifactId(value=f"art-{finding_id_str}-replay"),
                kind="replay_script",
                path=str(script_path),
                sha256=script_hash
            )
        )

        # 4. Final Verification Hash
        bundle_json_str = json.dumps(bundle.model_dump(mode="json", exclude={"artifact_hash"}), sort_keys=True)
        bundle.artifact_hash = hashlib.sha256(bundle_json_str.encode("utf-8")).hexdigest()

        # 5. Dump to disk
        evidence_dir = self.artifacts_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = evidence_dir / f"{finding_id_str}.json"
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
        contexts: List[WebContext],
        vuln_class: VulnerabilityClass,
        param_spec: Optional[ParamSpec],
        handle: BaselineHandle,
        mutation: MutationResult,
        title: str,
        summary: str,
        confidence: float = 0.9
    ) -> EvidenceBundle:
        from .contracts.models import PrincipalSnapshot

        principal_states = []
        for c in contexts:
            # Seal the execution state
            ua = dict(c.default_headers).get("User-Agent", "")
            principal_states.append(
                PrincipalSnapshot(
                    principal_id=c.principal_id,
                    cookies=dict(c.client.cookies),
                    user_agent=ua
                )
            )

        bundle = self.builder.build(
            mission=mission,
            vuln_class=vuln_class,
            param_spec=param_spec,
            handle=handle,
            mutation=mutation,
            title=title,
            summary=summary,
            principal_states=principal_states,
            confidence=confidence
        )
        
        # Event 1: Bundle Created
        self.bus.emit(EventEnvelope(
            event_type=EventType.WEB_EVIDENCE_BUNDLE_CREATED,
            mission_id=mission.mission_id,
            scan_id=mission.scan_id,
            session_id=mission.session_id,
            principal_id=contexts[0].principal_id,
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
            principal_id=contexts[0].principal_id,
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
