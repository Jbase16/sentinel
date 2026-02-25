import logging
from typing import List, Optional

from ..contracts.models import WebMission, ParamSpec
from ..contracts.enums import VulnerabilityClass, WebMethod
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult

logger = logging.getLogger(__name__)

class MultiPrincipalDiffEngine:
    """
    Implements deterministic cross-principal IDOR analysis.
    Establishes a baseline as Principal A, replays exactly as Principal B,
    and observes differences in authorization behavior.
    """
    vuln_class = VulnerabilityClass.IDOR

    def run(
        self,
        mission: WebMission,
        ctx_a: WebContext,
        ctx_b: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int
    ) -> List[MutationResult]:
        
        # 1. Establish baseline under Principal A
        handle_a = transport.establish_baseline(
            mission=mission,
            ctx=ctx_a,
            method=method,
            url=url
        )
        
        # If Principal A can't access their own supposedly public/owned resource, 
        # we can't reliably test for IDOR. For V1, require 2xx.
        if handle_a.signature.status_code not in range(200, 300):
            return []
            
        # 2. Force Execution under Principal B
        # Pass ctx_b for network execution, but handle_a for baseline diffing!
        # This is the core architectural insight: Cross-Principal Diffing
        res_b = transport.mutate(
            mission=mission,
            ctx=ctx_b,
            handle=handle_a,
            vuln_class=self.vuln_class,
            mutation_label="MultiPrincipal-B-to-A",
            budget_index=budget_index,
            mutated_url=url,
            mutated_method=method,
            # Let the context and policy apply B's authenticators
            mutated_headers=None, 
            mutated_body=None,
            # Stub param spec for Evidence output
            param_spec=None
        )
        
        delta = res_b.delta
        results = []
        
        # 3. Deterministic Confirmation Logic
        # V1: Same status code and extremely high structural similarity.
        if delta.status_delta in (0, None) and delta.structural_delta < 0.05:
            # B accessed A's resource successfully
            delta.severity = delta.severity.__class__.HIGH
            delta.notes.append("Cross-principal identical response detected.")
            results.append(res_b)
        elif delta.status_delta in (0, None) and handle_a.signature.json_shape_hash and handle_a.signature.json_shape_hash == self._get_json_shape(res_b):
            # Same JSON shape despite structural drift (e.g. timestamps changed, but schema matches 1:1)
            delta.severity = delta.severity.__class__.HIGH
            delta.notes.append("Cross-principal identical JSON shape detected.")
            results.append(res_b)
            
        return results

    def _get_json_shape(self, res: MutationResult) -> Optional[str]:
        # Helper to extract json shape off the mutation
        import base64
        from ..diff.baseline import _json_shape_hash
        if res.exchange.response_body_b64:
            try:
                raw = base64.b64decode(res.exchange.response_body_b64)
                return _json_shape_hash(raw)
            except Exception:
                pass
        return None
