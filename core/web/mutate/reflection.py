from __future__ import annotations

from dataclasses import dataclass
import hashlib
import base64
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from .base import Mutator
from ..contracts.enums import VulnerabilityClass, WebMethod, ParamLocation
from ..contracts.models import ParamSpec, WebMission
from ..context import WebContext
from ..transport import MutatingTransport, MutationResult


@dataclass
class ReflectionMutator:
    vuln_class: VulnerabilityClass = VulnerabilityClass.REFLECTION

    def run(
        self,
        mission: WebMission,
        ctx: WebContext,
        transport: MutatingTransport,
        url: str,
        method: WebMethod,
        budget_index: int,
    ) -> List[MutationResult]:
        results: List[MutationResult] = []
        
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        
        # 3. If none exist, return empty list. (Only GET param mutation in V1)
        if not params or method != WebMethod.GET:
            return results
            
        # 4. Establish baseline once using transport
        handle = transport.establish_baseline(mission, ctx, method, url)
        
        # 5. Mutate each parameter
        for i, (k, v) in enumerate(params):
            if budget_index + i >= mission.exploit_ceiling:
                break
                
            canary = f"sntnl_rflct_{hashlib.md5((k + str(ctx.request_counter)).encode()).hexdigest()[:8]}"
            
            mutated_params = list(params)
            mutated_params[i] = (k, canary)
            mutated_query = urlencode(mutated_params)
            mutated_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, mutated_query, parsed.fragment))
            
            param_spec = ParamSpec(
                name=k,
                location=ParamLocation.QUERY,
                example_value=v,
                type_guess="string",
                reflection_hint=True
            )
            
            mutation_res = transport.mutate(
                mission=mission,
                ctx=ctx,
                handle=handle,
                vuln_class=self.vuln_class,
                mutation_label=f"canary_reflect_{k}",
                budget_index=budget_index + i,
                mutated_url=mutated_url,
                mutated_method=method,
                param_spec=param_spec
            )
            
            # 6. Inspect MutationResult.delta AND response body for canary
            body_b64 = mutation_res.exchange.response_body_b64
            if body_b64:
                try:
                    body_decoded = base64.b64decode(body_b64).decode('utf-8', errors='ignore')
                    if canary in body_decoded:
                        # Reflection firmly detected. Intent only; evidence generation is external.
                        results.append(mutation_res)
                except Exception:
                    pass
        
        return results
