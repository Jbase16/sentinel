"""Module route_miner: inline documentation for /Users/jason/Developer/sentinelforge/core/sentient/mimic/route_miner.py."""
#
# PURPOSE:
# To infer the API structure (Routes) from raw traffic.
#
# CAL INTEGRATION:
# - New routes discovered → Assert Claim ("Endpoint {method} {path} exists")
# - Repeated observations → Add supporting Evidence (strengthens claim)
# - High observation count → Claim converges to VALIDATED
#
# ALGORITHM:
# 1. Ingest URL path (e.g. "/users/123/profile")
# 2. Tokenize path segments.
# 3. Insert into a Trie.
# 4. "Parameter Clustering":
#    - If a node has many children that look like IDs (integers, UUIDs),
#      collapse them into a single "{id}" node.
#

import re
import logging
from typing import List, Dict, Optional
from core.sentient.mimic.types import RouteNode, Endpoint
from core.cal.types import Evidence, Provenance

logger = logging.getLogger(__name__)

class RouteMiner:
    """
    The Cartographer. Builds a map of the API from observed traffic.
    
    CAL INTEGRATION:
    Every discovered route is a Claim in the global ReasoningSession.
    Repeated observations strengthen the claim until it reaches VALIDATED.
    """
    def __init__(self):
        self.root = RouteNode(segment="")
        
        # Regex for identifying likely parameters
        self.uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
        self.int_pattern = re.compile(r'^\d+$')
        
        # [CAL INTEGRATION]
        from core.cortex.reasoning import get_reasoning_engine
        self.reasoning_engine = get_reasoning_engine()
        
        # Track which routes have CAL claims (keyed by path_template)
        self._route_claims: Dict[str, str] = {}  # path_template -> claim_id
        
        logger.info("[MIMIC] CAL integration enabled - routes will emit Claims")

    def ingest(self, method: str, path: str) -> Endpoint:
        """
        Learn from a new request.
        1. Tokenize path.
        2. Walk/Build Trie.
        3. Detect Parameters.
        4. Return the resolved Endpoint model.
        5. [CAL] Assert/strengthen route Claim.
        """
        segments = [s for s in path.split('/') if s]
        current_node = self.root
        
        # We need to rebuild the template string as we walk (e.g. "/" -> "users" -> "{id}")
        template_parts = []
        path_params = []
        
        for segment in segments:
            # 1. Check if this segment is a known parameter value (int/uuid)
            is_param_val = self._is_likely_param_value(segment)
            
            # 2. Dynamic Routing Logic
            # Does a parameter node already exist here? (e.g. {id})
            param_child = current_node.get_child("{id}") 
            # Note: We use "{id}" as generic placeholder for now
            
            if param_child and is_param_val:
                # Follow existing parameter path
                current_node = param_child
                current_node.seen_values.add(segment)
                path_params.append(segment)
                template_parts.append("{id}")
                continue
                
            # 3. Dynamic clustering (The "Magic")
            # If we don't have a param node, but this looks like an ID...
            if is_param_val:
                # Check if we should MERGE into a param node
                # For now, simplistic: if it looks like an ID, treat as {id}
                child = current_node.add_child("{id}", is_param=True)
                child.seen_values.add(segment)
                current_node = child
                path_params.append(segment)
                template_parts.append("{id}")
                continue
                
            # 4. Literal Segment (e.g. "users")
            current_node = current_node.add_child(segment, is_param=False)
            current_node.seen_values.add(segment)
            template_parts.append(segment)

        # We are at the leaf node. Get or Create Endpoint.
        path_template = "/" + "/".join(template_parts)
        is_new_route = method not in current_node.endpoints
        
        if is_new_route:
            current_node.endpoints[method] = Endpoint(
                method=method,
                path_template=path_template,
                path_params=path_params
            )
            logger.info(f"[MIMIC] Discovered New Route: {method} {path_template}")
            
            # ═══════════════════════════════════════════════════════════════
            # CAL INTEGRATION: Assert Claim for new route
            # ═══════════════════════════════════════════════════════════════
            claim_key = f"{method}:{path_template}"
            claim = self.reasoning_engine.assert_claim(
                statement=f"API endpoint {method} {path_template} exists",
                source="Mimic",
                evidence_content={
                    "method": method,
                    "path_template": path_template,
                    "path_params": path_params,
                    "observed_path": path,
                    "observation_count": 1
                },
                confidence=0.6,  # First observation - moderate confidence
                metadata={
                    "method": method,
                    "path_template": path_template
                }
            )
            self._route_claims[claim_key] = claim.id
            logger.debug(f"[CAL] Mimic asserted Claim {claim.id} for route {claim_key}")
            
        endpoint = current_node.endpoints[method]
        endpoint.observation_count += 1
        
        # ═══════════════════════════════════════════════════════════════════
        # CAL INTEGRATION: Add Evidence for repeated observations
        # ═══════════════════════════════════════════════════════════════════
        if not is_new_route:
            claim_key = f"{method}:{path_template}"
            claim_id = self._route_claims.get(claim_key)
            if claim_id:
                observation_evidence = Evidence(
                    content={
                        "method": method,
                        "observed_path": path,
                        "observation_count": endpoint.observation_count
                    },
                    description=f"Additional observation of {method} {path_template}",
                    provenance=Provenance(
                        source="Mimic:observation",
                        method="traffic_analysis",
                        run_id="global"
                    ),
                    confidence=0.3  # Each observation adds a bit of confidence
                )
                self.reasoning_engine.add_evidence(claim_id, observation_evidence, supporting=True)
                
                if endpoint.observation_count % 10 == 0:
                    logger.debug(f"[CAL] Mimic strengthened Claim {claim_id} ({endpoint.observation_count} observations)")
        
        return endpoint

    def _is_likely_param_value(self, segment: str) -> bool:
        """Heuristic to decide if a segment is a parameter value."""
        if self.int_pattern.match(segment):
            return True
        if self.uuid_pattern.match(segment):
            return True
        if len(segment) > 20 and any(c.isdigit() for c in segment): # High entropy hash?
            return True
        return False

