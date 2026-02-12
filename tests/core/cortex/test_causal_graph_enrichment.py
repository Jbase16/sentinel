import sys
import os
sys.path.append(os.getcwd())

import pytest
from core.cortex.causal_graph import CausalGraphBuilder, Finding
from typing import Dict, Any, List

class TestCausalGraphEnrichment:
    
    def test_enrich_tier3_loose_match_explosion(self):
        """
        Verify that a broad issue (e.g. target='/') does NOT enrich every single finding 
        on the same host unless there is strict semantic overlap.
        """
        builder = CausalGraphBuilder()
        
        # 1. Create 100 raw findings on the same host but different paths
        findings = []
        for i in range(100):
            findings.append({
                "id": f"finding_{i}",
                "type": "http_response",
                "title": f"Endpoint {i}",
                "target": f"https://example.com/api/v1/endpoint_{i}",
                "data": {
                    "tool": "httpx",
                    "metadata": {"status": 200}
                }
            })
            
        builder.build(findings)
        assert builder.graph.number_of_nodes() == 100
        
        # 2. Create 1 "Issue" that is somewhat broad (e.g. on /api)
        # In the buggy version, this might match ALL 100 findings because /api is a prefix of /api/v1/...
        # We MUST provide a matching tool/type in supporting_findings so the semantic guard passes.
        # Otherwise the test passes trivially because the guard blocks everything.
        issue = {
            "id": "issue_broad",
            "title": "Broad Issue",
            "type": "configuration_issue",
            "target": "https://example.com/api",
            "score": 5.0,
            "confirmation_level": "confirmed",
            "capability_types": ["information"],
            # Matching tool ensures semantic guard passes!
            "supporting_findings": [{"tool": "httpx", "type": "http_response"}], 
            "tags": [] 
        }
        
        # 3. Enrich
        builder.enrich_from_issues([issue])
        
        # 4. Count how many findings got enriched with the score 5.0
        enriched_count = 0
        for f in builder.findings_map.values():
            if f.data.get("score") == 5.0:
                enriched_count += 1
                
        print(f"Enriched count: {enriched_count}")
        
        # We want to assert that we are CONSERVATIVE.
        # Ideally, an issue on /api should NOT automatically enrich /api/v1/endpoint_55 
        # unless there is stronger evidence.
        # ALLOWANCE: It might match 0 if strict, or 100 if loose.
        # We want to ensure it is NOT 100.
        # If strict matching is ON, this should be 0 or low. 
        # If loose, it will be 100.
        assert enriched_count < 10, f"Graph Explosion: Issue matched {enriched_count}/100 findings via prefix match!"

    def test_enrich_tier3_correct_match(self):
        """
        Verify that Tier 3 STILL matches when it makes sense (exact or near-exact path).
        """
        builder = CausalGraphBuilder()
        findings = [{
            "id": "f1",
            "type": "vuln",
            "target": "https://example.com/api/users",
            "data": {"tool": "nuclei"}
        }]
        builder.build(findings)
        
        issue = {
            "id": "i1",
            "target": "https://example.com/api/users", # Exact match
            "score": 9.0,
            "confirmation_level": "confirmed",
            "capability_types": ["execution"],
            "supporting_findings": [{"tool": "nuclei"}]
        }
        
        builder.enrich_from_issues([issue])
        
        # Verify enrichment happened
        node = builder.findings_map["f1"]
        assert node.data.get("score") == 9.0
