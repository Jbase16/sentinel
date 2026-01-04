import re
import logging
from typing import List, Set, Dict, Optional
from core.aegis.graph import BusinessModelGraph
from core.aegis.models import BusinessNode

logger = logging.getLogger(__name__)

class KeywordExtractor:
    """
    Identifies 'Crown Jewel' terms using heuristic regex patterns.
    """
    
    # Categories of high-value terms
    PATTERNS = {
        "Financial": [
            r"(?i)invoice", r"(?i)payment", r"(?i)billing", r"(?i)finance", 
            r"(?i)wallet", r"(?i)transaction", r"(?i)refund"
        ],
        "Auth/Privilege": [
            r"(?i)admin", r"(?i)super.?user", r"(?i)sso", r"(?i)saml", 
            r"(?i)oauth", r"(?i)role.*management"
        ],
        "Enterprise Features": [
            r"(?i)enterprise", r"(?i)business.?plan", r"(?i)api.?access", 
            r"(?i)audit.?log", r"(?i)compliance"
        ]
    }

    @staticmethod
    def extract_terms(text: str) -> Dict[str, List[str]]:
        """Scan text and return found terms by category."""
        findings = {}
        for category, patterns in KeywordExtractor.PATTERNS.items():
            matches = []
            for pat in patterns:
                # Find all unique matches
                found = set(re.findall(pat, text))
                if found:
                    matches.extend(list(found))
            if matches:
                findings[category] = list(set(matches))
        return findings


class PricingScraper:
    """
    Simulates scraping (for now just regexing HTML/Text) to find tiers.
    """
    
    # Heuristics for pricing tiers (e.g. "$49/mo", "Enterprise")
    TIER_PATTERN = r"(?i)(free|starter|professional|business|enterprise|corporate)"
    PRICE_PATTERN = r"[\$€£]\d+(?:[\.,]\d{2})?"

    def __init__(self, graph: BusinessModelGraph):
        self.graph = graph

    def process_text(self, text: str, source_url: str = "known_source"):
        """
        Ingest text from a pricing page or docs and populate the graph.
        """
        # 1. Extract General Keywords
        keywords = KeywordExtractor.extract_terms(text)
        
        for category, terms in keywords.items():
            for term in terms:
                # Determine value based on category
                score = 0.5
                if category == "Financial": score = 0.9
                if category == "Auth/Privilege": score = 1.0
                if category == "Enterprise Features": score = 0.8
                
                entity = BusinessNode(
                    id=f"{category.lower()}:{term.lower()}",
                    name=f"{category}: {term.capitalize()}",
                    type="asset",
                    value=score * 10.0, # Scale 0-1 to 0-10
                    description=f"Passive-ingested term from {category}. Source: {term}",
                    tags=self._guess_endpoints(term)
                )
                self.graph.add_node(entity)

        # 2. Extract Pricing Tiers specifically
        # (Very naive implementation for Phase 1)
        tiers = re.findall(self.TIER_PATTERN, text)
        for tier in set(tiers):
            entity = BusinessNode(
                id=f"plan:{tier.lower()}",
                name=f"Plan: {tier.capitalize()}",
                type="service",
                value=7.0 if "free" not in tier.lower() else 1.0,
                description="Detected Pricing Tier",
                tags=self._guess_endpoints(tier)
            )
            self.graph.add_node(entity)

    def _guess_endpoints(self, term: str) -> Set[str]:
        """
        Generate hypothetical endpoints for a term.
        Real implementation would use EntityLinker to crawl for these.
        """
        base = term.lower().replace(" ", "")
        return {
            f"/api/{base}",
            f"/v1/{base}",
            f"/{base}"
        }
