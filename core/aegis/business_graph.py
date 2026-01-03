from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class BusinessEntity:
    """
    Represents a high-value business concept extracted from passive sources.
    Example: 'Enterprise Plan' ($500/mo), 'Refund Policy'.
    """
    name: str
    value_score: float  # 0.0 to 1.0 (1.0 = Crown Jewel)
    source_term: str    # The actual text found (e.g., "Enterprise")
    related_endpoints: Set[str] = field(default_factory=set) # Mapped technical endpoints
    description: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value_score": self.value_score,
            "source_term": self.source_term,
            "related_endpoints": list(self.related_endpoints),
            "description": self.description
        }

class BusinessModelGraph:
    """
    The Value Map. Stores the relationship between Business Entities and the technical attack surface.
    """
    def __init__(self):
        self.entities: Dict[str, BusinessEntity] = {}
        # Mapping from endpoint substring to entity name for fast lookups
        self.endpoint_index: Dict[str, str] = {} 

    def add_entity(self, entity: BusinessEntity) -> None:
        """Add a business entity to the graph."""
        self.entities[entity.name] = entity
        self._update_index(entity)
        logger.debug(f"Added AEGIS Entity: {entity.name} (Value: {entity.value_score})")

    def _update_index(self, entity: BusinessEntity) -> None:
        """Update the reverse index for endpoint lookups."""
        for endpoint in entity.related_endpoints:
            self.endpoint_index[endpoint] = entity.name

    def map_endpoint(self, endpoint: str) -> List[BusinessEntity]:
        """
        Identify which Business Entities are impacted by a specific technical endpoint.
        Returns a list of entities sorted by value score.
        """
        matches = []
        # Direct match check (O(1) if exact, but we likely need substring)
        # 1. Exact/Index match
        if endpoint in self.endpoint_index:
            entity_name = self.endpoint_index[endpoint]
            if entity_name in self.entities:
                matches.append(self.entities[entity_name])
        
        # 2. Heuristic/Substring match against entity terms
        # This allows discovering that "/api/v1/enterprise/login" relates to "Enterprise Plan"
        for entity in self.entities.values():
            if entity.source_term.lower() in endpoint.lower():
                matches.append(entity)
            for known_ep in entity.related_endpoints:
                if known_ep in endpoint or endpoint in known_ep:
                     matches.append(entity)
        
        # Deduplicate and sort
        unique_matches = {e.name: e for e in matches}
        sorted_matches = sorted(unique_matches.values(), key=lambda x: x.value_score, reverse=True)
        return sorted_matches

    def to_json(self) -> str:
        """Serialize the graph to JSON."""
        return json.dumps({
            k: v.to_dict() for k, v in self.entities.items()
        }, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'BusinessModelGraph':
        """Load graph from JSON."""
        data = json.loads(json_str)
        graph = cls()
        for _, entity_data in data.items():
            # Convert list back to set
            entity_data['related_endpoints'] = set(entity_data.get('related_endpoints', []))
            entity = BusinessEntity(**entity_data)
            graph.add_entity(entity)
        return graph
