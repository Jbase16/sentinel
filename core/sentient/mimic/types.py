"""Module types: inline documentation for /Users/jason/Developer/sentinelforge/core/sentient/mimic/types.py."""
#
# PURPOSE:
# Defines the core data structures for Project MIMIC (API Reconstruction).
# 
# LOGIC:
# - RouteNode: specific path segment in a URL Trie (e.g. "api", "v1", "{id}")
# - Endpoint: A fully resolved API operation (GET /api/v1/users/{id})
# - APISchema: The inferred data shape (JSON Schema like)
#

from __future__ import annotations
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import time

class ParamType(str, Enum):
    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"

class DataType(str, Enum):
    STRING = "string"
    INTEGER = "integer" 
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"
    UNKNOWN = "unknown"

@dataclass
class APISchema:
    """Represents the inferred structure of a request/response body."""
    type: DataType = DataType.UNKNOWN
    properties: Dict[str, APISchema] = field(default_factory=dict)
    items: Optional[APISchema] = None # For arrays
    required: List[str] = field(default_factory=list)
    example: Any = None

    def to_dict(self) -> Dict:
        """Recursive serialization."""
        d = {"type": self.type.value}
        if self.properties:
            d["properties"] = {k: v.to_dict() for k, v in self.properties.items()}
        if self.items:
            d["items"] = self.items.to_dict()
        if self.required:
            d["required"] = self.required
        return d

@dataclass
class Endpoint:
    """A reconstructed API operation (e.g. GET /users/{id})."""
    method: str
    path_template: str # e.g. "/users/{id}"
    path_params: List[str] = field(default_factory=list)
    query_params: Set[str] = field(default_factory=set)
    request_schema: Optional[APISchema] = None
    response_schema: Optional[APISchema] = None
    last_seen: float = field(default_factory=time.time)
    observation_count: int = 0

@dataclass
class RouteNode:
    """Node in the Route Trie used for clustering."""
    segment: str # The path part (e.g. "users", or "{id}")
    children: Dict[str, RouteNode] = field(default_factory=dict)
    endpoints: Dict[str, Endpoint] = field(default_factory=dict) # Key: HTTP Method
    is_parameter: bool = False # If True, this segment is a variable like {id}
    
    # Metadata for clustering
    seen_values: Set[str] = field(default_factory=set) # Track actual values seen (1, 2, 55) to infer if param

    def get_child(self, segment: str) -> Optional[RouteNode]:
        return self.children.get(segment)

    def add_child(self, segment: str, is_param: bool = False) -> RouteNode:
        if segment not in self.children:
            self.children[segment] = RouteNode(segment=segment, is_parameter=is_param)
        return self.children[segment]
