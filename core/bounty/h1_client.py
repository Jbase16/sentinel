"""
core/bounty/h1_client.py
HackerOne Input Adapter

Fetches program records from HackerOne (via API, file, or HTML)
and converts them into a strictly typed H1ScopeDTO, which is
then poured into the universal ScopeRegistry.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from core.base.scope import ScopeRegistry, ScopeRule, AssetType, ScopeDecision

logger = logging.getLogger(__name__)

@dataclass
class H1ScopeElement:
    asset_identifier: str
    asset_type: str  # e.g., 'URL', 'CIDR', 'WILDCARD', 'OTHER'
    eligible_for_bounty: bool
    instruction: Optional[str]

@dataclass
class H1ScopeDTO:
    handle: str
    in_scope: List[H1ScopeElement] = field(default_factory=list)
    out_of_scope: List[H1ScopeElement] = field(default_factory=list)

class HackerOneClient:
    """
    Input Adapter for HackerOne scope data.
    Decoupled from execution; strictly responsible for fetching and standardizing inputs.
    """
    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token

    def fetch_via_api(self, handle: str) -> H1ScopeDTO:
        """Fetch scope directly via authenticated HackerOne API."""
        if not self.api_token:
            raise ValueError("API fetching requires a valid HackerOne API token.")
        # TODO: Implement actual authenticated fetch logic
        logger.warning("fetch_via_api is not fully implemented yet.")
        return H1ScopeDTO(handle=handle)

    def fetch_via_html(self, handle: str) -> H1ScopeDTO:
        """Fetch scope via HTML scraping (brittle, use as last resort)."""
        logger.warning("fetch_via_html is fragile. Prefer load_from_file or fetch_via_api.")
        # TODO: Implement fallback scraping
        return H1ScopeDTO(handle=handle)

    def load_from_file(self, path: str) -> H1ScopeDTO:
        """Parse an exported JSON scope file into the normalized DTO."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        dto = H1ScopeDTO(handle=data.get("handle", "unknown"))
        
        for item in data.get("in_scope", []):
            dto.in_scope.append(H1ScopeElement(
                asset_identifier=item.get("asset_identifier", ""),
                asset_type=item.get("asset_type", "URL"),
                eligible_for_bounty=item.get("eligible_for_submission", True),
                instruction=item.get("instruction", "")
            ))
            
        for item in data.get("out_of_scope", []):
            dto.out_of_scope.append(H1ScopeElement(
                asset_identifier=item.get("asset_identifier", ""),
                asset_type=item.get("asset_type", "URL"),
                eligible_for_bounty=False,
                instruction=item.get("instruction", "")
            ))
            
        return dto


def parse_to_registry(dto: H1ScopeDTO, registry: ScopeRegistry) -> None:
    """
    Translates the normalized HackerOne DTO into the engine's strict ScopeRegistry.
    """
    def _determine_asset_type(h1_type: str, identifier: str) -> AssetType:
        h1_type_upper = h1_type.upper()
        if h1_type_upper == "CIDR":
            return AssetType.CIDR
        if h1_type_upper == "WILDCARD" or identifier.startswith("*."):
            return AssetType.WILDCARD
        if "://" in identifier:
            return AssetType.URL
        if "/" in identifier:
            return AssetType.PATH
        return AssetType.DOMAIN

    # Processes in-scope
    for element in dto.in_scope:
        if not element.asset_identifier:
            continue
        asset_type = _determine_asset_type(element.asset_type, element.asset_identifier)
        registry.add_rule(ScopeRule(
            asset_type=asset_type,
            target=element.asset_identifier,
            decision=ScopeDecision.ALLOW
        ))
        
    # Processes out-of-scope (strict DENY overrides ALLOW based on precedence)
    for element in dto.out_of_scope:
        if not element.asset_identifier:
            continue
        asset_type = _determine_asset_type(element.asset_type, element.asset_identifier)
        registry.add_rule(ScopeRule(
            asset_type=asset_type,
            target=element.asset_identifier,
            decision=ScopeDecision.DENY
        ))
