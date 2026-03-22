"""
core/bounty/h1_client.py
HackerOne Input Adapter

Fetches program records from HackerOne (via API, file, or HTML)
and converts them into a strictly typed H1ScopeDTO, which is
then poured into the universal ScopeRegistry.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from core.base.scope import ScopeRegistry, ScopeRule, AssetType, ScopeDecision

logger = logging.getLogger(__name__)

H1_API_BASE = "https://api.hackerone.com/v1"
H1_PROGRAM_URL = "https://hackerone.com"

# Timeout for H1 API requests
_H1_TIMEOUT = 30.0


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
    def __init__(self, api_token: Optional[str] = None, api_username: Optional[str] = None):
        self.api_token = api_token
        self.api_username = api_username or ""

    def fetch_via_api(self, handle: str) -> H1ScopeDTO:
        """Fetch scope directly via authenticated HackerOne API.

        Uses the HackerOne API v1 with HTTP Basic Auth.
        Requires api_username (API identifier) and api_token.

        See: https://api.hackerone.com/core-resources/#programs
        """
        if not self.api_token:
            raise ValueError("API fetching requires a valid HackerOne API token.")

        url = f"{H1_API_BASE}/hackers/programs/{handle}"
        auth = (self.api_username, self.api_token)

        dto = H1ScopeDTO(handle=handle)

        try:
            with httpx.Client(timeout=_H1_TIMEOUT) as client:
                resp = client.get(url, auth=auth)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "HackerOne API returned %d for program '%s': %s",
                exc.response.status_code, handle, exc.response.text[:200],
            )
            raise ValueError(
                f"HackerOne API error for '{handle}': HTTP {exc.response.status_code}"
            ) from exc
        except Exception as exc:
            logger.error("HackerOne API request failed for '%s': %s", handle, exc)
            raise ValueError(f"HackerOne API request failed: {exc}") from exc

        # Parse the structured_scopes from the API response
        relationships = data.get("relationships", {})
        structured_scopes = relationships.get("structured_scopes", {})
        scope_data = structured_scopes.get("data", [])

        for scope_item in scope_data:
            attrs = scope_item.get("attributes", {})
            identifier = attrs.get("asset_identifier", "")
            asset_type = attrs.get("asset_type", "URL")
            eligible = attrs.get("eligible_for_bounty", False)
            instruction = attrs.get("instruction", "")

            if not identifier:
                continue

            element = H1ScopeElement(
                asset_identifier=identifier,
                asset_type=asset_type,
                eligible_for_bounty=eligible,
                instruction=instruction,
            )

            if attrs.get("eligible_for_submission", True):
                dto.in_scope.append(element)
            else:
                dto.out_of_scope.append(element)

        # If structured_scopes weren't nested, try flat policy format
        if not scope_data:
            dto = self._parse_flat_policy(data, handle, dto)

        logger.info(
            "HackerOne API: fetched %d in-scope, %d out-of-scope for '%s'",
            len(dto.in_scope), len(dto.out_of_scope), handle,
        )
        return dto

    def fetch_via_html(self, handle: str) -> H1ScopeDTO:
        """Fetch scope via HTML scraping (brittle, use as last resort).

        Scrapes the public program page for scope information.
        This is fragile and may break if HackerOne changes their HTML structure.
        """
        program_url = f"{H1_PROGRAM_URL}/{handle}"
        dto = H1ScopeDTO(handle=handle)

        try:
            with httpx.Client(
                timeout=_H1_TIMEOUT,
                follow_redirects=True,
                headers={"User-Agent": "SentinelForge/1.0"},
            ) as client:
                resp = client.get(program_url)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            logger.error("HackerOne HTML fetch failed for '%s': %s", handle, exc)
            raise ValueError(f"HackerOne HTML fetch failed: {exc}") from exc

        # Try to extract embedded JSON data (HackerOne embeds scope in script tags)
        json_data = self._extract_embedded_json(html)
        if json_data:
            scopes = self._extract_scopes_from_json(json_data)
            for scope in scopes:
                identifier = scope.get("asset_identifier", "")
                if not identifier:
                    continue
                element = H1ScopeElement(
                    asset_identifier=identifier,
                    asset_type=scope.get("asset_type", "URL"),
                    eligible_for_bounty=scope.get("eligible_for_bounty", False),
                    instruction=scope.get("instruction", ""),
                )
                if scope.get("eligible_for_submission", True):
                    dto.in_scope.append(element)
                else:
                    dto.out_of_scope.append(element)

        # Fallback: try to parse scope from visible HTML tables
        if not dto.in_scope and not dto.out_of_scope:
            dto = self._parse_scope_from_html(html, handle, dto)

        logger.info(
            "HackerOne HTML: scraped %d in-scope, %d out-of-scope for '%s'",
            len(dto.in_scope), len(dto.out_of_scope), handle,
        )
        return dto

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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_flat_policy(
        data: Dict[str, Any], handle: str, dto: H1ScopeDTO
    ) -> H1ScopeDTO:
        """Parse scope from flat policy format (some API responses)."""
        attrs = data.get("attributes", {})
        policy = attrs.get("policy") or ""

        # Very basic regex extraction of domains/URLs from policy text
        url_pattern = re.compile(r"https?://[\w\-.]+(?:/[\w\-./?=&%]*)?", re.I)
        domain_pattern = re.compile(r"\*?[\w\-]+\.[\w\-.]+", re.I)

        for match in url_pattern.finditer(policy):
            dto.in_scope.append(H1ScopeElement(
                asset_identifier=match.group(0),
                asset_type="URL",
                eligible_for_bounty=True,
                instruction=None,
            ))

        return dto

    @staticmethod
    def _extract_embedded_json(html: str) -> Optional[Dict]:
        """Try to extract JSON data embedded in script tags."""
        # HackerOne often embeds program data in __NEXT_DATA__ or similar
        patterns = [
            re.compile(r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>', re.S),
            re.compile(r'window\.__APOLLO_STATE__\s*=\s*({.*?});', re.S),
        ]
        for pattern in patterns:
            match = pattern.search(html)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
        return None

    @staticmethod
    def _extract_scopes_from_json(data: Dict) -> List[Dict]:
        """Recursively find scope objects in embedded JSON."""
        scopes: List[Dict] = []

        def walk(obj: Any, depth: int = 0) -> None:
            if depth > 10:
                return
            if isinstance(obj, dict):
                if "asset_identifier" in obj and "asset_type" in obj:
                    scopes.append(obj)
                for v in obj.values():
                    walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item, depth + 1)

        walk(data)
        return scopes

    @staticmethod
    def _parse_scope_from_html(
        html: str, handle: str, dto: H1ScopeDTO
    ) -> H1ScopeDTO:
        """Last-resort: extract scope targets from visible HTML content."""
        # Look for common scope table patterns
        scope_section = re.search(
            r"(?:in.scope|assets.in.scope)(.*?)(?:out.of.scope|$)",
            html, re.I | re.S,
        )
        if scope_section:
            text = scope_section.group(1)
            # Extract URLs and domains
            for match in re.finditer(r"https?://[\w\-.]+(?:/[\w\-./?=&%]*)?", text):
                dto.in_scope.append(H1ScopeElement(
                    asset_identifier=match.group(0),
                    asset_type="URL",
                    eligible_for_bounty=True,
                    instruction=None,
                ))
            for match in re.finditer(r"\*\.[\w\-.]+", text):
                dto.in_scope.append(H1ScopeElement(
                    asset_identifier=match.group(0),
                    asset_type="WILDCARD",
                    eligible_for_bounty=True,
                    instruction=None,
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
