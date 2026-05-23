"""
HackerOne platform adapter.

Recognized identifier forms:

  - ``hackerone:<handle>``                       (explicit prefix)
  - ``https://hackerone.com/<handle>`` (and ``…/<handle>/policy``)
  - ``https://www.hackerone.com/<handle>``

Two extraction paths, chosen automatically:

  1. **API path** (preferred). When a credential is present in the token
     store, we authenticate to ``https://api.hackerone.com/v1`` via HTTP
     Basic Auth (handle:token) and read:
       * ``relationships.structured_scopes`` → directly maps to
         ``ScopeRule`` objects with full asset-type metadata
       * ``attributes.policy`` markdown text → passed to the LLM
         extractor for personas + restrictions + signup_endpoint
     This is high-fidelity: scope is structured, prose is LLM-extracted.

  2. **Scraping path** (fallback, currently non-functional). Without a
     token we'd fetch ``https://hackerone.com/<handle>/policy`` through
     ``GenericUrlExtractor`` — but as Calibration Run #15 confirmed, this
     path is blocked by Cloudflare. We keep the code in place for the
     day H1 changes its bot policy, but it surfaces a clear actionable
     error today: "this program requires an API token."

Why both paths live in one class — the *capability* "extract HackerOne
data" is the same regardless of mechanism. The resolver picks
``HackerOneExtractor`` based on the identifier shape; once chosen, the
extractor itself picks the strongest available extraction mechanism.
That keeps the resolver simple and the operator's mental model clean.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.intel.extractors.base import Extractor, ExtractorError
from core.intel.extractors.generic_url import GenericUrlExtractor
from core.intel.llm_extraction import (
    EXTRACTOR_VERSION as LLM_VERSION,
    extract_scope_with_llm,
    to_persona,
    to_restriction,
)
from core.intel.program_scope import (
    Platform,
    ProgramScope,
    ScopeRule,
    ScopeRuleType,
    content_hash,
)

logger = logging.getLogger(__name__)

# Strict handle pattern: lowercase alphanumeric + hyphens + underscores.
# Length cap of 64 is generous; real handles are much shorter.
_HANDLE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,63}$")

# Hosts we treat as HackerOne. ``www.hackerone.com`` is a real redirect target.
_HACKERONE_HOSTS = frozenset({"hackerone.com", "www.hackerone.com"})

# Official HackerOne hacker API base.
_H1_API_BASE = "https://api.hackerone.com/v1"

# Map the H1 API's asset_type strings onto our ScopeRuleType enum.
# Unknown values coerce to OTHER rather than dropping the rule.
_H1_ASSET_TYPE_MAP: Dict[str, ScopeRuleType] = {
    "URL": ScopeRuleType.DOMAIN,         # H1 uses "URL" for domains/wildcards
    "WILDCARD": ScopeRuleType.DOMAIN,
    "CIDR": ScopeRuleType.IP_CIDR,
    "GOOGLE_PLAY_APP_ID": ScopeRuleType.MOBILE_APP,
    "APPLE_STORE_APP_ID": ScopeRuleType.MOBILE_APP,
    "OTHER_APK": ScopeRuleType.MOBILE_APP,
    "OTHER_IPA": ScopeRuleType.MOBILE_APP,
    "SOURCE_CODE": ScopeRuleType.SOURCE_CODE,
}


class HackerOneExtractor(Extractor):
    """Extract a ``ProgramScope`` from a HackerOne program identifier.

    Routes through the official API when a credential is configured in
    the token store; otherwise surfaces a clear error pointing the
    operator to ``sentinel-token add hackerone``.
    """

    name = "hackerone"
    version = "2.0"  # API path; was 1.0 (scraping-only)

    def __init__(
        self,
        *,
        http_factory=None,
        llm_extractor=extract_scope_with_llm,
        credential_lookup=None,
    ):
        # Composition: the generic extractor still does fetch+sanitize+LLM
        # for the scraping fallback path. The API path uses httpx directly.
        self._generic = GenericUrlExtractor(
            http_factory=http_factory,
            llm_extractor=llm_extractor,
        )
        self._http_factory = http_factory
        self._llm_extractor = llm_extractor

        # Injectable credential source (defaults to token_store.get).
        # Test code passes a stub that returns whatever credential it
        # wants without touching the real Keychain.
        if credential_lookup is None:
            from core.intel import token_store
            credential_lookup = lambda: token_store.get("hackerone")  # noqa: E731
        self._credential_lookup = credential_lookup

    # ─── Extractor protocol ───────────────────────────────────────────

    def can_handle(self, identifier: str) -> bool:
        if not isinstance(identifier, str) or not identifier:
            return False
        if identifier.startswith("hackerone:"):
            return True
        if identifier.startswith(("http://", "https://")):
            try:
                netloc = urlparse(identifier).netloc.lower()
            except (ValueError, AttributeError):
                return False
            return netloc in _HACKERONE_HOSTS
        return False

    async def extract(self, identifier: str) -> Optional[ProgramScope]:
        if not self.can_handle(identifier):
            raise ExtractorError(
                f"HackerOneExtractor cannot handle {identifier!r} — expected "
                "'hackerone:<handle>' or a hackerone.com URL."
            )

        handle = self._parse_handle(identifier)

        # Check if a credential is available. Token presence is the
        # only signal we need — auth-shape was empirically verified.
        credential = self._credential_lookup()
        if credential is not None:
            logger.info(
                "[intel.hackerone] using API path for handle=%s (credential found)",
                handle,
            )
            return await self._extract_via_api(handle, credential)

        # No credential. Scraping path is known-blocked by Cloudflare
        # (Calibration Run #15). Raise a clear actionable error.
        raise ExtractorError(
            f"hackerone:{handle} requires an API token (HackerOne blocks "
            f"anonymous scraping via Cloudflare).\n"
            f"  → Generate a token at https://hackerone.com/settings/api_token/edit\n"
            f"  → Store it with: sentinel-token add hackerone"
        )

    # ─── API path ─────────────────────────────────────────────────────

    async def _extract_via_api(
        self,
        handle: str,
        credential,  # StoredCredential
    ) -> Optional[ProgramScope]:
        """Fetch program data via the HackerOne hacker API and build a
        ProgramScope with structured scope + LLM-extracted prose."""
        if self._http_factory is None:
            from core.net.http_factory import create_async_client
            http_factory = create_async_client
        else:
            http_factory = self._http_factory

        url = f"{_H1_API_BASE}/hackers/programs/{handle}"
        auth = (credential.handle, credential.token)

        try:
            import httpx
            async with http_factory() as client:
                response = await client.get(
                    url,
                    auth=httpx.BasicAuth(*auth),
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "SentinelForge/Phase2-intel",
                    },
                    timeout=httpx.Timeout(30.0),
                )
        except Exception as e:  # noqa: BLE001 - any fetch failure is a soft fail
            logger.warning(
                "[intel.hackerone] API fetch failed for %s: %s", handle, e,
            )
            return None

        if response.status_code == 401:
            raise ExtractorError(
                f"HackerOne API returned 401 (unauthorized) for hackerone:{handle}.\n"
                f"  → Check that the stored token + handle are valid.\n"
                f"  → Re-create with: sentinel-token add hackerone"
            )
        if response.status_code == 404:
            logger.warning(
                "[intel.hackerone] API returned 404 for %s (program does not "
                "exist or you don't have access)", handle,
            )
            return None
        if response.status_code >= 400:
            logger.warning(
                "[intel.hackerone] API returned %d for %s", response.status_code, handle,
            )
            return None

        try:
            payload = response.json()
        except Exception as e:  # noqa: BLE001
            logger.warning("[intel.hackerone] non-JSON response for %s: %s", handle, e)
            return None

        return await self._build_scope_from_api(handle, payload)

    async def _build_scope_from_api(
        self,
        handle: str,
        payload: Dict[str, Any],
    ) -> ProgramScope:
        """Translate an H1 API response into a ProgramScope.

        - structured_scopes → ScopeRule list (no LLM, fully reliable)
        - attributes.policy text → LLM → personas + restrictions + signup
        """
        attrs = payload.get("attributes", {}) or {}
        program_name = attrs.get("name") or handle
        policy_text = attrs.get("policy", "") or ""

        # ─── Scope rules from structured_scopes ──────────────────────────
        scope_rules = self._parse_structured_scopes(payload)
        logger.info(
            "[intel.hackerone] %s: %d structured_scopes from API",
            handle, len(scope_rules),
        )

        # ─── LLM extraction over the policy text ─────────────────────────
        # The structured API doesn't expose personas, restrictions, or
        # signup endpoints — those live in the policy prose. We still
        # need the LLM for those, but the input is now high-signal text
        # (the actual policy, not a Cloudflare interstitial).
        personas: List = []
        restrictions: List = []
        signup_endpoint: Optional[str] = None
        rate_limit_rps: Optional[float] = None
        extraction_confidence = 1.0  # default when LLM extraction not invoked

        if policy_text.strip():
            try:
                extracted = await self._llm_extractor(policy_text)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "[intel.hackerone] LLM extraction failed for %s: %s — "
                    "continuing with API-only scope", handle, e,
                )
                extracted = None
            if extracted is not None:
                personas = [to_persona(p) for p in extracted.personas]
                restrictions = [to_restriction(r) for r in extracted.restrictions]
                signup_endpoint = extracted.signup_endpoint
                rate_limit_rps = extracted.rate_limit_rps
                extraction_confidence = extracted.extraction_confidence
                logger.info(
                    "[intel.hackerone] LLM-extracted from policy: "
                    "personas=%d restrictions=%d signup_endpoint=%s",
                    len(personas), len(restrictions), bool(signup_endpoint),
                )
        else:
            logger.info(
                "[intel.hackerone] no policy text in API response for %s — "
                "scope-only ProgramScope returned", handle,
            )

        return ProgramScope(
            handle=handle,
            platform=Platform.HACKERONE,
            name=program_name,
            source_url=f"{_H1_API_BASE}/hackers/programs/{handle}",
            fetched_at=datetime.now(timezone.utc),
            scope_rules=scope_rules,
            personas=personas,
            signup_endpoint=signup_endpoint,
            restrictions=restrictions,
            rate_limit_rps=rate_limit_rps,
            raw_content_hash=content_hash(policy_text),
            extractor_version=f"{self.version_stamp}+api+{LLM_VERSION}",
            extraction_confidence=extraction_confidence,
        )

    def _parse_structured_scopes(self, payload: Dict[str, Any]) -> List[ScopeRule]:
        """Convert the H1 API's structured_scopes array into ``ScopeRule`` objects."""
        relationships = payload.get("relationships", {}) or {}
        scopes_block = relationships.get("structured_scopes", {}) or {}
        items = scopes_block.get("data", []) or []

        rules: List[ScopeRule] = []
        for item in items:
            attrs = (item or {}).get("attributes", {}) or {}
            identifier = attrs.get("asset_identifier")
            if not identifier:
                continue
            h1_asset_type = (attrs.get("asset_type") or "OTHER").upper()
            rule_type = _H1_ASSET_TYPE_MAP.get(h1_asset_type, ScopeRuleType.OTHER)

            # H1 uses ``eligible_for_submission`` as the in-scope flag.
            # eligible_for_bounty is a separate dimension (paid vs not).
            in_scope = bool(attrs.get("eligible_for_submission", False))

            # Wildcard asset_identifiers from H1's API don't always carry
            # the leading "*." prefix. If the H1 asset_type was WILDCARD
            # and the identifier is bare, prepend the wildcard so our
            # scope-file emitter recognizes it correctly.
            if h1_asset_type == "WILDCARD" and not identifier.startswith("*."):
                identifier = f"*.{identifier}"

            instruction = attrs.get("instruction")
            max_severity = attrs.get("max_severity")
            notes_parts = []
            if instruction:
                notes_parts.append(instruction)
            if max_severity and max_severity != "none":
                notes_parts.append(f"max_severity={max_severity}")
            notes = "; ".join(notes_parts) if notes_parts else None

            rules.append(ScopeRule(
                pattern=identifier,
                rule_type=rule_type,
                in_scope=in_scope,
                notes=notes,
            ))
        return rules

    # ─── Identifier parsing ───────────────────────────────────────────

    def _parse_handle(self, identifier: str) -> str:
        """Extract the handle from any accepted identifier form."""
        if identifier.startswith("hackerone:"):
            handle = identifier[len("hackerone:"):].strip()
        else:
            parsed = urlparse(identifier)
            segments = [s for s in parsed.path.split("/") if s]
            if not segments:
                raise ExtractorError(
                    f"HackerOne URL {identifier!r} has no path — cannot resolve handle."
                )
            handle = segments[0]

        if not _HANDLE_PATTERN.match(handle):
            raise ExtractorError(
                f"HackerOne handle {handle!r} is not a valid program handle "
                "(expected lowercase alphanumeric/hyphen/underscore, 1-64 chars)."
            )
        return handle
