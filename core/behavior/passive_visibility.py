"""Bounded anonymous observation of content that is already publicly visible.

This boundary is intentionally incapable of producing finding authority.  It
performs an initial anonymous GET, follows only the same-origin links exposed by
that response, and records redacted structural evidence.  It never authenticates,
submits a form, mutates target state, runs an adaptive experiment, or creates an
execution receipt.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Awaitable, Callable, Dict, Mapping, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from core.behavior.normalize import stable_hash
from core.foundry.authorization import AuthorizationEnvelope


PASSIVE_VISIBILITY_MODE = "behavioral_anonymous_passive_visibility_v1"
PASSIVE_VISIBILITY_WORKFLOW = "behavioral_passive_visibility"
_MAX_RESPONSE_CHARS = 2 * 1024 * 1024


class PassiveVisibilityDenied(RuntimeError):
    """Raised before or during a passive run that cannot remain trustworthy."""


@dataclass(frozen=True)
class PassiveHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: str = field(repr=False)


PassiveFetch = Callable[[str], Awaitable[PassiveHTTPResponse]]


def _origin(value: str) -> Tuple[str, str, int]:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise PassiveVisibilityDenied("passive_visibility_url_is_invalid")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise PassiveVisibilityDenied("passive_visibility_url_is_invalid") from exc
    return scheme, parsed.hostname.lower(), port


def _canonical_same_origin(value: str, *, base: str, expected_origin: Tuple[str, str, int]) -> Optional[str]:
    candidate = urlsplit(urljoin(base, value))
    if candidate.username or candidate.password:
        return None
    candidate = candidate._replace(fragment="")
    normalized = urlunsplit(candidate)
    if len(normalized) > 4096:
        return None
    try:
        if _origin(normalized) != expected_origin:
            return None
    except PassiveVisibilityDenied:
        return None
    return normalized


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.title_parts: list[str] = []
        self.article_count = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        lowered = tag.lower()
        if lowered == "title":
            self._in_title = True
        elif lowered == "article":
            self.article_count += 1
        elif lowered == "a":
            for key, value in attrs:
                if key.lower() == "href" and isinstance(value, str):
                    self.links.append(value)
                    break

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            cleaned = " ".join(data.split())
            if cleaned:
                self.title_parts.append(cleaned)

    @property
    def title(self) -> Optional[str]:
        value = " ".join(self.title_parts).strip()
        return value[:160] or None


@dataclass(frozen=True)
class PassiveVisibilityConfig:
    max_total_requests: int = 15
    max_discovered_links: int = 14
    max_response_chars: int = _MAX_RESPONSE_CHARS

    def __post_init__(self) -> None:
        if not 1 <= self.max_total_requests <= 15:
            raise ValueError("passive visibility request budget must be between 1 and 15")
        if not 0 <= self.max_discovered_links < self.max_total_requests:
            raise ValueError("passive visibility link budget must fit the request budget")
        if not 1 <= self.max_response_chars <= _MAX_RESPONSE_CHARS:
            raise ValueError("passive visibility response limit is invalid")


class AnonymousPassiveVisibilityBoundary:
    """Observe one public surface without acquiring any adaptive authority."""

    def __init__(
        self,
        *,
        target_url: str,
        authorization: AuthorizationEnvelope,
        fetch: PassiveFetch,
        config: PassiveVisibilityConfig = PassiveVisibilityConfig(),
    ) -> None:
        self.target_url = _canonical_same_origin(
            target_url,
            base=target_url,
            expected_origin=_origin(target_url),
        )
        if self.target_url is None:
            raise PassiveVisibilityDenied("passive_visibility_target_is_invalid")
        try:
            authorization.authorize_action(
                target_origin=self.target_url,
                workflow=PASSIVE_VISIBILITY_WORKFLOW,
            )
        except Exception as exc:
            raise PassiveVisibilityDenied("passive_visibility_authorization_denied") from exc
        self.authorization = authorization
        self.fetch = fetch
        self.config = config
        self.expected_origin = _origin(target_url)

    async def observe(self) -> Dict[str, object]:
        queue = [self.target_url]
        queued = {self.target_url}
        pages: list[Dict[str, object]] = []
        requests_sent = 0

        while queue and requests_sent < self.config.max_total_requests:
            url = queue.pop(0)
            response = await self.fetch(url)
            requests_sent += 1
            if not isinstance(response, PassiveHTTPResponse):
                raise PassiveVisibilityDenied("passive_visibility_transport_contract_failed")
            if not 100 <= int(response.status) <= 599:
                raise PassiveVisibilityDenied("passive_visibility_response_status_is_invalid")

            raw_body = response.body if isinstance(response.body, str) else str(response.body)
            truncated = len(raw_body) > self.config.max_response_chars
            body = raw_body[: self.config.max_response_chars]
            content_type = str(response.headers.get("content-type", "")).lower()
            parser = _SurfaceParser()
            is_html = "html" in content_type or body.lstrip().lower().startswith(("<!doctype html", "<html"))
            if is_html:
                try:
                    parser.feed(body)
                except Exception as exc:
                    raise PassiveVisibilityDenied("passive_visibility_html_parse_failed") from exc

            body_digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
            page = {
                "url": url,
                "status": int(response.status),
                "content_type": content_type[:128],
                "title": parser.title,
                "article_count": parser.article_count,
                "body_sha256": body_digest,
                "body_truncated": truncated,
                "response_ref": stable_hash(
                    "passive_visibility_response",
                    {"url": url, "status": int(response.status), "body_sha256": body_digest},
                ),
            }
            pages.append(page)

            if requests_sent == 1 and not 200 <= int(response.status) < 300:
                raise PassiveVisibilityDenied("passive_visibility_initial_capture_failed")
            if requests_sent == 1 and is_html:
                for href in parser.links:
                    candidate = _canonical_same_origin(
                        href,
                        base=url,
                        expected_origin=self.expected_origin,
                    )
                    if candidate is None or candidate in queued:
                        continue
                    queued.add(candidate)
                    queue.append(candidate)
                    if len(queue) >= self.config.max_discovered_links:
                        break

        discovered = pages[1:]
        observation_id = stable_hash(
            "passive_visibility_observation",
            {
                "target_url": self.target_url,
                "responses": [page["response_ref"] for page in pages],
            },
        )
        return {
            "schema_version": 1,
            "kind": "passive_visibility_observation",
            "mode": PASSIVE_VISIBILITY_MODE,
            "status": "completed",
            "finding_authority": False,
            "finding_confirmed": False,
            "observation": {
                "classification": "preexisting_passive_visibility",
                "observation_id": observation_id,
                "initial_capture": pages[0],
                "discovered_public_pages": discovered,
                "discovered_public_page_count": len(discovered),
            },
            "execution": {
                "status": "completed",
                "requests_attempted": requests_sent,
                "requests_sent": requests_sent,
                "mutations": 0,
                "authenticated_sessions": 0,
            },
            "adaptive_execution": {
                "status": "skipped",
                "reason": "content_was_visible_in_passive_capture",
            },
            "independent_proof": {
                "status": "skipped",
                "reason": "no_adaptive_claim_requires_confirmation",
            },
            "feedback": {
                "status": "skipped",
                "reason": "no_execution_receipt_or_adaptive_disposition",
            },
            "scan_finding": {
                "status": "skipped",
                "finding_authority": False,
                "reason": "passive_observation_is_not_a_confirmed_finding",
            },
            "orchestration_receipt": None,
        }
