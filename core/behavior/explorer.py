"""Bounded paired-world discovery of exact, target-published read references.

The explorer is deliberately narrower than a crawler. It follows only same-origin
HTTP(S) links that appeared verbatim in an owned persona response, rejects URL
shapes associated with state changes, executes GETs through ``PolicyExecutor``,
and advances source and peer worlds as a pair before asking the planner to stop.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

from core.cortex.execution_policy import DENIED_STATUS, PolicyExecutor
from core.safety.action_classifier import SAFE_READ

_DANGEROUS_URL = re.compile(
    r"(?:^|[^a-z0-9])(?:activate|approve|cancel|checkout|confirm|deactivate|"
    r"delete|destroy|disable|impersonate|invite|join|leave|logout|pay|purchase|"
    r"remove|reset|revoke|signout|transfer|unsubscribe|verify|withdraw)"
    r"(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_STATIC_EXTENSION = re.compile(
    r"\.(?:avif|bmp|css|eot|gif|ico|jpe?g|js|map|mp3|mp4|pdf|png|svg|ttf|"
    r"webm|webp|woff2?|zip)$",
    re.IGNORECASE,
)
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_-]{12,128}$")


@dataclass(frozen=True)
class ReadExplorationLimits:
    max_pairs: int = 6
    max_candidates_per_world: int = 128
    max_references_per_record: int = 64
    max_json_depth: int = 12
    max_response_chars: int = 512 * 1024

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class ReadExplorationResult:
    source_records: Tuple[Dict[str, Any], ...]
    peer_records: Tuple[Dict[str, Any], ...]
    diagnostics: Dict[str, Any]


class _AnchorParser(HTMLParser):
    def __init__(self, limit: int) -> None:
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.references: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() not in {"a", "area"} or len(self.references) >= self.limit:
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.references.append(value)
                return


def _origin_key(value: str) -> Optional[tuple[str, str, int]]:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not hostname:
        return None
    return scheme, hostname, port or (443 if scheme == "https" else 80)


def _json_references(
    value: Any,
    *,
    limit: int,
    max_depth: int,
    depth: int = 0,
) -> list[str]:
    if depth > max_depth or limit <= 0:
        return []
    output: list[str] = []
    children: Iterable[Any]
    if isinstance(value, Mapping):
        children = value.values()
    elif isinstance(value, list):
        children = value
    elif isinstance(value, str):
        candidate = value.strip()
        if (
            len(candidate) <= 4096
            and not any(character.isspace() for character in candidate)
            and (
                candidate.startswith(("http://", "https://", "/", "./", "../"))
                or "/" in candidate
            )
        ):
            return [candidate]
        return []
    else:
        return []
    for child in children:
        remaining = limit - len(output)
        if remaining <= 0:
            break
        output.extend(
            _json_references(
                child,
                limit=remaining,
                max_depth=max_depth,
                depth=depth + 1,
            )
        )
    return output


def _published_references(body: str, limits: ReadExplorationLimits) -> Tuple[str, ...]:
    text = body.lstrip()
    if not text:
        return ()
    references: list[str] = []
    if text.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            references.extend(
                _json_references(
                    parsed,
                    limit=limits.max_references_per_record,
                    max_depth=limits.max_json_depth,
                )
            )
    if len(references) < limits.max_references_per_record and "<" in body:
        parser = _AnchorParser(limits.max_references_per_record - len(references))
        try:
            parser.feed(body)
        except Exception:
            pass
        references.extend(parser.references)
    return tuple(dict.fromkeys(references[: limits.max_references_per_record]))


def _safe_published_url(
    reference: str,
    *,
    base_url: str,
    target_origin: tuple[str, str, int],
) -> Optional[str]:
    if (
        not reference
        or len(reference) > 4096
        or any(
            character.isspace()
            or ord(character) < 0x20
            or ord(character) == 0x7F
            or character == "\\"
            for character in reference
        )
    ):
        return None
    try:
        absolute = urljoin(base_url, reference)
        parsed = urlsplit(absolute)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        _origin_key(absolute) != target_origin
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
    ):
        return None
    decoded_intent = f"{parsed.path}?{parsed.query}"
    for _ in range(2):
        decoded_intent = unquote(decoded_intent)
    if _DANGEROUS_URL.search(decoded_intent) or _STATIC_EXTENSION.search(parsed.path):
        return None
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in {"action", "cmd", "do", "operation"} and (
            not value or _DANGEROUS_URL.search(value)
        ):
            return None
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _route_template(value: str) -> str:
    parsed = urlsplit(value)
    segments = []
    for segment in parsed.path.split("/"):
        decoded = unquote(segment)
        long_identifier = bool(_LONG_TOKEN.fullmatch(decoded)) and any(
            character.isdigit()
            or character.isupper()
            or character in {"_", "-"}
            for character in decoded
        )
        if (
            decoded.isdigit()
            or _UUID.fullmatch(decoded)
            or long_identifier
        ) and not re.fullmatch(r"v\d+", decoded, re.IGNORECASE):
            segments.append("{id}")
        else:
            segments.append(decoded.lower())
    query_keys = sorted(key.lower() for key, _ in parse_qsl(parsed.query, True))
    query = "&".join(f"{key}={{value}}" for key in query_keys)
    return f"/{'/'.join(segments).lstrip('/')}" + (f"?{query}" if query else "")


def _response_is_eligible(record: Mapping[str, Any]) -> bool:
    try:
        status = int(record.get("response_status") or record.get("status") or 0)
    except (TypeError, ValueError):
        return False
    return status == 0 or 200 <= status < 300


def _frontier(
    records: Sequence[Mapping[str, Any]],
    *,
    target_origin: tuple[str, str, int],
    limits: ReadExplorationLimits,
    visited_urls: set[str],
    visited_templates: set[str],
) -> tuple[Dict[str, Tuple[str, ...]], int]:
    grouped: Dict[str, set[str]] = {}
    discovered = 0
    for record in records:
        if not _response_is_eligible(record):
            continue
        base_url = str(record.get("url") or "")
        body = record.get("response_body")
        if _origin_key(base_url) != target_origin or not isinstance(body, str):
            continue
        for reference in _published_references(body, limits):
            candidate = _safe_published_url(
                reference,
                base_url=base_url,
                target_origin=target_origin,
            )
            if candidate is None or candidate in visited_urls:
                continue
            template = _route_template(candidate)
            if template in visited_templates:
                continue
            grouped.setdefault(template, set()).add(candidate)
            discovered += 1
            if discovered >= limits.max_candidates_per_world:
                break
        if discovered >= limits.max_candidates_per_world:
            break
    return {key: tuple(sorted(values)) for key, values in grouped.items()}, discovered


def _body_text(value: Any, limit: int) -> tuple[str, bool]:
    if isinstance(value, str):
        return value[:limit], len(value) > limit or bool(
            getattr(value, "body_truncated", False)
        )
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        encoded = ""
    return encoded[:limit], len(encoded) > limit


class BehavioralReadExplorer:
    """Follow paired, exact read references until the planner has a candidate."""

    def __init__(
        self,
        *,
        target_origin: str,
        source_persona_id: str,
        peer_persona_id: str,
        executors: Mapping[str, PolicyExecutor],
        limits: Optional[ReadExplorationLimits] = None,
    ) -> None:
        origin = _origin_key(target_origin)
        if origin is None:
            raise ValueError("target_origin must be an absolute HTTP(S) origin")
        if source_persona_id == peer_persona_id:
            raise ValueError("read exploration requires two distinct personas")
        if set(executors) != {source_persona_id, peer_persona_id}:
            raise ValueError("read exploration executor persona set mismatch")
        self.target_origin = origin
        self.source_persona_id = source_persona_id
        self.peer_persona_id = peer_persona_id
        self.executors = dict(executors)
        self.limits = limits or ReadExplorationLimits()

    async def _fetch(
        self,
        *,
        persona_id: str,
        url: str,
        diagnostics: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        diagnostics["requests_attempted"] += 1
        try:
            status, body = await self.executors[persona_id].send(
                "GET",
                url,
                None,
                hint=SAFE_READ,
                actor=persona_id,
                target_owner=persona_id,
                target_is_researcher_owned=True,
                expected_side_effect="none",
                proof_goal="discover_owned_read_surface",
                _max_response_chars=self.limits.max_response_chars,
            )
        except Exception:
            diagnostics["failed_requests"] += 1
            return None
        if int(status) == DENIED_STATUS:
            diagnostics["policy_denials"] += 1
            return None
        diagnostics["requests_sent"] += 1
        text, truncated = _body_text(body, self.limits.max_response_chars)
        if 200 <= int(status) < 300:
            diagnostics["successful_responses"] += 1
        return {
            "action": "network_capture",
            "persona_id": persona_id,
            "type": "behavioral_read_exploration",
            "url": url,
            "method": "GET",
            "request_headers": {},
            "request_body": "",
            "response_status": int(status),
            "response_body": text,
            "request_truncated": False,
            "response_truncated": truncated,
        }

    async def explore(
        self,
        source_records: Sequence[Mapping[str, Any]],
        peer_records: Sequence[Mapping[str, Any]],
        *,
        stop_when: Callable[
            [Sequence[Mapping[str, Any]], Sequence[Mapping[str, Any]]], bool
        ],
    ) -> ReadExplorationResult:
        source = [dict(record) for record in source_records]
        peer = [dict(record) for record in peer_records]
        visited_urls = {
            str(record.get("url") or "") for record in (*source_records, *peer_records)
        }
        visited_templates: set[str] = set()
        diagnostics: Dict[str, Any] = {
            "pairs_attempted": 0,
            "pairs_completed": 0,
            "requests_attempted": 0,
            "requests_sent": 0,
            "successful_responses": 0,
            "policy_denials": 0,
            "failed_requests": 0,
            "candidates_discovered": 0,
            "selected_after_pair": 0,
            "frontier_exhausted": False,
        }
        for pair_index in range(1, self.limits.max_pairs + 1):
            source_frontier, source_discovered = _frontier(
                source,
                target_origin=self.target_origin,
                limits=self.limits,
                visited_urls=visited_urls,
                visited_templates=visited_templates,
            )
            peer_frontier, peer_discovered = _frontier(
                peer,
                target_origin=self.target_origin,
                limits=self.limits,
                visited_urls=visited_urls,
                visited_templates=visited_templates,
            )
            diagnostics["candidates_discovered"] = max(
                diagnostics["candidates_discovered"],
                source_discovered + peer_discovered,
            )
            shared_templates = list(set(source_frontier) & set(peer_frontier))
            shared_templates.sort(
                key=lambda item: (
                    source_frontier[item][0] == peer_frontier[item][0],
                    "{id}" not in item,
                    not item.startswith(("/api/", "/graphql", "/v1/", "/v2/")),
                    item,
                )
            )
            if not shared_templates:
                diagnostics["frontier_exhausted"] = True
                break
            template = shared_templates[0]
            source_url = source_frontier[template][0]
            peer_url = peer_frontier[template][0]
            visited_templates.add(template)
            visited_urls.update((source_url, peer_url))
            diagnostics["pairs_attempted"] += 1
            source_record = await self._fetch(
                persona_id=self.source_persona_id,
                url=source_url,
                diagnostics=diagnostics,
            )
            peer_record = await self._fetch(
                persona_id=self.peer_persona_id,
                url=peer_url,
                diagnostics=diagnostics,
            )
            if source_record is None or peer_record is None:
                continue
            if not (
                200 <= int(source_record["response_status"]) < 300
                and 200 <= int(peer_record["response_status"]) < 300
            ):
                continue
            source.append(source_record)
            peer.append(peer_record)
            diagnostics["pairs_completed"] += 1
            if stop_when(source, peer):
                diagnostics["selected_after_pair"] = pair_index
                break
        return ReadExplorationResult(
            source_records=tuple(source),
            peer_records=tuple(peer),
            diagnostics=diagnostics,
        )


__all__ = [
    "BehavioralReadExplorer",
    "ReadExplorationLimits",
    "ReadExplorationResult",
]
