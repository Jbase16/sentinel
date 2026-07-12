"""Bounded, fail-closed recovery of persisted GraphQL operation documents.

The catalog is pure analysis: it accepts already-captured records or caller-supplied
artifact text and has no transport. A persisted hash is resolved only by exact
SHA-256. A name-only operation is resolved only when one document is unambiguous.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, DefaultDict, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .normalize import stable_hash

_OPERATION = re.compile(
    r"\b(query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)\b",
    re.IGNORECASE,
)
_PERSISTED_HASH = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class GraphQLCatalogLimits:
    max_artifacts: int = 16
    max_artifact_bytes: int = 2 * 1024 * 1024
    max_total_artifact_bytes: int = 8 * 1024 * 1024
    max_documents: int = 2_048
    max_document_chars: int = 128 * 1024
    max_string_literals_per_artifact: int = 100_000

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class GraphQLOperationDocument:
    operation_name: str
    operation_type: str
    document: str
    document_hash: str
    source_ref: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "operation_name": self.operation_name,
            "operation_type": self.operation_type,
            "document_hash": self.document_hash,
            "source_ref": self.source_ref,
        }


@dataclass(frozen=True)
class GraphQLResolutionResult:
    records: Tuple[Dict[str, Any], ...]
    resolved_operations: int
    unresolved_operations: int
    ambiguous_operations: int

    def diagnostics(self) -> Dict[str, int]:
        return {
            "resolved_operations": self.resolved_operations,
            "unresolved_operations": self.unresolved_operations,
            "ambiguous_operations": self.ambiguous_operations,
        }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _balanced_graphql(value: str) -> bool:
    depth = 0
    quote: Optional[str] = None
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif value.startswith(quote, index):
                index += len(quote) - 1
                quote = None
        elif value.startswith('"""', index):
            quote = '"""'
            index += 2
        elif character == '"':
            quote = '"'
        elif character == "#":
            newline = value.find("\n", index)
            if newline < 0:
                break
            index = newline
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                return False
        index += 1
    return depth == 0 and quote is None and "{" in value


def _slice_document(value: str) -> Optional[str]:
    stripped = value.strip()
    match = _OPERATION.search(stripped)
    if match is None:
        return None
    # A JS string is normally the entire GraphQL document. Preserve it exactly
    # (including fragment definitions) so persisted hashes remain meaningful.
    if re.match(
        r"^(?:query|mutation|subscription|fragment)\b",
        stripped,
        re.IGNORECASE,
    ) and _balanced_graphql(stripped):
        return stripped
    start = match.start()
    brace = stripped.find("{", match.end())
    if brace < 0:
        return None
    depth = 0
    quote: Optional[str] = None
    escaped = False
    index = brace
    while index < len(stripped):
        character = stripped[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif stripped.startswith(quote, index):
                index += len(quote) - 1
                quote = None
        elif stripped.startswith('"""', index):
            quote = '"""'
            index += 2
        elif character == '"':
            quote = '"'
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                document = stripped[start:index + 1].strip()
                return document if _balanced_graphql(document) else None
        index += 1
    return None


def _decode_js_string(body: str, quote: str) -> Optional[str]:
    if quote == "`" and "${" in body:
        return None
    output: List[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}
    while index < len(body):
        character = body[index]
        if character != "\\":
            output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(body):
            return None
        escaped = body[index]
        if escaped in escapes:
            output.append(escapes[escaped])
        elif escaped in {"\\", "'", '"', "`", "/"}:
            output.append(escaped)
        elif escaped == "u" and index + 4 < len(body):
            digits = body[index + 1:index + 5]
            if not re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                return None
            output.append(chr(int(digits, 16)))
            index += 4
        elif escaped == "x" and index + 2 < len(body):
            digits = body[index + 1:index + 3]
            if not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                return None
            output.append(chr(int(digits, 16)))
            index += 2
        elif escaped in {"\n", "\r"}:
            pass
        else:
            output.append(escaped)
        index += 1
    return "".join(output)


def _iter_js_strings(value: str, *, limit: int) -> Iterable[str]:
    emitted = 0
    index = 0
    while index < len(value) and emitted < limit:
        quote = value[index]
        if quote not in {"'", '"', "`"}:
            index += 1
            continue
        start = index + 1
        index = start
        escaped = False
        while index < len(value):
            character = value[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                decoded = _decode_js_string(value[start:index], quote)
                if decoded is not None:
                    emitted += 1
                    yield decoded
                index += 1
                break
            index += 1


def _request_hash(item: Mapping[str, Any]) -> Tuple[bool, Optional[str]]:
    extensions = item.get("extensions")
    if isinstance(extensions, Mapping):
        persisted_key = next(
            (
                key
                for key in ("persistedQuery", "persisted_query")
                if key in extensions
            ),
            None,
        )
        persisted = extensions.get(persisted_key) if persisted_key is not None else None
        if persisted_key is not None and not isinstance(persisted, Mapping):
            return True, None
        if isinstance(persisted, Mapping):
            candidate = persisted.get("sha256Hash") or persisted.get("sha256_hash")
            if isinstance(candidate, str) and _PERSISTED_HASH.fullmatch(candidate):
                return True, candidate.lower()
            return True, None
    for key in ("documentId", "document_id", "queryId", "query_id"):
        if key not in item:
            continue
        candidate = item.get(key)
        if isinstance(candidate, str) and _PERSISTED_HASH.fullmatch(candidate):
            return True, candidate.lower()
        return True, None
    return False, None


def _body_items(record: Mapping[str, Any]) -> Optional[Tuple[List[Any], bool]]:
    raw = record.get("request_body")
    if not isinstance(raw, str) or not raw or raw == "[Binary/FormData]":
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, list):
        return list(parsed), True
    return [parsed], False


class PersistedOperationCatalog:
    """Bounded local catalog of exact GraphQL documents."""

    def __init__(self, limits: Optional[GraphQLCatalogLimits] = None) -> None:
        self.limits = limits or GraphQLCatalogLimits()
        self._by_hash: Dict[str, GraphQLOperationDocument] = {}
        self._by_name: DefaultDict[str, Dict[str, GraphQLOperationDocument]] = defaultdict(dict)
        self._artifact_count = 0
        self._artifact_bytes = 0
        self._document_count = 0
        self._dropped = {"artifacts": 0, "artifact_bytes": 0, "documents": 0}

    def _ingest_document(self, document: str, *, source_ref: str) -> int:
        if len(document) > self.limits.max_document_chars or not _balanced_graphql(document):
            return 0
        declarations = list(_OPERATION.finditer(document))
        if not declarations:
            return 0
        digest = _sha256(document)
        added = 0
        for declaration in declarations:
            operation_type = declaration.group(1).lower()
            operation_name = declaration.group(2)
            existing = self._by_name[operation_name].get(digest)
            if existing is not None:
                self._by_hash.setdefault(digest, existing)
                continue
            if self._document_count >= self.limits.max_documents:
                self._dropped["documents"] += 1
                continue
            entry = GraphQLOperationDocument(
                operation_name=operation_name,
                operation_type=operation_type,
                document=document,
                document_hash=digest,
                source_ref=source_ref,
            )
            self._by_name[operation_name][digest] = entry
            self._by_hash.setdefault(digest, entry)
            self._document_count += 1
            added += 1
        return added

    def ingest_capture_records(
        self, records: Sequence[Mapping[str, Any]], *, source: str = "capture"
    ) -> int:
        added = 0
        source_ref = stable_hash("graphql_catalog_source", source)
        for record in records:
            body = _body_items(record)
            if body is None:
                continue
            items, _ = body
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                query = item.get("query")
                if isinstance(query, str) and query.strip():
                    added += self._ingest_document(query, source_ref=source_ref)
        return added

    def ingest_artifact(self, source_url: str, text: str) -> int:
        encoded_bytes = len(text.encode("utf-8", errors="replace"))
        if self._artifact_count >= self.limits.max_artifacts:
            self._dropped["artifacts"] += 1
            return 0
        if encoded_bytes > self.limits.max_artifact_bytes:
            self._dropped["artifact_bytes"] += encoded_bytes
            return 0
        if self._artifact_bytes + encoded_bytes > self.limits.max_total_artifact_bytes:
            self._dropped["artifact_bytes"] += encoded_bytes
            return 0
        self._artifact_count += 1
        self._artifact_bytes += encoded_bytes
        source_ref = stable_hash("graphql_catalog_source", source_url)
        added = 0
        for candidate in _iter_js_strings(
            text, limit=self.limits.max_string_literals_per_artifact
        ):
            if not _OPERATION.search(candidate):
                continue
            document = _slice_document(candidate)
            if document is not None:
                added += self._ingest_document(document, source_ref=source_ref)
        return added

    def _resolve_item(
        self, item: Mapping[str, Any]
    ) -> Tuple[Optional[GraphQLOperationDocument], bool]:
        operation_name = item.get("operationName")
        has_persisted_binding, persisted_hash = _request_hash(item)
        if has_persisted_binding:
            if persisted_hash is None:
                return None, False
            if isinstance(operation_name, str) and operation_name:
                matching = self._by_name.get(operation_name, {}).get(persisted_hash)
                return matching, False
            matches = tuple(
                by_hash[persisted_hash]
                for by_hash in self._by_name.values()
                if persisted_hash in by_hash
            )
            if len(matches) != 1:
                return None, False
            return matches[0], False
        if not isinstance(operation_name, str) or not operation_name:
            return None, False
        candidates = tuple(self._by_name.get(operation_name, {}).values())
        if len(candidates) == 1:
            return candidates[0], False
        return None, len(candidates) > 1

    def resolve_records(
        self, records: Sequence[Mapping[str, Any]]
    ) -> GraphQLResolutionResult:
        output: List[Dict[str, Any]] = []
        resolved = 0
        unresolved = 0
        ambiguous = 0
        for record in records:
            copied = dict(record)
            body = _body_items(record)
            if body is None:
                output.append(copied)
                continue
            items, was_list = body
            changed = False
            new_items: List[Any] = []
            for item in items:
                if not isinstance(item, Mapping) or item.get("query"):
                    new_items.append(dict(item) if isinstance(item, Mapping) else item)
                    continue
                if not (
                    item.get("operationName")
                    or item.get("extensions")
                    or any(
                        key in item
                        for key in ("documentId", "document_id", "queryId", "query_id")
                    )
                ):
                    new_items.append(dict(item))
                    continue
                entry, is_ambiguous = self._resolve_item(item)
                if entry is None:
                    unresolved += 1
                    ambiguous += int(is_ambiguous)
                    new_items.append(dict(item))
                    continue
                enriched = dict(item)
                enriched["query"] = entry.document
                new_items.append(enriched)
                resolved += 1
                changed = True
            if changed:
                copied["request_body"] = json.dumps(
                    new_items if was_list else new_items[0], separators=(",", ":")
                )
            output.append(copied)
        return GraphQLResolutionResult(tuple(output), resolved, unresolved, ambiguous)

    def diagnostics(self) -> Dict[str, Any]:
        return {
            "artifacts": self._artifact_count,
            "artifact_bytes": self._artifact_bytes,
            "documents": self._document_count,
            "operation_names": len(self._by_name),
            "dropped": dict(self._dropped),
        }
