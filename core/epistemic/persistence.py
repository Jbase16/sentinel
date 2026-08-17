"""SQLite backing store for the canonical EvidenceLedger event stream."""

from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Tuple


_ENTITY_KINDS = frozenset({"observation", "finding"})


def _encode(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _session(value: str) -> str:
    normalized = str(value).strip()
    if not normalized or normalized == "global_scan":
        raise ValueError("canonical evidence requires an explicit session")
    return normalized


class CanonicalEvidenceRepository:
    """Append/load adapter; admission and epistemic decisions remain in the ledger."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path), timeout=30.0)
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS epistemic_entities (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL CHECK(session_id <> 'global_scan'),
                    kind TEXT NOT NULL CHECK(kind IN ('observation', 'finding')),
                    commitment TEXT NOT NULL UNIQUE,
                    data TEXT NOT NULL CHECK(json_valid(data))
                );
                CREATE INDEX IF NOT EXISTS idx_epistemic_entities_session
                    ON epistemic_entities(session_id, kind);

                CREATE TABLE IF NOT EXISTS epistemic_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    session_id TEXT NOT NULL CHECK(session_id <> 'global_scan'),
                    entity_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    data TEXT NOT NULL CHECK(json_valid(data))
                );
                CREATE INDEX IF NOT EXISTS idx_epistemic_events_session
                    ON epistemic_events(session_id, sequence);
                """
            )

    def append_entity_event(
        self,
        *,
        session_id: str,
        kind: str,
        entity_id: str,
        commitment: str,
        entity: Mapping[str, Any],
        event: Mapping[str, Any],
    ) -> None:
        session_id = _session(session_id)
        if kind not in _ENTITY_KINDS:
            raise ValueError("unsupported canonical evidence entity kind")
        entity_json = _encode(entity)
        event_json = _encode(event)
        with closing(self._connect()) as connection, connection:
            self._insert_or_verify_entity(
                connection,
                entity_id=entity_id,
                session_id=session_id,
                kind=kind,
                commitment=commitment,
                data=entity_json,
            )
            self._insert_or_verify_event(connection, session_id, event, event_json)

    def append_event(self, *, session_id: str, event: Mapping[str, Any]) -> None:
        session_id = _session(session_id)
        event_json = _encode(event)
        with closing(self._connect()) as connection, connection:
            self._insert_or_verify_event(connection, session_id, event, event_json)

    @staticmethod
    def _insert_or_verify_entity(
        connection: sqlite3.Connection,
        *,
        entity_id: str,
        session_id: str,
        kind: str,
        commitment: str,
        data: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO epistemic_entities(id, session_id, kind, commitment, data)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (entity_id, session_id, kind, commitment, data),
        )
        stored = connection.execute(
            "SELECT session_id, kind, commitment, data FROM epistemic_entities WHERE id = ?",
            (entity_id,),
        ).fetchone()
        if stored != (session_id, kind, commitment, data):
            raise ValueError("canonical evidence entity collision")

    @staticmethod
    def _insert_or_verify_event(
        connection: sqlite3.Connection,
        session_id: str,
        event: Mapping[str, Any],
        data: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO epistemic_events(id, session_id, entity_id, event_type, data)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                event["id"],
                session_id,
                event["entity_id"],
                event["event_type"],
                data,
            ),
        )
        stored = connection.execute(
            "SELECT session_id, data FROM epistemic_events WHERE id = ?",
            (event["id"],),
        ).fetchone()
        if stored != (session_id, data):
            raise ValueError("canonical evidence event collision")

    def load(self) -> Tuple[Tuple[dict[str, Any], ...], Tuple[dict[str, Any], ...]]:
        with closing(self._connect()) as connection:
            entities = tuple(
                {
                    "id": row[0],
                    "session_id": row[1],
                    "kind": row[2],
                    "commitment": row[3],
                    "data": json.loads(row[4]),
                }
                for row in connection.execute(
                    """
                    SELECT id, session_id, kind, commitment, data
                    FROM epistemic_entities
                    ORDER BY CASE kind WHEN 'observation' THEN 0 ELSE 1 END, id
                    """
                )
            )
            events = tuple(
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT data FROM epistemic_events ORDER BY sequence"
                )
            )
        return entities, events
