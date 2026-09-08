"""SQLite backing store for the canonical EvidenceLedger event stream."""

from __future__ import annotations

from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Optional, Sequence, Tuple

from core.behavior.normalize import stable_hash


_ENTITY_KINDS = frozenset({"observation", "finding"})
_CAPABILITY_PROMOTION_STATES = frozenset(
    {
        "source_incomplete",
        "awaiting_source",
        "blocked_by_policy",
        "eligible_awaiting_processing",
        "retryable_local_persistence_failure",
        "invalid_evidence",
        "not_replay_leak",
        "promoted",
    }
)
_MAX_CAPABILITY_ATTEMPT_HISTORY = 32
_MAX_CAPABILITY_ATTEMPT_BYTES = 4096
_MAX_CAPABILITY_ATTEMPTS_DATA_BYTES = (
    _MAX_CAPABILITY_ATTEMPT_HISTORY * _MAX_CAPABILITY_ATTEMPT_BYTES
)


def _plain_json(value: Any) -> Any:
    """Convert immutable Mapping projections into JSON encoder primitives."""

    if isinstance(value, Mapping):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in value]
    return value


def _encode(value: Mapping[str, Any]) -> str:
    return json.dumps(
        _plain_json(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _capability_promotion_state(value: str) -> str:
    if value not in _CAPABILITY_PROMOTION_STATES:
        raise ValueError("unsupported capability promotion journal state")
    return value


class CanonicalEvidenceRepositoryCorruption(ValueError):
    """A durable canonical row violates its declared persistence contract."""


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

                CREATE TABLE IF NOT EXISTS capability_effect_promotion_journal (
                    admission_id TEXT PRIMARY KEY,
                    intake_id TEXT NOT NULL UNIQUE,
                    session_id TEXT NOT NULL CHECK(session_id <> 'global_scan'),
                    target_origin TEXT NOT NULL,
                    identity_data TEXT NOT NULL CHECK(json_valid(identity_data)),
                    operation_data TEXT NOT NULL CHECK(json_valid(operation_data)),
                    producer_data TEXT NOT NULL CHECK(json_valid(producer_data)),
                    storage_data TEXT NOT NULL CHECK(json_valid(storage_data)),
                    source_receipt_id TEXT UNIQUE,
                    source_fingerprint TEXT UNIQUE,
                    event_timestamp REAL NOT NULL,
                    event_run_id TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0
                        CHECK(attempt_count >= 0),
                    attempts_data TEXT NOT NULL DEFAULT '[]'
                        CHECK(json_valid(attempts_data))
                        CHECK(json_type(attempts_data) = 'array'),
                    state TEXT NOT NULL CHECK(state IN (
                        'source_incomplete',
                        'awaiting_source',
                        'blocked_by_policy',
                        'eligible_awaiting_processing',
                        'retryable_local_persistence_failure',
                        'invalid_evidence',
                        'not_replay_leak',
                        'promoted'
                    )),
                    evidence_root TEXT,
                    cas_blob_hash TEXT,
                    observation_id TEXT,
                    finding_id TEXT,
                    last_error TEXT,
                    CHECK(
                        state <> 'promoted'
                        OR (
                            evidence_root IS NOT NULL
                            AND cas_blob_hash IS NOT NULL
                            AND observation_id IS NOT NULL
                            AND finding_id IS NOT NULL
                        )
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_capability_effect_promotion_state
                    ON capability_effect_promotion_journal(state, admission_id);

                CREATE TABLE IF NOT EXISTS capability_effect_persistence_preflight (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    token TEXT NOT NULL
                );
                """
            )

    def preflight(self, token: str) -> None:
        """Exercise one bounded SQLite write before capability dispatch."""

        if not isinstance(token, str) or not token:
            raise ValueError("persistence preflight token is required")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO capability_effect_persistence_preflight(id, token)
                    VALUES (1, ?)
                    ON CONFLICT(id) DO UPDATE SET token = excluded.token
                    """,
                    (token,),
                )
                connection.execute(
                    "DELETE FROM capability_effect_persistence_preflight WHERE id = 1"
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

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

    def reserve_capability_effect_admission(
        self,
        *,
        admission_id: str,
        intake_id: str,
        session_id: str,
        target_origin: str,
        identity: Mapping[str, Any],
        operation: Mapping[str, Any],
        producer: Mapping[str, Any],
        storage: Mapping[str, Any],
        event_timestamp: float,
        event_run_id: Optional[str],
        session_projection: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        """Reserve immutable execution ownership before target activity."""

        session_id = _session(session_id)
        immutable = (
            admission_id,
            intake_id,
            session_id,
            target_origin,
            _encode(identity),
            _encode(operation),
            _encode(producer),
            _encode(storage),
            event_timestamp,
            event_run_id,
        )
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    """
                    SELECT admission_id, intake_id, session_id, target_origin,
                           identity_data, operation_data, producer_data,
                           storage_data, event_timestamp, event_run_id
                    FROM capability_effect_promotion_journal
                    WHERE intake_id = ? OR admission_id = ?
                    """,
                    (intake_id, admission_id),
                ).fetchone()
                if existing is None:
                    if session_projection is not None:
                        projection_id = _session(
                            str(session_projection.get("id") or "")
                        )
                        if projection_id != session_id:
                            raise ValueError(
                                "capability admission session projection mismatch"
                            )
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS sessions (
                                id TEXT PRIMARY KEY,
                                target TEXT NOT NULL,
                                status TEXT,
                                start_time TEXT NOT NULL DEFAULT (datetime('now')),
                                end_time TEXT,
                                logs TEXT
                            )
                            """
                        )
                        connection.execute(
                            """
                            INSERT INTO sessions(id, target, status, start_time, end_time, logs)
                            VALUES (?, ?, ?, ?, ?, ?)
                            ON CONFLICT(id) DO NOTHING
                            """,
                            (
                                session_id,
                                str(session_projection.get("target") or target_origin),
                                str(
                                    session_projection.get("status")
                                    or "BehavioralEvidence"
                                ),
                                str(
                                    session_projection.get("start_time")
                                    or event_timestamp
                                ),
                                session_projection.get("end_time"),
                                json.dumps(
                                    session_projection.get("logs") or [],
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                            ),
                        )
                    connection.execute(
                        """
                        INSERT INTO capability_effect_promotion_journal(
                            admission_id, intake_id, session_id, target_origin,
                            identity_data, operation_data, producer_data,
                            storage_data, event_timestamp, event_run_id, state
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'source_incomplete')
                        """,
                        immutable,
                    )
                elif tuple(existing[:8]) != immutable[:8]:
                    raise ValueError("capability execution admission context collision")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        record = self.load_capability_effect_admission(admission_id)
        if record is None:
            raise ValueError("capability execution admission disappeared")
        return record

    def bind_capability_effect_source(
        self,
        *,
        admission_id: str,
        source_receipt_id: str,
        source_fingerprint: str,
    ) -> dict[str, Any]:
        """Append-once bind the exact inner receipt before its first request."""

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                owner = connection.execute(
                    """
                    SELECT admission_id FROM capability_effect_promotion_journal
                    WHERE source_receipt_id = ? OR source_fingerprint = ?
                    """,
                    (source_receipt_id, source_fingerprint),
                ).fetchone()
                if owner is not None and owner[0] != admission_id:
                    raise ValueError("capability source is owned by another admission")
                current = connection.execute(
                    """
                    SELECT source_receipt_id, source_fingerprint
                    FROM capability_effect_promotion_journal
                    WHERE admission_id = ?
                    """,
                    (admission_id,),
                ).fetchone()
                if current is None:
                    raise ValueError("capability execution admission is missing")
                if current == (None, None):
                    connection.execute(
                        """
                        UPDATE capability_effect_promotion_journal
                        SET source_receipt_id = ?, source_fingerprint = ?,
                            state = 'awaiting_source'
                        WHERE admission_id = ?
                        """,
                        (source_receipt_id, source_fingerprint, admission_id),
                    )
                elif current != (source_receipt_id, source_fingerprint):
                    raise ValueError("capability source binding is immutable")
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                raise ValueError("capability source binding collision") from exc
            except BaseException:
                connection.rollback()
                raise
        record = self.load_capability_effect_admission(admission_id)
        if record is None:
            raise ValueError("capability execution admission disappeared")
        return record

    @staticmethod
    def _promotion_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
        keys = (
            "admission_id",
            "intake_id",
            "session_id",
            "target_origin",
            "identity_data",
            "operation_data",
            "producer_data",
            "storage_data",
            "source_receipt_id",
            "source_fingerprint",
            "event_timestamp",
            "event_run_id",
            "attempt_count",
            "attempts_data",
            "state",
            "evidence_root",
            "cas_blob_hash",
            "observation_id",
            "finding_id",
            "last_error",
        )
        if len(row) != len(keys):
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal column count is invalid"
            )
        value = dict(zip(keys, row))
        try:
            for field in (
                "identity_data",
                "operation_data",
                "producer_data",
                "storage_data",
            ):
                decoded = json.loads(value[field])
                if not isinstance(decoded, dict):
                    raise TypeError(field)
                value[field] = decoded
            serialized_attempts = value["attempts_data"]
            if (
                not isinstance(serialized_attempts, str)
                or len(serialized_attempts.encode("utf-8"))
                > _MAX_CAPABILITY_ATTEMPTS_DATA_BYTES
            ):
                raise TypeError("attempts_data")
            attempts = json.loads(serialized_attempts)
            if (
                not isinstance(attempts, list)
                or len(attempts) > _MAX_CAPABILITY_ATTEMPT_HISTORY
                or any(not isinstance(item, dict) for item in attempts)
            ):
                raise TypeError("attempts_data")
            value["attempts_data"] = attempts
        except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal JSON shape is invalid"
            ) from exc

        state = value["state"]
        if state not in _CAPABILITY_PROMOTION_STATES:
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal state is invalid"
            )
        attempt_count = value["attempt_count"]
        if (
            type(attempt_count) is not int
            or attempt_count < len(value["attempts_data"])
            or attempt_count < 0
        ):
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion attempt count is invalid"
            )
        admission_id = value["admission_id"]
        intake_id = value["intake_id"]
        if (
            not isinstance(admission_id, str)
            or not admission_id.startswith("capability_effect_execution_admission:")
            or len(admission_id.rsplit(":", 1)[-1]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in admission_id.rsplit(":", 1)[-1]
            )
            or not isinstance(intake_id, str)
            or not intake_id.startswith("capability_effect_intake:")
            or len(intake_id.rsplit(":", 1)[-1]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in intake_id.rsplit(":", 1)[-1]
            )
            or not isinstance(value["session_id"], str)
            or not value["session_id"]
            or value["session_id"] == "global_scan"
            or not isinstance(value["target_origin"], str)
            or not value["target_origin"]
            or isinstance(value["event_timestamp"], bool)
            or not isinstance(value["event_timestamp"], (int, float))
            or not math.isfinite(float(value["event_timestamp"]))
            or float(value["event_timestamp"]) <= 0
        ):
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal identity is invalid"
            )
        identity_digest = value["identity_data"].get("digest")
        if not isinstance(identity_digest, str) or not identity_digest:
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal identity digest is invalid"
            )
        expected_admission_id = stable_hash(
            "capability_effect_execution_admission",
            {
                "intake_id": intake_id,
                "session_id": value["session_id"],
                "target_origin": value["target_origin"],
                "identity_digest": identity_digest,
                "operation": value["operation_data"],
                "producer": value["producer_data"],
                "storage": value["storage_data"],
            },
        )
        if admission_id != expected_admission_id:
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal admission commitment is invalid"
            )
        source_receipt_id = value["source_receipt_id"]
        source_fingerprint = value["source_fingerprint"]
        if (source_receipt_id is None) != (source_fingerprint is None) or (
            source_receipt_id is not None
            and (
                not isinstance(source_receipt_id, str)
                or not isinstance(source_fingerprint, str)
                or source_receipt_id != f"behavioral-{source_fingerprint}"
                or len(source_fingerprint) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in source_fingerprint
                )
            )
        ):
            raise CanonicalEvidenceRepositoryCorruption(
                "capability promotion journal source binding is invalid"
            )
        if state == "promoted":
            if not all(
                isinstance(value[field], str) and value[field]
                for field in (
                    "evidence_root",
                    "cas_blob_hash",
                    "observation_id",
                    "finding_id",
                )
            ):
                raise CanonicalEvidenceRepositoryCorruption(
                    "promoted capability journal result is incomplete"
                )
            for field in ("evidence_root", "cas_blob_hash"):
                reference = value[field]
                if len(reference) != 64 or any(
                    character not in "0123456789abcdef" for character in reference
                ):
                    raise CanonicalEvidenceRepositoryCorruption(
                        "promoted capability journal digest is invalid"
                    )
            if not value["observation_id"].startswith("obs-") or not value[
                "finding_id"
            ].startswith("find-"):
                raise CanonicalEvidenceRepositoryCorruption(
                    "promoted capability journal entity reference is invalid"
                )
        return value

    def load_capability_effect_admission(
        self,
        identifier: str,
    ) -> Optional[dict[str, Any]]:
        if identifier.startswith("capability_effect_execution_admission:"):
            column = "admission_id"
        elif identifier.startswith("capability_effect_intake:"):
            column = "intake_id"
        elif identifier.startswith("behavioral-"):
            column = "source_receipt_id"
        elif len(identifier) == 64 and all(
            character in "0123456789abcdef" for character in identifier
        ):
            column = "source_fingerprint"
        else:
            return None
        return self._load_capability_effect_admission_by(column, identifier)

    def _load_capability_effect_admission_by(
        self,
        column: str,
        identifier: str,
    ) -> Optional[dict[str, Any]]:
        if column not in {
            "admission_id",
            "intake_id",
            "source_receipt_id",
            "source_fingerprint",
        }:
            raise ValueError("unsupported capability journal lookup")
        with closing(self._connect()) as connection:
            row = connection.execute(
                f"""
                SELECT admission_id, intake_id, session_id, target_origin,
                       identity_data, operation_data, producer_data, storage_data,
                       source_receipt_id, source_fingerprint, event_timestamp,
                       event_run_id, attempt_count, attempts_data, state,
                       evidence_root, cas_blob_hash, observation_id, finding_id,
                       last_error
                FROM capability_effect_promotion_journal
                WHERE {column} = ?
                """,
                (identifier,),
            ).fetchone()
        return None if row is None else self._promotion_row(row)

    def list_capability_effect_admissions(
        self,
        *,
        states: Optional[Sequence[str]] = None,
        limit: int = 256,
    ) -> Tuple[dict[str, Any], ...]:
        if type(limit) is not int or limit < 1 or limit > 1000:
            raise ValueError("capability promotion journal limit is invalid")
        normalized_states = tuple(states or ())
        for state in normalized_states:
            _capability_promotion_state(state)
        where = ""
        parameters: list[Any] = []
        if normalized_states:
            placeholders = ",".join("?" for _ in normalized_states)
            where = f"WHERE state IN ({placeholders})"
            parameters.extend(normalized_states)
        parameters.append(limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT admission_id, intake_id, session_id, target_origin,
                       identity_data, operation_data, producer_data, storage_data,
                       source_receipt_id, source_fingerprint, event_timestamp,
                       event_run_id, attempt_count, attempts_data, state,
                       evidence_root, cas_blob_hash, observation_id, finding_id,
                       last_error
                FROM capability_effect_promotion_journal
                {where}
                ORDER BY admission_id
                LIMIT ?
                """,
                tuple(parameters),
            ).fetchall()
        return tuple(self._promotion_row(row) for row in rows)

    def list_capability_effect_admission_ids(
        self,
        *,
        states: Sequence[str],
        limit: int = 256,
    ) -> Tuple[str, ...]:
        """Return a bounded worklist without decoding unrelated journal rows."""

        if type(limit) is not int or limit < 1 or limit > 1000:
            raise ValueError("capability promotion journal limit is invalid")
        normalized_states = tuple(states)
        if not normalized_states:
            return ()
        for state in normalized_states:
            _capability_promotion_state(state)
        placeholders = ",".join("?" for _ in normalized_states)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT admission_id
                FROM capability_effect_promotion_journal
                WHERE state IN ({placeholders})
                ORDER BY admission_id
                LIMIT ?
                """,
                (*normalized_states, limit),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def record_capability_effect_attempt(
        self,
        *,
        admission_id: str,
        attempt: Mapping[str, Any],
        state: str,
        last_error: Optional[str] = None,
    ) -> dict[str, Any]:
        _capability_promotion_state(state)
        attempt_json = _encode(dict(attempt))
        if len(attempt_json.encode("utf-8")) > _MAX_CAPABILITY_ATTEMPT_BYTES:
            raise ValueError("capability promotion attempt is too large")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    """
                    SELECT attempts_data FROM capability_effect_promotion_journal
                    WHERE admission_id = ?
                    """,
                    (admission_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("capability execution admission is missing")
                try:
                    attempts = json.loads(row[0])
                except json.JSONDecodeError as exc:
                    raise CanonicalEvidenceRepositoryCorruption(
                        "capability promotion attempt history is invalid"
                    ) from exc
                if not isinstance(attempts, list) or any(
                    not isinstance(item, dict) for item in attempts
                ):
                    raise CanonicalEvidenceRepositoryCorruption(
                        "capability promotion attempt history is invalid"
                    )
                attempts = attempts[-(_MAX_CAPABILITY_ATTEMPT_HISTORY - 1) :]
                attempts.append(json.loads(attempt_json))
                connection.execute(
                    """
                    UPDATE capability_effect_promotion_journal
                    SET attempt_count = attempt_count + 1, attempts_data = ?,
                        state = CASE
                            WHEN state = 'promoted' THEN state ELSE ? END,
                        last_error = CASE
                            WHEN state = 'promoted' THEN NULL ELSE ? END
                    WHERE admission_id = ?
                    """,
                    (
                        json.dumps(attempts, sort_keys=True, separators=(",", ":")),
                        state,
                        last_error,
                        admission_id,
                    ),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        record = self.load_capability_effect_admission(admission_id)
        if record is None:
            raise ValueError("capability execution admission disappeared")
        return record

    def set_capability_effect_state(
        self,
        *,
        admission_id: str,
        state: str,
        last_error: Optional[str] = None,
    ) -> dict[str, Any]:
        """Update recoverable processing state without changing identity or policy audit."""

        _capability_promotion_state(state)
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """
                UPDATE capability_effect_promotion_journal
                SET state = CASE
                        WHEN state = 'promoted' THEN state ELSE ? END,
                    last_error = CASE
                        WHEN state = 'promoted' THEN NULL ELSE ? END
                WHERE admission_id = ?
                """,
                (state, last_error, admission_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("capability execution admission is missing")
        record = self.load_capability_effect_admission(admission_id)
        if record is None:
            raise ValueError("capability execution admission disappeared")
        return record

    def commit_capability_effect_promotion(
        self,
        *,
        admission_id: str,
        session_id: str,
        observation_id: str,
        observation_commitment: str,
        observation: Mapping[str, Any],
        observation_event: Mapping[str, Any],
        finding_id: str,
        finding_commitment: str,
        finding: Mapping[str, Any],
        finding_event: Mapping[str, Any],
        evidence_root: str,
        cas_blob_hash: str,
        source_receipt_id: str,
        source_fingerprint: str,
        identity: Mapping[str, Any],
        operation: Mapping[str, Any],
        producer: Mapping[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        """Commit both canonical entities, events, and the journal result once."""

        session_id = _session(session_id)
        created = False
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    """
                    SELECT session_id, state, evidence_root, cas_blob_hash,
                           observation_id, finding_id, source_receipt_id,
                           source_fingerprint, identity_data, operation_data,
                           producer_data
                    FROM capability_effect_promotion_journal
                    WHERE admission_id = ?
                    """,
                    (admission_id,),
                ).fetchone()
                if current is None or current[0] != session_id:
                    raise ValueError("capability promotion admission is invalid")
                if (
                    current[1]
                    not in {
                        "eligible_awaiting_processing",
                        "retryable_local_persistence_failure",
                        "promoted",
                    }
                    or current[6] != source_receipt_id
                    or current[7] != source_fingerprint
                    or current[8] != _encode(identity)
                    or current[9] != _encode(operation)
                    or current[10] != _encode(producer)
                ):
                    raise ValueError("capability promotion context does not match")
                expected = (
                    session_id,
                    "promoted",
                    evidence_root,
                    cas_blob_hash,
                    observation_id,
                    finding_id,
                )
                if current[1] == "promoted":
                    if tuple(current[:6]) != expected:
                        raise ValueError("capability promotion result collision")
                else:
                    self._insert_or_verify_entity(
                        connection,
                        entity_id=observation_id,
                        session_id=session_id,
                        kind="observation",
                        commitment=observation_commitment,
                        data=_encode(observation),
                    )
                    self._insert_or_verify_event(
                        connection,
                        session_id,
                        observation_event,
                        _encode(observation_event),
                    )
                    self._insert_or_verify_entity(
                        connection,
                        entity_id=finding_id,
                        session_id=session_id,
                        kind="finding",
                        commitment=finding_commitment,
                        data=_encode(finding),
                    )
                    self._insert_or_verify_event(
                        connection,
                        session_id,
                        finding_event,
                        _encode(finding_event),
                    )
                    connection.execute(
                        """
                        UPDATE capability_effect_promotion_journal
                        SET state = 'promoted', evidence_root = ?,
                            cas_blob_hash = ?, observation_id = ?, finding_id = ?,
                            last_error = NULL
                        WHERE admission_id = ?
                        """,
                        (
                            evidence_root,
                            cas_blob_hash,
                            observation_id,
                            finding_id,
                            admission_id,
                        ),
                    )
                    created = True
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        record = self.load_capability_effect_admission(admission_id)
        if record is None:
            raise ValueError("capability promotion result disappeared")
        return record, created

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
            # Keep entities and their event stream on one SQLite snapshot.  A
            # concurrent promotion transaction must be observed wholly before
            # or wholly after commit, never as a torn restore.
            connection.execute("BEGIN")
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
            connection.commit()
        return entities, events
