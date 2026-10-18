"""Session isolation for the read-only scan inspector."""

import sqlite3

from scripts import inspect_scan


def test_decisions_are_limited_to_requested_session():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(
            """
            CREATE TABLE sessions (id TEXT);
            CREATE TABLE findings (id TEXT, tool TEXT, type TEXT, severity TEXT,
                target TEXT, data TEXT, timestamp TEXT, session_id TEXT);
            CREATE TABLE issues (id TEXT, title TEXT, severity TEXT, target TEXT,
                data TEXT, timestamp TEXT, session_id TEXT);
            CREATE TABLE evidence (id TEXT, tool TEXT, metadata TEXT, timestamp TEXT,
                session_id TEXT);
            CREATE TABLE decisions (id TEXT, event_sequence INTEGER, type TEXT,
                chosen TEXT, reason TEXT, session_id TEXT);
            INSERT INTO sessions VALUES ('session-a'), ('session-b');
            INSERT INTO decisions VALUES
                ('other', 1, 'tool', 'b', 'private-b', 'session-b'),
                ('own', 2, 'tool', 'a', 'private-a', 'session-a');
            """
        )

        data = inspect_scan._gather_session_data(connection, "session-a")
        assert [row["id"] for row in data["decisions"]] == ["own"]
    finally:
        connection.close()
