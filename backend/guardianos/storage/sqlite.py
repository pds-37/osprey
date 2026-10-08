"""Small SQLite document store for local backend state.

The adapter keeps security objects as JSON documents so analysis services can
retain their existing Pydantic contracts. Audit events use a separate append-only
table through this API. This is a single-instance local adapter, not a distributed
database or tamper-proof audit system.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from guardianos.core.config import settings


class SQLiteDocumentStore:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        if database_path != ":memory:" and not database_path.startswith("file:"):
            Path(database_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(
            database_path,
            check_same_thread=False,
            uri=database_path.startswith("file:"),
        )
        self._connection.row_factory = sqlite3.Row
        self.corrupt_records: set[tuple[str, str]] = set()
        with self._lock:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS records ("
                "record_type TEXT NOT NULL, record_id TEXT NOT NULL, payload TEXT NOT NULL, "
                "updated_at TEXT NOT NULL, PRIMARY KEY (record_type, record_id))"
            )
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS audit_events ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)"
            )
            self._connection.commit()

    @staticmethod
    def _json(value: Any) -> str:
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        elif is_dataclass(value):
            value = asdict(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

    def put(self, record_type: str, record_id: str, value: Any) -> None:
        payload = self._json(value)
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO records(record_type, record_id, payload, updated_at) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(record_type, record_id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
                (record_type, record_id, payload, updated_at),
            )

    def update_if_field(
        self,
        record_type: str,
        record_id: str,
        expected_fields: dict[str, Any],
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Atomically update a JSON record only while expected fields still match."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT payload FROM records WHERE record_type=? AND record_id=?",
                    (record_type, record_id),
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    return None
                try:
                    value = json.loads(row["payload"])
                except (json.JSONDecodeError, TypeError):
                    self.corrupt_records.add((record_type, record_id))
                    self._connection.rollback()
                    return None
                if (not isinstance(value, dict)
                        or any(value.get(field) != expected for field, expected in expected_fields.items())):
                    self._connection.rollback()
                    return None
                value.update(updates)
                self._connection.execute(
                    "UPDATE records SET payload=?, updated_at=? WHERE record_type=? AND record_id=?",
                    (self._json(value), datetime.now(timezone.utc).isoformat(), record_type, record_id),
                )
                self._connection.commit()
                return value
            except Exception:
                self._connection.rollback()
                raise

    def get(self, record_type: str, record_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload FROM records WHERE record_type=? AND record_id=?",
                (record_type, record_id),
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["payload"])
        except (json.JSONDecodeError, TypeError):
            self.corrupt_records.add((record_type, record_id))
            return None
        if not isinstance(value, dict):
            self.corrupt_records.add((record_type, record_id))
            return None
        return value

    def list(self, record_type: str) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT record_id, payload FROM records WHERE record_type=? ORDER BY rowid",
                (record_type,),
            ).fetchall()
        records: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                value = json.loads(row["payload"])
            except (json.JSONDecodeError, TypeError):
                self.corrupt_records.add((record_type, row["record_id"]))
                continue
            if not isinstance(value, dict):
                self.corrupt_records.add((record_type, row["record_id"]))
                continue
            records[row["record_id"]] = value
        return records

    def delete(self, record_type: str, record_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM records WHERE record_type=? AND record_id=?",
                (record_type, record_id),
            )

    def clear(self, record_type: str) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM records WHERE record_type=?", (record_type,))

    def append_audit_event(self, value: Any) -> None:
        payload = self._json(value)
        with self._lock, self._connection:
            self._connection.execute("INSERT INTO audit_events(payload) VALUES(?)", (payload,))

    def recent_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(5000, limit))
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload FROM audit_events ORDER BY sequence DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def clear_audit_events(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM audit_events")
            self._connection.execute("DELETE FROM sqlite_sequence WHERE name='audit_events'")

    def close(self) -> None:
        with self._lock:
            self._connection.close()


state_store = SQLiteDocumentStore(settings.STATE_DB_PATH)
