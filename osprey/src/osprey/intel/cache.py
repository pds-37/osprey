"""Persistent local cache for vulnerability intelligence feeds.

Assumptions and Limitations:
- Uses built-in SQLite stored in ~/.cache/osprey/intel_cache.db (or $OSPREY_CACHE_DIR).
- TTL default is 24 hours (86,400 seconds).
- In --offline mode, returns cached records indefinitely and prevents all outbound network requests.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Optional


class IntelCache:
    """SQLite-backed cache manager with TTL enforcement and offline support."""

    def __init__(self, cache_dir: Optional[Path] = None, ttl_seconds: float = 86400.0, offline: bool = False):
        if cache_dir is None:
            custom = os.environ.get("OSPREY_CACHE_DIR")
            if custom:
                cache_dir = Path(custom)
            else:
                cache_dir = Path.home() / ".cache" / "osprey"

        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self.offline = offline
        self.db_path = self.cache_dir / "intel_cache.db"
        self._init_db()

    def _init_db(self) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(self.db_path)) as conn, conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS intel_cache (
                        namespace TEXT,
                        cache_key TEXT,
                        data TEXT,
                        updated_at REAL,
                        PRIMARY KEY (namespace, cache_key)
                    )
                    """
                )
                conn.commit()
        except Exception:
            pass

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """Retrieve a cached entry if valid under TTL (or anytime in offline mode)."""
        try:
            with closing(sqlite3.connect(self.db_path)) as conn, conn:
                cursor = conn.execute(
                    "SELECT data, updated_at FROM intel_cache WHERE namespace = ? AND cache_key = ?",
                    (namespace, key),
                )
                row = cursor.fetchone()
                if not row:
                    return None

                data_str, updated_at = row
                age = time.time() - float(updated_at)

                if self.offline or age <= self.ttl_seconds:
                    return json.loads(data_str)
                return None
        except Exception:
            return None

    def set(self, namespace: str, key: str, value: Any) -> None:
        """Store or update an entry in the local cache."""
        try:
            data_str = json.dumps(value)
            now = time.time()
            with closing(sqlite3.connect(self.db_path)) as conn, conn:
                conn.execute(
                    """
                    INSERT INTO intel_cache (namespace, cache_key, data, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(namespace, cache_key) DO UPDATE SET
                        data = excluded.data,
                        updated_at = excluded.updated_at
                    """,
                    (namespace, key, data_str, now),
                )
                conn.commit()
        except Exception:
            pass

    def clear(self) -> None:
        """Purge all entries from the cache."""
        try:
            with closing(sqlite3.connect(self.db_path)) as conn, conn:
                conn.execute("DELETE FROM intel_cache")
                conn.commit()
        except Exception:
            pass
