"""SQLite persistence for the archiver (the local catalog).

Each operation opens its own connection: with a single shared connection,
closing a read cursor rolls back any open write transaction on that same
connection. WAL mode keeps concurrent readers/writers working correctly.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id      TEXT NOT NULL,
    filename      TEXT NOT NULL,
    length        INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending','registered')),
    receipt       TEXT,
    last_error    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(batch_id, filename)
);
CREATE INDEX IF NOT EXISTS idx_files_batch ON files(batch_id);
"""


class Database:
    def __init__(self, path: str):
        self._path = path
        with self.cursor() as cur:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.executescript(SCHEMA)

    @contextmanager
    def cursor(self):
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def get_file(self, batch_id: str, filename: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM files WHERE batch_id=? AND filename=?",
                (batch_id, filename),
            )
            return cur.fetchone()

    def list_batch(self, batch_id: str) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM files WHERE batch_id=? ORDER BY filename",
                (batch_id,),
            )
            return cur.fetchall()

    def list_batches(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                """SELECT batch_id,
                          COUNT(*) AS file_count,
                          SUM(CASE WHEN status='registered' THEN 1 ELSE 0 END)
                              AS registered_count,
                          SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END)
                              AS pending_count,
                          MIN(created_at) AS first_seen
                   FROM files GROUP BY batch_id
                   ORDER BY MIN(created_at) DESC"""
            )
            return cur.fetchall()

    def list_pending(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM files WHERE status='pending' "
                "ORDER BY batch_id, filename"
            )
            return cur.fetchall()

    def upsert_pending(self, batch_id: str, filename: str,
                       length: int, sha256: str, error: str | None) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO files (batch_id, filename, length, sha256,
                                      status, last_error)
                   VALUES (?, ?, ?, ?, 'pending', ?)
                   ON CONFLICT(batch_id, filename) DO UPDATE SET
                       length=excluded.length, sha256=excluded.sha256,
                       last_error=excluded.last_error,
                       updated_at=datetime('now')""",
                (batch_id, filename, length, sha256, error),
            )

    def mark_registered(self, batch_id: str, filename: str,
                        length: int, sha256: str, receipt: str) -> None:
        # Upsert, not a bare UPDATE: a fresh upload may never have had a
        # pending row, and an UPDATE matching zero rows would silently drop
        # the registration.
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO files (batch_id, filename, length, sha256,
                                      status, receipt, last_error)
                   VALUES (?, ?, ?, ?, 'registered', ?, NULL)
                   ON CONFLICT(batch_id, filename) DO UPDATE SET
                       length=excluded.length, sha256=excluded.sha256,
                       status='registered', receipt=excluded.receipt,
                       last_error=NULL, updated_at=datetime('now')""",
                (batch_id, filename, length, sha256, receipt),
            )

    def set_error(self, batch_id: str, filename: str,
                  error: str) -> None:
        with self.cursor() as cur:
            cur.execute(
                """UPDATE files SET last_error=?,
                       updated_at=datetime('now')
                   WHERE batch_id=? AND filename=?""",
                (error, batch_id, filename),
            )

    def close(self) -> None:
        # Connections are per-operation; nothing persistent to close.
        return None
