"""SQLite persistence for the independent witness service.

Each operation opens its own connection: with a single shared connection,
closing a read cursor rolls back any open write transaction on that same
connection. WAL mode keeps concurrent readers/writers working correctly.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    length      INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    issued_at   TEXT NOT NULL,
    payload     TEXT NOT NULL,
    signature   TEXT NOT NULL,
    UNIQUE(batch_id, filename)
);
CREATE INDEX IF NOT EXISTS idx_receipts_batch ON receipts(batch_id);
"""


class Database:
    def __init__(self, path: str):
        self._path = path
        with self.cursor() as cur:
            cur.execute("PRAGMA journal_mode=WAL")
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

    def get(self, batch_id: str, filename: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM receipts WHERE batch_id=? AND filename=?",
                (batch_id, filename),
            )
            return cur.fetchone()

    def insert(self, fields: dict) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO receipts
                   (batch_id, filename, length, sha256, issued_at,
                    payload, signature)
                   VALUES (:batch_id, :filename, :length, :sha256,
                           :issued_at, :payload, :signature)""",
                fields,
            )

    def list_batch(self, batch_id: str) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM receipts WHERE batch_id=? ORDER BY filename",
                (batch_id,),
            )
            return cur.fetchall()

    def list_all(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM receipts ORDER BY batch_id, filename"
            )
            return cur.fetchall()

    def close(self) -> None:
        # Connections are per-operation; nothing persistent to close.
        return None
