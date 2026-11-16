"""SQLite persistence for the independent witness service.

Each operation opens its own connection: with a single shared connection,
closing a read cursor rolls back any open write transaction on that same
connection. WAL mode keeps concurrent readers/writers working correctly.

The database also stores the key-rotation proof chain (one row per successful
rotation, each proof signed by the key it rotates away from) and a one-row
state table pointing at the currently active signing key. Rotation state and
proof are committed in one transaction, so a crash at any point leaves either
the old complete state or the new complete state behind.
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

CREATE TABLE IF NOT EXISTS key_rotations (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    rotation_id               TEXT NOT NULL UNIQUE,
    old_public_key_fingerprint TEXT NOT NULL,
    new_public_key_fingerprint TEXT NOT NULL,
    new_public_key_pem        TEXT NOT NULL,
    issued_at                 TEXT NOT NULL,
    proof                     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    current_fingerprint TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Database:
    def __init__(self, path: str):
        self._path = path
        with self.cursor() as cur:
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=10000")
            cur.executescript(SCHEMA)

    @contextmanager
    def cursor(self):
        conn = sqlite3.connect(self._path, timeout=15)
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

    # ------------------------------------------------------------------ #
    # Key rotation state
    # ------------------------------------------------------------------ #
    def current_fingerprint(self) -> str | None:
        with self.cursor() as cur:
            cur.execute("SELECT current_fingerprint FROM key_state WHERE id=1")
            row = cur.fetchone()
            return row["current_fingerprint"] if row else None

    def set_current_fingerprint(self, fingerprint: str) -> None:
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO key_state (id, current_fingerprint)
                   VALUES (1, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       current_fingerprint=excluded.current_fingerprint,
                       updated_at=datetime('now')""",
                (fingerprint,),
            )

    def get_rotation(self, rotation_id: str) -> sqlite3.Row | None:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM key_rotations WHERE rotation_id=?",
                (rotation_id,),
            )
            return cur.fetchone()

    def list_rotations(self) -> list[sqlite3.Row]:
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM key_rotations ORDER BY id ASC"
            )
            return cur.fetchall()

    def commit_rotation(self, fields: dict, new_fingerprint: str) -> None:
        """Atomically persist the signed proof AND switch the active key.

        A UNIQUE(rotation_id) collision raises sqlite3.IntegrityError so the
        caller can answer an idempotent retry instead of rotating twice.
        """
        with self.cursor() as cur:
            cur.execute(
                """INSERT INTO key_rotations
                   (rotation_id, old_public_key_fingerprint,
                    new_public_key_fingerprint, new_public_key_pem,
                    issued_at, proof)
                   VALUES (:rotation_id, :old_fp, :new_fp, :new_pem,
                           :issued_at, :proof)""",
                fields,
            )
            cur.execute(
                """INSERT INTO key_state (id, current_fingerprint)
                   VALUES (1, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       current_fingerprint=excluded.current_fingerprint,
                       updated_at=datetime('now')""",
                (new_fingerprint,),
            )

    def close(self) -> None:
        # Connections are per-operation; nothing persistent to close.
        return None
