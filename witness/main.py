"""Independent witness service.

Persists batch id, byte length and SHA-256 of every accepted original and
issues an Ed25519 receipt. Same batch + filename + content reuses the stored
receipt; a different content under the same key is rejected. The witness
keeps its own SQLite database in its own persistent volume and never trusts
digests computed by the archiver: it hashes every upload itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import gc
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from common.receipt import (
    build_envelope,
    load_private_key,
    public_key_fingerprint,
)
from witness.db import Database

MAX_UPLOAD_BYTES = int(os.getenv("WITNESS_MAX_UPLOAD_BYTES", 2 * 1024 * 1024))
DB_PATH = os.getenv("WITNESS_DB", "/data/witness.db")
KEY_PATH = os.getenv("WITNESS_KEY", "/keys/witness_ed25519.pem")

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

db: Database
private_key = None


def validate_key(batch_id: str, filename: str) -> None:
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    if not KEY_RE.fullmatch(filename) or filename in (".", ".."):
        raise HTTPException(400, "invalid filename")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, private_key
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = Database(DB_PATH)
    private_key = load_private_key(KEY_PATH)
    # Grab the running uvicorn server so the test-only shutdown endpoint can
    # ask it to exit gracefully (the CI sandbox blocks the kill syscall).
    import uvicorn.server
    for obj in gc.get_objects():
        if isinstance(obj, uvicorn.server.Server):
            app.state.server = obj
            break
    yield
    db.close()


app = FastAPI(title="Independent Witness Service", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "service": "witness",
            "public_key_fingerprint": public_key_fingerprint(
                private_key.public_key())}


def _row_to_envelope(row) -> dict:
    envelope = json.loads(row["payload"])
    envelope["signature"] = row["signature"]
    return envelope


@app.post("/receipts")
async def accept_original(batch_id: str = Form(...),
                          filename: str = Form(...),
                          file: UploadFile = File(...)):
    """Accept an original, persist its identity and issue/reuse a receipt."""
    validate_key(batch_id, filename)

    # Stream to disk-bounded memory while independently hashing and measuring.
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413,
                f"file exceeds witness limit of {MAX_UPLOAD_BYTES} bytes",
            )
        hasher.update(chunk)
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(400, "empty file is not accepted")
    digest = hasher.hexdigest()

    existing = db.get(batch_id, filename)
    if existing is not None:
        if existing["sha256"] == digest and existing["length"] == total:
            # Same batch, same file, same content: reuse the stored receipt.
            return JSONResponse(
                status_code=200,
                content={"reused": True,
                         "receipt": _row_to_envelope(existing)},
            )
        # Same key, different content: refuse to overwrite history.
        raise HTTPException(
            409,
            {
                "error": "content_conflict",
                "message": "a different original is already witnessed under "
                           "this batch_id/filename",
                "existing": {"length": existing["length"],
                             "sha256": existing["sha256"]},
                "submitted": {"length": total, "sha256": digest},
            },
        )

    envelope = build_envelope(private_key, batch_id, filename, total, digest)
    payload = {k: envelope[k] for k in (
        "version", "batch_id", "filename", "length", "sha256",
        "issued_at", "algorithm", "public_key_fingerprint")}
    try:
        db.insert({
            "batch_id": batch_id,
            "filename": filename,
            "length": total,
            "sha256": digest,
            "issued_at": envelope["issued_at"],
            "payload": json.dumps(payload, sort_keys=True),
            "signature": envelope["signature"],
        })
    except sqlite3.IntegrityError:
        # A concurrent first submission won the UNIQUE(batch_id, filename)
        # race. Re-read and answer reuse vs. conflict instead of erroring.
        raced = db.get(batch_id, filename)
        if raced is not None \
                and raced["sha256"] == digest and raced["length"] == total:
            return JSONResponse(
                status_code=200,
                content={"reused": True,
                         "receipt": _row_to_envelope(raced)})
        raise HTTPException(
            409,
            {"error": "content_conflict",
             "message": "a different original is already witnessed under "
                        "this batch_id/filename"},
        )
    return JSONResponse(status_code=201,
                        content={"reused": False, "receipt": envelope})


@app.get("/receipts/{batch_id}/{filename}")
def get_receipt(batch_id: str, filename: str):
    validate_key(batch_id, filename)
    row = db.get(batch_id, filename)
    if row is None:
        raise HTTPException(404, "no receipt for this batch_id/filename")
    return {"receipt": _row_to_envelope(row)}


@app.get("/batches/{batch_id}")
def get_batch(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    rows = db.list_batch(batch_id)
    return {
        "batch_id": batch_id,
        "count": len(rows),
        "items": [
            {"filename": r["filename"], "length": r["length"],
             "sha256": r["sha256"], "issued_at": r["issued_at"],
             "receipt": _row_to_envelope(r)}
            for r in rows
        ],
    }


@app.get("/receipts")
def list_receipts():
    """The complete list of receipts the witness has ever issued.

    Each item carries the full signed envelope so a verifier needs only this
    one endpoint to check every receipt (plus the locally stored originals).
    """
    rows = db.list_all()
    return {
        "count": len(rows),
        "items": [
            {"batch_id": r["batch_id"], "filename": r["filename"],
             "length": r["length"], "sha256": r["sha256"],
             "issued_at": r["issued_at"], "receipt": _row_to_envelope(r)}
            for r in rows
        ],
    }


@app.post("/__selftest_shutdown")
def selftest_shutdown():
    """Test-only graceful shutdown (no signal permissions in CI sandbox)."""
    def _stop():
        app.state.server.should_exit = True
    import threading
    threading.Thread(target=_stop, daemon=True).start()
    return {"shutting_down": True}
