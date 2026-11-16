"""Independent witness service.

Persists batch id, byte length and SHA-256 of every accepted original and
issues an Ed25519 receipt. Same batch + filename + content reuses the stored
receipt; a different content under the same key is rejected. The witness
keeps its own SQLite database in its own persistent volume and never trusts
digests computed by the archiver: it hashes every upload itself.

Signing keys live in the witness volume and can be rotated through
``POST /rotations``. Every rotation produces a proof signed by the key being
retired; proofs form a chain back to the fixed bootstrap public key, and the
old private key is shredded only after the proof is durably committed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import gc
import sqlite3
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from common.receipt import (
    build_envelope,
    build_rotation_proof,
    public_key_fingerprint,
)
from witness.db import Database
from witness.keystore import KeyStore

MAX_UPLOAD_BYTES = int(os.getenv("WITNESS_MAX_UPLOAD_BYTES", 2 * 1024 * 1024))
DB_PATH = os.getenv("WITNESS_DB", "/data/witness.db")
# The bootstrap key ships in the image (read-only mount in compose) and
# anchors the very first trust relationship. On first start it is copied into
# the witness volume; all subsequent keys are generated there and never leave
# the witness container.
BOOTSTRAP_KEY_PATH = os.getenv("WITNESS_KEY",
                               "/app/keys/witness_ed25519.pem")
KEY_DIR = os.getenv("WITNESS_KEY_DIR", "/data/keys")

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

db: Database
key_store: KeyStore
private_key = None

# Serializes rotations against receipt signing so that once a rotation is
# committed no receipt can be signed with the retired key. Uploads only hold
# this lock for the few microseconds of signing, so service never stops.
rotation_lock = threading.Lock()


def validate_key(batch_id: str, filename: str) -> None:
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    if not KEY_RE.fullmatch(filename) or filename in (".", ".."):
        raise HTTPException(400, "invalid filename")


def _proof_row_to_dict(row) -> dict:
    return json.loads(row["proof"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, key_store, private_key
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = Database(DB_PATH)
    key_store = KeyStore(KEY_DIR, db, BOOTSTRAP_KEY_PATH)
    # Rebuild a consistent key state: copies in the bootstrap key on first
    # boot, shreds retired keys left behind by a crash, removes staging files.
    private_key = key_store.initialize()
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

    # Signing and the durable insert happen under the rotation lock: a key
    # switch cannot land in between, so post-rotation receipts always use the
    # new key and pre-switch receipts always keep the old one.
    with rotation_lock:
        envelope = build_envelope(private_key, batch_id, filename,
                                  total, digest)
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
                    and raced["sha256"] == digest \
                    and raced["length"] == total:
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


# --------------------------------------------------------------------------- #
# Signing-key rotation
# --------------------------------------------------------------------------- #
@app.get("/rotations")
def list_rotations():
    """The signed rotation chain plus the currently active fingerprint.

    A cold verifier walks this list starting from its pinned bootstrap public
    key: every proof is signed by the preceding key, so no self-reported key
    material ever has to be trusted.
    """
    rows = db.list_rotations()
    current = db.current_fingerprint()
    anchor = rows[0]["old_public_key_fingerprint"] if rows else current
    return {
        "count": len(rows),
        "anchor_public_key_fingerprint": anchor,
        "current_public_key_fingerprint": current,
        "rotations": [_proof_row_to_dict(r) for r in rows],
    }


@app.get("/rotations/{rotation_id}")
def get_rotation(rotation_id: str):
    if not KEY_RE.fullmatch(rotation_id):
        raise HTTPException(400, "invalid rotation_id")
    row = db.get_rotation(rotation_id)
    if row is None:
        raise HTTPException(404, "no rotation with this rotation_id")
    return {"rotated": True, "rotation": _proof_row_to_dict(row)}


@app.post("/rotations")
def rotate_signing_key(rotation_id: str = Form(...)):
    """Rotate the active Ed25519 signing key under a unique order id.

    The same rotation_id is idempotent: retries after a lost response return
    the original result instead of rotating a second time. Concurrent
    rotations are serialized and at most one can succeed.
    """
    if not KEY_RE.fullmatch(rotation_id):
        raise HTTPException(400, "invalid rotation_id")

    # Fast idempotent path without taking the lock.
    existing = db.get_rotation(rotation_id)
    if existing is not None:
        return JSONResponse(status_code=200, content={
            "rotated": False, "reused": True,
            "rotation": _proof_row_to_dict(existing),
            "current_public_key_fingerprint":
                db.current_fingerprint(),
        })

    with rotation_lock:
        # Re-check inside the lock: a concurrent request may have finished.
        existing = db.get_rotation(rotation_id)
        if existing is not None:
            return JSONResponse(status_code=200, content={
                "rotated": False, "reused": True,
                "rotation": _proof_row_to_dict(existing),
                "current_public_key_fingerprint":
                    db.current_fingerprint(),
            })

        old_key = key_store.current()
        old_fp = public_key_fingerprint(old_key.public_key())

        # 1) generate and persist the new key in the witness volume. A crash
        #    here leaves only an untracked .part/key file that startup removes.
        new_key, new_fp, new_pem = key_store.generate_new()

        # 2) the old key certifies the new one (proof chains to the anchor).
        proof = build_rotation_proof(old_key, rotation_id,
                                     new_key.public_key())

        # 3) one durable transaction: proof chain + active-key pointer.
        fields = {
            "rotation_id": rotation_id,
            "old_fp": old_fp,
            "new_fp": new_fp,
            "new_pem": new_pem,
            "issued_at": proof["issued_at"],
            "proof": json.dumps(proof, sort_keys=True),
        }
        try:
            db.commit_rotation(fields, new_fp)
        except sqlite3.IntegrityError:
            # Another process/container won the same rotation_id first.
            key_store.shred(new_fp)
            raced = db.get_rotation(rotation_id)
            if raced is not None:
                return JSONResponse(status_code=200, content={
                    "rotated": False, "reused": True,
                    "rotation": _proof_row_to_dict(raced),
                    "current_public_key_fingerprint":
                        db.current_fingerprint(),
                })
            raise HTTPException(500, "rotation storage conflict")
        except Exception:
            # Any other storage failure: the rotation never committed, so the
            # staged key must not linger (startup reconciliation would also
            # reap it, but do not rely on a restart).
            key_store.shred(new_fp)
            raise

        # 4) switch the in-process signer before anything else can sign.
        global private_key
        private_key = new_key

        # 5) only now remove the retired private key from persistent storage.
        key_store.shred(old_fp)

    return JSONResponse(status_code=201, content={
        "rotated": True, "reused": False, "rotation": proof,
        "current_public_key_fingerprint": new_fp,
    })


@app.post("/__selftest_shutdown")
def selftest_shutdown():
    """Test-only graceful shutdown (no signal permissions in CI sandbox)."""
    def _stop():
        app.state.server.should_exit = True
    import threading
    threading.Thread(target=_stop, daemon=True).start()
    return {"shutting_down": True}
