"""Research data archiving web service.

The archiver uploads originals to an independent witness, verifies every
Ed25519 receipt against a key ring derived from a single pinned anchor
public key (later signing keys are reached only through the witness's
signed rotation chain), and only reports success when the local original,
the catalog entry and the verified receipt are all present.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import gc
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from archive.db import Database
from archive.trust import build_ring, current_fingerprint, verify_receipt
from archive.witness_client import (
    WitnessClient,
    WitnessConflict,
    WitnessUnreachable,
)
from common.receipt import (
    load_public_key,
    public_key_fingerprint,
)

MAX_UPLOAD_BYTES = int(os.getenv("ARCHIVE_MAX_UPLOAD_BYTES", 2 * 1024 * 1024))
DB_PATH = os.getenv("ARCHIVE_DB", "/data/archive.db")
STORAGE_DIR = Path(os.getenv("ARCHIVE_STORAGE", "/data/originals"))
PUBKEY_PATH = os.getenv("ARCHIVE_PUBLIC_KEY",
                        "/app/keys/witness_ed25519.pub.pem")
WITNESS_URL = os.getenv("WITNESS_URL", "http://witness:8001")
CRASH_MARKER = Path(os.getenv("ARCHIVE_CRASH_MARKER",
                              "/data/crash_after_witness.flag"))

KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

db: Database
witness: WitnessClient
anchor_key = None
# Verified fingerprint -> public key ring, covering the anchor key and every
# key reachable through the signed rotation chain. Guarded by _ring_lock.
key_ring: dict = {}
ring_proofs: list = []
ring_error: str | None = None
_ring_lock = threading.Lock()
# Only one chain sync against the witness at a time; concurrent callers wait
# and then reuse the freshly installed ring instead of fanning out requests.
# Re-entrant because ring_for_fingerprint() calls sync_rotation_chain().
_sync_lock = threading.RLock()
templates = Jinja2Templates(directory=os.path.join(
    os.path.dirname(__file__), "templates"))

# One lock per batch: concurrent retries of the same batch are serialized so
# the same original can never be archived twice.
_batch_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def batch_lock(batch_id: str) -> threading.Lock:
    with _locks_guard:
        lock = _batch_locks.get(batch_id)
        if lock is None:
            lock = threading.Lock()
            _batch_locks[batch_id] = lock
        return lock


def validate_keys(batch_id: str, filename: str) -> None:
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    if not KEY_RE.fullmatch(filename) or filename in (".", ".."):
        raise HTTPException(400, "invalid filename")


def storage_path(batch_id: str, filename: str) -> Path:
    return STORAGE_DIR / batch_id / filename


def sha256_file(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    length = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(64 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            length += len(chunk)
    return hasher.hexdigest(), length


def row_to_dict(row) -> dict:
    data = dict(row)
    if data.get("receipt"):
        data["receipt"] = json.loads(data["receipt"])
    return data


def batch_status(batch_id: str) -> dict:
    rows = [row_to_dict(r) for r in db.list_batch(batch_id)]
    registered = [r for r in rows if r["status"] == "registered"]
    ok = bool(rows) and len(registered) == len(rows)
    # Success requires local originals AND catalog AND verified receipts.
    complete = False
    if ok:
        complete = all(
            storage_path(batch_id, r["filename"]).is_file()
            and check_catalog_receipt(r)[0] for r in registered
        )
    return {
        "batch_id": batch_id,
        "status": "complete" if complete else (
            "pending" if any(r["status"] == "pending" for r in rows)
            else "incomplete"),
        "file_count": len(rows),
        "registered_count": len(registered),
        "files": rows,
    }


def check_catalog_receipt(file_row: dict) -> tuple[bool, str | None]:
    """Verify a cataloged receipt against the verified key ring.

    A receipt signed by any key reachable from the fixed anchor through the
    rotation chain is accepted — including receipts that were issued before a
    rotation and registered only afterwards (late returns).
    """
    if not file_row.get("receipt"):
        return False, "no receipt in catalog"
    expected = {
        "batch_id": file_row["batch_id"],
        "filename": file_row["filename"],
        "length": file_row["length"],
        "sha256": file_row["sha256"],
    }
    with _ring_lock:
        ring = dict(key_ring)
    return verify_receipt(ring, file_row["receipt"], expected)


def ring_snapshot() -> tuple[dict, list, str | None]:
    with _ring_lock:
        return dict(key_ring), list(ring_proofs), ring_error


def ring_for_fingerprint(fingerprint: str) -> tuple[dict, str | None]:
    """Return a ring containing ``fingerprint``, syncing from the witness.

    The local ring is normally current, but an upload overlapping with a
    rotation can be signed by a key the archive has not synced yet. Rather
    than rejecting a perfectly valid receipt, the chain is re-fetched and
    re-derived from the fixed anchor (self-reported keys still never enter
    the ring without a valid signed proof).
    """
    with _ring_lock:
        if fingerprint in key_ring:
            return dict(key_ring), None
    # Serialize witness round-trips; another thread may finish the sync first.
    with _sync_lock:
        with _ring_lock:
            if fingerprint in key_ring:
                return dict(key_ring), None
        try:
            sync_rotation_chain()
        except HTTPException as exc:
            with _ring_lock:
                return dict(key_ring), str(exc.detail)
        except WitnessUnreachable as exc:
            with _ring_lock:
                return dict(key_ring), f"witness unreachable: {exc}"
    with _ring_lock:
        if fingerprint not in key_ring:
            return dict(key_ring), (
                "signing key is not in the verified rotation chain "
                f"(fingerprint={fingerprint})")
        return dict(key_ring), None


def load_local_chain() -> None:
    """Re-verify the rotation chain stored in the local catalog from scratch.

    On a cold start nothing on disk is trusted: the pinned anchor key is the
    only starting point, and every persisted proof must validate against the
    preceding key before its public key enters the ring.
    """
    global key_ring, ring_proofs, ring_error
    proofs = [json.loads(row["proof"]) for row in db.list_rotations()]
    ring, err = build_ring(anchor_key, proofs)
    with _ring_lock:
        key_ring = ring
        ring_proofs = proofs
        ring_error = err
    if err:
        print(f"[startup] local rotation chain failed verification: {err}")


def sync_rotation_chain() -> dict:
    """Fetch the witness rotation chain and re-derive the ring from anchor.

    Never installs a chain that cannot be traced back to the fixed public
    key; on failure the previously verified ring stays in place.
    """
    global key_ring, ring_proofs, ring_error
    with _sync_lock:
        data = witness.list_rotations()
        proofs = data.get("rotations", [])
        if data.get("anchor_public_key_fingerprint") and \
                data["anchor_public_key_fingerprint"] != \
                public_key_fingerprint(anchor_key):
            raise HTTPException(
                502,
                "witness rotation chain anchor does not match the fixed "
                "bootstrap public key; refusing to trust witness keys",
            )
        ring, err = build_ring(anchor_key, proofs)
        if err:
            with _ring_lock:
                ring_error = err
            raise HTTPException(
                502, f"rotation chain verification failed: {err}")
        with _ring_lock:
            key_ring = ring
            ring_proofs = proofs
            ring_error = None
        # Persist only what we independently verified, so a cold start with
        # the witness offline still has the full ring.
        db.replace_rotations(proofs)
        return {"rotations": len(proofs),
                "current_public_key_fingerprint":
                    current_fingerprint(ring, proofs),
                "ring_size": len(ring)}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, witness, anchor_key
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = Database(DB_PATH)
    witness = WitnessClient(WITNESS_URL)
    # The one and only pinned piece of key material, mounted with the image.
    anchor_key = load_public_key(PUBKEY_PATH)
    # Cold start: first rebuild the ring from the locally persisted,
    # independently verified chain (works with the witness offline), then try
    # to extend it from the witness. Late old-key receipts stay verifiable
    # because every historical key remains in the ring.
    load_local_chain()
    try:
        sync_rotation_chain()
    except (HTTPException, WitnessUnreachable, RuntimeError) as exc:
        print(f"[startup] rotation chain sync deferred: {exc}")
    # Grab the running uvicorn server for the test-only shutdown endpoint.
    import uvicorn.server
    for obj in gc.get_objects():
        if isinstance(obj, uvicorn.server.Server):
            app.state.server = obj
            break
    # After a restart, find and continue every batch left pending instead of
    # re-submitting anything blindly. Also recovers originals written before a
    # crash that happened ahead of local catalog registration.
    try:
        reconcile_pending()
    except Exception as exc:  # pragma: no cover - startup must not crash
        print(f"[startup] reconcile deferred: {exc}")
    yield
    db.close()


app = FastAPI(title="Research Data Archive", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def page_index(request: Request):
    batches = [dict(r) for r in db.list_batches()]
    return templates.TemplateResponse(
        request,
        "index.html",
        {"batches": batches, "witness_url": WITNESS_URL},
    )


@app.get("/batches/{batch_id}", response_class=HTMLResponse)
def page_batch(request: Request, batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    return templates.TemplateResponse(
        request,
        "batch.html",
        {"batch_id": batch_id},
    )


@app.get("/verify", response_class=HTMLResponse)
def page_verify(request: Request):
    return templates.TemplateResponse(request, "verify.html", {})


@app.get("/rotations", response_class=HTMLResponse)
def page_rotations(request: Request):
    ring, proofs, err = ring_snapshot()
    return templates.TemplateResponse(
        request,
        "rotations.html",
        {"anchor_fingerprint": public_key_fingerprint(anchor_key),
         "ring": ring, "proofs": proofs, "chain_error": err},
    )


# --------------------------------------------------------------------------- #
# Upload / download
# --------------------------------------------------------------------------- #
@app.post("/api/batches/{batch_id}/files")
def upload_file(batch_id: str,
                filename: str = Form(...),
                file: UploadFile = File(...)):
    # Sync endpoint on purpose: FastAPI runs it in a threadpool, so blocking
    # file IO and the synchronous witness call do not stall the event loop
    # and uploads of different batches truly run concurrently.
    validate_keys(batch_id, filename)

    # Read with the 2 MiB hard limit.
    hasher = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    src = file.file  # underlying sync spooled file object
    while True:
        chunk = src.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                413,
                f"file exceeds archive limit of {MAX_UPLOAD_BYTES} bytes",
            )
        hasher.update(chunk)
        chunks.append(chunk)
    if total == 0:
        raise HTTPException(400, "empty file is not accepted")
    content = b"".join(chunks)
    digest = hasher.hexdigest()

    with batch_lock(batch_id):
        existing = db.get_file(batch_id, filename)
        if existing is not None:
            if existing["status"] == "registered" \
                    and existing["sha256"] == digest:
                # Idempotent re-upload of identical content: nothing to do.
                return {"result": "already_registered",
                        "batch": batch_status(batch_id)}
            if existing["sha256"] != digest:
                raise HTTPException(
                    409,
                    "different content already exists for this "
                    "batch_id/filename; the witnessed original is preserved",
                )
            # Same content still pending: fall through to reconciliation.

        target = storage_path(batch_id, filename)
        # Never overwrite a stored original, even on failure/cleanup paths.
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            # Unique temp name: concurrent uploads must not share a .part file.
            tmp = target.with_name(
                f".{target.name}.{uuid.uuid4().hex}.part")
            with open(tmp, "wb") as fh:
                fh.write(content)
            os.replace(tmp, target)

        try:
            response = witness.submit(batch_id, filename, content, digest)
        except WitnessUnreachable as exc:
            # Not yet known to be accepted: mark PENDING for verification;
            # must never be treated as "not accepted" and re-submitted blind.
            db.upsert_pending(batch_id, filename, total, digest,
                              f"witness unreachable: {exc}")
            return JSONResponse(
                status_code=202,
                content={"result": "pending",
                         "reason": "witness_unreachable",
                         "batch": batch_status(batch_id)},
            )
        except WitnessConflict as exc:
            db.upsert_pending(batch_id, filename, total, digest,
                              f"content conflict: {exc}")
            raise HTTPException(409, exc.detail)

        # Demo fault: the process dies after the witness accepted the original
        # but before the local catalog records the receipt. A marker file in
        # the persistent volume guarantees the crash happens only once.
        if CRASH_MARKER.exists():
            try:
                CRASH_MARKER.unlink()
            except OSError:
                pass
            print("[fault-injection] crashing after witness acceptance, "
                  "before local registration", flush=True)
            os._exit(1)

        envelope = response["receipt"]
        ring, ring_err = ring_for_fingerprint(
            envelope.get("public_key_fingerprint", ""))
        if ring_err:
            db.upsert_pending(batch_id, filename, total, digest,
                              f"receipt verification failed: {ring_err}")
            raise HTTPException(502, f"receipt verification failed: {ring_err}")
        ok, err = verify_receipt(
            ring, envelope,
            expected={"batch_id": batch_id, "filename": filename,
                      "length": total, "sha256": digest},
        )
        if not ok:
            db.upsert_pending(batch_id, filename, total, digest,
                              f"receipt verification failed: {err}")
            raise HTTPException(502, f"receipt verification failed: {err}")

        db.mark_registered(batch_id, filename, total, digest,
                           json.dumps(envelope, sort_keys=True))
        return {"result": "registered", "reused": response.get("reused"),
                "batch": batch_status(batch_id)}


@app.get("/api/batches")
def list_batches():
    return {"batches": [dict(r) for r in db.list_batches()]}


@app.get("/api/batches/{batch_id}")
def get_batch(batch_id: str):
    if not KEY_RE.fullmatch(batch_id):
        raise HTTPException(400, "invalid batch_id")
    rows = db.list_batch(batch_id)
    if not rows:
        raise HTTPException(404, "batch not found in local catalog")
    return batch_status(batch_id)


@app.get("/api/batches/{batch_id}/download/{filename}")
def download(batch_id: str, filename: str):
    validate_keys(batch_id, filename)
    row = db.get_file(batch_id, filename)
    if row is None or row["status"] != "registered":
        raise HTTPException(404, "file is not registered; download closed")
    path = storage_path(batch_id, filename)
    if not path.is_file():
        raise HTTPException(410, "registered original is missing on disk")
    digest, length = sha256_file(path)
    if digest != row["sha256"] or length != row["length"]:
        raise HTTPException(409, "stored original fails integrity check; "
                                 "download refused")
    receipt = json.loads(row["receipt"])
    with _ring_lock:
        ring = dict(key_ring)
    ok, err = verify_receipt(
        ring, receipt,
        expected={"batch_id": batch_id, "filename": filename,
                  "length": length, "sha256": digest},
    )
    if not ok:
        raise HTTPException(409, f"receipt invalid: {err}")
    return FileResponse(path, filename=filename,
                        media_type="application/octet-stream")


# --------------------------------------------------------------------------- #
# Reconciliation after disconnect / restart
# --------------------------------------------------------------------------- #
def discover_orphans() -> list[dict]:
    """Find stored originals that have no catalog row.

    This covers the crash window after the witness accepted an original but
    before local registration: the file is on disk, the catalog has nothing.
    """
    orphans: list[dict] = []
    if not STORAGE_DIR.is_dir():
        return orphans
    for batch_dir in sorted(STORAGE_DIR.iterdir()):
        if not batch_dir.is_dir() or not KEY_RE.fullmatch(batch_dir.name):
            continue
        batch_id = batch_dir.name
        for path in sorted(batch_dir.iterdir()):
            if not path.is_file() or path.name.endswith(".part") \
                    or not KEY_RE.fullmatch(path.name):
                continue
            if db.get_file(batch_id, path.name) is not None:
                continue  # catalog already knows this file
            digest, length = sha256_file(path)
            orphans.append({"batch_id": batch_id, "filename": path.name,
                            "length": length, "sha256": digest})
    return orphans


def reconcile_one(target: dict) -> dict:
    """Check one pending/orphan target against the witness and continue it.

    ``target`` always carries batch_id, filename, length, sha256. The witness
    is queried first: an existing receipt is reused, so a disconnect can never
    cause a blind re-submission.
    """
    batch_id, filename = target["batch_id"], target["filename"]
    result = {"batch_id": batch_id, "filename": filename}

    # Make sure the catalog has a pending row so the work is visible even if
    # the witness is currently unreachable.
    if db.get_file(batch_id, filename) is None:
        db.upsert_pending(batch_id, filename, target["length"],
                          target["sha256"], "recovered orphan: pending")

    try:
        info = witness.get_batch(batch_id)
    except WitnessUnreachable as exc:
        # Still unknown: keep pending, show "to be verified", never resubmit.
        db.set_error(batch_id, filename, f"witness unreachable: {exc}")
        result.update(state="pending", reason="witness_unreachable")
        return result

    match = next((it for it in info["items"]
                  if it["filename"] == filename), None)
    if match is None:
        # Witness explicitly says it never accepted this file. It is safe to
        # (re)submit exactly the locally stored original.
        path = storage_path(batch_id, filename)
        if not path.is_file():
            db.set_error(batch_id, filename,
                         "witness 404 and local original missing")
            result.update(state="pending",
                          reason="witness_404_and_local_missing")
            return result
        content = path.read_bytes()
        try:
            response = witness.submit(batch_id, filename, content,
                                      target["sha256"])
        except WitnessUnreachable as exc:
            db.set_error(batch_id, filename, f"witness unreachable: {exc}")
            result.update(state="pending", reason="witness_unreachable")
            return result
        envelope = response["receipt"]
    else:
        envelope = match["receipt"]

    ring, ring_err = ring_for_fingerprint(
        envelope.get("public_key_fingerprint", ""))
    if ring_err:
        db.set_error(batch_id, filename,
                     f"receipt verification failed: {ring_err}")
        result.update(state="pending", reason=f"bad_receipt: {ring_err}")
        return result
    ok, err = verify_receipt(
        ring, envelope,
        expected={"batch_id": batch_id, "filename": filename,
                  "length": target["length"], "sha256": target["sha256"]},
    )
    if not ok:
        db.set_error(batch_id, filename, f"receipt verification failed: {err}")
        result.update(state="pending", reason=f"bad_receipt: {err}")
        return result

    db.mark_registered(batch_id, filename, target["length"],
                       target["sha256"],
                       json.dumps(envelope, sort_keys=True))
    result.update(state="registered",
                  reused=match is not None)
    return result


def reconcile_pending() -> dict:
    # Merge catalog-pending rows with on-disk orphans (crash before register),
    # keyed by (batch_id, filename) so nothing is processed twice.
    targets: dict[tuple[str, str], dict] = {}
    for row in db.list_pending():
        targets[(row["batch_id"], row["filename"])] = dict(row)
    for orphan in discover_orphans():
        targets.setdefault((orphan["batch_id"], orphan["filename"]), orphan)

    results = []
    for target in targets.values():
        with batch_lock(target["batch_id"]):
            # Re-read inside the lock: a concurrent upload may have finished.
            current = db.get_file(target["batch_id"], target["filename"])
            if current is not None and current["status"] == "registered":
                results.append({"batch_id": target["batch_id"],
                                "filename": target["filename"],
                                "state": "already_registered"})
                continue
            results.append(reconcile_one(target))
    return {"checked": len(results), "results": results}


@app.post("/api/reconcile")
def reconcile_endpoint():
    return reconcile_pending()


# --------------------------------------------------------------------------- #
# Independent verification against the witness's issued-receipt list
# --------------------------------------------------------------------------- #
@app.get("/api/verify")
def verify_against_witness():
    try:
        listing = witness.list_receipts()
    except WitnessUnreachable as exc:
        # Witness unreachable: verification must NEVER be reported as passed.
        return JSONResponse(
            status_code=503,
            content={"passed": False, "witness_reachable": False,
                     "error": f"witness unreachable: {exc}", "batches": []},
        )

    batches: dict[str, dict] = {}
    for item in listing["items"]:
        batch_id, filename = item["batch_id"], item["filename"]
        problems: list[dict] = []

        # The full signed envelope travels with the listing; verify it
        # against the key that actually signed it, looked up in the ring
        # derived from the fixed anchor via the rotation chain.
        envelope_resp = item.get("receipt")
        sig_ok, sig_err = (False, "no receipt in witness listing")
        if envelope_resp is not None:
            ring, ring_err = ring_for_fingerprint(
                envelope_resp.get("public_key_fingerprint", ""))
            if ring_err:
                sig_ok, sig_err = False, ring_err
            else:
                sig_ok, sig_err = verify_receipt(ring, envelope_resp)
        if not sig_ok:
            problems.append({"type": "receipt_signature_invalid",
                             "detail": sig_err})

        path = storage_path(batch_id, filename)
        if not path.is_file():
            problems.append({"type": "missing_original",
                             "detail": "witnessed file absent locally"})
            local_digest = local_length = None
        else:
            local_digest, local_length = sha256_file(path)
            if local_digest != item["sha256"] \
                    or local_length != item["length"]:
                problems.append({
                    "type": "tampered_original",
                    "detail": "local SHA-256/length differs from receipt",
                    "local_sha256": local_digest,
                    "receipt_sha256": item["sha256"],
                })

        catalog = db.get_file(batch_id, filename)
        if catalog is None:
            problems.append({"type": "catalog_missing",
                             "detail": "not registered in local catalog"})
        elif catalog["status"] != "registered":
            problems.append({"type": "catalog_pending",
                             "detail": f"catalog status is {catalog['status']}"})

        batches.setdefault(batch_id, {"batch_id": batch_id, "files": [],
                                      "passed": True})
        batches[batch_id]["files"].append({
            "filename": filename,
            "receipt": {"length": item["length"], "sha256": item["sha256"],
                        "issued_at": item["issued_at"]},
            "local": {"present": path.is_file(),
                      "length": local_length, "sha256": local_digest},
            "catalogued": catalog is not None,
            "receipt_signature_ok": sig_ok,
            "problems": problems,
        })
        if problems:
            batches[batch_id]["passed"] = False

    # An empty witness list is reported explicitly, not silently "passed":
    # there is nothing to verify, and callers must not read it as a clean bill.
    return {
        "passed": all(b["passed"] for b in batches.values())
        and bool(batches),
        "empty": not batches,
        "witness_reachable": True,
        "receipt_count": listing["count"],
        "batches": sorted(batches.values(), key=lambda b: b["batch_id"]),
    }


# --------------------------------------------------------------------------- #
# Signing-key rotation (archive-side, verifies every proof from the anchor)
# --------------------------------------------------------------------------- #
@app.get("/api/rotations")
def rotations_status():
    """Locally verified rotation state and the derived signing-key ring."""
    ring, proofs, err = ring_snapshot()
    return {
        "anchor_public_key_fingerprint":
            public_key_fingerprint(anchor_key),
        "current_public_key_fingerprint":
            current_fingerprint(ring, proofs) if ring else None,
        "rotation_count": len(proofs),
        "ring_fingerprints": sorted(ring.keys()),
        "chain_ok": err is None,
        "chain_error": err,
        "rotations": proofs,
    }


@app.get("/api/rotations/{rotation_id}")
def rotation_result(rotation_id: str):
    """Return a rotation order's result, syncing the chain from the witness.

    A lost HTTP response is therefore harmless: re-querying the same order id
    returns the original rotation instead of triggering a second one.
    """
    if not KEY_RE.fullmatch(rotation_id):
        raise HTTPException(400, "invalid rotation_id")
    local = db.get_rotation(rotation_id)
    try:
        witness_answer = witness.get_rotation(rotation_id)
    except WitnessUnreachable as exc:
        if local is None:
            raise HTTPException(
                503, f"witness unreachable and no local result: {exc}")
        return {"found": True, "source": "local_verified_chain",
                "rotation": json.loads(local["proof"])}
    if not witness_answer.get("rotated"):
        if local is not None:
            return {"found": True, "source": "local_verified_chain",
                    "rotation": json.loads(local["proof"])}
        raise HTTPException(404, "no rotation with this rotation_id")
    # The witness answered: re-verify the whole chain from the anchor before
    # exposing the result as trusted.
    sync_rotation_chain()
    local = db.get_rotation(rotation_id)
    if local is None:
        raise HTTPException(502, "witness reported a rotation that failed "
                                 "local chain verification")
    return {"found": True, "source": "witness_verified_chain",
            "rotation": json.loads(local["proof"])}


@app.post("/api/rotations")
def submit_rotation(rotation_id: str = Form(...)):
    """Submit a rotation order, then verify the new proof from the anchor.

    The rotation_id is generated and shown by the web page. Retrying the same
    id after a lost response returns the original result; concurrent distinct
    orders are serialized inside the witness and only one succeeds at a time.
    """
    if not KEY_RE.fullmatch(rotation_id):
        raise HTTPException(400, "invalid rotation_id")

    # Idempotency first: if we already verified this order, return its proof.
    local = db.get_rotation(rotation_id)
    if local is not None:
        ring, proofs, err = ring_snapshot()
        return {"rotated": False, "reused": True,
                "rotation": json.loads(local["proof"]),
                "current_public_key_fingerprint":
                    current_fingerprint(ring, proofs),
                "chain_ok": err is None}

    try:
        answer = witness.rotate(rotation_id)
    except WitnessUnreachable as exc:
        raise HTTPException(503, f"witness unreachable: {exc}")
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))

    # Do not trust the witness's self-reported new key: re-walk the entire
    # chain starting at the fixed anchor. A bad rotation is never installed.
    sync_info = sync_rotation_chain()
    local = db.get_rotation(rotation_id)
    if local is None:
        raise HTTPException(502, "rotation proof failed anchor verification")
    ring, proofs, err = ring_snapshot()
    return {
        "rotated": answer.get("rotated", False),
        "reused": answer.get("reused", False),
        "rotation": json.loads(local["proof"]),
        "current_public_key_fingerprint":
            current_fingerprint(ring, proofs),
        "chain_ok": err is None,
        "ring_fingerprints": sorted(ring.keys()),
        "sync": sync_info,
    }


# --------------------------------------------------------------------------- #
# Fault injection for the disconnect demo
# --------------------------------------------------------------------------- #
@app.post("/api/admin/arm-crash")
def arm_crash():
    CRASH_MARKER.parent.mkdir(parents=True, exist_ok=True)
    CRASH_MARKER.touch()
    return {"armed": True, "marker": str(CRASH_MARKER)}


@app.post("/__selftest_shutdown")
def selftest_shutdown():
    """Test-only graceful shutdown (no signal permissions in CI sandbox)."""
    def _stop():
        app.state.server.should_exit = True
    threading.Thread(target=_stop, daemon=True).start()
    return {"shutting_down": True}
