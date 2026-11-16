"""Ed25519 receipt payload construction, signing and verification.

A receipt covers exactly what the independent witness persistently observed:
batch id, filename, byte length and SHA-256 digest. The canonical byte form
is deterministic JSON so any party holding the public key can re-verify.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECEIPT_VERSION = 1


def canonicalize(payload: dict) -> bytes:
    """Deterministic byte encoding of a receipt payload."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def make_payload(batch_id: str, filename: str, length: int, sha256: str,
                 issued_at: str | None = None) -> dict:
    return {
        "version": RECEIPT_VERSION,
        "batch_id": batch_id,
        "filename": filename,
        "length": int(length),
        "sha256": sha256,
        "issued_at": issued_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_public_key(fh.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def sign_payload(private_key: Ed25519PrivateKey, payload: dict) -> str:
    signature = private_key.sign(canonicalize(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_payload(public_key: Ed25519PublicKey, payload: dict,
                   signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, canonicalize(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def build_envelope(private_key: Ed25519PrivateKey, batch_id: str,
                   filename: str, length: int, sha256: str,
                   issued_at: str | None = None) -> dict:
    payload = make_payload(batch_id, filename, length, sha256, issued_at)
    return {
        **payload,
        "algorithm": "Ed25519",
        "signature": sign_payload(private_key, payload),
        "public_key_fingerprint": public_key_fingerprint(
            private_key.public_key()
        ),
    }


def verify_envelope(public_key: Ed25519PublicKey, envelope: dict,
                    expected: dict | None = None) -> tuple[bool, str | None]:
    """Verify an envelope's signature against the fixed public key.

    ``expected`` optionally pins batch_id/filename/length/sha256 so a receipt
    cannot be replayed against a different original.
    """
    required = {"version", "batch_id", "filename", "length", "sha256",
                "issued_at", "signature", "algorithm"}
    missing = required - set(envelope)
    if missing:
        return False, f"receipt missing fields: {sorted(missing)}"
    if envelope.get("algorithm") != "Ed25519":
        return False, "unsupported receipt algorithm"
    if envelope.get("public_key_fingerprint") and \
            envelope["public_key_fingerprint"] != \
            public_key_fingerprint(public_key):
        return False, "public key fingerprint mismatch"
    payload = {k: envelope[k] for k in (
        "version", "batch_id", "filename", "length", "sha256", "issued_at")}
    if not verify_payload(public_key, payload, envelope["signature"]):
        return False, "Ed25519 signature verification failed"
    if expected:
        for field in ("batch_id", "filename", "length", "sha256"):
            if field in expected and payload.get(field) != expected[field]:
                return False, f"receipt field {field} does not match original"
    return True, None
