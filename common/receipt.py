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
ROTATION_PROOF_TYPE = "witness_key_rotation"
ROTATION_PROOF_VERSION = 1


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


# --------------------------------------------------------------------------- #
# Key serialization helpers (key rotation)
# --------------------------------------------------------------------------- #
def public_key_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def private_key_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_public_key_bytes(raw: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("material is not an Ed25519 public key")
    return key


# --------------------------------------------------------------------------- #
# Signed key-rotation proofs
#
# A rotation proof states that the holder of ``old_public_key`` certified a
# fresh ``new_public_key`` under a unique order id. It is signed by the OLD
# private key. Chaining these proofs starts at the deployment's fixed public
# key, so a verifier that only ever pinned that first key can derive every
# later signing key without trusting self-reported key material.
# --------------------------------------------------------------------------- #
def rotation_proof_payload(rotation_id: str, old_fingerprint: str,
                           new_fingerprint: str, new_public_pem: str,
                           issued_at: str | None = None) -> dict:
    return {
        "type": ROTATION_PROOF_TYPE,
        "version": ROTATION_PROOF_VERSION,
        "rotation_id": rotation_id,
        "old_public_key_fingerprint": old_fingerprint,
        "new_public_key_fingerprint": new_fingerprint,
        "new_public_key_pem": new_public_pem,
        "issued_at": issued_at
        or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def build_rotation_proof(old_private_key: Ed25519PrivateKey,
                         rotation_id: str,
                         new_public_key: Ed25519PublicKey,
                         issued_at: str | None = None) -> dict:
    old_fp = public_key_fingerprint(old_private_key.public_key())
    new_fp = public_key_fingerprint(new_public_key)
    payload = rotation_proof_payload(
        rotation_id, old_fp, new_fp, public_key_pem(new_public_key),
        issued_at)
    return {
        **payload,
        "algorithm": "Ed25519",
        "signature": sign_payload(old_private_key, payload),
    }


def verify_rotation_proof(proof: dict,
                          old_public_key: Ed25519PublicKey
                          ) -> tuple[bool, str | None,
                                     Ed25519PublicKey | None]:
    """Verify one rotation proof against the key it claims to rotate from.

    Returns ``(ok, error, new_public_key)``. On success the embedded new public
    key is returned so callers can walk the chain.
    """
    required = {"type", "version", "rotation_id",
                "old_public_key_fingerprint", "new_public_key_fingerprint",
                "new_public_key_pem", "issued_at", "algorithm", "signature"}
    missing = required - set(proof)
    if missing:
        return False, f"rotation proof missing fields: {sorted(missing)}", None
    if proof["type"] != ROTATION_PROOF_TYPE:
        return False, "rotation proof has wrong type", None
    if proof["algorithm"] != "Ed25519":
        return False, "unsupported rotation proof algorithm", None
    if proof["old_public_key_fingerprint"] != \
            public_key_fingerprint(old_public_key):
        return False, "old key fingerprint does not match chain", None
    payload = {k: proof[k] for k in (
        "type", "version", "rotation_id", "old_public_key_fingerprint",
        "new_public_key_fingerprint", "new_public_key_pem", "issued_at")}
    if not verify_payload(old_public_key, payload, proof["signature"]):
        return False, "rotation proof signature verification failed", None
    try:
        new_key = load_public_key_bytes(
            proof["new_public_key_pem"].encode("ascii"))
    except (ValueError, TypeError) as exc:
        return False, f"embedded new public key is invalid: {exc}", None
    if public_key_fingerprint(new_key) != proof["new_public_key_fingerprint"]:
        return False, "embedded key does not match its fingerprint", None
    return True, None, new_key
