"""Trust anchor and signing-key ring for the archiver.

The archive pins exactly one piece of key material: the deployment's fixed
bootstrap public key (mounted read-only with the image). Every later witness
signing key is *derived*, never taken on trust: the archive walks the signed
rotation chain it fetches from the witness, and each proof must be signed by
the preceding key. A witness that simply announces a new public key cannot
make the archive accept it.

The resulting ring maps every verified key fingerprint to its public key, so
receipts signed before a rotation (including late-returning ones) and receipts
signed after it are both verifiable.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from common.receipt import (
    public_key_fingerprint,
    verify_envelope,
    verify_rotation_proof,
)


class ChainError(RuntimeError):
    """The rotation chain cannot be traced back to the anchor key."""


def build_ring(anchor: Ed25519PublicKey,
               proofs: list[dict]) -> tuple[dict[str, Ed25519PublicKey],
                                            str | None]:
    """Derive the verified fingerprint -> public key ring.

    Returns ``(ring, error)``. On success ``error`` is ``None`` and the ring
    always contains at least the anchor key; on failure ``error`` explains
    which hop broke and the returned ring is partial and must not be used.
    """
    ring: dict[str, Ed25519PublicKey] = {}
    current = anchor
    ring[public_key_fingerprint(current)] = current
    seen_ids: set[str] = set()
    for index, proof in enumerate(proofs):
        rotation_id = proof.get("rotation_id", f"#{index}")
        if rotation_id in seen_ids:
            return ring, f"duplicate rotation_id {rotation_id} in chain"
        seen_ids.add(rotation_id)
        ok, err, new_key = verify_rotation_proof(proof, current)
        if not ok:
            return ring, f"rotation {rotation_id}: {err}"
        ring[public_key_fingerprint(new_key)] = new_key
        current = new_key
    return ring, None


def current_fingerprint(ring: dict[str, Ed25519PublicKey],
                        proofs: list[dict]) -> str:
    """The fingerprint of the newest key in a verified chain."""
    if not proofs:
        return next(iter(ring))
    return proofs[-1]["new_public_key_fingerprint"]


def verify_receipt(ring: dict[str, Ed25519PublicKey], envelope: dict,
                   expected: dict | None = None
                   ) -> tuple[bool, str | None]:
    """Verify a receipt using whatever verified key actually signed it."""
    fingerprint = envelope.get("public_key_fingerprint")
    if not fingerprint:
        return False, "receipt carries no public key fingerprint"
    signer = ring.get(fingerprint)
    if signer is None:
        return False, ("signing key is not in the verified rotation chain "
                       f"(fingerprint={fingerprint})")
    return verify_envelope(signer, envelope, expected)
