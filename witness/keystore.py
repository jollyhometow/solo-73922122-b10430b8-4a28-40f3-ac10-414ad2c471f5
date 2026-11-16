"""On-disk private key management for the witness.

Private keys live only in the witness's own persistent volume
(``/data/keys`` by default). The bootstrap key shipped in the image is copied
into the volume on first start; every later key is generated in place.

Crash-safety contract used together with ``witness.db.Database``:

* a new key is first staged as a uniquely named ``.part`` file and atomically
  renamed to ``<fingerprint>.pem``;
* the signed rotation proof and the current-key pointer are committed in one
  SQLite transaction;
* the OLD private key is shredded only after that commit;
* on startup, staged ``.part`` files and unknown key files are removed, while
  retired keys that could not be shredded before a crash are shredded now.

At every instant the database's current fingerprint names a key file that
exists on disk, so the service can always restart into a signable state.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from common.receipt import (
    load_private_key,
    private_key_pem,
    public_key_fingerprint,
)


class KeyStore:
    def __init__(self, keys_dir: str, db, bootstrap_key_path: str):
        self._dir = Path(keys_dir)
        self._db = db
        self._bootstrap = Path(bootstrap_key_path)

    def _key_path(self, fingerprint: str) -> Path:
        return self._dir / f"{fingerprint}.pem"

    def load(self, fingerprint: str) -> Ed25519PrivateKey:
        return load_private_key(str(self._key_path(fingerprint)))

    def current_fingerprint(self) -> str:
        fingerprint = self._db.current_fingerprint()
        if fingerprint is None:
            raise RuntimeError("key store is not initialized")
        return fingerprint

    def current(self) -> Ed25519PrivateKey:
        return self.load(self.current_fingerprint())

    def initialize(self) -> Ed25519PrivateKey:
        """(Re)build a consistent key state on (re)start and return active key."""
        self._dir.mkdir(parents=True, exist_ok=True)

        current = self._db.current_fingerprint()
        if current is None:
            # First boot: anchor the volume to the image's bootstrap key.
            bootstrap_key = load_private_key(str(self._bootstrap))
            fingerprint = public_key_fingerprint(
                bootstrap_key.public_key())
            target = self._key_path(fingerprint)
            if not target.exists():
                self._write_atomic(target, private_key_pem(bootstrap_key))
            self._db.set_current_fingerprint(fingerprint)
            current = fingerprint

        self._reconcile_files()
        return self.load(current)

    def _known_fingerprints(self) -> set[str]:
        """Fingerprints referenced by DB state: current, old and new keys."""
        known: set[str] = set()
        current = self._db.current_fingerprint()
        if current:
            known.add(current)
        for row in self._db.list_rotations():
            known.add(row["old_public_key_fingerprint"])
            known.add(row["new_public_key_fingerprint"])
        return known

    def _reconcile_files(self) -> None:
        """Finish interrupted rotations after a restart.

        * staging ``.part`` files and uncommitted key files are removed;
        * retired keys (signed away by a committed rotation, no longer
          current) are shredded to completion.
        """
        known = self._known_fingerprints()
        current = self._db.current_fingerprint()
        retired = {
            row["old_public_key_fingerprint"]
            for row in self._db.list_rotations()
        }
        for path in sorted(self._dir.iterdir()):
            if not path.is_file():
                continue
            if path.suffix == ".part":
                self._unlink(path)
                continue
            fingerprint = path.stem
            if fingerprint not in known:
                # Staged before the rotation transaction committed: safe to
                # remove, the DB never pointed at this key.
                self._unlink(path)
            elif fingerprint in retired and fingerprint != current:
                # Committed rotation whose final shred did not complete.
                self.shred(fingerprint)

    def generate_new(self) -> tuple[Ed25519PrivateKey, str, str]:
        """Generate a fresh key, persist it, return (key, fingerprint, pem)."""
        new_key = Ed25519PrivateKey.generate()
        fingerprint = public_key_fingerprint(new_key.public_key())
        target = self._key_path(fingerprint)
        pem = private_key_pem(new_key)
        # A crash here leaves only a .part file, which startup cleanup removes.
        self._write_atomic(target, pem)
        return new_key, fingerprint, pem.decode("ascii")

    def shred(self, fingerprint: str) -> None:
        """Best-effort secure removal of a retired private key."""
        path = self._key_path(fingerprint)
        if not path.exists():
            return
        try:
            size = path.stat().st_size
            with open(path, "r+b") as fh:
                fh.seek(0)
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
        self._unlink(path)

    def _write_atomic(self, target: Path, data: bytes) -> None:
        tmp = target.with_name(f".{target.name}.{os.urandom(8).hex()}.part")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
            os.chmod(target, 0o600)
        except BaseException:
            self._unlink(tmp)
            raise

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
