#!/usr/bin/env bash
# Generate the witness Ed25519 signing keypair (PEM).
# The private key is given only to the witness image; the matching public key
# is the fixed verification key baked into the archiver image.
set -euo pipefail

KEY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/keys"
mkdir -p "$KEY_DIR"
PRIV="$KEY_DIR/witness_ed25519.pem"
PUB="$KEY_DIR/witness_ed25519.pub.pem"

if [[ -f "$PRIV" && -f "$PUB" ]]; then
  echo "keys already exist in $KEY_DIR — keeping them"
  exit 0
fi

openssl genpkey -algorithm Ed25519 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"
chmod 600 "$PRIV"
chmod 644 "$PUB"
echo "generated:"
ls -l "$PRIV" "$PUB"
