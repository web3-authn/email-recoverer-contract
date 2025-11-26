#!/bin/bash
set -euo pipefail

# Upgrade the email-recoverer contract code
# using a non-reproducible WASM build (for development),
# without re-running initialization.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONTRACT_DIR="$REPO_ROOT/email-recoverer"

source "$CONTRACT_DIR/.env"

cd "$REPO_ROOT/email-recoverer"

cargo near deploy build-non-reproducible-wasm "$CONTRACT_ID" \
  without-init-call \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key \
  --signer-public-key "$DEPLOYER_PUBLIC_KEY" \
  --signer-private-key "$DEPLOYER_PRIVATE_KEY" \
  send


