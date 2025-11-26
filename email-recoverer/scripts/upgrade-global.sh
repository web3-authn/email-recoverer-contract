#!/bin/bash
set -euo pipefail

# Upgrade the email-recoverer NEP-0591 Global Contract code by
# rebuilding the reproducible WASM and re-deploying it to the same
# global contract account ID.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONTRACT_DIR="$REPO_ROOT/email-recoverer"

source "$CONTRACT_DIR/.env"

if [[ -z "${CONTRACT_ID:-}" ]]; then
  echo "CONTRACT_ID is not set in .env" >&2
  exit 1
fi

cd "$REPO_ROOT"

cargo near build reproducible-wasm \
  --manifest-path "$CONTRACT_DIR/Cargo.toml" \
  --out-dir target/near-repro

WASM_PATH="target/near-repro/email_recoverer_factory.wasm"

if [[ ! -f "$WASM_PATH" ]]; then
  echo "WASM file not found at $WASM_PATH" >&2
  exit 1
fi

near contract deploy-as-global \
  use-file "$WASM_PATH" \
  as-global-account-id "$CONTRACT_ID" \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key "$DEPLOYER_PRIVATE_KEY" \
  send
