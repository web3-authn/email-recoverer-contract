#!/bin/bash
set -euo pipefail

# Deploy the email-recoverer contract as a NEP-0591 Global Contract
# using a reproducible WASM build. This publishes the code once under
# a dedicated global contract account ID so that user accounts can
# attach it via `UseGlobalContractAction`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONTRACT_DIR="$REPO_ROOT/email-recoverer"

source "$CONTRACT_DIR/.env"

if [[ -z "${CONTRACT_ID:-}" ]]; then
  echo "CONTRACT_ID is not set in .env" >&2
  exit 1
fi

cd "$REPO_ROOT"

# Build reproducible WASM for the email-recoverer factory.
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
