#!/bin/bash
set -euo pipefail

# Deploy the email-recoverer contract as a reusable code host
# to a subaccount of the main Web3Authn contract, e.g.:
#   email-recoverer.w3a-v1.testnet
#
# Frontends can then fetch this account's WASM via RPC (`view_code`)
# and let users deploy it to their own accounts.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONTRACT_DIR="$REPO_ROOT/email-recoverer"

source "$CONTRACT_DIR/.env"

cd "$REPO_ROOT/email-recoverer"

cargo near deploy build-reproducible-wasm "$CONTRACT_ID" \
  with-init-call new json-args '{
    "zk_email_verifier": "zk-email-verifier-v1.testnet",
    "email_dkim_verifier": "email-dkim-verifier-v1.testnet",
    "policy": null,
    "recovery_emails": []
  }' \
  prepaid-gas '80.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config "$NEAR_NETWORK_ID" \
  sign-with-plaintext-private-key \
  --signer-public-key "$DEPLOYER_PUBLIC_KEY" \
  --signer-private-key "$DEPLOYER_PRIVATE_KEY" \
  send
