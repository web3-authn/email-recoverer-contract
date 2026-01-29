#!/bin/bash
set -euo pipefail

# Create a random dev account on testnet and send its full
# remaining balance to cyan-loong.testnet, then delete the
# dev account. Useful for quickly topping up the operator
# account from faucet-funded dev accounts.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

source "$CONTRACT_DIR/.env"

NETWORK="${NEAR_NETWORK_ID:-testnet}"
BENEFICIARY_ACCOUNT="cyan-loong.testnet"
# BENEFICIARY_ACCOUNT="w3a-email-recoverer-v1.testnet"

TIMESTAMP="$(date +%s)"
DEV_ACCOUNT_ID="w3a-dev-${TIMESTAMP}.${NETWORK}"

echo "Creating dev account: ${DEV_ACCOUNT_ID} on network: ${NETWORK}"

cd "$CONTRACT_DIR"

cargo near create-dev-account \
  use-specific-account-id "${DEV_ACCOUNT_ID}" \
  autogenerate-new-keypair save-to-legacy-keychain \
  network-config "${NETWORK}" \
  create

echo "Deleting dev account ${DEV_ACCOUNT_ID} and sending its balance to ${BENEFICIARY_ACCOUNT}"

near account delete-account "${DEV_ACCOUNT_ID}" \
  beneficiary "${BENEFICIARY_ACCOUNT}" \
  network-config "${NETWORK}" \
  sign-with-keychain \
  send
