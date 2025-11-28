# Web3Authn Contract Management Commands
# List all available commands
default:
    @echo "Available commands:"
    @echo "  just deploy                - Deploy email-recoverer global contract (NEP-0591)"
    @echo "  just upgrade               - Upgrade email-recoverer global contract (NEP-0591)"
    @echo ""
    @echo "Make sure to set up your .env file before running any commands."

# Deploy the email-recoverer contract as a NEP-0591 global contract (reproducible WASM)
deploy-email-recoverer:
    @echo "Deploying email-recoverer global contract (NEP-0591) to production..."
    sh ./email-recoverer/scripts/deploy-global.sh

# Upgrade the email-recoverer NEP-0591 global contract code (reproducible WASM)
upgrade-email-recoverer:
    @echo "Upgrading email-recoverer global contract (NEP-0591) in production..."
    sh ./email-recoverer/scripts/upgrade-global.sh

