# Web3Authn Contract Management Commands
# List all available commands
default:
    @echo "Available commands:"
    @echo "  just deploy      - Deploy contract to production"
    @echo "  just deploy-dev  - Deploy contract to development"
    @echo "  just upgrade     - Upgrade contract in production"
    @echo "  just upgrade-dev - Upgrade contract in development"
    @echo ""
    @echo "Make sure to set up your .env file before running any commands."

# Deploy the email-recoverer contract to production (reproducible WASM)
deploy-email-recoverer:
    @echo "Deploying email-recoverer contract to production..."
    sh ./email-recoverer/scripts/deploy.sh

deploy-dev-email-recoverer:
    @echo "Deploying email-recoverer contract to production..."
    sh ./email-recoverer/scripts/deploy-dev.sh

upgrade-email-recoverer:
    @echo "Upgrading email-recoverer contract to production..."
    sh ./email-recoverer/scripts/upgrade.sh

upgrade-dev-email-recoverer:
    @echo "Upgrading email-recoverer contract to production..."
    sh ./email-recoverer/scripts/upgrade-dev.sh
