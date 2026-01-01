# Email Recoverer Global Contract

This workspace contains the `email-recoverer` smart contract and related verifier contracts used to enable **email-based recovery** for NEAR accounts.

At a high level:

- `email-recoverer` is a **per-account recovery contract** that is:
  - Published once as a **NEP‑0591 global contract** under a code-host account (e.g. `w3a-email-recoverer-v1.testnet`), and
  - Attached to individual user accounts (e.g. `alice.near`, `berp61-w3a-v1.testnet`) via `UseGlobalContract`, so each account gets its own state but shares the same code.
- Each user account that opts in:
  - Attaches the global `email-recoverer` code to their own account.
  - Calls `init_email_recovery(...)` on `<user>.near` to configure:
    - Which recovery emails are allowed (stored as hashed emails),
    - A `RecoveryPolicy` (1‑of‑M or N‑of‑M, with a time window).

Recovery flows are implemented by two companion global verifier contracts:

- `email-dkim-verifier` (DKIM / Outlayer path):
  - Verifies DKIM signatures over raw email (`message.raw`) via an Outlayer/TEE integration.
  - Parses the email subject/body to extract:
    - The target NEAR account (`account_id`),
    - The requested new key (`new_public_key`),
    - An email timestamp (`email_timestamp_ms`).
  - Returns a structured `VerificationResult` to the per-account `email-recoverer`, which:
    - Checks that `account_id` matches `env::current_account_id()`,
    - Checks that the `From:` address (hashed) is in the configured recovery emails,
    - Applies the `RecoveryPolicy` over recent verifications,
    - If satisfied, adds the new full-access key to `<user>.near`.

- `zk-email-verifier` (ZK‑Email path):
  - Verifies zk-SNARK proofs generated from recovery emails (e.g. using zk.email Circom circuits).
  - Proves that the email satisfies the recovery policy inputs (`from_address_hash`, `account_id`, `new_public_key`, etc.).
  - Returns public outputs to `email-recoverer`, which:
    - Checks `account_id == env::current_account_id()`,
    - Confirms `from_address_hash` is one of the configured recovery emails,
    - Applies the same `RecoveryPolicy` logic before adding the new key.

In practice:

- Deploys `email-recoverer` as a **global contract** (via `near contract deploy-as-global`) once per environment.
- Deploys the `email-dkim-verifier` and `zk-email-verifier` contracts as shared verifiers.
- For each user that opts in:
  - Attaches the global `email-recoverer` code to their account with `UseGlobalContract`,
  - Initializes it via `init_email_recovery(...)` with appropriate verifier account IDs and policy,
  - Updates recovery emails over time via `set_recovery_emails` and `set_policy`.

End-users never see the global contracts directly; they interact with their own account (`<user>.near`), while relayers and verifiers handle the DKIM/ZK proof generation and on-chain verification.***
