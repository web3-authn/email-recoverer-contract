# Email Recoverer Contract

Per-account contract that enables email-based recovery for a NEAR account (e.g. `bob.near`) using:

- A ZK‑Email path via a global ZK verifier contract.
- A TEE/DKIM path via a global EmailDKIMVerifier contract.

The contract stores only **hashed recovery emails** and policy state; it never stores raw email addresses.

---

## 1. Hashed Email Format (`HashedEmail`)

The contract uses `HashedEmail = Vec<u8>` for configured recovery emails:

- A recovery email is represented on-chain as:

  ```text
  hashed_email = SHA256( canonical_email || "|" || account_id )
  ```

- `canonical_email`:
  - Lowercase the entire address (`local@domain`), e.g.:
    - `"Pta <Bob.Gmail@Example.com>"` → `"bob.gmail@example.com"`.
  - Strip display names; use only the bare address `local@domain`.
  - Trim surrounding whitespace.

- `account_id`:
  - The NEAR account ID that owns the per-user recoverer, e.g. `"bob.near"`.

- Concatenation:
  - Take `canonical_email` as UTF‑8 bytes.
  - Append a single ASCII pipe: `b'|'`.
  - Append `account_id` as UTF‑8 bytes.
  - Compute `SHA256` over that byte sequence; the 32‑byte digest is stored as `HashedEmail`.
  - The contract enforces that `HashedEmail` values are exactly 32 bytes.

**Implications**

- The same email used for two different accounts produces different hashes:

  ```text
  H("bob@gmail.com" || "|" || "bob.near") != H("bob@gmail.com" || "|" || "alice.near")
  ```

- ZK‑Email and DKIM verifiers are responsible for deriving the same `hashed_email` from the attested `from` address and `account_id`, so the contract can do a simple equality check against the configured `recovery_emails`.

---

## 2. Recovery Policy (`RecoveryPolicy`)

`RecoveryPolicy` is stored on-chain and controls how many recent, verified emails are required to trigger recovery:

```rust
pub struct RecoveryPolicy {
    pub min_required_emails: u8,
    pub max_age_ms: u64,
}
```

- `min_required_emails`:
  - `1` → single-email recovery (1‑of‑M).
  - `N` → N‑of‑M social recovery (e.g. 2‑of‑3).
  - `M` is `recovery_emails.len()` (unique configured emails).

- `max_age_ms`:
  - Maximum allowed age for each email verification (in milliseconds).
  - Only verifications where `now_ms - verified_emails[email].timestamp <= max_age_ms` count as “recent”.

**Validation and bounds**

- The contract enforces `1 <= min_required_emails <= recovery_emails.len()`.
- The contract enforces a maximum of 20 configured recovery emails to bound worst-case state and gas.

The owner can update the policy via `set_policy(policy: RecoveryPolicy)`. When `set_recovery_emails` is called, any previous `verified_emails` entries are cleared.

---

## 3. How Recovery Policy Is Enforced

The contract keeps:

- `recovery_emails: BTreeSet<HashedEmail>` (unique set)
- `verified_emails: BTreeMap<HashedEmail, VerifiedRecoveryIntent>`

where:

```rust
pub struct VerifiedRecoveryIntent {
    pub timestamp: u64,
    pub new_public_key: PublicKey,
}
```

When a ZK‑Email or DKIM verification succeeds for a `hashed_email` and yields a `new_public_key`:

1. The contract checks that:
   - The attested `account_id` equals `env::current_account_id()`.
   - `hashed_email` is present in `recovery_emails`.
2. It sets:

   ```rust
   verified_emails[hashed_email] = VerifiedRecoveryIntent {
       timestamp: email_timestamp_ms,
       new_public_key: new_public_key,
   };
   ```

3. It counts how many configured `recovery_emails` have a recent verification **for the same `new_public_key`**:

   ```rust
   recent = number of emails e in recovery_emails
            where verified_emails[e].new_public_key == new_public_key
              and now_ms - verified_emails[e].timestamp <= max_age_ms
   ```

4. If `recent >= min_required_emails`, it proceeds to add the new key:
   - Calls `add_full_access_key_internal(new_public_key)`, which will eventually be wired to a real NEAR `add_key` action.
   - Otherwise, it leaves `verified_emails` updated but does not yet add the key.

This gives you:

- 1‑of‑M recovery (single recovery email), or
- N‑of‑M social recovery (multiple independent recovery emails must verify within a time window).

---

## 4. DKIM Path Fees & Refunds (Relayer Semantics)

The DKIM/Outlayer path is designed so that a relayer attaches at least **0.01 NEAR** per verification request, while Outlayer may consume only a fraction of that. Any unused portion is handled inside the DKIM verifier contract.

- **Inputs**
  - Relayer calls `user.near::verify_email_onchain_and_recover(email_blob, expected_hashed_email, expected_new_public_key)` and attaches at least `0.01 NEAR` (matching the DKIM verifier’s `MIN_DEPOSIT`).

- **Flow**
  1. `EmailRecoverer::verify_email_onchain_and_recover`:
     - Forwards the full attached deposit to the global `EmailDkimVerifier` via `with_attached_deposit`, along with the relayer’s account ID as `payer_account_id`.
  2. `EmailDkimVerifier::request_email_verification`:
     - Uses `MIN_DEPOSIT` (currently 0.01 NEAR) as the DKIM/Outlayer budget.
     - Forwards only the portion needed (e.g. ~0.001 NEAR) to Outlayer.
     - Refunds any unused portion of the attached deposit directly to `payer_account_id`.
  3. `EmailRecoverer::on_verify_email_onchain_result`:
     - Receives `VerificationResult { verified, account_id, new_public_key, email_timestamp_ms }`.
     - Applies all normal checks (account binding, hashed email membership, `RecoveryPolicy`) and, if satisfied, adds the new full-access key.

- **Net effect**
  - The relayer’s net spend per DKIM recovery attempt is `actual Outlayer cost ≤ MIN_DEPOSIT` (typically a small fraction of 0.01 NEAR), with refunds handled by the DKIM verifier contract.
