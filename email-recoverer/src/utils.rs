use near_sdk::{env, log, Promise, PublicKey};
use crate::{EmailRecoverer, HashedEmail, VerifiedRecoveryIntent};

impl EmailRecoverer {
    /// Compute whether the recovery policy is satisfied based on
    /// `verified_emails` and `policy`, scoped to a specific `new_public_key`.
    pub(crate) fn is_recovery_policy_satisfied(
        &self,
        now_ms: u64,
        new_public_key: &PublicKey,
    ) -> bool {
        let mut num_recent = 0u8;
        for email in &self.recovery_emails {
            if let Some(intent) = self.verified_emails.get(email) {
                if &intent.new_public_key == new_public_key
                    && now_ms.saturating_sub(intent.timestamp) <= self.policy.max_age_ms
                {
                    num_recent = num_recent.saturating_add(1);
                }
            }
        }
        num_recent >= self.policy.min_required_emails
    }

    /// Mark a given hashed email as verified at the given timestamp and,
    /// if the policy is satisfied, add the provided key as a full-access key.
    pub(crate) fn mark_verified_and_maybe_recover(
        &mut self,
        hashed_email: HashedEmail,
        new_public_key: String,
        timestamp_ms: u64,
    ) {
        let new_public_key: PublicKey = match new_public_key.parse() {
            Ok(pk) => pk,
            Err(_err) => {
                log!("mark_verified_and_maybe_recover: failed to parse new_public_key");
                return;
            }
        };

        self.verified_emails.insert(
            hashed_email,
            VerifiedRecoveryIntent {
                timestamp: timestamp_ms,
                new_public_key: new_public_key.clone(),
            },
        );

        if !self.is_recovery_policy_satisfied(timestamp_ms, &new_public_key) {
            log!(
                "Recovery policy not yet satisfied; recent verified emails insufficient (min_required = {})",
                self.policy.min_required_emails
            );
            return;
        }

        self.add_full_access_key_internal(new_public_key);
    }

    /// Canonicalize an email-like string into a bare address:
    /// - Trim whitespace
    /// - If it contains a display name form like "Name <user@example.com>",
    ///   extract the part inside angle brackets.
    /// - Lowercase the result.
    pub(crate) fn canonicalize_email(raw: &str) -> String {
        let trimmed = raw.trim();

        // Handle common "Name <user@example.com>" pattern.
        if let Some(start) = trimmed.find('<') {
            if let Some(end_rel) = trimmed[start + 1..].find('>') {
                let end = start + 1 + end_rel;
                return trimmed[start + 1..end].trim().to_ascii_lowercase();
            }
        }

        trimmed.to_ascii_lowercase()
    }

    /// Check whether the given hashed email is present in the configured
    /// recovery emails set.
    pub(crate) fn is_configured_recovery_email(&self, hashed_email: &HashedEmail) -> bool {
        self.recovery_emails.iter().any(|e| e == hashed_email)
    }

    /// Hash a canonical email address using the current account ID as salt:
    /// H(email || "|" || account_id). Accepts either a bare address
    /// ("alice@example.com") or a display-name form ("Alice <alice@example.com>").
    pub(crate) fn hash_from_email_for_current_account(&self, email_address: &str) -> HashedEmail {
        let canonical = Self::canonicalize_email(email_address);
        let mut data = canonical.into_bytes();
        data.push(b'|');
        data.extend(env::current_account_id().as_bytes());

        env::sha256(&data)
    }

    /// Internal helper to actually add a full‑access key to this account.
    pub(crate) fn add_full_access_key_internal(&self, public_key: PublicKey) {
        log!("add_full_access_key_internal: adding full-access key for current account");
        let _ = Promise::new(env::current_account_id())
            .add_full_access_key(public_key);
    }

    /// Testing/debug helper: manually set the verified intent for a given
    /// hashed email. This is not called from production code.
    pub fn debug_set_verified_email_for_testing(
        &mut self,
        email: HashedEmail,
        new_public_key: PublicKey,
        timestamp_ms: u64,
    ) {
        self.verified_emails.insert(
            email,
            VerifiedRecoveryIntent {
                timestamp: timestamp_ms,
                new_public_key,
            },
        );
    }

    /// Testing/debug helper: check whether the policy is satisfied for the
    /// given `new_public_key` at `now_ms`.
    pub fn debug_is_recovery_policy_satisfied_for_testing(
        &self,
        now_ms: u64,
        new_public_key: PublicKey,
    ) -> bool {
        self.is_recovery_policy_satisfied(now_ms, &new_public_key)
    }
}
