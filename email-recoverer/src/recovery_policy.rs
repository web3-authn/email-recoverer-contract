use std::collections::BTreeSet;

use near_sdk::{env, log, near, Promise, PublicKey};

use crate::{EmailRecoverer, EmailRecovererExt, HashedEmail, HASHED_EMAIL_LEN};

/// Hard cap to keep worst-case state size and per-verification gas bounded.
pub const MAX_RECOVERY_EMAILS: usize = 20;

/// Allow some clock skew between the email timestamp and on-chain block time.
pub(crate) const ALLOWED_EMAIL_TIMESTAMP_SKEW_MS: u64 = 5 * 60 * 1000;

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct RecoveryPolicy {
    pub min_required_emails: u8,
    pub max_age_ms: u64,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            min_required_emails: 1,
            // 30 minutes by default
            max_age_ms: 30 * 60 * 1000,
        }
    }
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub(crate) struct VerifiedRecoveryIntent {
    pub(crate) timestamp: u64,
    pub(crate) new_public_key: PublicKey,
}

#[near]
impl EmailRecoverer {
    pub fn get_policy(&self) -> RecoveryPolicy {
        self.policy.clone()
    }

    pub fn set_policy(&mut self, policy: RecoveryPolicy) {
        self.assert_owner();
        Self::assert_valid_config(&policy, &self.recovery_emails);
        self.policy = policy;
    }

    /// Reset an in-progress recovery attempt without changing recovery emails.
    pub fn clear_verified_emails(&mut self) {
        self.assert_owner();
        self.verified_emails.clear();
        self.pending_recovery_intents.clear();
    }

    /// Return the set of recovery emails that currently satisfy the
    /// recency window (`max_age_ms`) in the configured policy.
    pub fn get_recent_verified_emails(&self) -> Vec<HashedEmail> {
        let now_ms = env::block_timestamp_ms();
        let mut recent = Vec::new();
        for email in &self.recovery_emails {
            if let Some(intent) = self.verified_emails.get(email) {
                if intent.timestamp > now_ms.saturating_add(ALLOWED_EMAIL_TIMESTAMP_SKEW_MS) {
                    continue;
                }
                if now_ms.saturating_sub(intent.timestamp) <= self.policy.max_age_ms {
                    recent.push(email.clone());
                }
            }
        }
        recent
    }
}

impl EmailRecoverer {
    pub(crate) fn assert_valid_config(policy: &RecoveryPolicy, recovery_emails: &BTreeSet<HashedEmail>) {
        assert!(
            policy.min_required_emails > 0,
            "min_required_emails must be >= 1"
        );
        assert!(policy.max_age_ms > 0, "max_age_ms must be > 0");
        assert!(
            !recovery_emails.is_empty(),
            "recovery_emails must not be empty"
        );
        assert!(
            recovery_emails.len() <= MAX_RECOVERY_EMAILS,
            "recovery_emails too large; max is {}",
            MAX_RECOVERY_EMAILS
        );
        for email in recovery_emails {
            assert!(
                email.len() == HASHED_EMAIL_LEN,
                "HashedEmail must be {} bytes",
                HASHED_EMAIL_LEN
            );
        }
        assert!(
            policy.min_required_emails as usize <= recovery_emails.len(),
            "min_required_emails must be <= number of configured recovery emails"
        );
    }

    pub(crate) fn set_pending_recovery_intent(
        &mut self,
        hashed_email: &HashedEmail,
        new_public_key: &PublicKey,
    ) {
        assert!(
            hashed_email.len() == HASHED_EMAIL_LEN,
            "HashedEmail must be {} bytes",
            HASHED_EMAIL_LEN
        );
        assert!(
            self.is_configured_recovery_email(hashed_email),
            "HashedEmail is not in configured recovery_emails"
        );
        self.pending_recovery_intents
            .insert(hashed_email.clone(), new_public_key.clone());
    }

    pub(crate) fn consume_pending_recovery_intent(
        &mut self,
        hashed_email: &HashedEmail,
        new_public_key: &PublicKey,
    ) -> bool {
        match self.pending_recovery_intents.get(hashed_email) {
            Some(expected_pk) if expected_pk == new_public_key => {
                self.pending_recovery_intents.remove(hashed_email);
                true
            }
            _ => false,
        }
    }

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
                // Reject unreasonably future-dated timestamps (clock skew allowance).
                if intent.timestamp > now_ms.saturating_add(ALLOWED_EMAIL_TIMESTAMP_SKEW_MS) {
                    continue;
                }

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
    ) -> Result<bool, String> {
        let now_ms = env::block_timestamp_ms();

        // Enforce that the email timestamp is plausibly close to on-chain time:
        // - not too far in the future (skew window)
        // - not too old (outside policy max_age_ms)
        if timestamp_ms > now_ms.saturating_add(ALLOWED_EMAIL_TIMESTAMP_SKEW_MS) {
            return Err(format!(
                "rejecting future email timestamp {} (now {})",
                timestamp_ms, now_ms
            ));
        }

        if now_ms.saturating_sub(timestamp_ms) > self.policy.max_age_ms {
            return Err(format!(
                "rejecting stale email timestamp {} (now {}, max_age_ms {})",
                timestamp_ms, now_ms, self.policy.max_age_ms
            ));
        }

        let new_public_key: PublicKey = new_public_key
            .parse()
            .map_err(|_err| "failed to parse new_public_key".to_string())?;

        self.verified_emails.insert(
            hashed_email,
            VerifiedRecoveryIntent {
                timestamp: timestamp_ms,
                new_public_key: new_public_key.clone(),
            },
        );

        if !self.is_recovery_policy_satisfied(now_ms, &new_public_key) {
            log!(
                "Recovery policy not yet satisfied; recent verified emails insufficient (min_required = {})",
                self.policy.min_required_emails
            );
            return Ok(false);
        }

        // Clear state after a successful recovery attempt so previous verified
        // intents cannot be reused for subsequent recoveries.
        self.verified_emails.clear();
        self.add_full_access_key_internal(new_public_key);
        Ok(true)
    }

    /// Internal helper to actually add a full‑access key to this account.
    pub(crate) fn add_full_access_key_internal(&self, public_key: PublicKey) {
        log!("add_full_access_key_internal: adding full-access key for current account");
        let _ = Promise::new(env::current_account_id()).add_full_access_key(public_key);
    }

    /// Testing/debug helper: manually set the verified intent for a given
    /// hashed email. This is not called from production code.
    #[cfg(not(target_arch = "wasm32"))]
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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn debug_is_recovery_policy_satisfied_for_testing(
        &self,
        now_ms: u64,
        new_public_key: PublicKey,
    ) -> bool {
        self.is_recovery_policy_satisfied(now_ms, &new_public_key)
    }
}
