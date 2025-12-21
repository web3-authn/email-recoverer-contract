use near_sdk::{
    env, near, ext_contract,
    PublicKey, AccountId, Promise, PromiseError
};
use std::collections::{BTreeMap, BTreeSet};
use serde_json::Value as JsonValue;

mod utils;
mod zk_email_verifier;
mod tee_outlayer_verifier;
mod onchain_public_verifier;

pub use crate::zk_email_verifier::{ProofInput, ZkEmailContext};
pub use crate::tee_outlayer_verifier::AeadContext;

/// Alias for a hashed email (e.g. H(email || salt)).
pub type HashedEmail = Vec<u8>;

/// SHA-256 output size in bytes.
pub const HASHED_EMAIL_LEN: usize = 32;

/// Hard cap to keep worst-case state size and per-verification gas bounded.
pub const MAX_RECOVERY_EMAILS: usize = 20;

pub(crate) const ALLOWED_EMAIL_TIMESTAMP_SKEW_MS: u64 = 5 * 60 * 1000;

#[near_sdk::near(serializers = [json, borsh])]
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

/// Result returned by the ZK‑Email and EmailDKIMVerifier contracts.
/// Mirrors the `VerificationResult` structs exposed by those verifier contracts.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: String,
    pub new_public_key: String,
    pub from_address: String,
    pub email_timestamp_ms: Option<u64>,
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
struct VerifiedRecoveryIntent {
    timestamp: u64,
    new_public_key: PublicKey,
}

/// Internal callbacks on this contract used for cross‑contract promises.
#[ext_contract(ext_self)]
pub trait EmailRecovererCallbacks {
    fn on_verify_zkemail_result(
        &mut self,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    );
    fn on_verify_email_onchain_result(
        &mut self,
        email_blob: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    );
    fn on_verify_encrypted_email_result(
        &mut self,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    );
}

/// Per‑account email‑based recovery contract deployed to `<user>.near`.
#[near(contract_state)]
pub struct EmailRecoverer {
    /// Configured recovery emails (hashed).
    recovery_emails: BTreeSet<HashedEmail>,
    /// Last successful verification intent per recovery email.
    verified_emails: BTreeMap<HashedEmail, VerifiedRecoveryIntent>,
    /// Pending expected recovery intents per email (defense-in-depth).
    pending_recovery_intents: BTreeMap<HashedEmail, PublicKey>,
    /// Recovery policy.
    policy: RecoveryPolicy,
    /// Global ZK‑Email verifier contract account ID.
    zk_email_verifier: AccountId,
    /// Global EmailDKIMVerifier contract account ID.
    email_dkim_verifier: AccountId,
}

impl Default for EmailRecoverer {
    fn default() -> Self {
        env::panic_str("EmailRecoverer::default is not supported; please call `init_email_recovery`")
    }
}

#[near]
impl EmailRecoverer {
    fn assert_valid_config(policy: &RecoveryPolicy, recovery_emails: &BTreeSet<HashedEmail>) {
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

    /// Initialize the per‑user recoverer for the current account.
    #[init(ignore_state)]
    pub fn init_email_recovery(
        zk_email_verifier: AccountId,
        email_dkim_verifier: AccountId,
        policy: Option<RecoveryPolicy>,
        recovery_emails: Vec<HashedEmail>,
    ) -> Self {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Only the account owner can initialize"
        );

        let recovery_emails: BTreeSet<HashedEmail> = recovery_emails.into_iter().collect();
        let policy = policy.unwrap_or_default();
        Self::assert_valid_config(&policy, &recovery_emails);

        Self {
            recovery_emails,
            verified_emails: BTreeMap::new(),
            pending_recovery_intents: BTreeMap::new(),
            policy,
            zk_email_verifier,
            email_dkim_verifier,
        }
    }

    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Only the contract owner can call this method"
        );
    }

    pub fn set_recovery_emails(&mut self, recovery_emails: Vec<HashedEmail>) {
        self.assert_owner();
        let recovery_emails: BTreeSet<HashedEmail> = recovery_emails.into_iter().collect();
        Self::assert_valid_config(&self.policy, &recovery_emails);
        self.recovery_emails = recovery_emails;
        // Reset timestamps when changing the set.
        self.verified_emails.clear();
        self.pending_recovery_intents.clear();
    }

    pub fn get_recovery_emails(&self) -> Vec<HashedEmail> {
        self.recovery_emails.iter().cloned().collect()
    }

    pub fn get_zk_email_verifier(&self) -> AccountId {
        self.zk_email_verifier.clone()
    }

    pub fn set_zk_email_verifier(&mut self, zk_email_verifier: AccountId) {
        self.assert_owner();
        self.zk_email_verifier = zk_email_verifier;
    }

    pub fn get_email_dkim_verifier(&self) -> AccountId {
        self.email_dkim_verifier.clone()
    }

    pub fn set_email_dkim_verifier(&mut self, email_dkim_verifier: AccountId) {
        self.assert_owner();
        self.email_dkim_verifier = email_dkim_verifier;
    }

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

    /// Verify proof with ZkEmailVerifier and recover if policy is satisfied.
    pub fn verify_zkemail_and_recover(
        &mut self,
        proof: ProofInput,
        public_inputs: Vec<String>,
        context: ZkEmailContext,
    ) -> Promise {
        let expected_hashed_email = self.hash_from_email_for_current_account(&context.from_email);
        let expected_pk: PublicKey = context
            .new_public_key
            .parse()
            .unwrap_or_else(|_| env::panic_str("verify_zkemail_and_recover: invalid new_public_key"));
        self.set_pending_recovery_intent(&expected_hashed_email, &expected_pk);
        zk_email_verifier::verify_zkemail_and_recover(
            &self.zk_email_verifier,
            proof,
            public_inputs,
            context,
        )
    }
    /// Callback after verify_zkemail_and_recover finishes.
    pub fn on_verify_zkemail_result(
        &mut self,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        zk_email_verifier::on_verify_zkemail_result(self, result)
    }

    /// TEE/encrypted path: ask the EmailDKIMVerifier to verify DKIM for the
    /// given encrypted email blob and recover the account
    ///
    /// @params `encrypted_email_blob`: forwarded to the DKIM verifier, then to Outlayer worker
    /// @params `aead_context`: used as AEAD associated data for decrypting email in worker:
    /// `{
    ///    account_id": "...",
    ///    network_id": "...",
    ///    payer_account_id": "..."
    /// }`
    #[payable]
    pub fn verify_encrypted_email_and_recover(
        &mut self,
        encrypted_email_blob: JsonValue,
        aead_context: AeadContext,
        expected_hashed_email: HashedEmail,
        expected_new_public_key: String,
    ) -> Promise {
        let expected_pk: PublicKey = expected_new_public_key.parse().unwrap_or_else(|_| {
            env::panic_str("verify_encrypted_email_and_recover: invalid expected_new_public_key")
        });
        self.set_pending_recovery_intent(&expected_hashed_email, &expected_pk);
        tee_outlayer_verifier::verify_encrypted_email_and_recover(
            &self.email_dkim_verifier,
            encrypted_email_blob,
            aead_context
        )
    }
    /// Callback after EmailDKIMVerifier finishes for encrypted emails.
    pub fn on_verify_encrypted_email_result(
        &mut self,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        tee_outlayer_verifier::on_verify_encrypted_email_result(self, result)
    }

    /// TEE/on-chain plaintext path: ask the EmailDKIMVerifier to verify DKIM
    /// for the given email blob and, if successful, potentially recover this
    /// account according to the configured policy.
    /// @deprecated Prefer `verify_encrypted_email_and_recover` (TEE encrypted path).
    #[payable]
    pub fn verify_email_onchain_and_recover(
        &mut self,
        email_blob: String,
        expected_hashed_email: HashedEmail,
        expected_new_public_key: String,
    ) -> Promise {
        let expected_pk: PublicKey = expected_new_public_key.parse().unwrap_or_else(|_| {
            env::panic_str("verify_email_onchain_and_recover: invalid expected_new_public_key")
        });
        self.set_pending_recovery_intent(&expected_hashed_email, &expected_pk);
        onchain_public_verifier::verify_email_onchain_and_recover(&self.email_dkim_verifier, email_blob)
    }
    /// Callback after EmailDKIMVerifier finishes for plaintext/on-chain emails.
    /// @deprecated Prefer `on_verify_encrypted_email_result` used by the encrypted TEE path.
    pub fn on_verify_email_onchain_result(
        &mut self,
        email_blob: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        onchain_public_verifier::on_verify_email_onchain_result(self, email_blob, result)
    }
}
