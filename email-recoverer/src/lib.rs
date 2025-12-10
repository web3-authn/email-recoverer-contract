use near_sdk::{
    env, near, ext_contract,
    AccountId, Promise, PromiseError
};
use std::collections::BTreeMap;
use serde_json::Value as JsonValue;

mod utils;
mod zk_email_verifier;
mod tee_outlayer_verifier;
mod onchain_public_verifier;

pub use crate::zk_email_verifier::ProofInput;

/// Alias for a hashed email (e.g. H(email || salt)).
pub type HashedEmail = Vec<u8>;

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
    recovery_emails: Vec<HashedEmail>,
    /// Last successful verification timestamp per recovery email.
    verified_timestamp: BTreeMap<HashedEmail, u64>,
    /// Recovery policy.
    policy: RecoveryPolicy,
    /// Global ZK‑Email verifier contract account ID.
    zk_email_verifier: AccountId,
    /// Global EmailDKIMVerifier contract account ID.
    email_dkim_verifier: AccountId,
}

impl Default for EmailRecoverer {
    fn default() -> Self {
        env::panic_str("EmailRecoverer::default is not supported; please call `new`")
    }
}

#[near]
impl EmailRecoverer {
    /// Initialize the per‑user recoverer for the current account.
    #[init(ignore_state)]
    pub fn new(
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

        Self {
            recovery_emails,
            verified_timestamp: BTreeMap::new(),
            policy: policy.unwrap_or_default(),
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
        self.recovery_emails = recovery_emails;
        // Reset timestamps when changing the set.
        self.verified_timestamp.clear();
    }

    pub fn get_recovery_emails(&self) -> Vec<HashedEmail> {
        self.recovery_emails.clone()
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
        self.policy = policy;
    }

    /// Return the set of recovery emails that currently satisfy the
    /// recency window (`max_age_ms`) in the configured policy.
    pub fn get_recent_verified_emails(&self) -> Vec<HashedEmail> {
        let now_ms = env::block_timestamp_ms();
        let mut recent = Vec::new();
        for email in &self.recovery_emails {
            if let Some(ts) = self.verified_timestamp.get(email) {
                if now_ms.saturating_sub(*ts) <= self.policy.max_age_ms {
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
        account_id: String,
        new_public_key: String,
        from_email: String,
        timestamp: String,
    ) -> Promise {
        zk_email_verifier::verify_zkemail_and_recover(
            &self.zk_email_verifier,
            proof,
            public_inputs,
            account_id,
            new_public_key,
            from_email,
            timestamp,
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
    #[payable]
    pub fn verify_encrypted_email_and_recover(
        &mut self,
        encrypted_email_blob: JsonValue,
    ) -> Promise {
        tee_outlayer_verifier::verify_encrypted_email_and_recover(
            &self.email_dkim_verifier,
            encrypted_email_blob,
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
    pub fn verify_email_onchain_and_recover(&mut self, email_blob: String) -> Promise {
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
