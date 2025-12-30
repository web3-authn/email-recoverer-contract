use near_sdk::store::LookupMap;
use near_sdk::{env, ext_contract, near, AccountId, Promise, PromiseError, PublicKey};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};

mod onchain_public_verifier;
mod recovery_policy;
mod recovery_status;
mod tee_outlayer_verifier;
mod utils;
mod zk_email_verifier;

pub use crate::recovery_policy::{RecoveryPolicy, MAX_RECOVERY_EMAILS};
pub use crate::recovery_status::{RecoveryAttempt, RecoveryAttemptStatus};
pub use crate::tee_outlayer_verifier::AeadContext;
pub use crate::zk_email_verifier::{ProofInput, ZkEmailContext};
use crate::recovery_policy::VerifiedRecoveryIntent;

/// Alias for a hashed email (e.g. H(email || salt)).
pub type HashedEmail = Vec<u8>;

/// SHA-256 output size in bytes.
pub const HASHED_EMAIL_LEN: usize = 32;

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
        request_id: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    );
    fn on_verify_email_onchain_result(
        &mut self,
        request_id: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    );
    fn on_verify_encrypted_email_result(
        &mut self,
        request_id: String,
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
    /// Pending expected recovery intents per email.
    pending_recovery_intents: BTreeMap<HashedEmail, PublicKey>,
    /// Pollable recovery attempt records keyed by frontend-provided request_id.
    recovery_attempts_by_request_id: LookupMap<String, RecoveryAttempt>,
    /// Recovery policy.
    policy: RecoveryPolicy,
    /// Global ZK‑Email verifier contract account ID.
    zk_email_verifier: AccountId,
    /// Global EmailDKIMVerifier contract account ID.
    email_dkim_verifier: AccountId,
}

impl Default for EmailRecoverer {
    fn default() -> Self {
        env::panic_str(
            "EmailRecoverer::default is not supported; please call `init_email_recovery`",
        )
    }
}

#[near]
impl EmailRecoverer {
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
            recovery_attempts_by_request_id: LookupMap::new(b"r"),
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

    pub fn get_recovery_emails(&self) -> Vec<HashedEmail> {
        self.recovery_emails.iter().cloned().collect()
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
        request_id: String,
    ) -> Promise {
        let request_id = request_id.trim().to_string();
        assert!(!request_id.is_empty(), "request_id is required");

        let now_ms = env::block_timestamp_ms();
        self.upsert_attempt(RecoveryAttempt {
            request_id: request_id.clone(),
            status: RecoveryAttemptStatus::Started,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            error: None,
            from_address: None,
            email_timestamp_ms: None,
            new_public_key: Some(expected_new_public_key.clone()),
        });

        if expected_hashed_email.len() != HASHED_EMAIL_LEN {
            self.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                format!(
                    "invalid expected_hashed_email length; expected {} bytes",
                    HASHED_EMAIL_LEN
                ),
            );
            return Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
        }

        let expected_pk: PublicKey = match expected_new_public_key.parse() {
            Ok(pk) => pk,
            Err(_err) => {
                self.fail_attempt(
                    &request_id,
                    RecoveryAttemptStatus::Failed,
                    "invalid expected_new_public_key",
                );
                return Promise::new(env::predecessor_account_id())
                    .transfer(env::attached_deposit());
            }
        };

        if !self.is_configured_recovery_email(&expected_hashed_email) {
            self.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::PolicyFailed,
                "HashedEmail is not in configured recovery_emails",
            );
            return Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
        }

        self.set_pending_recovery_intent(&expected_hashed_email, &expected_pk);
        self.update_attempt_status(&request_id, RecoveryAttemptStatus::VerifyingDkim, None);

        tee_outlayer_verifier::verify_encrypted_email_and_recover(
            &self.email_dkim_verifier,
            encrypted_email_blob,
            aead_context,
            request_id,
        )
    }
    /// Callback after EmailDKIMVerifier finishes for encrypted emails.
    pub fn on_verify_encrypted_email_result(
        &mut self,
        request_id: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        tee_outlayer_verifier::on_verify_encrypted_email_result(self, request_id, result)
    }

    /// Verify proof with ZkEmailVerifier and recover if policy is satisfied.
    pub fn verify_zkemail_and_recover(
        &mut self,
        proof: ProofInput,
        public_inputs: Vec<String>,
        context: ZkEmailContext,
        request_id: String,
    ) -> Promise {
        let request_id = request_id.trim().to_string();
        assert!(!request_id.is_empty(), "request_id is required");

        let now_ms = env::block_timestamp_ms();
        self.upsert_attempt(RecoveryAttempt {
            request_id: request_id.clone(),
            status: RecoveryAttemptStatus::Started,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            error: None,
            from_address: None,
            email_timestamp_ms: None,
            new_public_key: Some(context.new_public_key.clone()),
        });

        let current = env::current_account_id().to_string();
        if context.account_id != current {
            self.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                "verify_zkemail_and_recover: account_id must match current account",
            );
            return Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
        }

        let expected_hashed_email = self.hash_from_email_for_current_account(&context.from_email);
        let expected_pk: PublicKey = match context.new_public_key.parse() {
            Ok(pk) => pk,
            Err(_err) => {
                self.fail_attempt(
                    &request_id,
                    RecoveryAttemptStatus::Failed,
                    "verify_zkemail_and_recover: invalid new_public_key",
                );
                return Promise::new(env::predecessor_account_id())
                    .transfer(env::attached_deposit());
            }
        };

        if !self.is_configured_recovery_email(&expected_hashed_email) {
            self.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::PolicyFailed,
                "HashedEmail is not in configured recovery_emails",
            );
            return Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
        }

        self.set_pending_recovery_intent(&expected_hashed_email, &expected_pk);
        self.update_attempt_status(&request_id, RecoveryAttemptStatus::VerifyingZkEmail, None);
        zk_email_verifier::verify_zkemail_and_recover(
            &self.zk_email_verifier,
            proof,
            public_inputs,
            context,
            request_id,
        )
    }

    /// Callback after verify_zkemail_and_recover finishes.
    pub fn on_verify_zkemail_result(
        &mut self,
        request_id: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        zk_email_verifier::on_verify_zkemail_result(self, request_id, result)
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
        request_id: String,
    ) -> Promise {
        let request_id = request_id.trim().to_string();
        assert!(!request_id.is_empty(), "request_id is required");

        let now_ms = env::block_timestamp_ms();
        self.upsert_attempt(RecoveryAttempt {
            request_id: request_id.clone(),
            status: RecoveryAttemptStatus::Started,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            error: None,
            from_address: None,
            email_timestamp_ms: None,
            new_public_key: Some(expected_new_public_key.clone()),
        });

        if expected_hashed_email.len() != HASHED_EMAIL_LEN {
            self.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                format!(
                    "invalid expected_hashed_email length; expected {} bytes",
                    HASHED_EMAIL_LEN
                ),
            );
            return Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
        }

        let expected_pk: PublicKey = match expected_new_public_key.parse() {
            Ok(pk) => pk,
            Err(_err) => {
                self.fail_attempt(
                    &request_id,
                    RecoveryAttemptStatus::Failed,
                    "verify_email_onchain_and_recover: invalid expected_new_public_key",
                );
                return Promise::new(env::predecessor_account_id())
                    .transfer(env::attached_deposit());
            }
        };

        if !self.is_configured_recovery_email(&expected_hashed_email) {
            self.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::PolicyFailed,
                "HashedEmail is not in configured recovery_emails",
            );
            return Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
        }

        self.set_pending_recovery_intent(&expected_hashed_email, &expected_pk);
        self.update_attempt_status(&request_id, RecoveryAttemptStatus::VerifyingDkim, None);

        onchain_public_verifier::verify_email_onchain_and_recover(
            &self.email_dkim_verifier,
            email_blob,
            request_id,
        )
    }
    /// Callback after EmailDKIMVerifier finishes for plaintext/on-chain emails.
    /// @deprecated Prefer `on_verify_encrypted_email_result` used by the encrypted TEE path.
    pub fn on_verify_email_onchain_result(
        &mut self,
        request_id: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        onchain_public_verifier::on_verify_email_onchain_result(self, request_id, result)
    }
}
