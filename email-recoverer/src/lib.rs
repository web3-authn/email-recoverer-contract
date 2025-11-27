use near_sdk::{
    env, log, near, ext_contract,
    AccountId, Gas, Promise, PromiseError, NearToken, PublicKey,
};
use near_sdk::borsh::BorshDeserialize;
use std::collections::BTreeMap;
use serde_json::Value as JsonValue;

/// Alias for a hashed email (e.g. H(email || salt)).
pub type HashedEmail = Vec<u8>;

/// Recovery policy configuration.
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

/// Public outputs returned by the ZK‑Email verifier.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct ZkEmailPublicInputs {
    pub from_email_hash: Vec<u8>,
    pub account_id: String,
    pub new_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct ZkEmailVerificationResult {
    pub verified: bool,
    pub outputs: Option<ZkEmailPublicInputs>,
}

/// Result returned by the EmailDKIMVerifier TEE path.
/// Mirrors the VerificationResult struct exposed by the DKIM verifier contract.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: Option<String>,
    pub new_public_key: Option<String>,
    pub email_timestamp_ms: Option<u64>,
    pub unused_deposit_yocto: u128,
}

/// External interface for the global ZK‑Email verifier contract.
#[ext_contract(ext_zk_email_verifier)]
pub trait ZkEmailVerifier {
    fn verify(&self, proof: Vec<u8>, public_inputs: Vec<u8>) -> ZkEmailVerificationResult;
}

/// External interface for the global EmailDKIMVerifier contract (TEE path).
#[ext_contract(ext_email_dkim_verifier)]
pub trait EmailDkimVerifier {
    /// Start DKIM verification via Outlayer/TEE for a full email blob.
    /// `params` can carry additional verification options or metadata.
    #[payable]
    fn request_email_verification(
        &mut self,
        payer_account_id: AccountId,
        email_blob: String,
        params: Option<JsonValue>,
    ) -> VerificationResult;
}

/// Internal callbacks on this contract used for cross‑contract promises.
#[ext_contract(ext_self)]
pub trait EmailRecovererCallbacks {
    fn on_verify_zkemail_result(&mut self);
    fn on_verify_dkim_result(
        &mut self,
        email_blob: String,
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

    /// Compute whether the recovery policy is satisfied based on
    /// `verified_timestamp` and `policy`.
    fn is_recovery_policy_satisfied(&self, now_ms: u64) -> bool {
        let mut num_recent = 0u8;
        for email in &self.recovery_emails {
            if let Some(ts) = self.verified_timestamp.get(email) {
                if now_ms.saturating_sub(*ts) <= self.policy.max_age_ms {
                    num_recent = num_recent.saturating_add(1);
                }
            }
        }
        num_recent >= self.policy.min_required_emails
    }

    /// Mark a given hashed email as verified at the given timestamp and,
    /// if the policy is satisfied, add the provided key as a full-access key.
    fn mark_verified_and_maybe_recover(
        &mut self,
        hashed_email: HashedEmail,
        new_public_key: Vec<u8>,
        timestamp_ms: u64,
    ) {
        self.verified_timestamp.insert(hashed_email, timestamp_ms);

        if !self.is_recovery_policy_satisfied(timestamp_ms) {
            log!(
                "Recovery policy not yet satisfied; recent verified emails insufficient (min_required = {})",
                self.policy.min_required_emails
            );
            return;
        }

        self.add_full_access_key_internal(new_public_key);
    }

    /// Extract a canonical `from` email from the raw email blob and hash it
    /// using the current account ID as salt: H(email || "|" || account_id).
    fn hash_from_email_for_current_account(&self, email_blob: &str) -> Option<HashedEmail> {
        // Parse headers until the first blank line.
        let mut from_line: Option<String> = None;
        for line in email_blob.lines() {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }

            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("from:") {
                from_line = Some(trimmed.to_string());
                break;
            }
        }

        let from_line = from_line?;
        let after_colon = from_line.splitn(2, ':').nth(1)?.trim();

        // Very simple address extraction: prefer <addr>, otherwise use the rest.
        let addr = if let (Some(start), Some(end)) = (after_colon.find('<'), after_colon.find('>')) {
            after_colon[start + 1..end].trim()
        } else {
            after_colon
        };

        if addr.is_empty() {
            return None;
        }

        let canonical = addr.to_ascii_lowercase();
        let mut data = canonical.into_bytes();
        data.push(b'|');
        data.extend(env::current_account_id().as_bytes());

        Some(env::sha256(&data))
    }

    /// ZK‑Email path: verify proof via global ZkEmailVerifier and recover if policy is satisfied.
    pub fn verify_zkemail_and_recover(&mut self, zk_proof: Vec<u8>, zk_inputs: Vec<u8>) -> Promise {
        self.assert_owner();
        log!("verify_zkemail_and_recover called (ZK‑Email path)");

        ext_zk_email_verifier::ext(self.zk_email_verifier.clone())
            .with_static_gas(Gas::from_tgas(50))
            .verify(zk_proof, zk_inputs)
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(50))
                    .on_verify_zkemail_result(),
            )
    }

    /// Callback after ZK‑Email verifier finishes.
    pub fn on_verify_zkemail_result(&mut self) {
        let caller = env::predecessor_account_id();
        assert!(
            caller == self.zk_email_verifier || caller == env::current_account_id(),
            "Unauthorized caller for on_verify_zkemail_result"
        );

        let data = match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(data) => data,
            near_sdk::PromiseResult::Failed => {
                log!("ZK‑Email verification promise failed");
                return;
            }
        };

        let zk_result = match ZkEmailVerificationResult::try_from_slice(&data) {
            Ok(v) => v,
            Err(_err) => {
                log!("Failed to deserialize ZkEmailVerificationResult from promise result");
                return;
            }
        };

        if !zk_result.verified {
            log!("ZK‑Email verification returned verified = false");
            return;
        }

        let outputs = match zk_result.outputs {
            Some(o) => o,
            None => {
                log!("ZK‑Email verification succeeded but outputs are missing");
                return;
            }
        };

        // Bind proof to this account.
        if outputs.account_id != env::current_account_id().to_string() {
            log!(
                "ZK‑Email verification account_id {} does not match current account {}",
                outputs.account_id,
                env::current_account_id()
            );
            return;
        }

        // Ensure the hashed email from the proof is one of the configured recovery emails.
        if !self
            .recovery_emails
            .iter()
            .any(|e| *e == outputs.from_email_hash)
        {
            log!("ZK‑Email from_email_hash is not in configured recovery_emails");
            return;
        }

        let now_ms = env::block_timestamp_ms();
        self.mark_verified_and_maybe_recover(outputs.from_email_hash, outputs.new_public_key, now_ms);
    }

    /// TEE/DKIM path: ask the EmailDKIMVerifier to verify DKIM for the given email blob.
    #[payable]
    pub fn verify_dkim_and_recover(&mut self, email_blob: String) -> Promise {
        log!("verify_dkim_and_recover called (TEE/DKIM path)");
        let attached = env::attached_deposit().as_yoctonear();
        let caller = env::predecessor_account_id(); // relay account
        // relay account pays for Outlayer fees

        ext_email_dkim_verifier::ext(self.email_dkim_verifier.clone())
            // Forward the full attached deposit to the DKIM verifier.
            .with_attached_deposit(NearToken::from_yoctonear(attached))
            .with_static_gas(Gas::from_tgas(50))
            .request_email_verification(caller.clone(), email_blob.clone(), None)
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(50))
                    .on_verify_dkim_result(email_blob),
            )
    }

    /// Callback after EmailDKIMVerifier finishes.
    pub fn on_verify_dkim_result(
        &mut self,
        email_blob: String,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        assert_eq!(
            env::predecessor_account_id(),
            self.email_dkim_verifier,
            "Unauthorized caller for on_verify_dkim_result"
        );

        let verification = match result {
            Ok(v) => v,
            Err(_err) => {
                log!("Email DKIM verification promise failed");
                return;
            }
        };

        if !verification.verified {
            log!("Email DKIM verification returned verified = false");
            return;
        }

        let account_id = match verification.account_id {
            Some(a) => a,
            None => {
                log!("Email DKIM verification succeeded but account_id is missing");
                return;
            }
        };

        let current = env::current_account_id().to_string();
        if account_id != current {
            log!(
                "Email DKIM verification account_id {} does not match current account {}",
                account_id,
                env::current_account_id()
            );
            return;
        }

        let new_public_key_str = match verification.new_public_key {
            Some(pk) => pk,
            None => {
                log!("DKIM verification succeeded but new_public_key is missing");
                return;
            }
        };

        // Compute hashed email from the From: header and ensure it is configured.
        let hashed_email = match self.hash_from_email_for_current_account(&email_blob) {
            Some(h) => h,
            None => {
                log!("Email DKIM verification succeeded but failed to parse From: email");
                return;
            }
        };

        if !self.recovery_emails.iter().any(|e| *e == hashed_email) {
            log!("From: email is not in configured recovery_emails");
            return;
        }

        log!(
            "Email DKIM verification succeeded for email blob of length {} and new key string length {}",
            email_blob.len(),
            new_public_key_str.len()
        );

        let email_ts = match verification.email_timestamp_ms {
            Some(ts) => ts,
            None => {
                log!("Email DKIM verification succeeded but email_timestamp_ms is missing");
                return;
            }
        };

        // TODO: decode "ed25519:..." into raw key bytes instead of using the raw string.
        self.mark_verified_and_maybe_recover(hashed_email, new_public_key_str.into_bytes(), email_ts);
    }

    /// Internal helper to actually add a full‑access key to this account.
    fn add_full_access_key_internal(&self, public_key_bytes: Vec<u8>) {
        let key_str = match String::from_utf8(public_key_bytes) {
            Ok(s) => s,
            Err(_err) => {
                log!("add_full_access_key_internal: public key is not valid UTF-8");
                return;
            }
        };

        let public_key: PublicKey = match key_str.parse() {
            Ok(pk) => pk,
            Err(_err) => {
                log!("add_full_access_key_internal: failed to parse public key string");
                return;
            }
        };

        log!("add_full_access_key_internal: adding full-access key for current account");
        Promise::new(env::current_account_id()).add_full_access_key(public_key);
    }
}

// Non-contract helper methods (not exposed as NEAR externs).
impl EmailRecoverer {
    /// Testing/debug helper: manually set the verified timestamp for a given
    /// hashed email. This is not called from production code.
    pub fn debug_set_verified_timestamp_for_testing(
        &mut self,
        email: HashedEmail,
        timestamp_ms: u64,
    ) {
        self.verified_timestamp.insert(email, timestamp_ms);
    }
}
