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

/// Groth16 proof input used by the ZK‑Email verifier.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct ProofInput {
    /// pi_a: [Ax, Ay, Az]; we use Ax, Ay and assume Az = 1.
    pub pi_a: [String; 3],
    /// pi_b: [[Bx1, Bx0], [By1, By0], [Bz1, Bz0]]; we use the first two pairs.
    pub pi_b: [[String; 2]; 3],
    /// pi_c: [Cx, Cy, Cz]; we use Cx, Cy and assume Cz = 1.
    pub pi_c: [String; 3],
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

/// External interface for the global ZK‑Email verifier contract.
#[ext_contract(ext_zk_email_verifier)]
pub trait ZkEmailVerifier {
    /// Verify a zk-SNARK proof and ensure that the provided
    /// `account_id`, `new_public_key`, `from_email`, and `timestamp`
    /// are correctly bound into the public inputs.
    fn verify_with_binding(
        &self,
        proof: ProofInput,
        public_inputs: Vec<String>,
        account_id: String,
        new_public_key: String,
        from_email: String,
        timestamp: String,
    ) -> VerificationResult;
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
    fn on_verify_zkemail_result(
        &mut self,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    );
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

    /// Canonicalize an email-like string into a bare address:
    /// - Trim whitespace
    /// - If it contains a display name form like "Name <user@example.com>",
    ///   extract the part inside angle brackets.
    /// - Lowercase the result.
    fn canonicalize_email(raw: &str) -> String {
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

    /// Hash a canonical email address using the current account ID as salt:
    /// H(email || "|" || account_id). Accepts either a bare address
    /// ("alice@example.com") or a display-name form ("Alice <alice@example.com>").
    fn hash_from_email_for_current_account(&self, email_address: &str) -> HashedEmail {
        let canonical = Self::canonicalize_email(email_address);
        let mut data = canonical.into_bytes();
        data.push(b'|');
        data.extend(env::current_account_id().as_bytes());

        env::sha256(&data)
    }

    /// ZK‑Email path: verify proof via global ZkEmailVerifier and recover if policy is satisfied.
    pub fn verify_zkemail_and_recover(
        &mut self,
        proof: ProofInput,
        public_inputs: Vec<String>,
        account_id: String,
        new_public_key: String,
        from_email: String,
        timestamp: String,
    ) -> Promise {
        log!("verify_zkemail_and_recover called (ZK‑Email path)");

        // Cheap local binding: require the proof target account to be this account.
        let current = env::current_account_id().to_string();
        if account_id != current {
            env::panic_str("verify_zkemail_and_recover: account_id must match current account");
        }

        ext_zk_email_verifier::ext(self.zk_email_verifier.clone())
            .with_static_gas(Gas::from_tgas(50))
            .verify_with_binding(
                proof,
                public_inputs,
                account_id,
                new_public_key,
                from_email,
                timestamp,
            )
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(50))
                    .on_verify_zkemail_result(),
            )
    }

    /// Callback after ZK‑Email verifier finishes.
    pub fn on_verify_zkemail_result(
        &mut self,
        #[callback_result] result: Result<VerificationResult, PromiseError>,
    ) {
        // Callback is scheduled by this contract in `verify_zkemail_and_recover`
        // so the predecessor should be this contract.
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Unauthorized caller for on_verify_zkemail_result"
        );

        let verification = match result {
            Ok(v) => v,
            Err(_err) => {
                log!("ZK‑Email verification promise failed");
                return;
            }
        };

        if !verification.verified {
            log!("ZK‑Email verification returned verified = false");
            return;
        }

        let current = env::current_account_id().to_string();
        if verification.account_id != current {
            log!(
                "ZK‑Email verification account_id {} does not match current account {}",
                verification.account_id,
                env::current_account_id()
            );
            return;
        }

        // Compute hashed email from the proved From: address and ensure it is configured.
        let hashed_email = self.hash_from_email_for_current_account(&verification.from_address);
        if !self.recovery_emails.iter().any(|e| *e == hashed_email) {
            log!("ZK‑Email From: email is not in configured recovery_emails");
            return;
        }

        let timestamp_ms = match verification.email_timestamp_ms {
            Some(ts) => ts,
            None => {
                log!("ZK‑Email verification succeeded but email_timestamp_ms is missing");
                return;
            }
        };

        self.mark_verified_and_maybe_recover(
            hashed_email,
            verification.new_public_key.clone().into_bytes(),
            timestamp_ms,
        );
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
        // Callback is scheduled by this contract in `verify_dkim_and_recover`
        // Predecessor should always be this contract account.
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
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

        let current = env::current_account_id().to_string();
        if verification.account_id != current {
            log!(
                "Email DKIM verification account_id {} does not match current account {}",
                verification.account_id,
                env::current_account_id()
            );
            return;
        }

        // Compute hashed email from the DKIM-verifier-provided From: address
        // and ensure it is configured.
        let hashed_email = self.hash_from_email_for_current_account(&verification.from_address);

        if !self.recovery_emails.iter().any(|e| *e == hashed_email) {
            log!("From: email is not in configured recovery_emails");
            return;
        }

        log!(
            "Email DKIM verification succeeded for email blob of length {} and new key string length {}",
            email_blob.len(),
            verification.new_public_key.len()
        );

        let email_ts = match verification.email_timestamp_ms {
            Some(ts) => ts,
            None => {
                log!("Email DKIM verification succeeded but email_timestamp_ms is missing");
                return;
            }
        };

        self.mark_verified_and_maybe_recover(
            hashed_email,
            verification.new_public_key.clone().into_bytes(),
            email_ts,
        );
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
