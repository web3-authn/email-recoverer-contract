use near_sdk::{
    env, log, near, ext_contract,
    AccountId, Gas, Promise,
};
use std::collections::BTreeMap;

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
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct DkimVerificationResult {
    pub verified: bool,
    pub from_email_hash: Vec<u8>,
    pub account_id: String,
    pub new_public_key: Vec<u8>,
    pub timestamp_ms: u64,
}

/// External interface for the global ZK‑Email verifier contract.
#[ext_contract(ext_zk_email_verifier)]
pub trait ZkEmailVerifier {
    fn verify(&self, proof: Vec<u8>, public_inputs: Vec<u8>) -> ZkEmailVerificationResult;
}

/// External interface for the global EmailDKIMVerifier contract (TEE path).
#[ext_contract(ext_email_dkim_verifier)]
pub trait EmailDkimVerifier {
    fn verify_dkim(&self, payload: Vec<u8>) -> DkimVerificationResult;
}

/// Internal callbacks on this contract used for cross‑contract promises.
#[ext_contract(ext_self)]
pub trait EmailRecovererCallbacks {
    fn on_verify_zkemail_result(&mut self);
    fn on_verify_dkim_result(&mut self);
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

    /// ZK‑Email path: verify proof via global ZkEmailVerifier and recover if policy is satisfied.
    pub fn verify_and_recover(&mut self, zk_proof: Vec<u8>, zk_inputs: Vec<u8>) -> Promise {
        self.assert_owner();
        log!("verify_and_recover called (ZK‑Email path)");

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

        self.add_full_access_key_internal(outputs.new_public_key);
    }

    /// TEE/DKIM path: ask the EmailDKIMVerifier to verify DKIM for the given payload.
    pub fn verify_dkim_and_recover(&mut self, dkim_payload: Vec<u8>) -> Promise {
        self.assert_owner();
        log!("verify_dkim_and_recover called (TEE/DKIM path)");

        ext_email_dkim_verifier::ext(self.email_dkim_verifier.clone())
            .with_static_gas(Gas::from_tgas(50))
            .verify_dkim(dkim_payload)
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(50))
                    .on_verify_dkim_result(),
            )
    }

    /// Callback after EmailDKIMVerifier finishes.
    pub fn on_verify_dkim_result(&mut self) {
        let caller = env::predecessor_account_id();
        assert!(
            caller == self.email_dkim_verifier || caller == env::current_account_id(),
            "Unauthorized caller for on_verify_dkim_result"
        );

        let data = match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(data) => data,
            near_sdk::PromiseResult::Failed => {
                log!("DKIM verification promise failed");
                return;
            }
        };

        let dkim_result = match DkimVerificationResult::try_from_slice(&data) {
            Ok(v) => v,
            Err(_err) => {
                log!("Failed to deserialize DkimVerificationResult from promise result");
                return;
            }
        };

        if !dkim_result.verified {
            log!("DKIM verification returned verified = false");
            return;
        }

        self.add_full_access_key_internal(dkim_result.new_public_key);
    }

    /// Internal helper to actually add a full‑access key to this account.
    fn add_full_access_key_internal(&self, public_key_bytes: Vec<u8>) {
        // Stub implementation for now; wiring real key parsing will come later.
        log!(
            "add_full_access_key_internal called with {} bytes (stub)",
            public_key_bytes.len()
        );
    }
}
