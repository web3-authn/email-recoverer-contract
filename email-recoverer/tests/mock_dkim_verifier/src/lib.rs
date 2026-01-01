use near_sdk::{
    callback_result, env, near, payable,
    private, AccountId, Promise, PromiseError,
};
use near_sdk::serde_json::{json, Value};

/// Minimum deposit required to simulate Outlayer execution (0.1 NEAR).
const MIN_DEPOSIT: u128 = 10u128.pow(23);

/// Minimal stand-in for the real VerificationResult type used by the
/// email-dkim-verifier contract. This mirrors the shape expected by the
/// email-recoverer contract.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: String,
    pub new_public_key: String,
    pub from_address_hash: Vec<u8>,
    pub email_timestamp_ms: Option<u64>,
    pub request_id: String,
    #[borsh(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[near(contract_state)]
pub struct MockDkimVerifier {}

#[near]
impl MockDkimVerifier {
    #[init]
    pub fn new() -> Self {
        Self {}
    }

    /// Mock version of the real DKIM verifier's `request_email_verification` entrypoint.
    ///
    /// The signature matches the production contract, but the implementation is
    /// simplified and does not actually call Outlayer.
    #[payable]
    pub fn request_email_verification(
        &mut self,
        email_blob: String,
        params: Option<Value>,
    ) -> Promise {
        let caller = env::predecessor_account_id();
        let attached = env::attached_deposit().as_yoctonear();

        assert!(
            attached >= MIN_DEPOSIT,
            "Attach at least 0.1 NEAR for Outlayer execution"
        );

        let _input_payload = json!({
            "email_blob": email_blob,
            "params": params.unwrap_or_else(|| json!({})),
        })
        .to_string();

        env::log_str(&format!(
            "MockDkimVerifier::request_email_verification called by {}",
            caller
        ));

        // In the real contract this would forward to Outlayer and then `.then`
        // back to `on_email_verification_result`. For tests we just return a
        // stub promise to match the interface.
        Promise::new(env::current_account_id())
    }

    /// Mock callback that matches the production contract's signature.
    #[private]
    pub fn on_email_verification_result(
        &mut self,
        requested_by: AccountId,
        email_blob: String,
        #[callback_result] result: Result<Option<Value>, PromiseError>,
    ) -> VerificationResult {
        env::log_str(&format!(
            "MockDkimVerifier::on_email_verification_result for {} (email_len={})",
            requested_by,
            email_blob.len()
        ));

        // In the real contract this would parse DKIM records and verify them.
        // For the mock, treat any successful callback payload as "verified"
        // and return a minimal VerificationResult.
        let verified = matches!(result, Ok(Some(_)));
        let account_id_lower = requested_by.as_str().to_ascii_lowercase();
        let canonical_from = "mock@example.com".to_ascii_lowercase();
        let mut data = canonical_from.into_bytes();
        data.push(b'|');
        data.extend(account_id_lower.as_bytes());
        let from_address_hash = env::sha256(&data);

        VerificationResult {
            verified,
            account_id: requested_by.to_string(),
            // Use a simple, valid-looking public key string; callers that
            // care about the actual key bytes can ignore this in tests.
            new_public_key: "ed25519:1111111111111111111111111111111111111111111111".to_string(),
            from_address_hash,
            email_timestamp_ms: Some(env::block_timestamp_ms()),
            request_id: "mock-request-id".to_string(),
            error: None,
        }
    }
}
