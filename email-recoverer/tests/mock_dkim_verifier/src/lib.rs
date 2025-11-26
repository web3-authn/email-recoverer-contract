use near_sdk::{
    callback_result, env, near, payable,
    private, AccountId, Promise, PromiseError,
};
use near_sdk::serde_json::{json, Value};

/// Minimum deposit required to simulate Outlayer execution (0.01 NEAR).
const MIN_DEPOSIT: u128 = 10u128.pow(22);

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
            "Attach at least 0.01 NEAR for Outlayer execution"
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
    ) -> bool {
        env::log_str(&format!(
            "MockDkimVerifier::on_email_verification_result for {} (email_len={})",
            requested_by,
            email_blob.len()
        ));

        // In the real contract this would parse DKIM records and verify them.
        // For the mock, treat any successful callback payload as "verified".
        matches!(result, Ok(Some(_)))
    }
}
