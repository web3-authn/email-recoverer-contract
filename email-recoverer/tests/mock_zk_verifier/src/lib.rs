use near_sdk::{env, near};

/// Minimal stand-in for the real ProofInput type used by the zk-email-verifier
/// contract. Tests only care about the method shape, not the fields.
pub struct ProofInput;

/// Minimal stand-in for the real VerificationResult type used by the
/// zk-email-verifier contract. This mirrors the shape expected by the
/// email-recoverer contract.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: String,
    pub new_public_key: String,
    pub from_address: String,
    pub email_timestamp_ms: Option<u64>,
}

#[near(contract_state)]
pub struct MockZkVerifier {}

#[near]
impl MockZkVerifier {
    #[init]
    pub fn new() -> Self {
        Self {}
    }

    /// Mock verifier that always returns a successful VerificationResult and
    /// logs the call. It does not actually verify the proof.
    pub fn verify_with_binding(
        &self,
        _proof: ProofInput,
        public_inputs: Vec<String>,
        account_id: String,
        new_public_key: String,
        from_email: String,
        timestamp: String,
    ) -> VerificationResult {
        env::log_str(&format!(
            "MockZkVerifier::verify_with_binding called (num_inputs={}, account_id={}, from_email={})",
            public_inputs.len(),
            account_id,
            from_email
        ));

        let email_timestamp_ms = timestamp.parse::<u64>().ok();

        VerificationResult {
            verified: true,
            account_id,
            new_public_key,
            from_address: from_email,
            email_timestamp_ms,
        }
    }
}
