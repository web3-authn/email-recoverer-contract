use near_sdk::{env, near};

#[near(contract_state)]
pub struct MockZkVerifier {}

#[near]
impl MockZkVerifier {
    #[init]
    pub fn new() -> Self {
        Self {}
    }

    /// Mock verifier that always returns true and logs the call.
    pub fn verify(&self, proof: Vec<u8>, public_inputs: Vec<u8>) -> bool {
        env::log_str(&format!(
            "MockZkVerifier::verify called (proof_len={}, inputs_len={})",
            proof.len(),
            public_inputs.len()
        ));
        true
    }
}

