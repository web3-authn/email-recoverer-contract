use near_sdk::near;

/// Stub ZK‑Email verifier contract so the workspace builds.
#[near(contract_state)]
pub struct ZkEmailVerifier;

#[near]
impl ZkEmailVerifier {
    #[init]
    pub fn new() -> Self {
        Self
    }
}

