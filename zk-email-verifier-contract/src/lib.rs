use core::str::FromStr;

use near_sdk::{
    borsh::{self, BorshDeserialize, BorshSerialize},
    near,
    serde::{Deserialize, Serialize},
};
use schemars::JsonSchema;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof};

/// ZK‑Email verifier contract (WASM) for `RecoverEmailCircuit`.
///
/// This contract exposes view methods that verify Groth16 proofs and
/// return a structured `VerificationResult` containing the verification
/// outcome and the human‑readable fields anchored in the circuit.
#[near(contract_state)]
#[derive(Default)]
pub struct ZkEmailVerifier;

#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub account_id: String,
    pub new_public_key: String,
    pub from_address: String,
    pub email_timestamp_ms: Option<u64>,
}

#[near]
impl ZkEmailVerifier {
    #[init]
    pub fn new() -> Self {
        // In the future we may precompute and cache a PreparedVerifyingKey here.
        Self
    }
}
