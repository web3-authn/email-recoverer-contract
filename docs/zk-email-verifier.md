This document outlines how to implement an on‑chain verifier for zk.email proofs on NEAR, using Circom Groth16 circuits and arkworks, without trusting the relayer.

---

## 1. Goals and Scope

- Verify zk.email proofs on NEAR:
  - Proofs are Groth16 over BN254, generated from Circom circuits.
  - Public inputs encode only the fields we care about (e.g. `from_email_hash`, `account_id`, `new_public_key`, `nonce`, `dkim_public_key_hash`).
- Keep the NEAR contract verifier:
  - As small and gas‑efficient as possible.
  - Independent of Circom tooling (no witness generation, no R1CS parsing).
- Off‑chain proving:
  - Happens in a separate prover service (Node/Rust) using Circom + `snarkjs`/`rapidsnark` or `ark-circom`.
  - The relayer only transports `{proof, publicInputs}`; it is not trusted to validate emails itself.

---

## 2. Off‑Chain: Circom Circuits and Prover Service

**2.1 Circuit design (zk.email)**

- Start from the zk.email Circom circuits (or adapt them) so that the circuit:
  - Parses DKIM‑signed headers and body.
  - Verifies the DKIM signature against the domain’s public key (provided as private input).
  - Extracts and enforces:
    - `from_email` (and its domain).
    - `to_email` (expected recovery address).
    - `account_id` in the subject/body (e.g. `bob.near`).
    - `new_public_key` and optional `nonce`/timestamp.
  - Exposes the following as **public signals**:
    - `dkim_public_key_hash` (to verify against on-chain registry).
    - `from_email_hash` (or `H(email || account_id)` for privacy).
    - `account_id`
    - `new_public_key`
    - `nonce` / `timestamp`

**2.2 Compile and setup**

- Run once, off‑chain:
  - `circom zk-email.circom --r1cs --wasm --sym`
  - Trusted setup for Groth16:
    - `snarkjs groth16 setup zk-email.r1cs powersOfTau.ptau zk-email_0000.zkey`
    - `snarkjs zkey contribute ...`
    - Export verifying key:
      - `snarkjs zkey export verificationkey zk-email_final.zkey verification_key.json`

**2.3 Prover service**

- Implement a prover server (Node.js + `snarkjs` or Rust + `ark-circom`) with an HTTP API:
  - `POST /prove`
    - Input: normalized email payload (raw MIME or structured fields) and any extra metadata (nonce, expected account_id).
    - Steps:
      - Construct circuit input JSON for zk.email.
      - Run witness generator (`generate_witness` or `ark-circom`).
      - Run Groth16 proof generation.
    - Output: `{ proof, publicSignals }`, where:
      - `proof` is Groth16 proof (compressed/serialized).
      - `publicSignals` is an array/struct matching the circuit’s public outputs.

The relayer (Cloudflare Worker) calls this API and forwards `{proof, publicSignals}` to NEAR.

---

## 3. On‑Chain: NEAR ZkEmailVerifier Contract

**3.1 Arkworks Integration Strategy**

- **Verification**: Use `ark-groth16` (part of `arkworks-rs`) directly in the NEAR contract. It supports `no_std` and is compatible with NEAR's WASM environment.
- **Tooling**: Use `ark-circom` (from `circom-compat`) *off-chain* to parse Circom artifacts and generate the Rust constants for the `VerifyingKey`. We do *not* use `ark-circom` on-chain to avoid overhead (witness generation, WASM runtime) that is unnecessary for verification.

**3.2 Dependencies**

- In the NEAR contract, depend on a minimal arkworks stack:

```toml
[dependencies]
ark-std      = { version = "0.4", default-features = false }
ark-ff       = { version = "0.4", default-features = false }
ark-ec       = { version = "0.4", default-features = false }
ark-bn254    = { version = "0.4", default-features = false }
ark-groth16  = { version = "0.4", default-features = false }
ark-serialize = { version = "0.4", default-features = false }
```

- Configure NEAR crate to compile for `wasm32-unknown-unknown` with these crates, ensuring `std` features are disabled.

**3.3 Embed verifying key and public input mapping**

- Offline, write a small Rust script using `ark-circom` or `serde_json` that:
  - Reads `verification_key.json` or the `.zkey`.
  - Converts the G1/G2 points and pairing parameters into Rust constants:
    - E.g. `const ALPHA_G1: G1Affine = G1Affine::new_unchecked(...);`
  - Defines how `publicSignals` indices map to logical fields:
    - `publicSignals[0] = dkim_public_key_hash`
    - `publicSignals[1] = from_email_hash`
    - `publicSignals[2] = account_id_hash`
    - `publicSignals[3..]` = parts of `new_public_key`, `nonce`, etc.

- Paste these constants into the NEAR `ZkEmailVerifier` contract.

**3.4 Verifier entrypoint**

- Contract interface (sketch):

```rust
#[near_sdk::near(serializers = [json])]
pub struct ZkEmailPublicInputs {
    pub dkim_public_key_hash: Vec<u8>,
    pub from_email_hash: Vec<u8>,
    pub account_id: String,
    pub new_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[near_sdk::near(serializers = [json])]
pub struct ZkEmailVerificationResult {
    pub verified: bool,
    pub outputs: Option<ZkEmailPublicInputs>,
}

#[near_sdk::near(contract_state)]
pub struct ZkEmailVerifier {
    // DKIM Registry: domain_hash -> public_key_hash
    pub dkim_registry: LookupMap<Vec<u8>, Vec<u8>>,
}
```

- Main method:

```rust
impl ZkEmailVerifier {
    pub fn verify(
        &self,
        proof_bytes: Vec<u8>,
        public_signals: Vec<String>, // or Vec<Vec<u8>>
    ) -> ZkEmailVerificationResult {
        // 1. Decode proof_bytes into ark_groth16::Proof<BN254>.
        // 2. Decode public_signals into field elements.
        // 3. Call ark_groth16::verify_proof(&VK, &proof, &inputs).
        // 4. If verified:
        //    a. Map inputs to ZkEmailPublicInputs.
        //    b. Verify dkim_public_key_hash against the on-chain registry (optional here, or in caller).
        //    c. Return result.
    }
}
```

**3.5 DKIM Registry**

- The system requires a **DKIM Registry** to map email domains (e.g., `gmail.com`) to their active DKIM public keys.
- The circuit proves: "This email was signed by Key X".
- The Registry confirms: "Key X is valid for gmail.com".
- Without this, an attacker could generate a valid proof using their own key for a spoofed domain.

---

## 4. Integration with Relayer and Recovery Contracts

**4.1 Cloudflare Email Worker**

- Receives email via Email Routing at `recover@web3authn.org`.
- Extracts headers/body, normalizes to circuit input format.
- POSTs to the Relayer Worker: `/email-recovery` with `{raw_email, metadata}`.

**4.2 Relayer Worker + Circom prover**

- Validates request and sends payload to the Circom prover service (`/prove`).
- Receives `{proof, publicSignals}`.
- Submits NEAR tx to `bob.near::verify_and_recover(proof, publicSignals)`:
  - `bob.near` (zk-email-recovery contract) calls the global `ZkEmailVerifier::verify`.
  - On success and policy satisfaction, `bob.near` calls `add_full_access_key(new_public_key)` on itself.

**4.3 Web3Authn contract**

- Unchanged: once the new NEAR key exists, the user can call `verify_and_register_user` as usual to attach a new WebAuthn authenticator.

---

## 5. Implementation Phases

1. **Verifier prototype**
   - Hard‑code a tiny test circuit and verifying key.
   - Implement Groth16 verification in a NEAR contract using `ark-groth16`.
   - Benchmark gas/memory.

2. **zk.email circuit integration**
   - Swap the test VK for the real zk.email VK.
   - Implement the **DKIM Registry** (can be a simple hardcoded map initially).
   - Implement the Circom prover service.

3. **Recovery contract wiring**
   - Implement per‑user `zk-email-recovery` contract that:
     - Stores `recovery_emails` and timestamps.
     - Calls `ZkEmailVerifier` and enforces email‑based policy before adding keys.

4. **Hardening**
   - Add replay protection (nonces/timestamps).
   - Add rate‑limits and logging.
   - Optimize verifier constants and serialization for minimal gas.

This plan keeps the heavy proving logic off‑chain, uses Circom/zk.email for trustless email verification, and relies on a slim `ark-groth16` verifier compiled to NEAR WASM to validate proofs on‑chain.***
