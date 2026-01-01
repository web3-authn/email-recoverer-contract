This document describes how zk.email proof verification fits into the **email‑recoverer** system:

- What the global `zk-email-verifier` contract is expected to do.
- How off‑chain proving works.
- How the `email-recoverer` contract in this repo talks to that verifier.

The actual `zk-email-verifier` NEAR contract code now lives in a **separate repository**; this repo only contains the per‑account `email-recoverer` contract and the Rust interface it uses to call the global verifier.

---

## 1. Goals and Scope

- Verify zk.email proofs on NEAR via a **global verifier contract** (deployed once) that:
  - Accepts a Groth16 proof over BN254 generated from Circom circuits.
  - Ensures the proof is bound to:
    - A `near` `account_id` (the target account being recovered),
    - A `new_public_key` to add as a full‑access key,
    - A `from_address_hash` and timestamp.
  - Returns a simple `VerificationResult` struct.
- Keep the per‑account `email-recoverer` contract:
  - Small and focused on policy (which emails are allowed, how many, recency window).
  - Independent of circuit/arkworks details; it only calls the global verifier.
- Off‑chain proving:
  - Happens in a separate prover service (Node/Rust) using Circom + `snarkjs`/`rapidsnark` or `ark‑circom`.
  - The relayer only transports `{proof, publicInputs}` and submits them to NEAR; it is not trusted to validate emails itself.

---

## 2. Off‑Chain: Circom Circuits and Prover Service

**2.1 Circuit design (zk.email)**

- Start from the zk.email Circom circuits (or adapt them) so that the circuit:
  - Parses DKIM‑signed headers and body.
  - Verifies the DKIM signature against the domain’s public key (provided as private input).
  - Extracts and enforces:
    - The sender email (private) and its domain.
    - `to_email` (expected recovery address).
    - `account_id` in the subject/body (e.g. `bob.near`).
    - `new_public_key` and optional `nonce`/timestamp.
  - Exposes the following as **public signals**:
    - `dkim_public_key_hash` (to verify against on-chain registry).
    - `from_address_hash` (`sha256("<canonical_from>|<account_id_lower>")`).
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

## 3. On‑Chain: Global ZkEmailVerifier Contract (External Repo)

The `ZkEmailVerifier` NEAR contract is implemented and built in a **separate repository**. From the perspective of this repo, we care about:

- The **interface** exposed by that contract.
- The **binding** guarantees it provides.

### 3.1 Interface expected by `email-recoverer`

In `email-recoverer/src/zk_email_verifier.rs` we define the external interface:

```rust
#[near_sdk::ext_contract(ext_zk_email_verifier)]
pub trait ZkEmailVerifier {
    /// Verify a zk-SNARK proof and ensure that the provided
    /// `account_id`, `new_public_key`, `from_address_hash`, and `timestamp`
    /// are correctly bound into the public inputs.
    fn verify_with_binding(
        &self,
        proof: ProofInput,
        public_inputs: Vec<String>,
        account_id: String,
        new_public_key: String,
        from_address_hash: Vec<u8>,
        timestamp: String,
    ) -> VerificationResult;
}
```

The helper `verify_zkemail_and_recover` inside the same module calls this interface:

```rust
ext_zk_email_verifier::ext(zk_email_verifier.clone())
    .with_static_gas(Gas::from_tgas(50))
    .verify_with_binding(
        proof,
        public_inputs,
        account_id,
        new_public_key,
        from_address_hash,
        timestamp,
    )
    .then(
        ext_self::ext(env::current_account_id())
            .with_static_gas(Gas::from_tgas(50))
            .on_verify_zkemail_result(),
    )
```

The verifier contract is responsible for:

- Parsing the proof and public inputs.
- Checking the Groth16 pairing equation using its embedded verifying key.
- Ensuring the proof is bound to the exact `(account_id, new_public_key, from_address_hash, timestamp)` values supplied.
- Returning a `VerificationResult`:

```rust
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
```

All arkworks / VK‑embedding details live in the external `zk-email-verifier` repo; this repo just relies on the interface above.

---

## 4. Integration with Relayer and Recovery Contracts

**4.1 Cloudflare Email Worker**

- Receives email via Email Routing at `recover@web3authn.org`.
- Extracts headers/body, normalizes to circuit input format.
- POSTs to the Relayer Worker: `/email-recovery` with `{raw_email, metadata}`.

**4.2 Relayer Worker + Circom prover**

- Validates request and sends payload to the Circom prover service (`/prove`).
- Receives `{proof, publicSignals}`.
- Submits NEAR tx to:
  - `bob.near::verify_zkemail_and_recover(proof, publicSignals, context, request_id)`
  - `bob.near` is the per‑account `EmailRecoverer` contract in this repo.
  - It invokes the global `zk-email-verifier` contract via `ext_zk_email_verifier::verify_with_binding`.
  - On success and policy satisfaction, `bob.near` adds `new_public_key` as a full‑access key on itself.

**4.3 Web3Authn contract**

- Unchanged: once the new NEAR key exists, the user can call `verify_and_register_user` as usual to attach a new WebAuthn authenticator.

---

## 5. Implementation Phases (High‑Level)

1. **Off‑chain circuits + prover**
   - Design/choose zk.email Circom circuits.
   - Run trusted setup and build a prover service that exposes `{proof, publicSignals}`.

2. **Global zk-email-verifier contract (external repo)**
   - Implement a NEAR contract that:
     - Embeds the verifying key.
     - Implements `verify_with_binding` with the interface above.
     - Returns `VerificationResult`.

3. **Recovery contract wiring (this repo)**
   - Use `zk_email_verifier::verify_zkemail_and_recover` in `EmailRecoverer` to call the global verifier.
   - Enforce email‑based recovery policy before adding keys.

4. **Hardening**
   - Add replay protection and timestamp checks.
   - Add rate‑limits and logging at the relayer/verifier layers.

In short: this repo no longer implements the zk-email verifier itself; it integrates with a shared global verifier contract using the `ZkEmailVerifier` interface defined in `email-recoverer/src/zk_email_verifier.rs`.
