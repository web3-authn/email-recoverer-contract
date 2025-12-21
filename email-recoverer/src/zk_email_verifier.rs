use near_sdk::{env, log, Gas, Promise, PromiseError, PublicKey};

use crate::{ext_self, EmailRecoverer, VerificationResult};

/// External interface for the global [zk-email] verifier contract.
#[near_sdk::ext_contract(ext_zk_email_verifier)]
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

/// Groth16 proof input used by the [zk-email] verifier.
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

/// Context for a [zk-email] recovery proof. These fields are
/// bound into the public inputs of the circuit and must match
/// the values encoded in the proof.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct ZkEmailContext {
    pub account_id: String,
    pub new_public_key: String,
    pub from_email: String,
    pub timestamp: String,
}

/// [zk-email] path helpers: perform the cross‑contract call into the global
/// ZkEmailVerifier and handle the callback, delegating recovery to the core
/// policy helpers on `EmailRecoverer`.

pub fn verify_zkemail_and_recover(
    zk_email_verifier: &near_sdk::AccountId,
    proof: ProofInput,
    public_inputs: Vec<String>,
    context: ZkEmailContext,
) -> Promise {
    // Require proof target account to be this account.
    let current = env::current_account_id().to_string();
    if context.account_id != current {
        env::panic_str("verify_zkemail_and_recover: account_id must match current account");
    }

    ext_zk_email_verifier::ext(zk_email_verifier.clone())
        .with_static_gas(Gas::from_tgas(50))
        .verify_with_binding(
            proof,
            public_inputs,
            context.account_id,
            context.new_public_key,
            context.from_email,
            context.timestamp,
        )
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_zkemail_result(),
        )
}

pub fn on_verify_zkemail_result(
    contract: &mut EmailRecoverer,
    result: Result<VerificationResult, PromiseError>,
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
            log!("[zk-email] verification promise failed");
            return;
        }
    };

    if !verification.verified {
        log!("[zk-email] verification returned verified = false");
        return;
    }

    let current = env::current_account_id().to_string();
    if verification.account_id != current {
        log!(
            "[zk-email] verification account_id {} does not match current account {}",
            verification.account_id,
            env::current_account_id()
        );
        return;
    }

    // Compute hashed email from the proved From: address and ensure it is configured.
    let hashed_email = contract.hash_from_email_for_current_account(&verification.from_address);
    if !contract.is_configured_recovery_email(&hashed_email) {
        log!("[zk-email] From: email is not in configured recovery_emails");
        return;
    }

    let new_pk: PublicKey = match verification.new_public_key.parse() {
        Ok(pk) => pk,
        Err(_err) => {
            log!("[zk-email] invalid new_public_key in verification result");
            return;
        }
    };

    if !contract.consume_pending_recovery_intent(&hashed_email, &new_pk) {
        log!("[zk-email] verification result does not match any pending recovery intent");
        return;
    }

    let timestamp_ms = match verification.email_timestamp_ms {
        Some(ts) => ts,
        None => {
            log!("[zk-email] verification succeeded but email_timestamp_ms is missing");
            return;
        }
    };

    contract.mark_verified_and_maybe_recover(
        hashed_email,
        verification.new_public_key.clone(),
        timestamp_ms,
    );
}
