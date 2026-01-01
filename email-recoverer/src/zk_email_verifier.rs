use near_sdk::{env, Gas, Promise, PromiseError, PublicKey};

use crate::{
    ext_self, EmailRecoverer, HashedEmail, RecoveryAttemptStatus, VerificationResult,
    HASHED_EMAIL_LEN,
};

/// External interface for the global [zk-email] verifier contract.
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
        from_address_hash: HashedEmail,
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
    pub from_address_hash: HashedEmail,
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
    request_id: String,
) -> Promise {
    ext_zk_email_verifier::ext(zk_email_verifier.clone())
        .with_static_gas(Gas::from_tgas(50))
        .verify_with_binding(
            proof,
            public_inputs,
            context.account_id,
            context.new_public_key,
            context.from_address_hash,
            context.timestamp,
        )
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_zkemail_result(request_id),
        )
}

pub fn on_verify_zkemail_result(
    contract: &mut EmailRecoverer,
    request_id: String,
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
        Err(err) => {
            contract.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                format!(
                    "Email verification failed due to an internal error. Details: {err:?}"
                ),
            );
            return;
        }
    };

    contract.update_attempt_fields_from_verifier(&request_id, &verification);

    if !verification.verified {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::ZkEmailFailed,
            "Email verification failed.",
        );
        return;
    }

    let current = env::current_account_id().to_string();
    if verification.account_id != current {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::Failed,
            format!(
                "Verification result is for a different account (expected {}, got {}).",
                env::current_account_id(),
                verification.account_id
            ),
        );
        return;
    }

    // Ensure the ZK verifier provided a valid hashed From: address and that it is configured.
    let hashed_email = verification.from_address_hash.clone();
    if hashed_email.len() != HASHED_EMAIL_LEN {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::Failed,
            format!(
                "Invalid recovery email hash in verification result (expected {} bytes).",
                HASHED_EMAIL_LEN
            ),
        );
        return;
    }
    if !contract.is_configured_recovery_email(&hashed_email) {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::PolicyFailed,
            "Sender email is not one of your configured recovery emails.",
        );
        return;
    }

    let new_pk: PublicKey = match verification.new_public_key.parse() {
        Ok(pk) => pk,
        Err(_err) => {
            contract.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                "Invalid new public key in verification result.",
            );
            return;
        }
    };

    if !contract.consume_pending_recovery_intent(&hashed_email, &new_pk) {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::Failed,
            "Verification result does not match this recovery request.",
        );
        return;
    }

    let timestamp_ms = match verification.email_timestamp_ms {
        Some(ts) => ts,
        None => {
            contract.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                "Email timestamp is missing from the verification result.",
            );
            return;
        }
    };

    contract.update_attempt_status(&request_id, RecoveryAttemptStatus::Recovering, None);

    let outcome = contract.mark_verified_and_maybe_recover(
        hashed_email,
        verification.new_public_key.clone(),
        timestamp_ms,
    );

    match outcome {
        Ok(true) => contract.update_attempt_status(&request_id, RecoveryAttemptStatus::Complete, None),
        Ok(false) => contract.update_attempt_status(
            &request_id,
            RecoveryAttemptStatus::AwaitingMoreEmails,
            None,
        ),
        Err(err) => contract.fail_attempt(&request_id, RecoveryAttemptStatus::Failed, err),
    }
}
