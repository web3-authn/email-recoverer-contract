use crate::{ext_self, EmailRecoverer, RecoveryAttemptStatus, VerificationResult};
use near_sdk::{env, AccountId, Gas, NearToken, Promise, PromiseError, PublicKey};
use serde_json::Value as JsonValue;

/// External interface for the global EmailDKIMVerifier contract (TEE path).
#[near_sdk::ext_contract(ext_email_dkim_verifier)]
pub trait EmailDkimVerifier {
    /// Start DKIM verification via Outlayer/TEE for an encrypted email blob.
    ///
    /// `aead_context` is required AEAD associated data forwarded to Outlayer worker
    /// for email decryption
    #[payable]
    fn request_email_verification_private(
        &mut self,
        payer_account_id: AccountId,
        encrypted_email_blob: serde_json::Value,
        aead_context: AeadContext,
    ) -> VerificationResult;
}

/// Context forwarded as AEAD associated data to the Outlayer worker
/// by the EmailDKIMVerifier contract. This is used when decrypting
/// the encrypted email blob.
#[near_sdk::near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct AeadContext {
    pub account_id: String,
    pub network_id: String,
    pub payer_account_id: String,
}

/// TEE/encrypted path: calls EmailDKIMVerifier to verify DKIM for the
/// given encrypted email blob and, recover account
///
/// @params `encrypted_email_blob`: forwarded to the DKIM verifier, then to Outlayer worker
/// @params `aead_context`: used as AEAD associated data for decrypting email in worker:
/// `{
///    account_id": "...",
///    network_id": "...",
///    payer_account_id": "..."
/// }`
pub fn verify_encrypted_email_and_recover(
    email_dkim_verifier: &near_sdk::AccountId,
    encrypted_email_blob: JsonValue,
    aead_context: AeadContext,
    request_id: String,
) -> Promise {
    let attached = env::attached_deposit().as_yoctonear();
    let caller = env::predecessor_account_id(); // relay account pays for Outlayer fees

    ext_email_dkim_verifier::ext(email_dkim_verifier.clone())
        // Forward the full attached deposit to the DKIM verifier.
        .with_attached_deposit(NearToken::from_yoctonear(attached))
        .with_static_gas(Gas::from_tgas(50))
        .request_email_verification_private(caller.clone(), encrypted_email_blob, aead_context)
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_encrypted_email_result(request_id),
        )
}

/// Callback after EmailDKIMVerifier finishes for encrypted emails.
pub fn on_verify_encrypted_email_result(
    contract: &mut EmailRecoverer,
    request_id: String,
    result: Result<VerificationResult, PromiseError>,
) {
    // Callback is scheduled by this contract in
    // `verify_encrypted_email_and_recover`. Predecessor should always be
    // this contract account.
    assert_eq!(
        env::predecessor_account_id(),
        env::current_account_id(),
        "Unauthorized caller for on_verify_encrypted_email_result"
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
            RecoveryAttemptStatus::DkimFailed,
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

    // Compute hashed email from the DKIM-verifier-provided From: address
    // and ensure it is configured.
    let hashed_email = contract.hash_from_email_for_current_account(&verification.from_address);

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
                "Invalid new public key.",
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

    let email_ts = match verification.email_timestamp_ms {
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
        email_ts,
    );

    match outcome {
        Ok(true) => {
            contract.update_attempt_status(&request_id, RecoveryAttemptStatus::Complete, None)
        }
        Ok(false) => contract.update_attempt_status(
            &request_id,
            RecoveryAttemptStatus::AwaitingMoreEmails,
            None,
        ),
        Err(err) => contract.fail_attempt(&request_id, RecoveryAttemptStatus::Failed, err),
    }
}
