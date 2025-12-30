use crate::{ext_self, EmailRecoverer, RecoveryAttemptStatus, VerificationResult};
use near_sdk::{env, log, AccountId, Gas, NearToken, Promise, PromiseError, PublicKey};

/// External interface for the global EmailDKIMVerifier contract (TEE path).
#[near_sdk::ext_contract(ext_email_dkim_verifier)]
pub trait EmailDkimVerifier {
    /// Start DKIM verification onchain for a full email blob.
    #[payable]
    fn request_email_verification_onchain(
        &mut self,
        payer_account_id: AccountId,
        email_blob: String,
    ) -> VerificationResult;
}

/// TEE/on-chain plaintext path: ask the EmailDKIMVerifier to verify DKIM onchain.
/// @deprecated Prefer the TEE encrypted path via `verify_encrypted_email_and_recover`.
pub fn verify_email_onchain_and_recover(
    email_dkim_verifier: &near_sdk::AccountId,
    email_blob: String,
    request_id: String,
) -> Promise {
    log!("verify_email_onchain_and_recover called (TEE/on-chain plaintext path)");
    let attached = env::attached_deposit().as_yoctonear();
    let caller = env::predecessor_account_id(); // relay account
                                                // relay account pays for Outlayer fees

    ext_email_dkim_verifier::ext(email_dkim_verifier.clone())
        // Forward the full attached deposit to the DKIM verifier.
        .with_attached_deposit(NearToken::from_yoctonear(attached))
        .with_static_gas(Gas::from_tgas(50))
        .request_email_verification_onchain(caller.clone(), email_blob.clone())
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_email_onchain_result(request_id),
        )
}
/// Callback after EmailDKIMVerifier finishes for plaintext/on-chain emails.
/// @deprecated Prefer `on_verify_encrypted_email_result` used by the encrypted TEE path.
pub fn on_verify_email_onchain_result(
    contract: &mut EmailRecoverer,
    request_id: String,
    result: Result<VerificationResult, PromiseError>,
) {
    // Callback is scheduled by this contract in
    // `verify_email_onchain_and_recover`. Predecessor should always be
    // this contract account.
    assert_eq!(
        env::predecessor_account_id(),
        env::current_account_id(),
        "Unauthorized caller for on_verify_email_onchain_result"
    );

    let verification = match result {
        Ok(v) => v,
        Err(err) => {
            contract.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                format!("DKIM promise error: {err:?}"),
            );
            return;
        }
    };

    contract.update_attempt_fields_from_verifier(&request_id, &verification);

    if !verification.verified {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::DkimFailed,
            "DKIM verification returned verified = false",
        );
        return;
    }

    let current = env::current_account_id().to_string();
    if verification.account_id != current {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::Failed,
            format!(
                "verification account_id {} does not match current account {}",
                verification.account_id,
                env::current_account_id()
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
            "From: email is not in configured recovery_emails",
        );
        return;
    }

    let new_pk: PublicKey = match verification.new_public_key.parse() {
        Ok(pk) => pk,
        Err(_err) => {
            contract.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                "invalid new_public_key",
            );
            return;
        }
    };

    if !contract.consume_pending_recovery_intent(&hashed_email, &new_pk) {
        contract.fail_attempt(
            &request_id,
            RecoveryAttemptStatus::Failed,
            "verification result does not match any pending recovery intent",
        );
        return;
    }

    let email_ts = match verification.email_timestamp_ms {
        Some(ts) => ts,
        None => {
            contract.fail_attempt(
                &request_id,
                RecoveryAttemptStatus::Failed,
                "email_timestamp_ms is missing",
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
        Ok(true) => contract.update_attempt_status(&request_id, RecoveryAttemptStatus::Complete, None),
        Ok(false) => contract.update_attempt_status(
            &request_id,
            RecoveryAttemptStatus::AwaitingMoreEmails,
            None,
        ),
        Err(err) => contract.fail_attempt(&request_id, RecoveryAttemptStatus::Failed, err),
    }
}
