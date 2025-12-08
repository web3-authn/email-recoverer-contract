use near_sdk::{env, log, Gas, NearToken, Promise, PromiseError, AccountId};
use serde_json::Value as JsonValue;

use crate::{ext_self, EmailRecoverer, VerificationResult};

/// External interface for the global EmailDKIMVerifier contract (TEE path).
#[near_sdk::ext_contract(ext_email_dkim_verifier)]
pub trait EmailDkimVerifier {
    /// Start DKIM verification via Outlayer/TEE for a full email blob.
    ///
    /// `params` is an optional JSON object that is forwarded verbatim to the
    /// global `EmailDkimVerifier` contract.
    #[payable]
    fn request_email_verification(
        &mut self,
        payer_account_id: AccountId,
        email_blob: Option<String>,
        encrypted_email_blob: Option<JsonValue>,
        params: Option<JsonValue>,
    ) -> VerificationResult;
}

/// TEE/on-chain plaintext path: ask the EmailDKIMVerifier to verify DKIM
/// for the given email blob and, if successful, potentially recover this
/// account according to the configured policy.
pub fn verify_email_onchain_and_recover(
    email_dkim_verifier: &near_sdk::AccountId,
    email_blob: String,
) -> Promise {
    log!("verify_email_onchain_and_recover called (TEE/on-chain plaintext path)");
    let attached = env::attached_deposit().as_yoctonear();
    let caller = env::predecessor_account_id(); // relay account
    // relay account pays for Outlayer fees

    ext_email_dkim_verifier::ext(email_dkim_verifier.clone())
        // Forward the full attached deposit to the DKIM verifier.
        .with_attached_deposit(NearToken::from_yoctonear(attached))
        .with_static_gas(Gas::from_tgas(50))
        .request_email_verification(caller.clone(), Some(email_blob.clone()), None, None)
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_email_onchain_result(email_blob),
        )
}

/// TEE/encrypted path: ask the EmailDKIMVerifier to verify DKIM for the
/// given encrypted email blob and, if successful, potentially recover this
/// account according to the configured policy.
///
/// The `encrypted_email_blob` is forwarded as-is to the DKIM verifier
/// contract; its exact structure is defined there (for example, it may
/// contain a ciphertext and any associated metadata required for decryption).
pub fn verify_encrypted_email_and_recover(
    email_dkim_verifier: &near_sdk::AccountId,
    encrypted_email_blob: JsonValue,
) -> Promise {
    log!("verify_encrypted_email_and_recover called (TEE/encrypted path)");
    let attached = env::attached_deposit().as_yoctonear();
    let caller = env::predecessor_account_id(); // relay account
    // relay account pays for Outlayer fees

    ext_email_dkim_verifier::ext(email_dkim_verifier.clone())
        // Forward the full attached deposit to the DKIM verifier.
        .with_attached_deposit(NearToken::from_yoctonear(attached))
        .with_static_gas(Gas::from_tgas(50))
        .request_email_verification(caller.clone(), None, Some(encrypted_email_blob), None)
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_encrypted_email_result(),
        )
}

/// Callback after EmailDKIMVerifier finishes for plaintext/on-chain emails.
pub fn on_verify_email_onchain_result(
    contract: &mut EmailRecoverer,
    email_blob: String,
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
        Err(_err) => {
            log!("Email DKIM verification promise failed");
            return;
        }
    };

    if !verification.verified {
        log!("Email DKIM verification returned verified = false");
        return;
    }

    let current = env::current_account_id().to_string();
    if verification.account_id != current {
        log!(
            "Email DKIM verification account_id {} does not match current account {}",
            verification.account_id,
            env::current_account_id()
        );
        return;
    }

    // Compute hashed email from the DKIM-verifier-provided From: address
    // and ensure it is configured.
    let hashed_email = contract.hash_from_email_for_current_account(&verification.from_address);

    if !contract.is_configured_recovery_email(&hashed_email) {
        log!("From: email is not in configured recovery_emails");
        return;
    }

    log!(
        "Email DKIM verification succeeded for email blob of length {} and new key string length {}",
        email_blob.len(),
        verification.new_public_key.len()
    );

    let email_ts = match verification.email_timestamp_ms {
        Some(ts) => ts,
        None => {
            log!("Email DKIM verification succeeded but email_timestamp_ms is missing");
            return;
        }
    };

    contract.mark_verified_and_maybe_recover(
        hashed_email,
        verification.new_public_key.clone().into_bytes(),
        email_ts,
    );
}

/// Callback after EmailDKIMVerifier finishes for encrypted emails.
pub fn on_verify_encrypted_email_result(
    contract: &mut EmailRecoverer,
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
        Err(_err) => {
            log!("Encrypted email DKIM verification promise failed");
            return;
        }
    };

    if !verification.verified {
        log!("Encrypted email DKIM verification returned verified = false");
        return;
    }

    let current = env::current_account_id().to_string();
    if verification.account_id != current {
        log!(
            "Encrypted email DKIM verification account_id {} does not match current account {}",
            verification.account_id,
            env::current_account_id()
        );
        return;
    }

    // Compute hashed email from the DKIM-verifier-provided From: address
    // and ensure it is configured.
    let hashed_email = contract.hash_from_email_for_current_account(&verification.from_address);

    if !contract.is_configured_recovery_email(&hashed_email) {
        log!("From: email is not in configured recovery_emails");
        return;
    }

    let email_ts = match verification.email_timestamp_ms {
        Some(ts) => ts,
        None => {
            log!("Encrypted email DKIM verification succeeded but email_timestamp_ms is missing");
            return;
        }
    };

    contract.mark_verified_and_maybe_recover(
        hashed_email,
        verification.new_public_key.clone().into_bytes(),
        email_ts,
    );
}
