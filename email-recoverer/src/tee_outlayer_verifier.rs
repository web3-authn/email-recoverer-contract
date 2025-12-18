use near_sdk::{env, log, Gas, NearToken, Promise, PromiseError, AccountId};
use serde_json::{Value as JsonValue, json};
use crate::{ext_self, EmailRecoverer, VerificationResult};

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
) -> Promise {

    let attached = env::attached_deposit().as_yoctonear();
    let caller = env::predecessor_account_id(); // relay account pays for Outlayer fees

    ext_email_dkim_verifier::ext(email_dkim_verifier.clone())
        // Forward the full attached deposit to the DKIM verifier.
        .with_attached_deposit(NearToken::from_yoctonear(attached))
        .with_static_gas(Gas::from_tgas(50))
        .request_email_verification_private(
            caller.clone(),
            encrypted_email_blob,
            aead_context,
        ).then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(50))
                .on_verify_encrypted_email_result(),
        )
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
        verification.new_public_key.clone(),
        email_ts,
    );
}
