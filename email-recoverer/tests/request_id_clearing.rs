use anyhow::Result;
use email_recoverer_contract::{RecoveryAttempt, RecoveryAttemptStatus, HASHED_EMAIL_LEN};
use near_workspaces::types::Gas;
use serde_json::json;

#[tokio::test]
async fn request_id_is_cleared_after_yield_timeout() -> Result<()> {
    let wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;
    let contract = sandbox.dev_deploy(&wasm).await?;

    // Dummy verifier accounts for initialization.
    let zk_verifier = sandbox.dev_create_account().await?;
    let dkim_verifier = sandbox.dev_create_account().await?;

    let init_outcome = contract
        .call("init_email_recovery")
        .args_json(json!({
            "zk_email_verifier": zk_verifier.id(),
            "email_dkim_verifier": dkim_verifier.id(),
            "policy": null,
            "recovery_emails": vec![vec![0u8; HASHED_EMAIL_LEN]],
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert!(init_outcome.is_success());

    // NOTE: We can't call the internal Rust helpers `fail_attempt()` /
    // `update_attempt_status()` directly over RPC, but we can exercise them via
    // public entrypoints that invoke them internally.
    //
    // - `fail_attempt()` is exercised via an early policy failure.
    // - `update_attempt_status()` is exercised by reaching the "verifying" stage
    //   (which updates status) before the cross-contract call fails and the
    //   callback records a failure.

    let request_id_fail_attempt = "REQ_YIELD_TIMEOUT_FAIL_ATTEMPT_1";
    let request_id_update_attempt_status = "REQ_YIELD_TIMEOUT_UPDATE_STATUS_1";

    // Early policy-fail path still stores + schedules yield cleanup (calls `fail_attempt`).
    let _ = contract
        .call("verify_encrypted_email_and_recover")
        .args_json(json!({
            "encrypted_email_blob": { "ciphertext": "deadbeef" },
            "aead_context": {
                "account_id": contract.id(),
                "network_id": "testnet",
                "payer_account_id": contract.id()
            },
            "expected_hashed_email": vec![1u8; HASHED_EMAIL_LEN], // not configured -> PolicyFailed
            "expected_new_public_key": "ed25519:11111111111111111111111111111111",
            "request_id": request_id_fail_attempt,
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    let now_fail_attempt: Option<RecoveryAttempt> = contract
        .view("get_recovery_attempt")
        .args_json(json!({ "request_id": request_id_fail_attempt }))
        .await?
        .json()?;
    let now_fail_attempt = now_fail_attempt.expect("attempt should exist immediately (fail_attempt path)");
    assert_eq!(now_fail_attempt.status, RecoveryAttemptStatus::PolicyFailed);

    // Reaching the verifying stage updates status via `update_attempt_status`.
    // We still expect yield cleanup to remove the entry later even if the
    // cross-contract call fails (the dummy verifier account has no code).
    let _ = contract
        .call("verify_encrypted_email_and_recover")
        .args_json(json!({
            "encrypted_email_blob": { "ciphertext": "deadbeef" },
            "aead_context": {
                "account_id": contract.id(),
                "network_id": "testnet",
                "payer_account_id": contract.id()
            },
            "expected_hashed_email": vec![0u8; HASHED_EMAIL_LEN], // configured -> reaches VerifyingDkim
            "expected_new_public_key": "ed25519:11111111111111111111111111111111",
            "request_id": request_id_update_attempt_status,
        }))
        // Needs enough prepaid gas to create the cross-contract call + callback
        // (50 Tgas + 50 Tgas) plus the yield cleanup promise.
        .gas(Gas::from_tgas(200))
        .transact()
        .await?;

    let now_update_attempt_status: Option<RecoveryAttempt> = contract
        .view("get_recovery_attempt")
        .args_json(json!({ "request_id": request_id_update_attempt_status }))
        .await?
        .json()?;
    let now_update_attempt_status =
        now_update_attempt_status.expect("attempt should exist immediately (update_attempt_status path)");
    assert!(
        now_update_attempt_status.status != RecoveryAttemptStatus::Started,
        "status should have advanced past Started"
    );

    sandbox.fast_forward(220).await?;
    let _ = sandbox.view_block().await?;

    let later_fail_attempt: Option<RecoveryAttempt> = contract
        .view("get_recovery_attempt")
        .args_json(json!({ "request_id": request_id_fail_attempt }))
        .await?
        .json()?;
    assert!(
        later_fail_attempt.is_none(),
        "attempt should be cleared after timeout (fail_attempt path)"
    );

    let later_update_attempt_status: Option<RecoveryAttempt> = contract
        .view("get_recovery_attempt")
        .args_json(json!({ "request_id": request_id_update_attempt_status }))
        .await?
        .json()?;
    assert!(
        later_update_attempt_status.is_none(),
        "attempt should be cleared after timeout (update_attempt_status path)"
    );

    Ok(())
}
