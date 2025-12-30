use anyhow::Result;
use email_recoverer_contract::HASHED_EMAIL_LEN;
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

    let request_id = "REQ_YIELD_TIMEOUT_1";

    // Early policy-fail path still stores + schedules yield cleanup.
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
            "request_id": request_id,
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    let now: Option<serde_json::Value> = contract
        .view("get_recovery_attempt")
        .args_json(json!({ "request_id": request_id }))
        .await?
        .json()?;
    assert!(now.is_some(), "attempt should exist immediately");

    sandbox.fast_forward(220).await?;
    let _ = sandbox.view_block().await?;

    let later: Option<serde_json::Value> = contract
        .view("get_recovery_attempt")
        .args_json(json!({ "request_id": request_id }))
        .await?
        .json()?;
    assert!(later.is_none(), "attempt should be cleared after timeout");

    Ok(())
}

