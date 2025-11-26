use anyhow::Result;
use email_recoverer_factory::{EmailRecoverer, RecoveryPolicy, HashedEmail};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId};
use near_workspaces::types::Gas;
use serde_json::json;

fn get_context(account_id: &str) -> VMContextBuilder {
    let mut builder = VMContextBuilder::new();
    let account: AccountId = account_id.parse().unwrap();
    builder
        .current_account_id(account.clone())
        .signer_account_id(account.clone())
        .predecessor_account_id(account);
    builder
}

/// Unit tests using near-sdk's testing_env
#[test]
fn test_init_and_get_policy() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    let policy = contract.get_policy();
    assert_eq!(policy.min_required_emails, 1);
    assert!(policy.max_age_ms > 0);
}

#[test]
fn test_set_and_get_recovery_emails() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    let email1: HashedEmail = vec![1, 2, 3];
    let email2: HashedEmail = vec![4, 5, 6];

    contract.set_recovery_emails(vec![email1.clone(), email2.clone()]);
    let stored = contract.get_recovery_emails();

    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0], email1);
    assert_eq!(stored[1], email2);
}

#[test]
fn test_set_and_get_zk_email_verifier() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    // Initial value from constructor
    assert_eq!(
        contract.get_zk_email_verifier(),
        "zk-email-verifier.testnet"
            .parse::<AccountId>()
            .unwrap()
    );

    // Updated value via setter
    contract.set_zk_email_verifier("new-zk-verifier.testnet".parse().unwrap());
    assert_eq!(
        contract.get_zk_email_verifier(),
        "new-zk-verifier.testnet"
            .parse::<AccountId>()
            .unwrap()
    );
}

#[test]
fn test_set_and_get_email_dkim_verifier() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    // Initial value from constructor
    assert_eq!(
        contract.get_email_dkim_verifier(),
        "email-dkim-verifier.testnet"
            .parse::<AccountId>()
            .unwrap()
    );

    // Updated value via setter
    contract.set_email_dkim_verifier("new-dkim-verifier.testnet".parse().unwrap());
    assert_eq!(
        contract.get_email_dkim_verifier(),
        "new-dkim-verifier.testnet"
            .parse::<AccountId>()
            .unwrap()
    );
}

#[test]
fn test_verify_and_recover_does_not_panic() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    // Just ensure that calling the method constructs a promise without panicking.
    let proof = vec![1u8, 2, 3];
    let inputs = vec![4u8, 5, 6];
    let _promise = contract.verify_and_recover(proof, inputs);
}

#[test]
fn test_verify_dkim_and_recover_does_not_panic() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    let payload = vec![10u8, 20, 30];
    let _promise = contract.verify_dkim_and_recover(payload);
}

/// Helper to compile the contract and create a sandbox + deployment.
async fn setup_recoverer(
) -> Result<(
    near_workspaces::Worker<near_workspaces::network::Sandbox>,
    near_workspaces::Contract,
    Vec<u8>,
)> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;

    // Deploy the EmailRecoverer contract
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Create dummy verifier accounts used for initialization
    let zk_verifier = sandbox.dev_create_account().await?;
    let dkim_verifier = sandbox.dev_create_account().await?;

    // Initialize the recoverer with default policy and no recovery emails
    let outcome = contract
        .call("new")
        .args_json(json!({
            "zk_email_verifier": zk_verifier.id(),
            "email_dkim_verifier": dkim_verifier.id(),
            "policy": null,
            "recovery_emails": [],
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(
        outcome.is_success(),
        "EmailRecoverer initialization should succeed"
    );

    Ok((sandbox, contract, contract_wasm))
}

/// Integration test: deploy and initialize EmailRecoverer on a sandbox account.
#[tokio::test]
async fn test_deploy_email_recoverer() -> Result<()> {
    let (_sandbox, _contract, _wasm) = setup_recoverer().await?;
    Ok(())
}

/// Integration test: once deployed, a user can call set/get recovery emails.
#[tokio::test]
async fn test_user_can_set_and_get_recovery_emails_in_sandbox() -> Result<()> {
    let contract_wasm = near_workspaces::compile_project("./").await?;
    let sandbox = near_workspaces::sandbox().await?;

    // Deploy EmailRecoverer contract to a fresh account.
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Dummy verifier accounts for initialization.
    let zk_verifier = sandbox.dev_create_account().await?;
    let dkim_verifier = sandbox.dev_create_account().await?;

    let init_outcome = contract
        .call("new")
        .args_json(json!({
            "zk_email_verifier": zk_verifier.id(),
            "email_dkim_verifier": dkim_verifier.id(),
            "policy": null,
            "recovery_emails": [],
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(init_outcome.is_success(), "EmailRecoverer init should succeed");

    // Create a user account that will act as the caller.
    let user = sandbox.dev_create_account().await?;

    let recovery_emails: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6]];

    let set_outcome = user
        .call(contract.id(), "set_recovery_emails")
        .args_json(json!({
            "recovery_emails": recovery_emails,
        }))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;

    assert!(
        set_outcome.is_success(),
        "set_recovery_emails should succeed when called by a user"
    );

    let view_result = contract
        .view("get_recovery_emails")
        .args_json(json!({}))
        .await?;

    let stored: Vec<Vec<u8>> = view_result.json()?;
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0], vec![1, 2, 3]);
    assert_eq!(stored[1], vec![4, 5, 6]);

    Ok(())
}
