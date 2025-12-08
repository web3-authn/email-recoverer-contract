use anyhow::Result;
use email_recoverer_contract::{
    EmailRecoverer,
    RecoveryPolicy,
    HashedEmail,
    ProofInput,
    VerificationResult,
};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId, env};
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
fn test_recovery_policy_one_of_two_recent() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier-v1.testnet".parse().unwrap(),
        "email-dkim-verifier-v1.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 1,
            max_age_ms: 30 * 60 * 1000,
        }),
        Vec::new(),
    );

    let email1: HashedEmail = vec![1, 2, 3];
    let email2: HashedEmail = vec![4, 5, 6];
    contract.set_recovery_emails(vec![email1.clone(), email2.clone()]);

    // Initially, no recent verified emails.
    assert_eq!(contract.get_recent_verified_emails().len(), 0);

    // Simulate a successful verification of email1 "now".
    {
        let now_ms = 1_000_000;
        contract.debug_set_verified_timestamp_for_testing(email1.clone(), now_ms);
        assert_eq!(contract.get_recent_verified_emails().len(), 1);
    }
}

#[test]
fn test_recovery_policy_two_of_three_with_expiry() {
    // Start with a specific block timestamp so we can reason about recency.
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        // Block timestamp is in nanoseconds; this corresponds to 10 ms.
        .block_timestamp(10 * 1_000_000);
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 1_000,
        }),
        Vec::new(),
    );

    let e1: HashedEmail = vec![1];
    let e2: HashedEmail = vec![2];
    let e3: HashedEmail = vec![3];
    contract.set_recovery_emails(vec![e1.clone(), e2.clone(), e3.clone()]);

    // At time t = 10 ms, verify e1 and e2.
    let start_ms = 10;
    contract.debug_set_verified_timestamp_for_testing(e1.clone(), start_ms);
    contract.debug_set_verified_timestamp_for_testing(e2.clone(), start_ms);

    // At time t = 10 + max_age_ms - 1, both are still recent.
    let now_ms = start_ms + contract.get_policy().max_age_ms - 1;
    let mut context_recent = VMContextBuilder::new();
    context_recent
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(now_ms * 1_000_000);
    testing_env!(context_recent.build());

    let recent = contract.get_recent_verified_emails();
    assert_eq!(recent.len(), 2);

    // After the window passes, none should be recent.
    let later_ms = start_ms + contract.get_policy().max_age_ms + 1;
    let mut context_late = VMContextBuilder::new();
    context_late
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(later_ms * 1_000_000);
    testing_env!(context_late.build());

    let recent_after: Vec<HashedEmail> = contract.get_recent_verified_emails();
    assert_eq!(recent_after.len(), 0);
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
fn test_verify_zkemail_and_recover_does_not_panic() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    // Just ensure that calling the method constructs a promise without panicking.
    let proof = ProofInput {
        pi_a: ["0".to_string(), "0".to_string(), "1".to_string()],
        pi_b: [
            ["0".to_string(), "0".to_string()],
            ["0".to_string(), "0".to_string()],
            ["0".to_string(), "0".to_string()],
        ],
        pi_c: ["0".to_string(), "0".to_string(), "1".to_string()],
    };
    let public_inputs = vec!["dummy".to_string()];
    let account_id = "alice.testnet".to_string();
    let new_public_key =
        "ed25519:111111111111111111111111111111111111111111111111111111111111".to_string();
    let from_email = "alice@example.com".to_string();
    let timestamp = "0".to_string();

    let _promise = contract.verify_zkemail_and_recover(
        proof,
        public_inputs,
        account_id,
        new_public_key,
        from_email,
        timestamp,
    );
}

#[test]
fn test_verify_email_onchain_and_recover_does_not_panic() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        Vec::new(),
    );

    // Attach the minimum required deposit for DKIM verification.
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .attached_deposit(near_sdk::NearToken::from_yoctonear(
            10_000_000_000_000_000_000_000,
        ));
    testing_env!(context.build());

    let email_blob =
        "From: alice@example.com\nTo: recover@web3authn.org\n\nTest".to_string();
    let _promise = contract.verify_email_onchain_and_recover(email_blob);
}

#[test]
fn test_dkim_from_with_display_name_matches_configured_email() {
    // Set up context for a specific user account.
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        // Block timestamp in nanoseconds; corresponds to 1_000 ms.
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    // Initialize contract with a simple policy: 1 recent email required.
    let mut contract = EmailRecoverer::new(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 1,
            max_age_ms: 30 * 60 * 1000,
        }),
        Vec::new(),
    );

    // Pre-compute the hashed email exactly as the contract does for a bare address.
    let canonical = "n6378056@gmail.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    // Configure this hashed email as a recovery email.
    contract.set_recovery_emails(vec![hashed_email.clone()]);

    // Simulate a DKIM verification result where the From: address includes a
    // display name, e.g. "Pta <n6378056@gmail.com>".
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key:
            "ed25519:111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
        from_address: "Pta <n6378056@gmail.com>".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    // Call the DKIM plaintext callback directly; this should treat the
    // display-name form as matching the configured recovery email and mark it
    // as verified.
    contract.on_verify_email_onchain_result("dummy".to_string(), Ok(verification));

    let recent = contract.get_recent_verified_emails();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0], hashed_email);
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

/// Integration test: once deployed, the contract account can call set/get recovery emails.
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

    let recovery_emails: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6]];

    let set_outcome = contract
        .call("set_recovery_emails")
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
