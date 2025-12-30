use anyhow::Result;
use email_recoverer_contract::{
    AeadContext, EmailRecoverer, HashedEmail, ProofInput, RecoveryAttemptStatus, RecoveryPolicy,
    VerificationResult, ZkEmailContext, HASHED_EMAIL_LEN,
};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{env, testing_env, AccountId, CurveType, PublicKey};
use near_workspaces::types::Gas;
use serde_json::json;

fn test_hashed_email(byte: u8) -> HashedEmail {
    vec![byte; HASHED_EMAIL_LEN]
}

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

    let contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![test_hashed_email(0)],
    );

    let policy = contract.get_policy();
    assert_eq!(policy.min_required_emails, 1);
    assert!(policy.max_age_ms > 0);
}

#[test]
fn test_set_and_get_recovery_emails() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![test_hashed_email(0)],
    );

    let email1: HashedEmail = test_hashed_email(1);
    let email2: HashedEmail = test_hashed_email(2);

    contract.set_recovery_emails(vec![email1.clone(), email2.clone()]);
    let stored = contract.get_recovery_emails();

    let mut stored_sorted = stored;
    stored_sorted.sort();
    let mut expected = vec![email1, email2];
    expected.sort();
    assert_eq!(stored_sorted, expected);
}

#[test]
fn test_recovery_policy_one_of_two_recent() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier-v1.testnet".parse().unwrap(),
        "email-dkim-verifier-v1.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 1,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![test_hashed_email(0)],
    );

    let email1: HashedEmail = test_hashed_email(1);
    let email2: HashedEmail = test_hashed_email(2);
    contract.set_recovery_emails(vec![email1.clone(), email2.clone()]);

    // Initially, no recent verified emails.
    assert_eq!(contract.get_recent_verified_emails().len(), 0);

    // Simulate a successful verification of email1 "now".
    {
        let now_ms = 1_000_000;
        let mut context_now = VMContextBuilder::new();
        context_now
            .current_account_id("alice.testnet".parse().unwrap())
            .signer_account_id("alice.testnet".parse().unwrap())
            .predecessor_account_id("alice.testnet".parse().unwrap())
            .block_timestamp(now_ms * 1_000_000);
        testing_env!(context_now.build());

        let pk =
            PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
        contract.debug_set_verified_email_for_testing(email1.clone(), pk, now_ms);
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

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 1_000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    let e1: HashedEmail = test_hashed_email(1);
    let e2: HashedEmail = test_hashed_email(2);
    let e3: HashedEmail = test_hashed_email(3);
    contract.set_recovery_emails(vec![e1.clone(), e2.clone(), e3.clone()]);

    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");

    // At time t = 10 ms, verify e1 and e2.
    let start_ms = 10;
    contract.debug_set_verified_email_for_testing(e1.clone(), pk.clone(), start_ms);
    contract.debug_set_verified_email_for_testing(e2.clone(), pk.clone(), start_ms);

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
fn test_recovery_policy_is_scoped_to_new_public_key() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier-v1.testnet".parse().unwrap(),
        "email-dkim-verifier-v1.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    let email1: HashedEmail = test_hashed_email(1);
    let email2: HashedEmail = test_hashed_email(2);
    contract.set_recovery_emails(vec![email1.clone(), email2.clone()]);

    let pk1 = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let pk2 = PublicKey::from_parts(CurveType::ED25519, vec![1u8; 32]).expect("valid ed25519 key");

    let now_ms = 1_000_000;
    contract.debug_set_verified_email_for_testing(email1.clone(), pk1.clone(), now_ms);
    contract.debug_set_verified_email_for_testing(email2.clone(), pk2.clone(), now_ms);

    assert!(
        !contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk1.clone()),
        "Should not mix verified emails across different new_public_keys"
    );
    assert!(
        !contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk2.clone()),
        "Should not mix verified emails across different new_public_keys"
    );

    // If both emails are verified for the same key, the policy should be satisfied.
    contract.debug_set_verified_email_for_testing(email1.clone(), pk2.clone(), now_ms);
    assert!(
        contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk2),
        "Should satisfy policy once both verifications target the same new_public_key"
    );
}

#[test]
fn test_recovery_policy_only_counts_recent_emails_for_specific_new_public_key() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier-v1.testnet".parse().unwrap(),
        "email-dkim-verifier-v1.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 1_000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    let email1: HashedEmail = test_hashed_email(1);
    let email2: HashedEmail = test_hashed_email(2);
    let email3: HashedEmail = test_hashed_email(3);
    contract.set_recovery_emails(vec![email1.clone(), email2.clone(), email3.clone()]);

    let pk_target =
        PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let pk_other =
        PublicKey::from_parts(CurveType::ED25519, vec![1u8; 32]).expect("valid ed25519 key");

    let now_ms = 10_000;

    // One recent email for target key.
    contract.debug_set_verified_email_for_testing(email1.clone(), pk_target.clone(), now_ms);
    // One stale email for target key (outside max_age_ms).
    contract.debug_set_verified_email_for_testing(
        email2.clone(),
        pk_target.clone(),
        now_ms - 1_001,
    );
    // One recent email, but for a different key.
    contract.debug_set_verified_email_for_testing(email3.clone(), pk_other.clone(), now_ms);

    assert!(
        !contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk_target.clone()),
        "Should ignore stale verifications and verifications for other keys"
    );
    assert!(
        !contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk_other.clone()),
        "Should only count verifications targeting the provided new_public_key"
    );

    // Make the second email recent for the target key; now it should satisfy the policy.
    contract.debug_set_verified_email_for_testing(email2.clone(), pk_target.clone(), now_ms - 500);
    assert!(contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk_target));
}

#[test]
fn test_recovery_policy_does_not_mix_new_public_keys_then_satisfies_for_pk1() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier-v1.testnet".parse().unwrap(),
        "email-dkim-verifier-v1.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    let email1: HashedEmail = test_hashed_email(1);
    let email2: HashedEmail = test_hashed_email(2);
    contract.set_recovery_emails(vec![email1.clone(), email2.clone()]);

    let pk1 = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let pk2 = PublicKey::from_parts(CurveType::ED25519, vec![1u8; 32]).expect("valid ed25519 key");

    let now_ms = 1_000_000;
    contract.debug_set_verified_email_for_testing(email1.clone(), pk1.clone(), now_ms);
    contract.debug_set_verified_email_for_testing(email2.clone(), pk2.clone(), now_ms);

    // One verification for pk1 and one for pk2 should NOT satisfy the policy for either key.
    assert!(!contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk1.clone()));
    assert!(!contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk2.clone()));

    // Add a second verification targeting pk1; now pk1 should satisfy the policy.
    contract.debug_set_verified_email_for_testing(email2.clone(), pk1.clone(), now_ms);
    assert!(contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk1));
    assert!(!contract.debug_is_recovery_policy_satisfied_for_testing(now_ms, pk2));
}

#[test]
fn test_set_and_get_zk_email_verifier() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![test_hashed_email(0)],
    );

    // Initial value from constructor
    assert_eq!(
        contract.get_zk_email_verifier(),
        "zk-email-verifier.testnet".parse::<AccountId>().unwrap()
    );

    // Updated value via setter
    contract.set_zk_email_verifier("new-zk-verifier.testnet".parse().unwrap());
    assert_eq!(
        contract.get_zk_email_verifier(),
        "new-zk-verifier.testnet".parse::<AccountId>().unwrap()
    );
}

#[test]
fn test_set_and_get_email_dkim_verifier() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![test_hashed_email(0)],
    );

    // Initial value from constructor
    assert_eq!(
        contract.get_email_dkim_verifier(),
        "email-dkim-verifier.testnet".parse::<AccountId>().unwrap()
    );

    // Updated value via setter
    contract.set_email_dkim_verifier("new-dkim-verifier.testnet".parse().unwrap());
    assert_eq!(
        contract.get_email_dkim_verifier(),
        "new-dkim-verifier.testnet".parse::<AccountId>().unwrap()
    );
}

#[test]
fn test_verify_zkemail_and_recover_does_not_panic() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![hashed_email],
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
    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let context = ZkEmailContext {
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(&pk),
        from_email: "alice@example.com".to_string(),
        timestamp: "0".to_string(),
    };

    let _promise = contract.verify_zkemail_and_recover(
        proof,
        public_inputs,
        context,
        "REQ_ZK_1".to_string(),
    );
}

#[test]
fn test_verify_zkemail_and_recover_stores_attempt_immediately() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![hashed_email],
    );

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
    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let expected_new_public_key = String::from(&pk);
    let context = ZkEmailContext {
        account_id: "alice.testnet".to_string(),
        new_public_key: expected_new_public_key.clone(),
        from_email: "alice@example.com".to_string(),
        timestamp: "0".to_string(),
    };

    let request_id = "REQ_ZK_STORE".to_string();
    let _promise =
        contract.verify_zkemail_and_recover(proof, public_inputs, context, request_id.clone());

    let attempt = contract
        .get_recovery_attempt(request_id)
        .expect("attempt should be stored");
    assert_eq!(attempt.status, RecoveryAttemptStatus::VerifyingZkEmail);
    assert_eq!(attempt.new_public_key, Some(expected_new_public_key));
}

#[test]
fn test_verify_email_onchain_and_recover_does_not_panic() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![hashed_email.clone()],
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

    let email_blob = "From: alice@example.com\nTo: recover@web3authn.org\n\nTest".to_string();
    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let expected_new_public_key = String::from(&pk);
    let _promise = contract.verify_email_onchain_and_recover(
        email_blob,
        hashed_email,
        expected_new_public_key,
        "REQ_ONCHAIN_1".to_string(),
    );
}

#[test]
fn test_verify_email_onchain_and_recover_stores_attempt_immediately() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![hashed_email.clone()],
    );

    let email_blob = "From: alice@example.com\nTo: recover@web3authn.org\n\nTest".to_string();
    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let expected_new_public_key = String::from(&pk);
    let request_id = "REQ_ONCHAIN_STORE".to_string();

    let _promise = contract.verify_email_onchain_and_recover(
        email_blob,
        hashed_email,
        expected_new_public_key.clone(),
        request_id.clone(),
    );

    let attempt = contract
        .get_recovery_attempt(request_id)
        .expect("attempt should be stored");
    assert_eq!(attempt.status, RecoveryAttemptStatus::VerifyingDkim);
    assert_eq!(attempt.new_public_key, Some(expected_new_public_key));
}

#[test]
fn test_verify_encrypted_email_and_recover_stores_attempt_immediately() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![test_hashed_email(7)],
    );

    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let expected_new_public_key = String::from(&pk);
    let request_id = "REQ123".to_string();

    let _promise = contract.verify_encrypted_email_and_recover(
        json!({"ciphertext": "deadbeef"}),
        AeadContext {
            account_id: "alice.testnet".to_string(),
            network_id: "testnet".to_string(),
            payer_account_id: "relayer.testnet".to_string(),
        },
        test_hashed_email(7),
        expected_new_public_key.clone(),
        request_id.clone(),
    );

    let attempt = contract
        .get_recovery_attempt(request_id)
        .expect("attempt should be stored");
    assert_eq!(attempt.status, RecoveryAttemptStatus::VerifyingDkim);
    assert_eq!(attempt.new_public_key, Some(expected_new_public_key));
}

#[test]
fn test_verify_encrypted_email_and_recover_policy_failure_is_recorded() {
    let context = get_context("alice.testnet");
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        None,
        vec![test_hashed_email(1)],
    );

    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let expected_new_public_key = String::from(&pk);
    let request_id = "REQ456".to_string();

    let _promise = contract.verify_encrypted_email_and_recover(
        json!({"ciphertext": "deadbeef"}),
        AeadContext {
            account_id: "alice.testnet".to_string(),
            network_id: "testnet".to_string(),
            payer_account_id: "relayer.testnet".to_string(),
        },
        test_hashed_email(2), // not configured
        expected_new_public_key,
        request_id.clone(),
    );

    let attempt = contract
        .get_recovery_attempt(request_id)
        .expect("attempt should be stored");
    assert_eq!(attempt.status, RecoveryAttemptStatus::PolicyFailed);
    assert!(
        attempt
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("configured recovery_emails"),
        "unexpected error message: {:?}",
        attempt.error
    );
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
    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    // Pre-compute the hashed email exactly as the contract does for a bare address.
    let canonical = "n6378056@gmail.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    // Configure this hashed email as a recovery email.
    contract.set_recovery_emails(vec![hashed_email.clone(), test_hashed_email(9)]);

    // Simulate a DKIM verification result where the From: address includes a
    // display name, e.g. "Pta <n6378056@gmail.com>".
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(
            &PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key"),
        ),
        from_address: "Pta <n6378056@gmail.com>".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    // Set a pending expectation so the callback can be accepted.
    let _ = contract.verify_email_onchain_and_recover(
        "dummy".to_string(),
        hashed_email.clone(),
        verification.new_public_key.clone(),
        "REQ_ONCHAIN_DISPLAY".to_string(),
    );

    // Call the DKIM plaintext callback directly; this should treat the
    // display-name form as matching the configured recovery email and mark it
    // as verified.
    contract.on_verify_email_onchain_result("REQ_ONCHAIN_DISPLAY".to_string(), Ok(verification));

    let recent = contract.get_recent_verified_emails();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0], hashed_email);
}

#[test]
fn test_on_verify_email_onchain_result_is_noop_without_matching_pending_intent() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![hashed_email.clone(), test_hashed_email(9)],
    );

    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(&pk),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    // Call the callback without setting any pending expectation. This should be a no-op.
    contract.on_verify_email_onchain_result("REQ_ONCHAIN_NO_PENDING".to_string(), Ok(verification));
    assert_eq!(contract.get_recent_verified_emails().len(), 0);
}

#[test]
fn test_on_verify_encrypted_email_result_is_noop_without_matching_pending_intent() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![hashed_email.clone(), test_hashed_email(9)],
    );

    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(&pk),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    // Call the callback without setting any pending expectation. This should be a no-op.
    contract.on_verify_encrypted_email_result("dummy".to_string(), Ok(verification));
    assert_eq!(contract.get_recent_verified_emails().len(), 0);
}

#[test]
fn test_on_verify_zkemail_result_is_noop_without_matching_pending_intent() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![hashed_email.clone(), test_hashed_email(9)],
    );

    let pk = PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(&pk),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    // Call the callback without setting any pending expectation. This should be a no-op.
    contract.on_verify_zkemail_result("REQ_ZK_NO_PENDING".to_string(), Ok(verification));
    assert_eq!(contract.get_recent_verified_emails().len(), 0);
}

#[test]
fn test_on_verify_email_onchain_result_does_not_consume_pending_intent_on_mismatch() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![hashed_email.clone(), test_hashed_email(9)],
    );

    let pk_expected =
        PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key");
    let pk_other =
        PublicKey::from_parts(CurveType::ED25519, vec![1u8; 32]).expect("valid ed25519 key");

    let verification_other_pk = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(&pk_other),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    // Set pending expectation for pk_expected...
    let _ = contract.verify_email_onchain_and_recover(
        "dummy".to_string(),
        hashed_email.clone(),
        String::from(&pk_expected),
        "REQ_ONCHAIN_MISMATCH".to_string(),
    );

    // ...but callback arrives with a different key, so it should be a no-op and
    // should not consume the pending intent.
    contract.on_verify_email_onchain_result(
        "REQ_ONCHAIN_MISMATCH".to_string(),
        Ok(verification_other_pk),
    );
    assert_eq!(contract.get_recent_verified_emails().len(), 0);

    // Now deliver the callback with the expected key; it should be accepted.
    let verification_expected_pk = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(&pk_expected),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000),
    };
    contract.on_verify_email_onchain_result(
        "REQ_ONCHAIN_MISMATCH".to_string(),
        Ok(verification_expected_pk),
    );
    assert_eq!(contract.get_recent_verified_emails().len(), 1);
}

#[test]
fn test_rejects_future_email_timestamps() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    contract.set_recovery_emails(vec![hashed_email.clone(), test_hashed_email(9)]);

    // Far-future timestamp should be rejected and not stored.
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(
            &PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key"),
        ),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000 + 24 * 60 * 60 * 1000),
    };

    let _ = contract.verify_email_onchain_and_recover(
        "dummy".to_string(),
        hashed_email.clone(),
        verification.new_public_key.clone(),
        "REQ_ONCHAIN_FUTURE".to_string(),
    );

    contract.on_verify_email_onchain_result("REQ_ONCHAIN_FUTURE".to_string(), Ok(verification));
    assert_eq!(contract.get_recent_verified_emails().len(), 0);
}

#[test]
fn test_rejects_stale_email_timestamps() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(10_000 * 1_000_000);
    testing_env!(context.build());

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 2,
            max_age_ms: 1_000,
        }),
        vec![test_hashed_email(0), test_hashed_email(1)],
    );

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    contract.set_recovery_emails(vec![hashed_email.clone(), test_hashed_email(9)]);

    // Too-old timestamp (outside max_age_ms) should be rejected and not stored.
    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(
            &PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key"),
        ),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(10_000 - 1_001),
    };

    let _ = contract.verify_email_onchain_and_recover(
        "dummy".to_string(),
        hashed_email.clone(),
        verification.new_public_key.clone(),
        "REQ_ONCHAIN_STALE".to_string(),
    );

    contract.on_verify_email_onchain_result("REQ_ONCHAIN_STALE".to_string(), Ok(verification));
    assert_eq!(contract.get_recent_verified_emails().len(), 0);
}

#[test]
fn test_clears_verified_emails_after_successful_recovery() {
    let mut context = VMContextBuilder::new();
    context
        .current_account_id("alice.testnet".parse().unwrap())
        .signer_account_id("alice.testnet".parse().unwrap())
        .predecessor_account_id("alice.testnet".parse().unwrap())
        .block_timestamp(1_000 * 1_000_000);
    testing_env!(context.build());

    let canonical = "alice@example.com".to_ascii_lowercase();
    let mut data = canonical.into_bytes();
    data.push(b'|');
    data.extend("alice.testnet".as_bytes());
    let hashed_email = env::sha256(&data);

    let mut contract = EmailRecoverer::init_email_recovery(
        "zk-email-verifier.testnet".parse().unwrap(),
        "email-dkim-verifier.testnet".parse().unwrap(),
        Some(RecoveryPolicy {
            min_required_emails: 1,
            max_age_ms: 30 * 60 * 1000,
        }),
        vec![hashed_email.clone()],
    );

    let verification = VerificationResult {
        verified: true,
        account_id: "alice.testnet".to_string(),
        new_public_key: String::from(
            &PublicKey::from_parts(CurveType::ED25519, vec![0u8; 32]).expect("valid ed25519 key"),
        ),
        from_address: "alice@example.com".to_string(),
        email_timestamp_ms: Some(1_000),
    };

    let _ = contract.verify_email_onchain_and_recover(
        "dummy".to_string(),
        hashed_email.clone(),
        verification.new_public_key.clone(),
        "REQ_ONCHAIN_CLEAR".to_string(),
    );

    contract.on_verify_email_onchain_result("REQ_ONCHAIN_CLEAR".to_string(), Ok(verification));
    assert_eq!(contract.get_recent_verified_emails().len(), 0);
}

/// Helper to compile the contract and create a sandbox + deployment.
async fn setup_recoverer() -> Result<(
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

    assert!(
        init_outcome.is_success(),
        "EmailRecoverer init should succeed"
    );

    let recovery_emails: Vec<Vec<u8>> =
        vec![vec![1u8; HASHED_EMAIL_LEN], vec![2u8; HASHED_EMAIL_LEN]];

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
    assert_eq!(stored[0], vec![1u8; HASHED_EMAIL_LEN]);
    assert_eq!(stored[1], vec![2u8; HASHED_EMAIL_LEN]);

    Ok(())
}
