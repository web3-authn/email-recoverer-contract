use near_sdk::store::lookup_map::Entry;
use near_sdk::{env, near, Gas, GasWeight};
use serde_json::json;

use crate::{EmailRecoverer, EmailRecovererExt, VerificationResult};

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAttemptStatus {
    Started,
    VerifyingDkim,
    VerifyingZkEmail,
    DkimFailed,
    ZkEmailFailed,
    PolicyFailed,
    Recovering,
    AwaitingMoreEmails,
    Complete,
    Failed,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct RecoveryAttempt {
    pub request_id: String,
    pub status: RecoveryAttemptStatus,

    pub created_at_ms: u64,
    pub updated_at_ms: u64,

    pub error: Option<String>,

    pub from_address: Option<String>,
    pub email_timestamp_ms: Option<u64>,

    pub new_public_key: Option<String>,
}

#[near]
impl EmailRecoverer {
    pub fn get_recovery_attempt(&self, request_id: String) -> Option<RecoveryAttempt> {
        let request_id = request_id.trim().to_string();
        if request_id.is_empty() {
            return None;
        }

        self.recovery_attempts_by_request_id
            .get(&request_id)
            .cloned()
    }

    #[private]
    pub fn clear_recovery_attempt(&mut self, request_id: String) {
        let request_id = request_id.trim().to_string();
        if request_id.is_empty() {
            return;
        }

        self.recovery_attempts_by_request_id.remove(&request_id);
    }
}

impl EmailRecoverer {
    fn schedule_attempt_cleanup(&self, request_id: &str) {
        if request_id.is_empty() {
            return;
        }

        let args = serde_json::to_vec(&json!({ "request_id": request_id })).unwrap_or_default();
        env::promise_yield_create(
            "clear_recovery_attempt",
            &args,
            Gas::from_tgas(8),
            GasWeight(0),
            0,
        );
    }

    pub(crate) fn upsert_attempt(&mut self, attempt: RecoveryAttempt) {
        let request_id = attempt.request_id.trim().to_string();
        if request_id.is_empty() {
            return;
        }

        let is_new = !self
            .recovery_attempts_by_request_id
            .contains_key(&request_id);
        self.recovery_attempts_by_request_id
            .insert(request_id.clone(), attempt);
        if is_new {
            self.schedule_attempt_cleanup(&request_id);
        }
    }

    pub(crate) fn update_attempt_status(
        &mut self,
        request_id: &str,
        status: RecoveryAttemptStatus,
        error: Option<String>,
    ) {
        let request_id = request_id.trim().to_string();
        if request_id.is_empty() {
            return;
        }

        let now_ms = env::block_timestamp_ms();

        match self
            .recovery_attempts_by_request_id
            .entry(request_id.clone())
        {
            Entry::Occupied(mut entry) => {
                let attempt = entry.get_mut();
                attempt.status = status;
                attempt.updated_at_ms = now_ms;
                attempt.error = error;
            }
            Entry::Vacant(entry) => {
                entry.insert(RecoveryAttempt {
                    request_id: request_id.clone(),
                    status,
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                    error,
                    from_address: None,
                    email_timestamp_ms: None,
                    new_public_key: None,
                });
                self.schedule_attempt_cleanup(&request_id);
            }
        }
    }

    pub(crate) fn update_attempt_fields_from_verifier(
        &mut self,
        request_id: &str,
        vr: &VerificationResult,
    ) {
        let request_id = request_id.trim().to_string();
        if request_id.is_empty() {
            return;
        }

        let now_ms = env::block_timestamp_ms();

        match self
            .recovery_attempts_by_request_id
            .entry(request_id.clone())
        {
            Entry::Occupied(mut entry) => {
                let attempt = entry.get_mut();
                attempt.updated_at_ms = now_ms;
                attempt.from_address = Some(vr.from_address.clone());
                attempt.email_timestamp_ms = vr.email_timestamp_ms;
                attempt.new_public_key = Some(vr.new_public_key.clone());
            }
            Entry::Vacant(entry) => {
                entry.insert(RecoveryAttempt {
                    request_id: request_id.clone(),
                    status: RecoveryAttemptStatus::Started,
                    created_at_ms: now_ms,
                    updated_at_ms: now_ms,
                    error: None,
                    from_address: Some(vr.from_address.clone()),
                    email_timestamp_ms: vr.email_timestamp_ms,
                    new_public_key: Some(vr.new_public_key.clone()),
                });
                self.schedule_attempt_cleanup(&request_id);
            }
        }
    }

    pub(crate) fn fail_attempt(
        &mut self,
        request_id: &str,
        status: RecoveryAttemptStatus,
        error: impl Into<String>,
    ) {
        self.update_attempt_status(request_id, status, Some(error.into()));
    }
}
