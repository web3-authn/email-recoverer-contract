use crate::{EmailRecoverer, HashedEmail};

impl EmailRecoverer {
    /// Check whether the given hashed email is present in the configured
    /// recovery emails set.
    pub(crate) fn is_configured_recovery_email(&self, hashed_email: &HashedEmail) -> bool {
        self.recovery_emails.contains(hashed_email)
    }
}
