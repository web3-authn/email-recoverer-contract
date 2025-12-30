use crate::{EmailRecoverer, HashedEmail};
use near_sdk::env;

impl EmailRecoverer {
    /// Canonicalize an email-like string into a bare address:
    /// - Trim whitespace
    /// - If it contains a display name form like "Name <user@example.com>",
    ///   extract the part inside angle brackets.
    /// - Lowercase the result.
    pub(crate) fn canonicalize_email(raw: &str) -> String {
        let trimmed = raw.trim();

        // Handle common "Name <user@example.com>" pattern.
        if let Some(start) = trimmed.find('<') {
            if let Some(end_rel) = trimmed[start + 1..].find('>') {
                let end = start + 1 + end_rel;
                return trimmed[start + 1..end].trim().to_ascii_lowercase();
            }
        }

        trimmed.to_ascii_lowercase()
    }

    /// Check whether the given hashed email is present in the configured
    /// recovery emails set.
    pub(crate) fn is_configured_recovery_email(&self, hashed_email: &HashedEmail) -> bool {
        self.recovery_emails.contains(hashed_email)
    }

    /// Hash a canonical email address using the current account ID as salt:
    /// H(email || "|" || account_id). Accepts either a bare address
    /// ("alice@example.com") or a display-name form ("Alice <alice@example.com>").
    pub(crate) fn hash_from_email_for_current_account(&self, email_address: &str) -> HashedEmail {
        let canonical = Self::canonicalize_email(email_address);
        let mut data = canonical.into_bytes();
        data.push(b'|');
        data.extend(env::current_account_id().as_bytes());

        env::sha256(&data)
    }
}
