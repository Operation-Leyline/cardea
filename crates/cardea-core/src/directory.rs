//! What the identity rules need from storage and the user pool.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{Error, Provider};

/// How long a native signup holds its mailbox before it is confirmed: as long
/// as Cognito's signup confirmation code stays valid (24 hours). A lapsed
/// claim nobody confirmed may be taken by another signup of the same mailbox,
/// so a typo or an abandoned signup cannot keep its owner out for good.
pub const UNCONFIRMED_CLAIM_LIFETIME_SECONDS: i64 = 24 * 60 * 60;

/// The [`EmailOwner::origin`] of an account made with email and password. A
/// provider-made account's origin is the provider's
/// [`cognito_name`](crate::ProviderRule::cognito_name).
pub const NATIVE_ORIGIN: &str = "Cognito";

/// The user a mailbox belongs to. Stored as JSON: field names and order are
/// part of the directory's wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailOwner {
    /// The address as claimed, normalized, in its owner's spelling.
    pub email: String,
    /// The name the Cognito user is looked up by.
    pub username: String,
    /// How the account was first made: [`NATIVE_ORIGIN`] or a provider.
    pub origin: String,
}

impl EmailOwner {
    /// Whether password is a sign-in method of this account, given the
    /// directory row's `passwordSet`. A row without it is read by origin: a
    /// native account has the password its owner chose, and an account made
    /// behind a provider sign-in has only a random one nobody was told.
    pub fn password_set(&self, stored: Option<bool>) -> bool {
        stored.unwrap_or(self.origin == NATIVE_ORIGIN)
    }
}

/// A confirmed account. Stored as JSON: field names and order are part of the
/// directory's wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// The Cognito `sub`: the product's permanent user id.
    pub user_id: String,
    /// The Cognito username.
    pub username: String,
    /// The account's own email address.
    pub email: String,
}

/// Durable mailbox and provider ownership, and the user pool behind it.
///
/// Ownership is claimed with conditional writes before any outside side effect,
/// so a retry reconciles with what is there instead of creating again.
#[async_trait]
pub trait Directory: Send + Sync {
    /// Refuses with [`Error::NotReady`] until the directory may be written.
    async fn ready(&self) -> Result<(), Error>;
    /// The owner of the mailbox `email` reaches, under any alias spelling. A
    /// lapsed unconfirmed claim ([`UNCONFIRMED_CLAIM_LIFETIME_SECONDS`]) owns
    /// nothing.
    async fn email(&self, email: &str) -> Result<Option<EmailOwner>, Error>;
    /// Conditional create, keyed by the person ([`crate::person_key`]) rather
    /// than the spelling, replacing only a lapsed unconfirmed claim. The claim
    /// made here never lapses. Returns the winning record on contention or
    /// retry.
    async fn claim_email(&self, owner: &EmailOwner) -> Result<EmailOwner, Error>;
    /// The user a provider subject is bound to.
    async fn provider(&self, provider: Provider, subject: &str) -> Result<Option<User>, Error>;
    /// Whether Cognito holds a user at `username` still awaiting confirmation.
    async fn awaits_confirmation(&self, username: &str) -> Result<bool, Error>;
    /// Bind the subject to `user`, or refuse with [`Error::Conflict`] when it
    /// is another's. The binding holds even while Cognito linking is pending.
    async fn claim_provider(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<(), Error>;
    /// The confirmed account `owner` names.
    async fn native_user(&self, owner: &EmailOwner) -> Result<User, Error>;
    /// Find or make the password account behind a provider-claimed mailbox.
    async fn create_social_user(&self, owner: &EmailOwner) -> Result<User, Error>;
    /// Link the subject onto `user` in the user pool; a link already there
    /// succeeds.
    async fn link(&self, provider: Provider, subject: &str, user: &User) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(origin: &str) -> EmailOwner {
        EmailOwner {
            email: "a@example.com".into(),
            username: "a@example.com".into(),
            origin: origin.into(),
        }
    }

    #[test]
    fn password_set_defaults_by_origin_and_a_stored_value_wins() {
        assert!(owner(NATIVE_ORIGIN).password_set(None));
        for provider in Provider::ALL {
            let made = owner(provider.rule().cognito_name);
            assert!(!made.password_set(None));
            assert!(made.password_set(Some(true)));
        }
        assert!(!owner(NATIVE_ORIGIN).password_set(Some(false)));
    }
}
