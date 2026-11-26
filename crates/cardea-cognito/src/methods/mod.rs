//! A signed-in person's ways of signing in: listing them and removing one.
//!
//! A product's API service calls these for the user its verified session
//! names. **API keys must not reach them** (nor [`crate::link`]'s): the
//! library cannot tell an API key from a person, so the product refuses keys
//! before calling.
//!
//! The user pool says which providers are linked. The directory adds whether a
//! password was chosen (the mailbox's row) and each identity's address as the
//! provider gave it ([`MethodsRow`](crate::record::MethodsRow)). Where the two
//! disagree the pool is followed.
//!
//! The service needs `GetItem`, `PutItem`, `UpdateItem` and `DeleteItem` on the
//! directory table, and `cognito-idp:AdminGetUser`, `AdminLinkProviderForUser`
//! and `AdminDisableProviderForUser` on the pool.

use cardea_core::{Error, Provider, User};

use crate::directory::AwsDirectory;

mod admit;
mod list;
mod pool;
mod row;
mod unlink;

pub use list::{SignInMethod, list_sign_in_methods};
pub use unlink::unlink_sign_in_method;

impl AwsDirectory {
    /// Whether password is a sign-in method of `user`: the mailbox's row is
    /// this user's and says a password was chosen
    /// ([`EmailRow::has_password`](crate::record::EmailRow::has_password)).
    /// `None` when the directory holds no row of theirs.
    async fn password_method(&self, user: &User) -> Result<Option<bool>, Error> {
        let Some(row) = self.email_row(&user.email).await? else {
            return Ok(None);
        };
        if !self.owns(&row, &user.username, &user.user_id).await? {
            return Ok(None);
        }
        Ok(Some(row.has_password()))
    }

    /// Whether the subject's binding names `user`.
    pub(crate) async fn binds(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<bool, Error> {
        use cardea_core::Directory;

        Ok(self
            .provider(provider, subject)
            .await?
            .is_some_and(|bound| bound.user_id == user.user_id))
    }
}

#[cfg(test)]
mod tests;
