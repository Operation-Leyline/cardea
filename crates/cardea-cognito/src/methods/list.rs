//! `ListSignInMethods`.

use cardea_core::{Directory, Error, Provider, User};

use crate::{OperationError, directory::AwsDirectory, record::MethodsRow};

/// One way a person can sign in to their account.
#[derive(Clone, PartialEq, Eq)]
pub enum SignInMethod {
    /// Email and a password the person chose.
    Password,
    /// A linked provider identity.
    Provider {
        /// Who signs the person in.
        provider: Provider,
        /// The address as the provider gave it; `None` for a link made before
        /// it was recorded, until that identity next signs in or is linked.
        email: Option<String>,
    },
}

/// Leaves the address out, so that printing a method cannot log it.
impl std::fmt::Debug for SignInMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => f.write_str("Password"),
            Self::Provider { provider, .. } => f
                .debug_struct("Provider")
                .field("provider", provider)
                .finish_non_exhaustive(),
        }
    }
}

/// The ways `user` can sign in: password first when one was chosen, then each
/// linked identity, in [`Provider::ALL`]'s order.
///
/// `user` must come from a verified session token. The pool decides which
/// identities are listed. Places where the directory says otherwise are
/// counted in a warning, and identities the user's list lacks are added to it.
pub async fn list_sign_in_methods(
    directory: &AwsDirectory,
    user: &User,
) -> Result<Vec<SignInMethod>, OperationError> {
    directory.ready().await?;
    // The list first: an identity an unlink has taken off it by now is gone
    // from the pool answer read after.
    let read = directory.methods_row(user).await?;
    let linked = directory.pool_identities(user).await?;
    let password = directory.password_method(user).await?;
    let mut disagreements = usize::from(password.is_none());
    let version = read.as_ref().map_or(0, |row| row.version);
    let mut next = read.clone().unwrap_or_else(|| MethodsRow::empty(user));
    let mut methods = Vec::new();
    if password == Some(true) {
        methods.push(SignInMethod::Password);
    }
    for identity in &linked {
        let bound = directory
            .binds(identity.provider, &identity.subject, user)
            .await?;
        // A missing entry is expected only before the list first exists.
        let unlisted = read
            .as_ref()
            .is_some_and(|row| row.find(identity).is_none());
        disagreements += usize::from(!bound || unlisted);
        methods.push(SignInMethod::Provider {
            provider: identity.provider,
            email: next.entry(identity).email.clone(),
        });
    }
    // Listed identities the pool does not link.
    disagreements += read.as_ref().map_or(0, |row| {
        let listed = row.identities.iter().filter(|entry| !entry.removing);
        listed
            .filter(|entry| {
                !linked.iter().any(|identity| {
                    identity.subject == entry.subject
                        && identity.provider.rule().cognito_name == entry.provider
                })
            })
            .count()
    });
    if disagreements > 0 {
        tracing::warn!(
            disagreements,
            "the user pool and the directory disagree about sign-in methods"
        );
    }
    if read.as_ref() != Some(&next) {
        // A convenience: the answer stands whether or not the list is saved,
        // and a write that lost to another is that other's to make.
        match directory.replace_methods_row(version, next).await {
            Ok(_) | Err(Error::Unavailable) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(methods)
}
