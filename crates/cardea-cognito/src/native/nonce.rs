//! The nonce a native sign-in's provider token must carry: issued here, spent
//! once.
//!
//! It is stored rather than signed. A signed nonce would still need a record of
//! the ones already used, so it would save no state and add a second thing to
//! get right.

use cardea_core::{Directory, Error, Provider};
use tabulary::{FailureKind, WriteError};

use super::{NONCE_LIFETIME_SECONDS, NativeSignIn, TicketKey, load_key, random_value};
use crate::{
    OperationError,
    directory::{AwsDirectory, now},
    record::{NonceRow, NonceRowAttrs, NonceRowKey},
};

/// What the app needs to get a provider token.
#[derive(Clone, PartialEq, Eq)]
pub struct SignInNonce {
    /// What the provider's ID token must carry.
    pub nonce: String,
    /// The product's client id with the provider.
    pub client_id: String,
    /// Epoch seconds after which the nonce is refused. A product's API reports
    /// it as a date and time: the web package reads a bare number as
    /// milliseconds.
    pub expires_at: u64,
}

/// Leaves the nonce out.
impl std::fmt::Debug for SignInNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignInNonce")
            .field("client_id", &self.client_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn nonce_tag(directory: &AwsDirectory, key: &TicketKey, nonce: &str) -> String {
    key.tag(&["cardea.sign-in-nonce.v1", directory.pool(), nonce])
}

/// A new nonce for signing in with `provider`.
///
/// Anyone may ask, and each call writes a row: the product rate-limits it.
pub async fn create_sign_in_nonce(
    directory: &AwsDirectory,
    native: &NativeSignIn,
    provider: Provider,
) -> Result<SignInNonce, OperationError> {
    let client_id = native.client_id(provider)?;
    directory.ready().await?;
    let key = load_key(&native.keys).await?;
    let nonce = random_value();
    let expires_at = u64::try_from(now()).unwrap_or(0) + NONCE_LIFETIME_SECONDS;
    let row = NonceRow {
        tag: nonce_tag(directory, &key, &nonce),
        deadline: expires_at,
        expires_at,
    };
    let request = directory
        .rows()?
        .put(&row)
        .expect_new()
        .build()
        .map_err(|_| Error::Invalid)?;
    request
        .decode(request.apply(directory.dynamodb().put_item()).send().await)
        .map_err(|_| Error::Unavailable)?;
    Ok(SignInNonce {
        nonce,
        client_id: client_id.to_owned(),
        expires_at,
    })
}

/// Spend `nonce`: [`Error::Invalid`] unless it was issued, is unused and has
/// not expired at `now`. One conditional delete decides, so of any number of
/// callers one succeeds.
pub(super) async fn spend_nonce(
    directory: &AwsDirectory,
    key: &TicketKey,
    nonce: &str,
    now: u64,
) -> Result<(), Error> {
    let row = NonceRowKey::new(nonce_tag(directory, key, nonce)).map_err(|_| Error::Invalid)?;
    let request = directory
        .rows()?
        .delete(row)
        .condition(NonceRowAttrs::DEADLINE.gt(now))
        .build()
        .map_err(|_| Error::Invalid)?;
    match request.decode(
        request
            .apply(directory.dynamodb().delete_item())
            .send()
            .await,
    ) {
        Ok(_) => Ok(()),
        Err(WriteError::Refused { failure, .. })
            if failure.kind == FailureKind::ConditionFailed =>
        {
            Err(Error::Invalid)
        }
        Err(_) => Err(Error::Unavailable),
    }
}
