//! `CreateIdentityLink`.

use cardea_core::{Directory, Error, Provider, User};

use super::{
    LINK_LIFETIME_SECONDS, LINK_RECEIPT_SECONDS, ProviderClients, challenge_provider, digest,
    link_key,
};
use crate::{
    OperationError,
    directory::{AwsDirectory, now},
    record::{LinkRow, ProviderRow},
};

/// What the browser needs to get a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityLinkChallenge {
    /// Names the challenge on completion.
    pub link_id: String,
    /// What the provider's ID token must carry.
    pub nonce: String,
    /// The product's client id with the provider.
    pub client_id: String,
    /// Epoch seconds after which the nonce proves nothing. A product's API
    /// reports it as a date and time: the web package reads a bare number as
    /// milliseconds.
    pub expires_at: u64,
}

/// The link id a client token names: the token's digest. The token itself is
/// never stored.
fn link_id(token: &str) -> Result<String, Error> {
    if token.is_empty() || token.len() > 128 || !token.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Error::Invalid);
    }
    Ok(digest(token))
}

/// A challenge for `user` to link `provider`.
///
/// The same `client_token` within the challenge's lifetime answers with the
/// same challenge. After that, or for another provider
/// ([`Error::ClientTokenMismatch`]), it is refused, and a new token starts a
/// new one. `user` must come from a verified session token.
pub async fn create_identity_link(
    directory: &AwsDirectory,
    clients: &ProviderClients,
    user: &User,
    provider: Provider,
    client_token: &str,
) -> Result<IdentityLinkChallenge, OperationError> {
    let client_id = clients
        .client_id(provider)
        .ok_or(OperationError::ProviderNotConfigured)?;
    directory.ready().await?;
    let link_id = link_id(client_token)?;
    let time = u64::try_from(now()).unwrap_or(0);
    // A retry of the same token finds the first attempt's challenge: the
    // winner is read back whatever the put answered.
    directory
        .put_new(&LinkRow {
            user_id: user.user_id.clone(),
            link_id: link_id.clone(),
            nonce: format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ),
            deadline: time + LINK_LIFETIME_SECONDS,
            expires_at: time + LINK_RECEIPT_SECONDS,
            token_hash: None,
            provider_subject: None,
            status: None,
            provider: Some(ProviderRow::provider_name(provider)),
        })
        .await?;
    let row: LinkRow = directory
        .row(link_key(&user.user_id, &link_id)?)
        .await?
        .ok_or(Error::Unavailable)?;
    if challenge_provider(row.provider.as_deref())? != provider {
        return Err(Error::ClientTokenMismatch.into());
    }
    if time >= row.deadline {
        return Err(Error::Invalid.into());
    }
    Ok(IdentityLinkChallenge {
        link_id: row.link_id,
        nonce: row.nonce,
        client_id: client_id.to_owned(),
        expires_at: row.deadline,
    })
}
