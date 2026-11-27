//! Linking a provider identity to a signed-in account: `CreateIdentityLink`
//! and `CompleteIdentityLink`, with the provider as a parameter.
//!
//! 1. [`create_identity_link`] makes a challenge bound to the caller and a
//!    fresh nonce, and names the product's client id with the provider.
//! 2. The browser gets an ID token from the provider carrying that nonce.
//! 3. [`complete_identity_link`] checks the token, binds the identity to the
//!    caller and links it in the user pool.
//!
//! A challenge has five minutes to complete, binds to the first proof it is
//! given, and answers a repeat of a completed request for 24 hours. Which
//! identities a person may link is [`cardea_core::resolve`]'s rule: the same
//! mailbox, or an Apple relay address within
//! [`RECENT_SIGN_IN_SECONDS`](cardea_core::RECENT_SIGN_IN_SECONDS) of signing
//! in.
//!
//! A product's API service calls these for the user its verified session names.
//! **API keys must not reach them**: the library cannot tell an API key from a
//! person, so the product refuses keys before calling. [`crate::methods`] lists
//! the permissions the service needs.

use cardea_core::{Error, Provider};
use sha2::{Digest, Sha256};

use crate::record::{LinkRowKey, ProviderRow};

mod complete;
mod create;

pub use complete::complete_identity_link;
pub use create::{IdentityLinkChallenge, create_identity_link};

/// How long a challenge's nonce can be used.
pub const LINK_LIFETIME_SECONDS: u64 = 5 * 60;

/// How long a challenge's row, and so the answer to a completed request, is
/// kept.
pub const LINK_RECEIPT_SECONDS: u64 = 24 * 60 * 60;

/// The product's client id with each provider it offers: the audience a proof
/// must name (a Google client id, an Apple Services ID).
#[derive(Clone, Debug, Default)]
pub struct ProviderClients(Vec<(Provider, String)>);

impl ProviderClients {
    /// No provider yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer `provider` under `client_id`. An empty id leaves it not offered.
    pub fn with(mut self, provider: Provider, client_id: impl Into<String>) -> Self {
        let client_id = client_id.into();
        self.0.retain(|(of, _)| *of != provider);
        if !client_id.is_empty() {
            self.0.push((provider, client_id));
        }
        self
    }

    /// The client id `provider` is offered under, if it is.
    pub fn client_id(&self, provider: Provider) -> Option<&str> {
        self.0
            .iter()
            .find(|(of, _)| *of == provider)
            .map(|(_, id)| id.as_str())
    }
}

fn link_key(user_id: &str, link_id: &str) -> Result<LinkRowKey, Error> {
    LinkRowKey::new(user_id.to_owned(), link_id.to_owned()).map_err(|_| Error::Invalid)
}

/// The provider a challenge row is for: Google when it names none. A name this
/// library does not know makes the challenge invalid.
fn challenge_provider(named: Option<&str>) -> Result<Provider, Error> {
    let name = named.map_or_else(
        || ProviderRow::provider_name(Provider::Google),
        str::to_owned,
    );
    Provider::from_cognito_name(&name).ok_or(Error::Invalid)
}

/// SHA-256 in hex: how client tokens and proofs are remembered without being
/// stored.
fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text))
}

#[cfg(test)]
mod tests;
