//! Signing in with a provider natively: the app gets the provider's ID token
//! itself (an account sheet, a popup) and exchanges it for ordinary Cognito
//! tokens, without the browser redirect.
//!
//! 1. [`create_sign_in_nonce`] issues a nonce and names the product's client id
//!    with the provider.
//! 2. The app gets an ID token from the provider carrying that nonce.
//! 3. [`begin_provider_sign_in`] checks the token, spends the nonce, resolves
//!    the person by the same rules as a redirect sign-in
//!    ([`cardea_core::resolve`]) and answers a username and a single-use
//!    ticket.
//! 4. The app starts Cognito's `CUSTOM_AUTH` flow for that username and answers
//!    its one challenge with the ticket. The trigger handler
//!    ([`crate::triggers`]) redeems it, and Cognito issues its usual tokens.
//!
//! Google is the one provider offered this way.
//!
//! # What the product owes
//!
//! A product's API exposes the first and third steps to people who are **not
//! signed in**, so it must:
//!
//! - rate-limit both, per caller; the library does not;
//! - serve them over TLS only;
//! - log neither the nonce, the token, the ticket nor the username;
//! - report [`Error::LinkRequired`](cardea_core::Error) as
//!   `identityLinkRequired`, and any other failure without detail of its own.
//!
//! The service needs `GetItem`, `PutItem`, `UpdateItem` and `DeleteItem` on the
//! directory table, `cognito-idp:AdminGetUser`, `AdminCreateUser`,
//! `AdminSetUserPassword` and `AdminLinkProviderForUser` on the pool, and the
//! ticket key ([`TicketKey`]), which the trigger function reads too.

use std::sync::Arc;

use cardea_core::{Error, Provider};

use crate::{OperationError, cause::cause, link::ProviderClients};

mod begin;
mod key;
mod nonce;
#[cfg(feature = "native-sign-in")]
mod secret;
pub(crate) mod ticket;

pub use begin::{SignInTicket, begin_provider_sign_in};
pub use key::{TicketKey, TicketKeyError, TicketKeySource};
pub use nonce::{SignInNonce, create_sign_in_nonce};
#[cfg(feature = "native-sign-in")]
pub use secret::{KEY_REFRESH_INTERVAL, SecretsManagerTicketKey, TICKET_KEY_VARIABLE};

/// How long a nonce may be used: the person picks an account within it.
pub const NONCE_LIFETIME_SECONDS: u64 = 10 * 60;

/// How long a ticket may be redeemed. The app does so at once.
pub const TICKET_LIFETIME_SECONDS: u64 = 2 * 60;

// A ticket is a bearer credential: it never lasts longer than this.
const _: () = assert!(TICKET_LIFETIME_SECONDS <= 5 * 60);

/// What a product offers for native sign-in.
#[derive(Clone)]
pub struct NativeSignIn {
    providers: ProviderClients,
    app_clients: Vec<String>,
    keys: Arc<dyn TicketKeySource>,
}

impl NativeSignIn {
    /// `providers` holds the product's client id with each provider (for
    /// Google, the web client, whose audience an Android token names too).
    /// `app_clients` are the Cognito app clients allowed to sign in this way;
    /// each needs `ALLOW_CUSTOM_AUTH`.
    pub fn new<S: Into<String>>(
        providers: ProviderClients,
        app_clients: impl IntoIterator<Item = S>,
        keys: impl TicketKeySource + 'static,
    ) -> Self {
        Self {
            providers,
            app_clients: app_clients
                .into_iter()
                .map(Into::into)
                .filter(|client| !client.is_empty())
                .collect(),
            keys: Arc::new(keys),
        }
    }

    /// The product's client id with `provider`, if it signs in natively.
    fn client_id(&self, provider: Provider) -> Result<&str, OperationError> {
        // Apple has no native sign-in here, whatever the product configured.
        match provider {
            Provider::Google => self.providers.client_id(provider),
            Provider::Apple => None,
        }
        .ok_or(OperationError::ProviderNotConfigured)
    }

    fn allows(&self, app_client: &str) -> bool {
        self.app_clients.iter().any(|client| client == app_client)
    }
}

/// The key now, or [`Error::Unavailable`] with the cause logged.
async fn load_key(keys: &(impl TicketKeySource + ?Sized)) -> Result<TicketKey, Error> {
    keys.load().await.map_err(|error| {
        tracing::error!(cause = %cause(&error), "the sign-in ticket key is unavailable");
        Error::Unavailable
    })
}

/// 244 random bits as 64 hexadecimal characters: a nonce or a ticket.
fn random_value() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Whether `text` has the shape of a [`random_value`].
fn well_formed(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests;
