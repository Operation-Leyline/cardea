//! The secret native sign-in's rows are named under.
//!
//! The directory table names a nonce and a ticket by HMAC-SHA-256, so that
//! reading the table yields nothing to sign in with, and writing to it without
//! the secret cannot make a row the library will find.
//!
//! It is a secret of its own, not the mail budget's key: a product has it only
//! when it offers native sign-in, whether or not it sends its own mail; its two
//! readers (the API service and the trigger function) are not the mail
//! sender's.
//!
//! A change costs native sign-ins alone, and not only those in flight: while the
//! two readers can still hold different keys, new ones fail too.
//!
//! **Format:** 32 random bytes as 64 hexadecimal characters, as the mail
//! budget's key. Surrounding white space is ignored; anything else is refused.

use std::sync::Arc;

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// How many random bytes a key is.
const KEY_BYTES: usize = 32;

/// Why there is no key. No variant carries any part of the secret.
#[derive(Debug, thiserror::Error)]
pub enum TicketKeyError {
    /// The secret holds binary data, or nothing.
    #[error("the sign-in ticket key secret has no text value")]
    NoValue,
    /// The secret's text is not a key.
    #[error("the sign-in ticket key is not 64 hexadecimal characters")]
    Format,
    /// The secret could not be read.
    #[error("the sign-in ticket key secret could not be read")]
    Read(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A product's sign-in ticket key. It prints as `<redacted>`.
#[derive(Clone)]
pub struct TicketKey([u8; KEY_BYTES]);

impl TicketKey {
    /// The key a secret's text spells.
    pub fn from_secret(text: &str) -> Result<Self, TicketKeyError> {
        let mut key = [0; KEY_BYTES];
        hex::decode_to_slice(text.trim(), &mut key).map_err(|_| TicketKeyError::Format)?;
        Ok(Self(key))
    }

    /// HMAC-SHA-256 of `parts` under this key, in lower-case hex. The parts are
    /// encoded as a JSON list, so that no two lists share a tag.
    pub(super) fn tag(&self, parts: &[&str]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes a key of any length");
        let message = serde_json::to_vec(parts).expect("a list of strings encodes");
        mac.update(&message);
        hex::encode(mac.finalize().into_bytes())
    }
}

impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Where the key comes from: Secrets Manager, or a product's own secrets layer.
///
/// It is asked at every step, so a source that is slow or dear to read caches.
/// The API service and the trigger function must be given the same key.
#[async_trait]
pub trait TicketKeySource: Send + Sync {
    /// The key to use now, or why there is none. Without one nobody signs in
    /// natively.
    async fn load(&self) -> Result<TicketKey, TicketKeyError>;
}

/// A source the caller keeps a handle to.
#[async_trait]
impl<S: TicketKeySource + ?Sized> TicketKeySource for Arc<S> {
    async fn load(&self) -> Result<TicketKey, TicketKeyError> {
        (**self).load().await
    }
}

/// A key already in hand.
#[async_trait]
impl TicketKeySource for TicketKey {
    async fn load(&self) -> Result<TicketKey, TicketKeyError> {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests;
