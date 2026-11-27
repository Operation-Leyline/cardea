//! The secret the mail budget's row keys are computed under.
//!
//! The budget table names a mailbox and a message by HMAC-SHA-256 of their
//! names, so that someone who can read the table, but not the secret, cannot
//! test a guessed address against it.
//!
//! **Format:** the secret's text is 32 random bytes as 64 hexadecimal
//! characters, the form Secrets Manager's own generator can produce
//! (`openssl rand -hex 32` makes one too). Surrounding white space is ignored.
//! Anything else is refused: there is no unkeyed or default key to fall back
//! to.

use std::sync::Arc;

use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// How many random bytes a key is.
const KEY_BYTES: usize = 32;

/// Why there is no key. No variant carries any part of the secret.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// The secret holds binary data, or nothing.
    #[error("the mail budget key secret has no text value")]
    NoValue,
    /// The secret's text is not a key.
    #[error("the mail budget key is not 64 hexadecimal characters")]
    Format,
    /// The secret could not be read.
    #[error("the mail budget key secret could not be read")]
    Read(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A product's mail budget key. It prints as `<redacted>`.
#[derive(Clone)]
pub struct BudgetKey([u8; KEY_BYTES]);

impl BudgetKey {
    /// The key a secret's text spells.
    pub fn from_secret(text: &str) -> Result<Self, KeyError> {
        let mut key = [0; KEY_BYTES];
        hex::decode_to_slice(text.trim(), &mut key).map_err(|_| KeyError::Format)?;
        Ok(Self(key))
    }

    /// HMAC-SHA-256 of `name` under this key, in lower-case hex.
    pub(super) fn tag(&self, name: &str) -> String {
        hex::encode(self.mac(name.as_bytes()))
    }

    fn mac(&self, data: &[u8]) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes a key of any length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl std::fmt::Debug for BudgetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Where a sender gets its key: Secrets Manager, or a product's own secrets
/// layer.
///
/// How often a source is asked depends on how the sender was given it.
/// [`EmailSender::new`](super::EmailSender::new) asks until it has a key and
/// keeps that one for as long as it lives.
/// [`EmailSender::with_key_source`](super::EmailSender::with_key_source), and
/// what takes a source for a Lambda function, ask for every message, so that a
/// changed key takes effect in a running function. A source that is slow or
/// dear to read then caches, as
/// [`RefreshingKeySource`](super::RefreshingKeySource) does.
#[async_trait]
pub trait BudgetKeySource: Send + Sync {
    /// The key to name rows under now, or why there is none. Without one no
    /// message is sent.
    async fn load(&self) -> Result<BudgetKey, KeyError>;
}

/// A source the caller keeps a handle to.
#[async_trait]
impl<S: BudgetKeySource + ?Sized> BudgetKeySource for Arc<S> {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        (**self).load().await
    }
}

/// A key already in hand.
#[async_trait]
impl BudgetKeySource for BudgetKey {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests;
