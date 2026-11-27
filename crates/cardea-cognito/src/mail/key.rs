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

/// Where a sender gets its key. It asks once and keeps the answer for as long
/// as it lives; after a failure it asks again for the next message.
#[async_trait]
pub trait BudgetKeySource: Send + Sync {
    /// The product's key, or why there is none.
    async fn load(&self) -> Result<BudgetKey, KeyError>;
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
