//! A provider's ID token as proof that the person holds the provider account
//! they are linking.
//!
//! [`ProofVerifier`] is the seam: [`JwtVerifier`] checks a signed token
//! against the provider's published keys, and tests put a fake in its place.
//! Raw tokens are never stored or logged.

use async_trait::async_trait;
use cardea_core::{Error, Provider, ProviderIdentity};

mod keys;
mod verifier;

pub use keys::{HttpKeyFetcher, KeyFetchError, KeyFetcher};
pub use verifier::{JwtVerifier, PROOF_MAX_AGE_SECONDS};

/// One token to check, and what it must be bound to.
#[derive(Clone, Copy)]
pub struct ProofRequest<'a> {
    /// Who must have signed it.
    pub provider: Provider,
    /// The ID token.
    pub token: &'a str,
    /// The audience it must name: the product's Google client id or Apple
    /// Services ID.
    pub client_id: &'a str,
    /// The nonce it must carry.
    pub nonce: &'a str,
    /// The current time, in epoch seconds.
    pub now: i64,
}

/// A token that checked out.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    /// The person as the provider vouches for them.
    pub identity: ProviderIdentity,
    /// The `email` claim exactly as the provider wrote it, for showing the
    /// person which provider account is linked.
    pub email: String,
}

/// Checks provider proofs.
#[async_trait]
pub trait ProofVerifier: Send + Sync {
    /// The person `request.token` proves, or [`Error::Invalid`] when it does
    /// not check out, and [`Error::Unavailable`] when it cannot be checked
    /// right now.
    async fn verify(&self, request: ProofRequest<'_>) -> Result<VerifiedProof, Error>;
}
