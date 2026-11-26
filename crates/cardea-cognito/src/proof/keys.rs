//! One provider's signing keys, cached. Moved from Leyline's JWKS cache.
//!
//! Providers rotate their keys. The cache has a lifetime, and an unknown `kid`
//! is read as a rotation: it forces a refetch, no more often than
//! [`UNKNOWN_KID_BACKOFF`], so tokens carrying made-up kids cannot turn
//! verification into a load generator against the provider. The fetch is
//! bounded in time and size.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use tokio::sync::Mutex;

/// How long a fetched set is trusted before it is fetched again regardless.
const TTL: Duration = Duration::from_secs(3600);
/// How often an unknown `kid` may force a fetch ahead of the lifetime.
const UNKNOWN_KID_BACKOFF: Duration = Duration::from_secs(60);
const TIMEOUT: Duration = Duration::from_secs(3);
/// A real set is a few kilobytes; anything past this is not a key set.
const MAX_BYTES: usize = 256 * 1024;

/// Why a key set could not be read.
#[derive(Debug, thiserror::Error)]
pub enum KeyFetchError {
    /// The provider could not be reached, or refused the request.
    #[error("the key set could not be fetched")]
    Fetch(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The answer is larger than a key set is.
    #[error("the key set is too large")]
    TooLarge,
    /// The answer is not a key set.
    #[error("the key set could not be read")]
    Malformed(#[source] serde_json::Error),
}

/// Retrieves the bytes of a key set.
#[async_trait]
pub trait KeyFetcher: Send + Sync {
    /// The body published at `url`.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, KeyFetchError>;
}

/// Fetches key sets over HTTPS.
pub struct HttpKeyFetcher(reqwest::Client);

impl HttpKeyFetcher {
    /// A client with the fetch's time limit.
    pub fn new() -> Result<Self, KeyFetchError> {
        reqwest::Client::builder()
            .timeout(TIMEOUT)
            .https_only(true)
            .build()
            .map(Self)
            .map_err(|error| KeyFetchError::Fetch(Box::new(error)))
    }
}

#[async_trait]
impl KeyFetcher for HttpKeyFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, KeyFetchError> {
        let failed = |error: reqwest::Error| KeyFetchError::Fetch(Box::new(error));
        let mut response = self
            .0
            .get(url)
            .send()
            .await
            .map_err(failed)?
            .error_for_status()
            .map_err(failed)?;
        // Read piece by piece, so an oversized answer is dropped while it is
        // still small.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(failed)? {
            if body.len() + chunk.len() > MAX_BYTES {
                return Err(KeyFetchError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    #[serde(default)]
    kty: String,
}

#[derive(Deserialize)]
struct KeySet {
    keys: Vec<Jwk>,
}

struct Cached {
    fetched: Instant,
    keys: HashMap<String, DecodingKey>,
}

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The cached key set published at one URL.
pub(super) struct Keys {
    url: &'static str,
    fetcher: Arc<dyn KeyFetcher>,
    /// Held across the fetch, so concurrent misses make one request.
    state: Mutex<Option<Cached>>,
    clock: Clock,
}

impl Keys {
    pub(super) fn new(url: &'static str, fetcher: Arc<dyn KeyFetcher>) -> Self {
        Self {
            url,
            fetcher,
            state: Mutex::new(None),
            clock: Arc::new(Instant::now),
        }
    }

    /// The key published under `kid`, or `None` when there is none: a forged
    /// header, or a rotation too recent for the backoff to have noticed.
    pub(super) async fn key(&self, kid: &str) -> Result<Option<DecodingKey>, KeyFetchError> {
        let mut cached = self.state.lock().await;
        let now = (self.clock)();
        let stale = cached.as_ref().is_none_or(|c| {
            let age = now.saturating_duration_since(c.fetched);
            age >= TTL || (!c.keys.contains_key(kid) && age >= UNKNOWN_KID_BACKOFF)
        });
        if stale {
            let keys = self.fetch().await?;
            *cached = Some(Cached { fetched: now, keys });
        }
        Ok(cached.as_ref().and_then(|c| c.keys.get(kid)).cloned())
    }

    async fn fetch(&self) -> Result<HashMap<String, DecodingKey>, KeyFetchError> {
        let bytes = self.fetcher.fetch(self.url).await?;
        if bytes.len() > MAX_BYTES {
            return Err(KeyFetchError::TooLarge);
        }
        let set: KeySet = serde_json::from_slice(&bytes).map_err(KeyFetchError::Malformed)?;
        Ok(set
            .keys
            .into_iter()
            // A set may carry keys of other types, which cannot sign RS256.
            .filter(|k| !k.kid.is_empty() && (k.kty.is_empty() || k.kty == "RSA"))
            .filter_map(|k| {
                DecodingKey::from_rsa_components(&k.n, &k.e)
                    .ok()
                    .map(|key| (k.kid, key))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
