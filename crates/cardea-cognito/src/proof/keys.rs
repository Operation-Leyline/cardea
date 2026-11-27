//! One provider's signing keys, cached.
//!
//! Providers rotate their keys. The cache has a lifetime, and an unknown `kid`
//! is read as a rotation: it forces a refetch, no more often than
//! [`UNKNOWN_KID_BACKOFF`], so tokens carrying made-up kids cannot turn
//! verification into a load generator against the provider. A failed fetch is
//! remembered, so an outage does not make every request fetch again. A set past
//! its lifetime is never used, whether or not a new one can be had. The fetch
//! is bounded in time and size.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;

/// How long a fetched set is trusted before it is fetched again regardless.
const TTL: Duration = Duration::from_secs(3600);
/// How often an unknown `kid` may force a fetch ahead of the lifetime.
const UNKNOWN_KID_BACKOFF: Duration = Duration::from_secs(60);
/// How soon a failed fetch is tried again when there is no set to answer from.
const FAILURE_BACKOFF: Duration = Duration::from_secs(5);
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
    /// The last fetch failed too recently to try again.
    #[error("the key set could not be fetched a moment ago")]
    RecentlyFailed,
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

#[derive(Default)]
struct State {
    /// The last set fetched.
    set: Option<Cached>,
    /// When the last fetch failed, unless one has succeeded since.
    failed: Option<Instant>,
}

/// The cached key set published at one URL.
pub(super) struct Keys {
    url: &'static str,
    fetcher: Arc<dyn KeyFetcher>,
    /// Never held across a wait, so a known key is answered during a fetch.
    state: Mutex<State>,
    /// Held across the fetch, so concurrent misses make one request.
    fetching: tokio::sync::Mutex<()>,
    clock: Clock,
}

impl Keys {
    pub(super) fn new(url: &'static str, fetcher: Arc<dyn KeyFetcher>) -> Self {
        Self {
            url,
            fetcher,
            state: Mutex::default(),
            fetching: tokio::sync::Mutex::default(),
            clock: Arc::new(Instant::now),
        }
    }

    /// The key published under `kid`, or `None` when there is none: a forged
    /// header, or a rotation too recent for the backoff to have noticed.
    pub(super) async fn key(&self, kid: &str) -> Result<Option<DecodingKey>, KeyFetchError> {
        if let Some(answer) = self.cached(kid) {
            return answer;
        }
        let _one = self.fetching.lock().await;
        // The fetch waited for may have settled it.
        if let Some(answer) = self.cached(kid) {
            return answer;
        }
        let started = (self.clock)();
        let fetched = self.fetch().await;
        let mut state = self.state();
        match fetched {
            Ok(keys) => {
                let key = keys.get(kid).cloned();
                *state = State {
                    set: Some(Cached {
                        fetched: started,
                        keys,
                    }),
                    failed: None,
                };
                Ok(key)
            }
            Err(error) => {
                state.failed = Some((self.clock)());
                Err(error)
            }
        }
    }

    /// The answer for `kid` without fetching, or `None` when it is time to
    /// fetch.
    fn cached(&self, kid: &str) -> Option<Result<Option<DecodingKey>, KeyFetchError>> {
        let state = self.state();
        let now = (self.clock)();
        let since = |then: Instant| now.saturating_duration_since(then);
        let current = state.set.as_ref().filter(|set| since(set.fetched) < TTL);
        if let Some(key) = current.and_then(|set| set.keys.get(kid)) {
            return Some(Ok(Some(key.clone())));
        }
        if let Some(failed) = state.failed {
            let wait = if current.is_some() {
                UNKNOWN_KID_BACKOFF
            } else {
                FAILURE_BACKOFF
            };
            if since(failed) < wait {
                return Some(Err(KeyFetchError::RecentlyFailed));
            }
            // The wait is over: try again.
            return None;
        }
        current
            .filter(|set| since(set.fetched) < UNKNOWN_KID_BACKOFF)
            .map(|_| Ok(None))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Every write replaces whole values, so a poisoned state is still sound.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
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
