//! The cache policy, over a scripted provider and a clock the test moves.

use std::sync::{
    Mutex as SyncMutex,
    atomic::{AtomicUsize, Ordering},
};

use super::*;

/// Serves whichever kids it is told to, and counts how often it is asked.
struct Scripted {
    kids: SyncMutex<Vec<&'static str>>,
    fetches: AtomicUsize,
}

#[async_trait]
impl KeyFetcher for Scripted {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, KeyFetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let keys: Vec<serde_json::Value> = self
            .kids
            .lock()
            .unwrap()
            .iter()
            // Any valid modulus and exponent will do: the cache never
            // verifies a signature.
            .map(|kid| serde_json::json!({"kid": kid, "kty": "RSA", "n": "AQAB", "e": "AQAB"}))
            .collect();
        Ok(serde_json::json!({ "keys": keys }).to_string().into_bytes())
    }
}

/// A cache over a scripted provider, with a clock the test moves by hand.
fn scripted(kids: &[&'static str]) -> (Arc<Scripted>, Keys, Arc<SyncMutex<Instant>>) {
    let fetcher = Arc::new(Scripted {
        kids: SyncMutex::new(kids.to_vec()),
        fetches: AtomicUsize::new(0),
    });
    let now = Arc::new(SyncMutex::new(Instant::now()));
    let clock = Arc::clone(&now);
    let mut keys = Keys::new("https://issuer.test/jwks", fetcher.clone());
    keys.clock = Arc::new(move || *clock.lock().unwrap());
    (fetcher, keys, now)
}

fn advance(now: &SyncMutex<Instant>, by: Duration) {
    *now.lock().unwrap() += by;
}

fn fetches(fetcher: &Scripted) -> usize {
    fetcher.fetches.load(Ordering::SeqCst)
}

#[tokio::test]
async fn a_known_kid_is_served_from_one_fetch() {
    let (fetcher, keys, _) = scripted(&["a"]);
    assert!(keys.key("a").await.unwrap().is_some());
    assert!(keys.key("a").await.unwrap().is_some());
    assert_eq!(fetches(&fetcher), 1);
}

/// The rotation case: a token signed by a key the cache has never seen makes
/// the cache look again once the backoff has passed.
#[tokio::test]
async fn an_unknown_kid_refetches_after_the_backoff() {
    let (fetcher, keys, now) = scripted(&["a"]);
    assert!(keys.key("a").await.unwrap().is_some());
    *fetcher.kids.lock().unwrap() = vec!["a", "b"];

    advance(&now, UNKNOWN_KID_BACKOFF);
    assert!(keys.key("b").await.unwrap().is_some());
    assert_eq!(fetches(&fetcher), 2);
}

/// The flood case: unknown kids inside the backoff are answered from the
/// cache, not with another request.
#[tokio::test]
async fn a_second_unknown_kid_inside_the_backoff_does_not_refetch() {
    let (fetcher, keys, now) = scripted(&["a"]);
    assert!(keys.key("a").await.unwrap().is_some());
    *fetcher.kids.lock().unwrap() = vec!["a", "b"];

    advance(&now, UNKNOWN_KID_BACKOFF - Duration::from_secs(1));
    assert!(keys.key("b").await.unwrap().is_none());
    assert!(keys.key("c").await.unwrap().is_none());
    assert!(keys.key("a").await.unwrap().is_some());
    assert_eq!(fetches(&fetcher), 1);
}

#[tokio::test]
async fn a_known_kid_is_refetched_after_the_lifetime() {
    let (fetcher, keys, now) = scripted(&["a"]);
    assert!(keys.key("a").await.unwrap().is_some());
    advance(&now, TTL);
    assert!(keys.key("a").await.unwrap().is_some());
    assert_eq!(fetches(&fetcher), 2);
}

#[tokio::test]
async fn keys_are_only_fetched_over_https() {
    let fetcher = HttpKeyFetcher::new().unwrap();
    // Refused before anything is sent.
    assert!(matches!(
        fetcher.fetch("http://127.0.0.1:1/keys").await,
        Err(KeyFetchError::Fetch(_))
    ));
}

#[tokio::test]
async fn an_oversized_or_malformed_set_is_an_error_not_a_key() {
    struct Body(Vec<u8>);
    #[async_trait]
    impl KeyFetcher for Body {
        async fn fetch(&self, _: &str) -> Result<Vec<u8>, KeyFetchError> {
            Ok(self.0.clone())
        }
    }
    let read = |body: Vec<u8>| async {
        Keys::new("https://issuer.test/jwks", Arc::new(Body(body)))
            .key("a")
            .await
    };
    assert!(matches!(
        read(vec![b'{'; MAX_BYTES + 1]).await,
        Err(KeyFetchError::TooLarge)
    ));
    assert!(matches!(
        read(b"not json".to_vec()).await,
        Err(KeyFetchError::Malformed(_))
    ));
}
