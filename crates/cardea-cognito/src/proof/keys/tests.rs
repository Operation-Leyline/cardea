//! The cache policy, over a scripted provider and a clock the test moves.

use std::sync::{
    Mutex as SyncMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use tokio::sync::Notify;

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

/// Serves one key, unless it is told to be down; a request may be held.
#[derive(Default)]
struct Flaky {
    down: AtomicBool,
    hold: AtomicBool,
    held: Notify,
    release: Notify,
    fetches: AtomicUsize,
}

#[async_trait]
impl KeyFetcher for Flaky {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, KeyFetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            self.held.notify_one();
            self.release.notified().await;
        }
        if self.down.load(Ordering::SeqCst) {
            return Err(KeyFetchError::TooLarge);
        }
        let key = serde_json::json!({"kid": "a", "kty": "RSA", "n": "AQAB", "e": "AQAB"});
        Ok(serde_json::json!({"keys": [key]}).to_string().into_bytes())
    }
}

fn flaky() -> (Arc<Flaky>, Arc<Keys>, Arc<SyncMutex<Instant>>) {
    let fetcher = Arc::new(Flaky::default());
    let now = Arc::new(SyncMutex::new(Instant::now()));
    let clock = Arc::clone(&now);
    let mut keys = Keys::new("https://issuer.test/jwks", fetcher.clone());
    keys.clock = Arc::new(move || *clock.lock().unwrap());
    (fetcher, Arc::new(keys), now)
}

#[tokio::test]
async fn an_outage_with_no_set_is_not_fetched_again_at_once() {
    let (fetcher, keys, now) = flaky();
    fetcher.down.store(true, Ordering::SeqCst);
    assert!(matches!(keys.key("a").await, Err(KeyFetchError::TooLarge)));
    for kid in ["a", "b"] {
        assert!(matches!(
            keys.key(kid).await,
            Err(KeyFetchError::RecentlyFailed)
        ));
    }
    assert_eq!(fetcher.fetches.load(Ordering::SeqCst), 1);

    fetcher.down.store(false, Ordering::SeqCst);
    advance(&now, FAILURE_BACKOFF);
    assert!(keys.key("a").await.unwrap().is_some());
}

#[tokio::test]
async fn an_outage_keeps_the_backoff_and_the_current_set() {
    let (fetcher, keys, now) = flaky();
    assert!(keys.key("a").await.unwrap().is_some());
    fetcher.down.store(true, Ordering::SeqCst);
    advance(&now, UNKNOWN_KID_BACKOFF);
    assert!(keys.key("made-up").await.is_err());
    advance(&now, UNKNOWN_KID_BACKOFF - Duration::from_secs(1));
    assert!(keys.key("another").await.is_err());
    assert!(keys.key("a").await.unwrap().is_some());
    assert_eq!(fetcher.fetches.load(Ordering::SeqCst), 2);

    // Past its lifetime the set is not used, reachable provider or not.
    advance(&now, TTL);
    assert!(keys.key("a").await.is_err());
}

#[tokio::test]
async fn a_known_key_is_answered_while_a_fetch_is_under_way() {
    let (fetcher, keys, now) = flaky();
    assert!(keys.key("a").await.unwrap().is_some());
    fetcher.hold.store(true, Ordering::SeqCst);
    advance(&now, UNKNOWN_KID_BACKOFF);
    let slow = {
        let keys = Arc::clone(&keys);
        tokio::spawn(async move { keys.key("b").await.map(|key| key.is_some()) })
    };
    fetcher.held.notified().await;

    let known = tokio::time::timeout(Duration::from_secs(10), keys.key("a")).await;
    assert!(known.expect("not held up").unwrap().is_some());

    fetcher.release.notify_one();
    assert!(!slow.await.unwrap().unwrap());
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
