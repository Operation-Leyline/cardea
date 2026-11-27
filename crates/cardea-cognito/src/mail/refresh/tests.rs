//! On Tokio's paused clock, which moves only when a test moves it.

use std::sync::{Arc, Mutex};

use tokio::time::advance;

use super::*;

const INTERVAL: Duration = Duration::from_secs(300);
const MAX_AGE: Duration = Duration::from_secs(900);
const SECOND: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
enum Answer {
    Key(u8),
    Fail,
    Hang,
    /// A key, after this long.
    Slow(u8, Duration),
    /// A failure, after this long.
    SlowFail(Duration),
}

/// A source that answers as the test last said, and counts the reads.
#[derive(Clone)]
struct Source(Arc<Mutex<(Answer, usize)>>);

impl Source {
    fn answering(answer: Answer) -> Self {
        Self(Arc::new(Mutex::new((answer, 0))))
    }

    fn set(&self, answer: Answer) {
        self.0.lock().unwrap().0 = answer;
    }

    fn reads(&self) -> usize {
        self.0.lock().unwrap().1
    }
}

fn key_of(byte: u8) -> BudgetKey {
    BudgetKey::from_secret(&hex::encode([byte; 32])).unwrap()
}

#[async_trait]
impl BudgetKeySource for Source {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        let answer = {
            let mut state = self.0.lock().unwrap();
            state.1 += 1;
            state.0
        };
        let failed = || KeyError::Read("secrets layer down".into());
        match answer {
            Answer::Key(byte) => Ok(key_of(byte)),
            Answer::Fail => Err(failed()),
            Answer::Hang => std::future::pending().await,
            Answer::Slow(byte, delay) => {
                tokio::time::sleep(delay).await;
                Ok(key_of(byte))
            }
            Answer::SlowFail(delay) => {
                tokio::time::sleep(delay).await;
                Err(failed())
            }
        }
    }
}

fn refreshing(source: &Source) -> RefreshingKeySource<Source> {
    RefreshingKeySource::new(source.clone(), INTERVAL).with_max_age(MAX_AGE)
}

/// Which of the test keys `source` gives.
async fn given(source: &impl BudgetKeySource) -> u8 {
    let tag = source.load().await.unwrap().tag("name");
    (0..=u8::MAX)
        .find(|byte| key_of(*byte).tag("name") == tag)
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_key_is_kept_for_the_interval_and_then_read_again() {
    let source = Source::answering(Answer::Key(1));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Key(2));
    advance(INTERVAL - SECOND).await;
    assert_eq!(given(&key).await, 1);
    assert_eq!(source.reads(), 1);
    advance(SECOND).await;
    assert_eq!(given(&key).await, 2);
    // The new key has an interval of its own.
    assert_eq!(given(&key).await, 2);
    assert_eq!(source.reads(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_failed_refresh_keeps_the_last_key_and_the_next_call_reads_again() {
    let source = Source::answering(Answer::Key(1));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Fail);
    advance(INTERVAL).await;
    assert_eq!(given(&key).await, 1);
    assert_eq!(given(&key).await, 1);
    assert_eq!(source.reads(), 3);
    source.set(Answer::Key(2));
    assert_eq!(given(&key).await, 2);
}

#[tokio::test(start_paused = true)]
async fn past_the_maximum_age_there_is_no_key_until_a_read_succeeds() {
    let source = Source::answering(Answer::Key(1));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Fail);
    advance(MAX_AGE - SECOND).await;
    assert_eq!(given(&key).await, 1);
    // A failure does not make the key younger.
    advance(SECOND).await;
    for _ in 0..2 {
        assert!(matches!(key.load().await, Err(KeyError::Read(_))));
    }
    source.set(Answer::Key(2));
    assert_eq!(given(&key).await, 2);
}

#[tokio::test(start_paused = true)]
async fn with_no_key_yet_a_failure_is_the_answer() {
    let source = Source::answering(Answer::Fail);
    let key = refreshing(&source);
    assert!(matches!(key.load().await, Err(KeyError::Read(_))));
    source.set(Answer::Key(1));
    assert_eq!(given(&key).await, 1);
}

#[tokio::test(start_paused = true)]
async fn a_maximum_age_shorter_than_the_interval_shortens_it() {
    let source = Source::answering(Answer::Key(1));
    let key = RefreshingKeySource::new(source.clone(), INTERVAL).with_max_age(SECOND);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Fail);
    advance(SECOND).await;
    assert!(key.load().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn the_default_maximum_age_is_an_hour() {
    let source = Source::answering(Answer::Key(1));
    let key = RefreshingKeySource::new(source.clone(), INTERVAL);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Fail);
    advance(DEFAULT_MAX_KEY_AGE - SECOND).await;
    assert_eq!(given(&key).await, 1);
    advance(SECOND).await;
    assert!(key.load().await.is_err());
    assert_eq!(DEFAULT_MAX_KEY_AGE, Duration::from_secs(3600));
}

#[tokio::test(start_paused = true)]
async fn a_refresh_that_hangs_counts_as_failed() {
    let source = Source::answering(Answer::Key(1));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Hang);
    advance(INTERVAL).await;
    let before = Instant::now();
    assert_eq!(given(&key).await, 1);
    assert_eq!(before.elapsed(), REFRESH_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn a_key_that_ages_out_during_a_failing_refresh_is_not_given() {
    let source = Source::answering(Answer::Key(1));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    for answer in [Answer::Hang, Answer::SlowFail(SECOND)] {
        source.set(Answer::Key(1));
        advance(MAX_AGE).await;
        assert_eq!(given(&key).await, 1);
        source.set(answer);
        advance(MAX_AGE - SECOND).await;
        assert!(matches!(key.load().await, Err(KeyError::Read(_))));
    }
}

/// With nothing to fall back to, a slow read is waited for.
#[tokio::test(start_paused = true)]
async fn the_time_limit_applies_only_while_there_is_a_key_to_fall_back_to() {
    let slow = REFRESH_TIMEOUT * 3;
    let source = Source::answering(Answer::Slow(1, slow));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Slow(2, slow));
    advance(MAX_AGE).await;
    assert_eq!(given(&key).await, 2);
}

#[tokio::test(start_paused = true)]
async fn a_read_that_lasts_the_maximum_age_gives_no_key() {
    let source = Source::answering(Answer::Slow(1, MAX_AGE));
    let key = refreshing(&source);
    // With no key yet, and again with one that has aged out.
    assert!(matches!(key.load().await, Err(KeyError::Read(_))));
    source.set(Answer::Key(1));
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Slow(2, MAX_AGE));
    advance(MAX_AGE).await;
    assert!(matches!(key.load().await, Err(KeyError::Read(_))));
    // Neither answer was kept.
    source.set(Answer::Fail);
    assert!(key.load().await.is_err());
}

/// The age counts from when the read began, not from its answer.
#[tokio::test(start_paused = true)]
async fn a_key_ages_from_the_start_of_its_read() {
    let source = Source::answering(Answer::Slow(1, INTERVAL));
    let key = refreshing(&source);
    assert_eq!(given(&key).await, 1);
    source.set(Answer::Key(2));
    assert_eq!(given(&key).await, 2);
}
