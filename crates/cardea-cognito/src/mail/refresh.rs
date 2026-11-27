//! A key read again on an interval.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio::{sync::Mutex, time::Instant};

use super::{BudgetKey, BudgetKeySource, KeyError};
use crate::cause::cause;

/// How old a key may grow while reading it again fails, unless
/// [`RefreshingKeySource::with_max_age`] says otherwise: one hour.
pub const DEFAULT_MAX_KEY_AGE: Duration = Duration::from_secs(60 * 60);

/// How long a read may take while there is still a key to fall back to.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(2);

/// Why a refresh counts as failed when its source says nothing.
#[derive(Debug, thiserror::Error)]
#[error("the mail budget key was not read again in time")]
struct TimedOut;

/// Keeps another source's key and reads it again once it is `interval` old, so
/// that a changed key takes effect in a running function.
///
/// Nothing runs in the background: the first [`load`](BudgetKeySource::load) to
/// find the key `interval` old reads it, and waits for the answer.
///
/// **A failed read** keeps the last good key, logs a warning, and is tried
/// again by the next call. A read that takes longer than [`REFRESH_TIMEOUT`]
/// has failed, if there is a key to fall back to.
///
/// **The bound.** A key is not given out once its age reaches the maximum
/// ([`DEFAULT_MAX_KEY_AGE`], or [`with_max_age`](Self::with_max_age)), counted
/// from the start of the read that gave it. From then on `load` fails, and
/// nothing is sent, until a read succeeds. So after the source's key changes,
/// the old one is given out for less than `interval` while reads succeed, and
/// for less than the maximum age while they fail. A source that caches adds its
/// own cache's age to both. A maximum shorter than `interval` also shortens the
/// interval.
pub struct RefreshingKeySource<S> {
    source: S,
    interval: Duration,
    max_age: Duration,
    held: Mutex<Option<Held>>,
}

/// The last key the source gave.
struct Held {
    key: BudgetKey,
    read: ReadTime,
}

/// When a read started, on both clocks: a suspended host may stop the
/// monotonic one, and the wall clock may be set back.
#[derive(Clone, Copy)]
struct ReadTime {
    monotonic: Instant,
    wall: SystemTime,
}

impl ReadTime {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    /// The longer of the two clocks' answers.
    fn age(self) -> Duration {
        self.monotonic
            .elapsed()
            .max(self.wall.elapsed().unwrap_or_default())
    }
}

impl<S: BudgetKeySource> RefreshingKeySource<S> {
    /// `source`'s key, read again once it is `interval` old.
    pub fn new(source: S, interval: Duration) -> Self {
        Self {
            source,
            interval,
            max_age: DEFAULT_MAX_KEY_AGE,
            held: Mutex::new(None),
        }
    }

    /// Give out a key only while it is younger than `max_age`.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }
}

#[async_trait]
impl<S: BudgetKeySource> BudgetKeySource for RefreshingKeySource<S> {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        // Held across the read: one runs at a time, and those waiting on a
        // successful one use its key.
        let mut held = self.held.lock().await;
        let age = held.as_ref().map(|held| held.read.age());
        if let Some(held) = &*held
            && age.is_some_and(|age| age < self.interval.min(self.max_age))
        {
            return Ok(held.key.clone());
        }
        let started = ReadTime::now();
        let read = if age.is_some_and(|age| age < self.max_age) {
            tokio::time::timeout(REFRESH_TIMEOUT, self.source.load())
                .await
                .unwrap_or_else(|_| Err(KeyError::Read(Box::new(TimedOut))))
        } else {
            // Nothing to fall back to: wait as long as the caller does.
            self.source.load().await
        };
        match read {
            Ok(key) => {
                *held = Some(Held {
                    key: key.clone(),
                    read: started,
                });
                Ok(key)
            }
            // The age is taken again: the read itself took time.
            Err(error) => match &*held {
                Some(last) if last.read.age() < self.max_age => {
                    tracing::warn!(
                        cause = %cause(&error),
                        "mail budget key not read again; keeping the last one"
                    );
                    Ok(last.key.clone())
                }
                _ => Err(error),
            },
        }
    }
}

#[cfg(test)]
mod tests;
