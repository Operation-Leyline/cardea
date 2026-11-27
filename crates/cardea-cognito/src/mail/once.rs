//! A key read once.

use async_trait::async_trait;
use tokio::sync::OnceCell;

use super::{BudgetKey, BudgetKeySource, KeyError};

/// Asks `source` until it gives a key, then answers with that key. A failure is
/// not remembered.
pub(super) struct ReadOnce<S> {
    source: S,
    key: OnceCell<BudgetKey>,
}

impl<S> ReadOnce<S> {
    pub(super) fn new(source: S) -> Self {
        Self {
            source,
            key: OnceCell::new(),
        }
    }
}

#[async_trait]
impl<S: BudgetKeySource> BudgetKeySource for ReadOnce<S> {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        self.key
            .get_or_try_init(|| self.source.load())
            .await
            .cloned()
    }
}
