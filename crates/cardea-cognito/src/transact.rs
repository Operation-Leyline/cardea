//! A DynamoDB transaction that goes again when it only lost a race.

use std::time::Duration;

use aws_sdk_dynamodb::{
    Client, error::SdkError, operation::transact_write_items::TransactWriteItemsError,
    types::TransactWriteItem,
};

/// A transaction DynamoDB refused or never answered.
#[derive(Debug, thiserror::Error)]
#[error("the transaction failed")]
pub struct TransactError(#[source] pub Box<SdkError<TransactWriteItemsError>>);

/// Whether a transaction was cancelled only because another transaction held
/// one of its items: nothing was decided, so the same writes can go again.
fn only_conflicted(error: Option<&TransactWriteItemsError>) -> bool {
    let Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) = error else {
        return false;
    };
    let reasons = cancelled.cancellation_reasons();
    reasons
        .iter()
        .any(|reason| reason.code() == Some("TransactionConflict"))
        && reasons
            .iter()
            .all(|reason| matches!(reason.code(), None | Some("None" | "TransactionConflict")))
}

/// Send `items` as one transaction, again after a short pause when it only
/// lost a race. Token refreshes from two tabs repeat the same idempotent guard
/// write at once, and the loser must not fail the person's sign-in.
pub async fn transact(client: &Client, items: Vec<TransactWriteItem>) -> Result<(), TransactError> {
    const ATTEMPTS: u32 = 4;
    let mut attempt = 1;
    loop {
        match client
            .transact_write_items()
            .set_transact_items(Some(items.clone()))
            .send()
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) if attempt < ATTEMPTS && only_conflicted(error.as_service_error()) => {
                tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
                attempt += 1;
            }
            Err(error) => return Err(TransactError(Box::new(error))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cancelled(codes: &[&str]) -> TransactWriteItemsError {
        use aws_sdk_dynamodb::types::{CancellationReason, error::TransactionCanceledException};
        let reasons = codes
            .iter()
            .map(|code| CancellationReason::builder().code(*code).build())
            .collect();
        TransactWriteItemsError::TransactionCanceledException(
            TransactionCanceledException::builder()
                .set_cancellation_reasons(Some(reasons))
                .build(),
        )
    }

    #[test]
    fn only_a_pure_conflict_is_retried() {
        assert!(only_conflicted(Some(&cancelled(&["TransactionConflict"]))));
        assert!(only_conflicted(Some(&cancelled(&[
            "None",
            "TransactionConflict",
            "None"
        ]))));
        assert!(!only_conflicted(Some(&cancelled(&[
            "ConditionalCheckFailed",
            "TransactionConflict"
        ]))));
        assert!(!only_conflicted(Some(&cancelled(&["None", "None"]))));
    }
}
