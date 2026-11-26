//! A DynamoDB transaction that goes again when it only lost a race.

use std::time::Duration;

use aws_sdk_dynamodb::{
    Client,
    error::{ProvideErrorMetadata, SdkError},
    operation::transact_write_items::TransactWriteItemsError,
    types::TransactWriteItem,
};

/// A transaction DynamoDB refused or never answered.
#[derive(Debug, thiserror::Error)]
#[error("the transaction failed")]
pub struct TransactError(#[source] pub Box<SdkError<TransactWriteItemsError>>);

impl TransactError {
    /// AWS's code for what stopped the transaction. `None` only when the
    /// cancellation says a condition or a race did: the table was not as the
    /// writes expected, and nothing else was wrong.
    pub(crate) fn fault(&self) -> Option<String> {
        fault_in(self.0.as_service_error())
    }
}

fn fault_in(error: Option<&TransactWriteItemsError>) -> Option<String> {
    let cancelled = match error {
        Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) => cancelled,
        Some(refused) => return Some(refused.code().unwrap_or("unknown error").to_owned()),
        None => return Some("no answer".into()),
    };
    let mut raced = false;
    for reason in cancelled.cancellation_reasons() {
        match reason.code() {
            None | Some("None") => {}
            Some("ConditionalCheckFailed" | "TransactionConflict") => raced = true,
            Some(other) => return Some(other.to_owned()),
        }
    }
    // A cancellation that gives no reason is not taken for a race.
    (!raced).then(|| "TransactionCanceledException".into())
}

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
    fn a_fault_is_anything_but_a_condition_or_a_race() {
        let fault = |codes: &[&str]| fault_in(Some(&cancelled(codes)));
        assert_eq!(fault(&["None", "ConditionalCheckFailed"]), None);
        assert_eq!(fault(&["TransactionConflict", "None"]), None);
        assert_eq!(
            fault(&["ConditionalCheckFailed", "ThrottlingError"]),
            Some("ThrottlingError".into())
        );
        let denied = TransactWriteItemsError::generic(
            aws_sdk_dynamodb::error::ErrorMetadata::builder()
                .code("AccessDeniedException")
                .build(),
        );
        assert_eq!(
            fault_in(Some(&denied)),
            Some("AccessDeniedException".into())
        );
        assert_eq!(fault_in(None), Some("no answer".into()));
        for unexplained in [&[][..], &["None", "None"]] {
            assert_eq!(
                fault(unexplained),
                Some("TransactionCanceledException".into())
            );
        }
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
