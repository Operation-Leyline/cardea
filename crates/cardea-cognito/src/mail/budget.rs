//! A per-recipient daily budget for the mail Cognito asks us to send.
//!
//! `SignUp`, `ResendConfirmationCode` and `ForgotPassword` take an address and
//! mail it, so anyone can aim them at a victim's inbox. Cognito throttles its
//! own API, but that bounds the rate, not the day's total, and every message
//! is also a mark against the sender's reputation. The custom email sender
//! spends from this budget before it decrypts or sends.
//!
//! The table is the caller's (`partitionKey`, `sortKey`, TTL `expiresAt`). A
//! row is keyed by the hash of the recipient's [`person_key`], never the
//! address: aliases of one mailbox share a budget, and no address is stored. A
//! row exists only for a day in which mail was sent, and expires after it.
use aws_sdk_dynamodb::{
    Client,
    operation::transact_write_items::TransactWriteItemsError,
    types::{AttributeValue as Av, Put, TransactWriteItem, Update},
};
use cardea_core::person_key;
use sha2::{Digest, Sha256};

use crate::{TransactError, cause::cause, transact};

/// Messages of [`Counter::General`] one mailbox may be sent in a UTC day. A
/// person legitimately needs a handful (the signup code, a resend or two, a
/// sign-in code), so eight leaves headroom, while a mail-bombed victim gets a
/// bounded number a day instead of as many as the attacker can request.
pub const DAILY_CAP: i64 = 8;

/// Password reset messages one mailbox may be sent in a UTC day.
pub const RESET_DAILY_CAP: i64 = 3;

const DAY_SECONDS: i64 = 86_400;

/// Why a message was not allowed. Cognito quotes the sender's error text to
/// the caller verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The mailbox has used today's budget.
    #[error("too many emails were requested for this address today; try again tomorrow")]
    CapReached,
    /// The recipient is not an address.
    #[error("the recipient address is not valid")]
    Invalid,
    /// The counter could not be read or written. Refused rather than sent:
    /// an unmetered send is exactly what this guard exists to prevent.
    #[error("email service is unavailable; retry the same request")]
    Unavailable,
}

/// Which of a mailbox's daily counters a message draws on. Anyone can ask for
/// a reset code for any address, so resets are counted apart: running them out
/// leaves signup and sign-in codes untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    /// Signup, resend, attribute verification and sign-in codes.
    General,
    /// Password reset codes.
    PasswordReset,
}

impl Counter {
    /// The most messages this counter allows in a UTC day.
    pub fn daily_cap(self) -> i64 {
        match self {
            Self::General => DAILY_CAP,
            Self::PasswordReset => RESET_DAILY_CAP,
        }
    }

    /// How the counter's rows start their sort key.
    fn sort_prefix(self) -> &'static str {
        match self {
            Self::General => "SEND",
            Self::PasswordReset => "RESET",
        }
    }
}

/// The counter's key: one row per mailbox per counter per UTC day.
fn key(recipient: &str, counter: Counter, now: i64) -> Result<(String, String), Refusal> {
    let mailbox = person_key(recipient).map_err(|_| Refusal::Invalid)?;
    Ok((
        format!("MAIL#{}", hex::encode(Sha256::digest(mailbox.as_bytes()))),
        format!("{}#{}", counter.sort_prefix(), now.div_euclid(DAY_SECONDS)),
    ))
}

/// Spend one message from `recipient`'s `counter` for the UTC day containing
/// `now` (Unix seconds), or say why not.
///
/// `delivery` names the message (the sender's idempotency key): a retry of a
/// message already counted spends nothing and is allowed, so a transient
/// failure that Cognito or Lambda retries cannot drain the budget one
/// message at a time. A marker row and the counter are one transaction: the
/// marker's condition says "already counted", the counter's says "cap
/// reached", and the count and the cap check are one conditional write, so
/// concurrent requests cannot overshoot the cap. A request that only lost the
/// race for a row to another one goes again ([`transact`]).
pub async fn spend(
    ddb: &Client,
    table: &str,
    recipient: &str,
    delivery: &str,
    counter: Counter,
    now: i64,
) -> Result<(), Refusal> {
    let (partition, sort) = key(recipient, counter, now)?;
    // The rows outlive their day by one more, so a clock that is a little
    // behind the table's never reads a lapsed counter as a fresh budget.
    let expires = Av::N(((now.div_euclid(DAY_SECONDS) + 2) * DAY_SECONDS).to_string());
    let marker = Put::builder()
        .table_name(table)
        .item("partitionKey", Av::S(partition.clone()))
        .item(
            "sortKey",
            Av::S(format!(
                "DELIVERY#{}",
                hex::encode(Sha256::digest(delivery.as_bytes()))
            )),
        )
        .item("expiresAt", expires.clone())
        .condition_expression("attribute_not_exists(partitionKey)")
        .build()
        .map_err(|_| Refusal::Unavailable)?;
    let count = Update::builder()
        .table_name(table)
        .key("partitionKey", Av::S(partition))
        .key("sortKey", Av::S(sort))
        .update_expression("SET expiresAt = :expires ADD #count :one")
        .condition_expression("attribute_not_exists(#count) OR #count < :cap")
        .expression_attribute_names("#count", "count")
        .expression_attribute_values(":one", Av::N("1".into()))
        .expression_attribute_values(":cap", Av::N(counter.daily_cap().to_string()))
        .expression_attribute_values(":expires", expires)
        .build()
        .map_err(|_| Refusal::Unavailable)?;
    let items = vec![
        TransactWriteItem::builder().put(marker).build(),
        TransactWriteItem::builder().update(count).build(),
    ];
    match transact(ddb, items).await {
        Ok(()) => Ok(()),
        Err(TransactError(error)) => match failed_conditions(error.as_service_error()).as_slice() {
            // The marker exists: this message was counted when it first came.
            failed if failed.contains(&0) => Ok(()),
            [] => {
                tracing::error!(cause = %cause(&error), "mail budget unavailable");
                Err(Refusal::Unavailable)
            }
            _ => Err(Refusal::CapReached),
        },
    }
}

/// The positions of a cancelled transaction's items whose condition was false.
/// A condition failure is a fact about the data, so it counts even beside a
/// transient reason on another item.
fn failed_conditions(error: Option<&TransactWriteItemsError>) -> Vec<usize> {
    let Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) = error else {
        return Vec::new();
    };
    cancelled
        .cancellation_reasons()
        .iter()
        .enumerate()
        .filter(|(_, reason)| reason.code() == Some("ConditionalCheckFailed"))
        .map(|(position, _)| position)
        .collect()
}

#[cfg(test)]
mod tests;
