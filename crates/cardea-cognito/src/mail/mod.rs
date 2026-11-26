//! Cognito's mail, for a pool with a custom email sender: a code that could
//! complete an email change is refused; every other message a stranger can
//! request is counted against one of its mailbox's daily budgets
//! ([`Counter`]), its code decrypted, and handed to the product to deliver.
//!
//! A pool may route these events to the trigger function
//! ([`crate::triggers::run`]) or to a function of their own (`mail::run`).
//! Both need the `email-sender` feature, `MAIL_BUDGET_TABLE` (a table keyed by
//! `partitionKey` and `sortKey`, TTL `expiresAt`) with `PutItem` and
//! `UpdateItem` on it, and `COGNITO_EMAIL_KEY_ARN` with `kms:Decrypt` on that
//! key.

pub mod budget;
mod message;

#[cfg(feature = "email-sender")]
mod esdk;
#[cfg(feature = "email-sender")]
mod runtime;
mod sender;

pub use budget::{Counter, DAILY_CAP, RESET_DAILY_CAP, Refusal};
#[cfg(feature = "email-sender")]
pub use esdk::KmsDecryptor;
pub use message::{Code, MailDelivery, MailMessage, MessageKind, Template};
#[cfg(feature = "email-sender")]
pub use runtime::{run, serve};
pub use sender::{CodeDecryptor, EmailSender, MailError};
