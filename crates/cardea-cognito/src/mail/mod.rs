//! Cognito's mail, for a pool with a custom email sender: a code that could
//! complete an email change is refused; every other message a stranger can
//! request is counted against one of its mailbox's daily budgets
//! ([`Counter`]), its code decrypted, and handed to the product to deliver.
//!
//! A pool may route these events to the trigger function
//! ([`crate::triggers::run`]) or to a function of their own (`mail::run`).
//! Both need the `email-sender` feature and:
//!
//! - `MAIL_BUDGET_TABLE`: a table keyed by `partitionKey` and `sortKey`, TTL
//!   `expiresAt`, with `PutItem` and `UpdateItem` on it;
//! - `MAIL_BUDGET_KEY_SECRET`: the name or ARN of the product's Secrets
//!   Manager secret holding the budget's key ([`BudgetKey`] has the format),
//!   with `secretsmanager:GetSecretValue` on it;
//! - `COGNITO_EMAIL_KEY_ARN`: the custom sender's KMS key, with `kms:Decrypt`
//!   on it.
//!
//! Without a readable key nothing is sent, not even the uncounted messages: the
//! event fails and the cause is logged.

pub mod budget;
mod key;
mod message;

#[cfg(feature = "email-sender")]
mod esdk;
#[cfg(feature = "email-sender")]
mod runtime;
#[cfg(feature = "email-sender")]
mod secret;
mod sender;

pub use budget::{Counter, DAILY_CAP, RESET_DAILY_CAP, Refusal};
#[cfg(feature = "email-sender")]
pub use esdk::KmsDecryptor;
pub use key::{BudgetKey, BudgetKeySource, KeyError};
pub use message::{Code, MailDelivery, MailMessage, MessageKind, Template};
#[cfg(feature = "email-sender")]
pub use runtime::{run, serve};
#[cfg(feature = "email-sender")]
pub use secret::SecretsManagerKey;
pub use sender::{CodeDecryptor, EmailSender, MailError};
