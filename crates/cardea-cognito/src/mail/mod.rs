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
//!
//! # A product's own secrets layer
//!
//! By default a function reads the secret for its first mail event and keeps
//! the key for as long as it lives. A product that reads every secret through
//! its own secrets layer, or that wants a changed key to take effect without
//! replacing the function, implements [`BudgetKeySource`] and gives it to the
//! handler ([`crate::triggers::TriggerHandler::with_budget_key_source`]) or to
//! a sender of its own (`EmailSender::from_env_with_key_source`). The function
//! then needs no `MAIL_BUDGET_KEY_SECRET`, and whatever access the layer needs
//! in place of the grant on it. [`RefreshingKeySource`] reads the source again
//! on an interval and bounds how old a key may grow when that fails; a layer
//! that already does both can be given as it is.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use async_trait::async_trait;
//! use cardea_cognito::{
//!     mail::{BudgetKey, BudgetKeySource, KeyError, RefreshingKeySource},
//!     triggers::{Product, TriggerHandler},
//! };
//!
//! /// Stands for the product's secrets layer.
//! struct Secrets;
//!
//! impl Secrets {
//!     async fn read(&self, name: &str) -> Result<String, std::io::Error> {
//!         // The product's own reading, auditing and so on.
//! #       let _ = name;
//! #       Ok("00".repeat(32))
//!     }
//! }
//!
//! struct ProductKey(Secrets);
//!
//! #[async_trait]
//! impl BudgetKeySource for ProductKey {
//!     async fn load(&self) -> Result<BudgetKey, KeyError> {
//!         let text = self
//!             .0
//!             .read("mail-budget-key")
//!             .await
//!             .map_err(|error| KeyError::Read(Box::new(error)))?;
//!         BudgetKey::from_secret(&text)
//!     }
//! }
//!
//! /// What `main` awaits, in place of calling `triggers::run`.
//! async fn serve(product: impl Product, secrets: Secrets) -> Result<(), lambda_runtime::Error> {
//!     let five_minutes = Duration::from_secs(300);
//!     let key = RefreshingKeySource::new(ProductKey(secrets), five_minutes);
//!     TriggerHandler::new(product)
//!         .await
//!         .with_budget_key_source(key)
//!         .serve()
//!         .await
//! }
//! # fn main() {}
//! ```

pub mod budget;
mod key;
mod message;
mod once;
mod refresh;

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
pub use refresh::{DEFAULT_MAX_KEY_AGE, REFRESH_TIMEOUT, RefreshingKeySource};
#[cfg(feature = "email-sender")]
pub(crate) use runtime::{defaults, environment};
#[cfg(feature = "email-sender")]
pub use runtime::{run, serve};
#[cfg(feature = "email-sender")]
pub use secret::SecretsManagerKey;
pub use sender::{CodeDecryptor, EmailSender, MailError};
