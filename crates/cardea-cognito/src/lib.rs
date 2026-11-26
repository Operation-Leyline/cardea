//! Cardea over AWS: the directory table, the Cognito admin calls, the trigger
//! handler a product runs as its Lambda, and the verification-mail budget.
//!
//! A product implements [`triggers::Product`] and calls [`triggers::run`].
//! The rules these act on are [`cardea_core`]'s.

mod cause;
pub mod directory;
mod email_change;
pub mod mail;
pub mod record;
mod transact;
pub mod triggers;

#[cfg(test)]
mod testing;

pub use aws_sdk_dynamodb;
pub use cardea_core;
pub use directory::{AwsDirectory, HolderReadError, mailbox_holder};
pub use transact::{TransactError, transact};
