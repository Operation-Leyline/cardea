//! Cardea over AWS: the directory table, the Cognito admin calls, the trigger
//! handler a product runs as its Lambda, the operations its API offers a
//! signed-in person ([`link`] and [`methods`]), and the verification-mail
//! budget. For adoption and account deletion it also fills the directory for a
//! pool that has users ([`backfill`]) and removes a deleted account's rows
//! ([`erasure`]).
//!
//! A product implements [`triggers::Product`] and calls [`triggers::run`].
//! The rules these act on are [`cardea_core`]'s.

// The AWS SDKs' futures nest deeply: Rust 1.97.1 overflows the default 128 laying them out.
#![recursion_limit = "256"]

pub mod backfill;
mod cause;
pub mod directory;
mod email_change;
pub mod erasure;
mod error;
pub mod link;
pub mod mail;
pub mod methods;
pub mod proof;
pub mod record;
mod transact;
pub mod triggers;

#[cfg(test)]
mod testing;

pub use aws_sdk_dynamodb;
pub use cardea_core;
pub use directory::{AwsDirectory, HolderReadError, mailbox_holder};
pub use error::OperationError;
pub use transact::{TransactError, transact};
