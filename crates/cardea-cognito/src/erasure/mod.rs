//! Erasing an account: removing the directory rows a deleted user would leave
//! behind, so that its mailbox and provider identities can be used again.
//!
//! The product deletes the Cognito user; this module never does. Call them in
//! this order, with the same [`User`](cardea_core::User):
//!
//! 1. `AdminDisableUser` (recommended), so that nothing signs in or links
//!    while the account goes;
//! 2. [`plan_erasure`]: read what the account holds, and record in the
//!    directory whatever only the pool knows;
//! 3. `AdminDeleteUser`;
//! 4. [`erase_user`]: delete the rows that still name this user.
//!
//! A link request already under way when the user was deleted can still write
//! after step 4. It writes the user's list with the binding, so running steps 2
//! and 4 once more, after the longest such a request can run (the function's
//! timeout), removes both.
//!
//! After any failure, run the sequence again from the start, treating a user
//! that is already gone as deleted. Keep the user's id, username and email
//! until the last pass (below) has succeeded: they are how a repeat finds the
//! rows. The plan itself need not be kept.
//!
//! The caller needs `GetItem`, `PutItem`, `UpdateItem` and `DeleteItem` on the
//! directory table and `cognito-idp:AdminGetUser` on the pool, besides what it
//! needs to disable and delete the user.

use cardea_core::Error;

mod erase;
mod plan;

pub use erase::{ErasureReport, erase_user};
pub use plan::{ErasurePlan, plan_erasure};

/// A refused or failed [`erase_user`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErasureError {
    /// The directory refused, or a dependency failed.
    #[error(transparent)]
    Identity(#[from] Error),
    /// The pool still holds the account. Delete it first: an account that
    /// outlives its rows can no longer sign in properly.
    #[error("delete the user from the pool before erasing its directory rows")]
    UserStillExists,
}

#[cfg(test)]
mod tests;
