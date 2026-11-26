//! Filling the directory for a pool that already has users, before the
//! directory is opened.
//!
//! With `SYSTEM#READY` written and no rows, an existing person's mailbox looks
//! unclaimed and their linked identities unknown. [`backfill`] gives every pool
//! user:
//!
//! - the mailbox row, `EMAIL#{personKey}`, with their `userId` (a user who
//!   never confirmed gets an unconfirmed claim instead, which lapses like any
//!   other);
//! - a `PROVIDER#` binding for each identity the pool links onto them, and a
//!   `METHODS#` row listing those identities.
//!
//! It never overwrites a row and never chooses between claimants. Whatever it
//! cannot write is a [`Finding`] for an operator, and the directory is not
//! opened while a blocking one remains.
//!
//! Run it after the Cardea triggers are deployed, which refuse new accounts
//! until the directory is open, so that none can appear outside it. Cognito's
//! `ListUsers` is eventually consistent, and an open directory is only read: wait
//! some minutes after the deployment, so that accounts made just before it are
//! listed. The `cardea-backfill` binary runs it from a terminal. It needs
//! `cognito-idp:ListUsers` and `AdminGetUser` on the pool, and `GetItem` and
//! `PutItem` on the table.
//!
//! Neither a report nor an error holds an address, a username or a provider
//! subject: users are named by their `sub`.

use cardea_core::Error;

use crate::directory::AwsDirectory;

mod pool;
mod report;
mod survey;
mod write;

pub use report::{BackfillReport, Finding, Outcome, Problem, RowCounts, RowKind};

/// What [`backfill`] may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Read the pool and the table, and write nothing.
    DryRun,
    /// Write the missing rows.
    Apply,
    /// Write the missing rows and, once a second pass finds every user covered,
    /// open the directory.
    ApplyAndActivate,
}

/// A backfill that could not run to its end. Rows already written stay, and a
/// repeat continues from them.
#[derive(Debug, thiserror::Error)]
pub enum BackfillError {
    /// The pool's users could not be listed. The text is AWS's error code.
    #[error("the user pool could not be listed ({0})")]
    ListUsers(String),
    /// The directory could not be read.
    #[error("the directory could not be read: {0}")]
    Read(#[from] Error),
    /// A row could not be written. The text is AWS's error code.
    #[error("a directory row could not be written ({0})")]
    Write(String),
    /// `SYSTEM#READY` holds something other than this library's version.
    #[error("the directory's readiness marker is not one this version knows")]
    UnknownMarker,
}

/// Backfill the directory of `directory`'s pool.
///
/// An open directory is only read, whatever `mode` says: its triggers write
/// rows themselves, so the report is all a run has to add.
pub async fn backfill(
    directory: &AwsDirectory,
    mode: Mode,
) -> Result<BackfillReport, BackfillError> {
    let open = directory.is_open().await?;
    let first = directory.survey().await?;
    if open || mode == Mode::DryRun {
        let outcome = if open {
            Outcome::AlreadyActive
        } else {
            Outcome::DryRun
        };
        return Ok(first.into_report(outcome));
    }
    let written = directory.write_missing(&first.missing).await?;
    // The second pass: the pool listed again and every row read back.
    let mut report = directory.survey().await?.into_report(Outcome::Applied);
    report.present = first.present;
    report.written = written;
    if mode == Mode::ApplyAndActivate {
        report.outcome = if report.needs_attention() {
            Outcome::ActivationRefused
        } else {
            directory.open().await?;
            Outcome::Activated
        };
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
