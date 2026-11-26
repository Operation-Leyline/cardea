//! What binds a mailbox's row to its account: whether a row is an account's,
//! the guard a product commits with its own writes, and the record that a
//! password was chosen.

use aws_sdk_dynamodb::types::TransactWriteItem;
use cardea_core::{Directory, Error, normalize_email};
use tabulary::Update;

use super::{AwsDirectory, email_key};
use crate::record::{EmailRow, EmailRowAttrs};

impl AwsDirectory {
    /// The condition that no other Cognito user owns this mailbox, binding it
    /// to `user_id`. Put it in the same transaction as the account's first
    /// writes: a second Cognito `sub` then cannot produce a second product
    /// user, even if a trigger is bypassed.
    pub async fn profile_guard(
        &self,
        email: &str,
        username: &str,
        user_id: &str,
    ) -> Result<TransactWriteItem, Error> {
        self.ready().await?;
        let email = normalize_email(email)?;
        // Lapsed or not: a signup nobody has displaced may still confirm, and
        // the condition below refuses one that was.
        let owner = self.email_row(&email).await?.ok_or(Error::Conflict)?.record;
        if owner.username != username {
            let user = self.native_user(&owner).await?;
            if user.user_id != user_id {
                return Err(Error::Conflict);
            }
        }
        let user = EmailRowAttrs::USER_ID;
        let guard = self
            .rows()?
            .update(email_key(&email)?)
            .changes(
                Update::new()
                    .and(user.set(user_id.to_owned()))
                    // A confirmed mailbox never lapses.
                    .and(EmailRowAttrs::UNCONFIRMED_EXPIRES_AT.remove()),
            )
            .condition(
                EmailRowAttrs::RECORD
                    .eq(owner)
                    .and(user.not_exists().or(user.eq(user_id.to_owned()))),
            )
            .into_tx()
            .map_err(|_| Error::Invalid)?;
        // The provisioning transaction also writes tables this crate does not
        // type, so the guard joins it as a plain item.
        Ok(guard.input().clone())
    }

    /// Whether the mailbox's `row` is the account `user_id`'s: bound to it,
    /// or not yet bound and claimed under `username` or held by it in the pool.
    async fn owns(&self, row: &EmailRow, username: &str, user_id: &str) -> Result<bool, Error> {
        if let Some(bound) = &row.user_id {
            return Ok(bound == user_id);
        }
        // Not provisioned yet: the guard's own test of ownership.
        if row.record.username == username {
            return Ok(true);
        }
        match self.native_user(&row.record).await {
            Ok(owner) => Ok(owner.user_id == user_id),
            Err(Error::Unavailable) => Err(Error::Unavailable),
            // No confirmed account there, so it is not this one.
            Err(_) => Ok(false),
        }
    }

    /// Refuse, with [`Error::EmailChange`], to verify an address that does not
    /// reach the account's own mailbox: ownership in the directory would not
    /// follow it. `email` is the address the code is for.
    pub async fn check_verification(
        &self,
        email: &str,
        username: &str,
        user_id: &str,
    ) -> Result<(), Error> {
        match self.email_row(email).await? {
            Some(row) if self.owns(&row, username, user_id).await? => Ok(()),
            _ => Err(Error::EmailChange),
        }
    }

    /// Record that the account chose a password (a confirmed reset): set
    /// `passwordSet` on the mailbox's row, only when that row is this user's.
    /// A mailbox with no row, or another user's, is left alone.
    pub async fn record_password_set(
        &self,
        email: &str,
        username: &str,
        user_id: &str,
    ) -> Result<(), Error> {
        let Some(row) = self.email_row(email).await? else {
            return Ok(());
        };
        if !self.owns(&row, username, user_id).await? {
            return Ok(());
        }
        let request = self
            .rows()?
            .update(email_key(email)?)
            .changes(Update::new().and(EmailRowAttrs::PASSWORD_SET.set(true)))
            .condition(EmailRowAttrs::RECORD.eq(row.record))
            .build()
            .map_err(|_| Error::Invalid)?;
        request
            .decode(request.apply(self.dynamodb().update_item()).send().await)
            .map(|_| ())
            .map_err(|_| Error::Unavailable)
    }
}
