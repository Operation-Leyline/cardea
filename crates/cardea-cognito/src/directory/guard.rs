//! The writes that bind a mailbox's row to its account: the guard a product
//! commits with its own writes, and the record that a password was chosen.

use aws_sdk_dynamodb::types::TransactWriteItem;
use cardea_core::{Directory, Error, normalize_email};
use tabulary::Update;

use super::{AwsDirectory, email_key};
use crate::record::EmailRowAttrs;

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
        let owned = match &row.user_id {
            Some(bound) => bound == user_id,
            // Not provisioned yet: the guard's own test of ownership.
            None => {
                row.record.username == username
                    || match self.native_user(&row.record).await {
                        Ok(owner) => owner.user_id == user_id,
                        Err(Error::Unavailable) => return Err(Error::Unavailable),
                        // No confirmed account there, so it is not this one.
                        Err(_) => false,
                    }
            }
        };
        if !owned {
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
