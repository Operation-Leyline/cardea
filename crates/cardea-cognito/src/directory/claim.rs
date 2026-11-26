//! A mailbox's claim over time: who may take its directory row, and when an
//! unconfirmed native signup stops holding it. It never calls Cognito.

use std::time::{SystemTime, UNIX_EPOCH};

use cardea_core::{EmailOwner, Error, UNCONFIRMED_CLAIM_LIFETIME_SECONDS, person_key};

use super::AwsDirectory;
use crate::record::{EmailRow, EmailRowAttrs};

/// The wall clock in epoch seconds. A host clock before 1970 reads as the
/// epoch, which keeps the request alive.
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// How long a new claim holds its mailbox.
#[derive(Clone, Copy)]
pub(crate) enum Hold {
    /// A self-signup nobody has confirmed: it lapses after
    /// [`UNCONFIRMED_CLAIM_LIFETIME_SECONDS`].
    Unconfirmed,
    /// Until an operator removes it.
    Permanent,
}

/// When `row`'s claim stops holding its mailbox, if it ever does. A row naming
/// a user is a confirmed account's and never lapses, whatever else it carries.
fn lapses_at(row: &EmailRow) -> Option<i64> {
    row.unconfirmed_expires_at.filter(|_| row.user_id.is_none())
}

impl AwsDirectory {
    /// The row holding `email`'s mailbox at `now`.
    async fn live_row(&self, email: &str, now: i64) -> Result<Option<EmailRow>, Error> {
        Ok(self
            .email_row(email)
            .await?
            .filter(|row| lapses_at(row).is_none_or(|until| until > now)))
    }

    /// The owner holding `email`'s mailbox at `now`.
    pub(super) async fn live_owner(
        &self,
        email: &str,
        now: i64,
    ) -> Result<Option<EmailOwner>, Error> {
        Ok(self.live_row(email, now).await?.map(|row| row.record))
    }

    /// Take `owner`'s mailbox if it is free at `now`: never claimed, or held
    /// by a lapsed claim. A [`Hold::Permanent`] claim also ends the lapse of
    /// an unconfirmed claim that is already `owner`'s. The write's outcome is
    /// not trusted; the winner is read back. A read that finds only a lapsed
    /// claim, or `owner`'s claim still lapsing when a permanent one was asked
    /// for, means this write did not land.
    pub(crate) async fn claim_email_at(
        &self,
        owner: &EmailOwner,
        hold: Hold,
        now: i64,
    ) -> Result<EmailOwner, Error> {
        let row = EmailRow {
            person: person_key(&owner.email)?,
            record: owner.clone(),
            user_id: None,
            password_initialization: None,
            unconfirmed_expires_at: match hold {
                Hold::Unconfirmed => Some(now + UNCONFIRMED_CLAIM_LIFETIME_SECONDS),
                Hold::Permanent => None,
            },
            // The origin already says it; see `EmailOwner::password_set`.
            password_set: None,
        };
        let user = EmailRowAttrs::USER_ID;
        // No row, or a claim `lapses_at` puts at or before `now`, decided
        // atomically with the write. A claim without an expiry compares false,
        // so it is never taken.
        let free = EmailRowAttrs::RECORD
            .not_exists()
            .and(user.not_exists())
            .or(user
                .not_exists()
                .and(EmailRowAttrs::UNCONFIRMED_EXPIRES_AT.le(now)));
        let free = match hold {
            Hold::Unconfirmed => free,
            Hold::Permanent => free.or(user
                .not_exists()
                .and(EmailRowAttrs::UNCONFIRMED_EXPIRES_AT.exists())
                .and(EmailRowAttrs::RECORD.eq(owner.clone()))),
        };
        let request = self
            .rows()?
            .put(&row)
            .condition(free)
            .build()
            .map_err(|_| Error::Invalid)?;
        let _ = request.apply(self.dynamodb().put_item()).send().await;
        let held = self
            .live_row(&owner.email, now)
            .await?
            .ok_or(Error::Unavailable)?;
        if matches!(hold, Hold::Permanent) && held.record == *owner && lapses_at(&held).is_some() {
            return Err(Error::Unavailable);
        }
        Ok(held.record)
    }
}
