//! Deleting the rows that still name a deleted user.
//!
//! Each delete is conditional on the row naming this user, so a row someone
//! else has since claimed stays. Provider bindings go first, so a mailbox is
//! not free while its identities still lead to the old account; the user's list
//! goes last, because it is how a repeat finds the bindings.

use std::collections::{BTreeMap, BTreeSet};

use cardea_core::{Directory, Error, User, person_key};
use tabulary::{FailureKind, WriteError};

use super::{ErasureError, ErasurePlan, plan::named};
use crate::{
    directory::{AwsDirectory, email_key},
    methods::row::ATTEMPTS,
    record::{
        EmailRowAttrs, MethodsRowAttrs, MethodsRowKey, ProviderRow, ProviderRowAttrs,
        ProviderRowKey,
    },
};

/// How many rows one [`erase_user`] call removed and left. A repeat counts only
/// what it did itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErasureReport {
    /// Mailbox rows (`EMAIL#`) removed.
    pub emails: usize,
    /// Provider bindings (`PROVIDER#`) removed.
    pub providers: usize,
    /// Identity lists (`METHODS#`) removed.
    pub methods: usize,
    /// Mailbox rows and bindings found and left alone, because they do not name
    /// this user.
    pub kept: usize,
}

/// What became of one row.
enum Row {
    Absent,
    Kept,
    Removed,
}

/// Delete the directory rows of the user `plan` names, **after** the user is
/// gone from the pool. Safe to repeat; see [the order](crate::erasure).
///
/// Refused with [`ErasureError::UserStillExists`], with nothing deleted, while
/// the pool holds the account.
pub async fn erase_user(
    directory: &AwsDirectory,
    plan: &ErasurePlan,
) -> Result<ErasureReport, ErasureError> {
    directory.ready().await?;
    let user = &plan.user;
    if directory.pool_account(user).await?.is_some() {
        return Err(ErasureError::UserStillExists);
    }
    let mut report = ErasureReport::default();
    let (mut kept_bindings, mut kept_claims) = (BTreeSet::new(), BTreeSet::new());
    // Again only when the list changed while its rows were being erased.
    for _ in 0..ATTEMPTS {
        let list = directory.methods_row(user).await?;
        let listed = list.iter().flat_map(|row| row.identities.iter().map(named));
        let identities: BTreeSet<_> = plan.identities.iter().cloned().chain(listed).collect();
        // All of them each time: a link under way may have bound one since it
        // was last looked at, which is what changes the list.
        for identity in identities {
            match directory.erase_binding(user, &identity).await? {
                Row::Absent => {}
                Row::Removed => report.providers += 1,
                Row::Kept => {
                    kept_bindings.insert(identity);
                }
            }
        }
        let learned = list
            .iter()
            .flat_map(|row| row.erasing_mailboxes.iter().flatten());
        // By mailbox, so that two spellings of one are one row.
        let mut mailboxes = BTreeMap::new();
        for address in plan.mailboxes.iter().chain(learned) {
            mailboxes.insert(person_key(address)?, address);
        }
        for (mailbox, address) in mailboxes {
            match directory.erase_claim(user, address).await? {
                Row::Absent => {}
                Row::Removed => report.emails += 1,
                Row::Kept => {
                    kept_claims.insert(mailbox);
                }
            }
        }
        report.kept = kept_bindings.len() + kept_claims.len();
        let Some(list) = list else {
            return Ok(report);
        };
        if directory.erase_list(user, list.version).await? {
            report.methods += 1;
            return Ok(report);
        }
    }
    Err(Error::Unavailable.into())
}

impl AwsDirectory {
    /// Delete the identity's binding if it names `user`.
    async fn erase_binding(
        &self,
        user: &User,
        (provider, subject): &(String, String),
    ) -> Result<Row, Error> {
        let key =
            || ProviderRowKey::new(provider.clone(), subject.clone()).map_err(|_| Error::Invalid);
        let Some(row) = self.row::<ProviderRow>(key()?).await? else {
            return Ok(Row::Absent);
        };
        if row.record.user_id != user.user_id {
            return Ok(Row::Kept);
        }
        let request = self
            .rows()?
            .delete(key()?)
            .condition(ProviderRowAttrs::RECORD.eq(row.record))
            .build()
            .map_err(|_| Error::Invalid)?;
        request
            .decode(request.apply(self.dynamodb().delete_item()).send().await)
            .map(|_| Row::Removed)
            .map_err(|_| Error::Unavailable)
    }

    /// Delete the mailbox's row if it names `user`.
    async fn erase_claim(&self, user: &User, mailbox: &str) -> Result<Row, Error> {
        let Some(row) = self.email_row(mailbox).await? else {
            return Ok(Row::Absent);
        };
        if row.user_id.as_deref() != Some(user.user_id.as_str()) {
            return Ok(Row::Kept);
        }
        let request = self
            .rows()?
            .delete(email_key(mailbox)?)
            .condition(EmailRowAttrs::USER_ID.eq(user.user_id.clone()))
            .build()
            .map_err(|_| Error::Invalid)?;
        request
            .decode(request.apply(self.dynamodb().delete_item()).send().await)
            .map(|_| Row::Removed)
            .map_err(|_| Error::Unavailable)
    }

    /// Delete the user's list if it is still at `version`. `false` when another
    /// write came first.
    async fn erase_list(&self, user: &User, version: i64) -> Result<bool, Error> {
        let key = MethodsRowKey::new(user.user_id.clone()).map_err(|_| Error::Invalid)?;
        let request = self
            .rows()?
            .delete(key)
            .condition(MethodsRowAttrs::VERSION.eq(version))
            .build()
            .map_err(|_| Error::Invalid)?;
        match request.decode(request.apply(self.dynamodb().delete_item()).send().await) {
            Ok(_) => Ok(true),
            Err(WriteError::Refused { failure, .. })
                if matches!(
                    failure.kind,
                    FailureKind::ConditionFailed | FailureKind::TransactionConflict
                ) =>
            {
                Ok(false)
            }
            Err(_) => Err(Error::Unavailable),
        }
    }
}
