//! Reading what an account holds while the pool can still say.
//!
//! A repeat may come after the user is gone from the pool, so whatever only the
//! pool knows is written into the directory here: each linked identity goes on
//! the user's list, with the pool's address if the caller named another, and an
//! unbound mailbox row the pool shows to be the user's gets its `userId`. A
//! repeat then needs only the caller's [`User`] and the rows.

use aws_sdk_cognitoidentityprovider::operation::admin_get_user::AdminGetUserOutput;
use cardea_core::{Directory, Error, User, person_key};
use tabulary::Update;

use crate::{
    directory::{AwsDirectory, attribute, email_key},
    methods::{
        pool::identities_of,
        row::{ATTEMPTS, Identity},
    },
    record::{EmailRowAttrs, LinkedIdentity, MethodsRow},
};

/// What [`erase_user`](super::erase_user) will look at. It deletes only the
/// rows among these that still name the user.
#[derive(Clone)]
pub struct ErasurePlan {
    pub(super) user: User,
    /// Addresses whose mailbox rows may be the user's.
    pub(super) mailboxes: Vec<String>,
    /// `(provider, subject)` pairs, the provider as the directory spells it.
    pub(super) identities: Vec<(String, String)>,
}

/// Leaves addresses and subjects out, so that printing a plan cannot log them.
impl std::fmt::Debug for ErasurePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasurePlan")
            .field("user_id", &self.user.user_id)
            .field("identities", &self.identities.len())
            .finish_non_exhaustive()
    }
}

/// An entry of the list as a plan names it.
pub(super) fn named(entry: &LinkedIdentity) -> (String, String) {
    (entry.provider.clone(), entry.subject.clone())
}

/// Plan the erasure of `user`'s directory rows. Call it **before** deleting the
/// user from the pool; a repeat after the deletion is safe and finds what the
/// first call recorded. See [the order](crate::erasure).
///
/// `user` is the account being deleted: its id (`sub`), pool username and email.
/// A pool user of that username with another `sub` is someone else's, and
/// nothing is read from it.
pub async fn plan_erasure(directory: &AwsDirectory, user: &User) -> Result<ErasurePlan, Error> {
    directory.ready().await?;
    // Refuses an unusable address before anything is written.
    person_key(&user.email)?;
    let account = directory.pool_account(user).await?;
    let linked = match &account {
        Some(account) => identities_of(account.user_attributes())?,
        None => Vec::new(),
    };
    // The pool's address, should it reach another mailbox than the caller's.
    let held = account
        .as_ref()
        .and_then(|account| attribute(account, "email"))
        .filter(|held| person_key(held).is_ok_and(|key| person_key(&user.email) != Ok(key)));
    let list = directory.record_for_erasure(user, &linked, held).await?;
    let mut mailboxes = vec![user.email.clone()];
    mailboxes.extend(list.erasing_mailboxes.into_iter().flatten());
    if account.is_some() {
        for mailbox in &mailboxes {
            directory.bind_claim(mailbox, user).await?;
        }
    }
    Ok(ErasurePlan {
        user: user.clone(),
        mailboxes,
        identities: list.identities.iter().map(named).collect(),
    })
}

impl AwsDirectory {
    /// The pool's record of this very account, whatever its state: `None` once
    /// it is deleted, even if the username has since gone to another.
    pub(super) async fn pool_account(
        &self,
        user: &User,
    ) -> Result<Option<AdminGetUserOutput>, Error> {
        Ok(self
            .get_user(&user.username)
            .await?
            .filter(|raw| attribute(raw, "sub") == Some(user.user_id.as_str())))
    }

    /// Add `linked` and the address `held` to the user's list, and return the
    /// list as it then is. A user with neither and no list gets none.
    async fn record_for_erasure(
        &self,
        user: &User,
        linked: &[Identity],
        held: Option<&str>,
    ) -> Result<MethodsRow, Error> {
        for _ in 0..ATTEMPTS {
            let read = self.methods_row(user).await?;
            let version = read.as_ref().map_or(0, |row| row.version);
            let mut next = read.clone().unwrap_or_else(|| MethodsRow::empty(user));
            for identity in linked {
                next.entry(identity);
            }
            if let Some(held) = held {
                let mailboxes = next.erasing_mailboxes.get_or_insert_default();
                if !mailboxes.iter().any(|mailbox| mailbox == held) {
                    mailboxes.push(held.to_owned());
                }
            }
            let unchanged = match &read {
                Some(row) => *row == next,
                None => next == MethodsRow::empty(user),
            };
            if unchanged || self.replace_methods_row(version, next.clone()).await? {
                return Ok(next);
            }
        }
        Err(Error::Unavailable)
    }

    /// Give the mailbox's row `user`'s id, if it has none and the pool shows
    /// that the username it was claimed under is this account's.
    async fn bind_claim(&self, mailbox: &str, user: &User) -> Result<(), Error> {
        let Some(row) = self.email_row(mailbox).await? else {
            return Ok(());
        };
        if row.user_id.is_some() {
            return Ok(());
        }
        // Not `native_user`: the account being deleted may be disabled or
        // never confirmed.
        let claimant = User {
            username: row.record.username.clone(),
            ..user.clone()
        };
        if self.pool_account(&claimant).await?.is_none() {
            return Ok(());
        }
        let request = self
            .rows()?
            .update(email_key(mailbox)?)
            .changes(
                Update::new()
                    .and(EmailRowAttrs::USER_ID.set(user.user_id.clone()))
                    .and(EmailRowAttrs::UNCONFIRMED_EXPIRES_AT.remove()),
            )
            .condition(
                EmailRowAttrs::RECORD
                    .eq(row.record)
                    .and(EmailRowAttrs::USER_ID.not_exists()),
            )
            .build()
            .map_err(|_| Error::Invalid)?;
        // A row that changed meanwhile fails here, and the repeat reads it anew.
        request
            .decode(request.apply(self.dynamodb().update_item()).send().await)
            .map(|_| ())
            .map_err(|_| Error::Unavailable)
    }
}
