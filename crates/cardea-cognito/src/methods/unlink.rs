//! `UnlinkSignInMethod`.
//!
//! The steps, each safe to repeat:
//!
//! 1. mark the provider's identities as being removed on the user's list, on
//!    the condition that the list has not changed since the remaining methods
//!    were counted;
//! 2. take each off the user in the pool;
//! 3. delete its binding, so that it may be linked elsewhere;
//! 4. drop it from the list.
//!
//! Step 1 is what keeps two removals apart: the second one's write is refused,
//! and counting again it no longer sees the identity the first is removing.
//! The marks stay until step 4, so a repeat after any failure finds what is
//! left to do, even when the pool no longer names it.

use cardea_core::{Directory, Error, Provider, User};

use super::row::{ATTEMPTS, Identity};
use crate::{
    OperationError,
    directory::{AwsDirectory, provider_key},
    record::{MethodsRow, ProviderRow, ProviderRowAttrs},
};

/// Remove every identity of `provider` from `user`'s account. Nothing of the
/// provider linked is a success, so a repeat after a timeout succeeds.
///
/// Refused with [`OperationError::LastSignInMethod`] when no chosen password
/// and no other identity both linked in the pool and bound to this account
/// would be left. The account and its data stay,
/// and the provider identity may then be linked to another account. An
/// identity whose address the provider owns (Gmail, an Apple mailbox) still
/// signs in to the account of that mailbox, and doing so links it again.
///
/// `user` must come from a verified session token.
pub async fn unlink_sign_in_method(
    directory: &AwsDirectory,
    user: &User,
    provider: Provider,
) -> Result<(), OperationError> {
    directory.ready().await?;
    let targets = directory.mark_for_removal(user, provider).await?;
    if targets.is_empty() {
        return Ok(());
    }
    // Read after the marks, which keep any new link of these away.
    let linked = directory.pool_identities(user).await?;
    for identity in targets.iter().filter(|target| linked.contains(target)) {
        directory.disable_identity(user, identity).await?;
    }
    directory.finish_removal(user, &targets).await?;
    Ok(())
}

impl AwsDirectory {
    /// Mark `provider`'s identities, as the pool and the list know them, as
    /// being removed, and return them.
    async fn mark_for_removal(
        &self,
        user: &User,
        provider: Provider,
    ) -> Result<Vec<Identity>, OperationError> {
        for _ in 0..ATTEMPTS {
            // The list first, then the pool: every removal changes the list
            // before the pool, so a write that succeeds against this version
            // counted no method that has since been taken away.
            let read = self.methods_row(user).await?;
            let linked = self.pool_identities(user).await?;
            let version = read.as_ref().map_or(0, |row| row.version);
            let mut next = read.unwrap_or_else(|| MethodsRow::empty(user));
            let takes_a_method = linked
                .iter()
                .any(|i| i.provider == provider && !next.is_removing(i));
            if takes_a_method
                && self.password_method(user).await? != Some(true)
                && !self
                    .another_signs_in(user, provider, &linked, &next)
                    .await?
            {
                return Err(OperationError::LastSignInMethod);
            }
            for identity in &linked {
                next.entry(identity);
            }
            let name = ProviderRow::provider_name(provider);
            let mut targets = Vec::new();
            for entry in next.identities.iter_mut().filter(|e| e.provider == name) {
                entry.removing = true;
                targets.push(Identity {
                    provider,
                    subject: entry.subject.clone(),
                });
            }
            // Written even when nothing is to be removed: a user without a
            // list gets one.
            if self.replace_methods_row(version, next).await? {
                return Ok(targets);
            }
        }
        Err(Error::Unavailable.into())
    }

    /// Whether an identity of another provider would still sign `user` in:
    /// the pool links it, no unlink of it is under way, and its binding names
    /// `user`. A sign-in through an unbound identity can be refused, so such a
    /// one is not counted on.
    async fn another_signs_in(
        &self,
        user: &User,
        removing: Provider,
        linked: &[Identity],
        list: &MethodsRow,
    ) -> Result<bool, Error> {
        for other in linked {
            if other.provider != removing
                && !list.is_removing(other)
                && self.binds(other.provider, &other.subject, user).await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Steps 3 and 4, for identities the pool no longer links onto `user`.
    pub(super) async fn finish_removal(
        &self,
        user: &User,
        targets: &[Identity],
    ) -> Result<(), Error> {
        let list = self.methods_row(user).await?;
        for identity in targets {
            // Only while still marked. Otherwise another caller finished this
            // removal, and a binding there now belongs to a newer link.
            if list.as_ref().is_some_and(|row| row.is_removing(identity)) {
                self.release_binding(user, identity).await?;
            }
        }
        for _ in 0..ATTEMPTS {
            let Some(mut next) = self.methods_row(user).await? else {
                return Ok(());
            };
            let version = next.version;
            let before = next.identities.len();
            next.identities.retain(|entry| {
                !(entry.removing
                    && targets.iter().any(|target| {
                        target.subject == entry.subject
                            && target.provider.rule().cognito_name == entry.provider
                    }))
            });
            if next.identities.len() == before || self.replace_methods_row(version, next).await? {
                return Ok(());
            }
        }
        Err(Error::Unavailable)
    }

    /// Delete the subject's binding if it is `user`'s. Another user's is left
    /// alone.
    async fn release_binding(&self, user: &User, identity: &Identity) -> Result<(), Error> {
        let Some(bound) = self.provider(identity.provider, &identity.subject).await? else {
            return Ok(());
        };
        if bound.user_id != user.user_id {
            return Ok(());
        }
        let request = self
            .rows()?
            .delete(provider_key(identity.provider, &identity.subject)?)
            .condition(ProviderRowAttrs::RECORD.eq(bound))
            .build()
            .map_err(|_| Error::Invalid)?;
        request
            .decode(request.apply(self.dynamodb().delete_item()).send().await)
            .map(|_| ())
            .map_err(|_| Error::Unavailable)
    }
}
