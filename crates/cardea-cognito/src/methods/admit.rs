//! The directory's side of a link: the subject is bound and the identity goes
//! on the user's list in one write, and the list is read again just before the
//! pool is told. Neither happens while an unlink of the identity is unfinished.
//!
//! A binding is therefore never written without a list that leads to it, which
//! is how [erasure](crate::erasure) finds a link that stopped part-way.

use async_trait::async_trait;
use cardea_core::{Directory, EmailOwner, Error, Provider, User};

use super::row::{ATTEMPTS, Identity};
use crate::{
    directory::AwsDirectory,
    record::{MethodsRow, ProviderRow},
};

impl AwsDirectory {
    /// Bind the subject to `user`, or refuse with [`Error::Conflict`] when it
    /// is another's. A new binding is written in one transaction with the
    /// identity's place on `user`'s list, with `email`, the provider's own
    /// spelling of its address, when this caller saw it. A binding already
    /// `user`'s is left to [`AwsDirectory::admit_identity`].
    ///
    /// Refused with [`Error::NotReady`] while an unlink of the identity is
    /// unfinished.
    pub(crate) async fn bind_identity(
        &self,
        user: &User,
        provider: Provider,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), Error> {
        let identity = Identity {
            provider,
            subject: subject.to_owned(),
        };
        let binding = ProviderRow {
            provider: ProviderRow::provider_name(provider),
            subject: subject.to_owned(),
            record: user.clone(),
        };
        // Each turn reads the winner back, whatever became of the last write.
        for _ in 0..ATTEMPTS {
            if let Some(bound) = self.provider(provider, subject).await? {
                return if bound == *user {
                    Ok(())
                } else {
                    Err(Error::Conflict)
                };
            }
            let mut next = self.list_open_to(user, &identity).await?;
            let version = next.version;
            let entry = next.entry(&identity);
            if let Some(email) = email {
                entry.email = Some(email.to_owned());
            }
            if self
                .replace_methods_row_binding(version, next, &binding)
                .await?
            {
                return Ok(());
            }
        }
        Err(Error::Unavailable)
    }

    /// Put the identity on `user`'s list before it is linked, with `email`,
    /// the provider's own spelling of its address, when this caller saw it.
    /// Nothing is written when the list already says so.
    ///
    /// Refused with [`Error::NotReady`] while an unlink of the identity is
    /// unfinished.
    pub(crate) async fn admit_identity(
        &self,
        user: &User,
        provider: Provider,
        subject: &str,
        email: Option<&str>,
    ) -> Result<(), Error> {
        let identity = Identity {
            provider,
            subject: subject.to_owned(),
        };
        for _ in 0..ATTEMPTS {
            let mut next = self.list_open_to(user, &identity).await?;
            let version = next.version;
            // A first list is saved even when this link adds nothing to it.
            if version > 0
                && next
                    .find(&identity)
                    .is_some_and(|entry| email.is_none() || entry.email.as_deref() == email)
            {
                return Ok(());
            }
            let entry = next.entry(&identity);
            if let Some(email) = email {
                entry.email = Some(email.to_owned());
            }
            if self.replace_methods_row(version, next).await? {
                return Ok(());
            }
        }
        Err(Error::Unavailable)
    }

    /// The list `identity` may be added to: the stored one, or a first one at
    /// version 0.
    ///
    /// An identity with an unfinished unlink is refused with
    /// [`Error::NotReady`], whatever this attempt read before the unlink. If
    /// the pool has already let go of it, the unlink is finished first, so
    /// that a repeat of the request starts afresh.
    async fn list_open_to(&self, user: &User, identity: &Identity) -> Result<MethodsRow, Error> {
        let list = match self.methods_row(user).await? {
            Some(row) => row,
            // The first list holds what the pool already links, too.
            None => self.first_list(user).await?,
        };
        if list.is_removing(identity) {
            if !self.pool_identities(user).await?.contains(identity) {
                self.finish_removal(user, std::slice::from_ref(identity))
                    .await?;
            }
            return Err(Error::NotReady);
        }
        Ok(list)
    }

    /// The list of a user who has none: the identities the pool links, their
    /// addresses not yet seen.
    async fn first_list(&self, user: &User) -> Result<MethodsRow, Error> {
        let mut list = MethodsRow::empty(user);
        for linked in self.pool_identities(user).await? {
            list.entry(&linked);
        }
        Ok(list)
    }

    /// The directory as one provider proof or sign-in resolves against it:
    /// `email` is the address as that provider wrote it.
    pub(crate) fn recording<'a>(&'a self, email: Option<&'a str>) -> Recording<'a> {
        Recording {
            directory: self,
            email,
        }
    }
}

/// [`AwsDirectory`], recording the provider's address with the identity it
/// links.
pub(crate) struct Recording<'a> {
    directory: &'a AwsDirectory,
    email: Option<&'a str>,
}

#[async_trait]
impl Directory for Recording<'_> {
    async fn ready(&self) -> Result<(), Error> {
        self.directory.ready().await
    }

    async fn email(&self, email: &str) -> Result<Option<EmailOwner>, Error> {
        self.directory.email(email).await
    }

    async fn claim_email(&self, owner: &EmailOwner) -> Result<EmailOwner, Error> {
        self.directory.claim_email(owner).await
    }

    async fn provider(&self, provider: Provider, subject: &str) -> Result<Option<User>, Error> {
        self.directory.provider(provider, subject).await
    }

    async fn awaits_confirmation(&self, username: &str) -> Result<bool, Error> {
        self.directory.awaits_confirmation(username).await
    }

    async fn claim_provider(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<(), Error> {
        self.directory
            .bind_identity(user, provider, subject, self.email)
            .await
    }

    async fn native_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        self.directory.native_user(owner).await
    }

    async fn create_social_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        self.directory.create_social_user(owner).await
    }

    async fn link(&self, provider: Provider, subject: &str, user: &User) -> Result<(), Error> {
        self.directory
            .admit_identity(user, provider, subject, self.email)
            .await?;
        // The binding this attempt read or made must still stand: an unlink
        // may have run to its end since.
        if !self.directory.binds(provider, subject, user).await? {
            return Err(Error::NotReady);
        }
        self.directory.link_provider(provider, subject, user).await
    }
}
