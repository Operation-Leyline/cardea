//! The step every link takes just before the pool is told of it: the identity
//! goes on the user's list, unless an unlink of it is unfinished.

use async_trait::async_trait;
use cardea_core::{Directory, EmailOwner, Error, Provider, User};

use super::row::{ATTEMPTS, Identity};
use crate::{directory::AwsDirectory, record::MethodsRow};

impl AwsDirectory {
    /// Put the identity on `user`'s list before it is linked, with `email`,
    /// the provider's own spelling of its address, when this caller saw it.
    /// Nothing is written when the list already says so.
    ///
    /// An identity with an unfinished unlink is refused with
    /// [`Error::NotReady`], whatever this attempt read before the unlink. If
    /// the pool has already let go of it, the unlink is finished first, so
    /// that a repeat of the request starts afresh.
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
            let read = self.methods_row(user).await?;
            let version = read.as_ref().map_or(0, |row| row.version);
            let stored = read.is_some();
            let mut next = match read {
                Some(row) => row,
                // The first list holds what the pool already links, too.
                None => self.first_list(user).await?,
            };
            if next.is_removing(&identity) {
                if !self.pool_identities(user).await?.contains(&identity) {
                    self.finish_removal(user, std::slice::from_ref(&identity))
                        .await?;
                }
                return Err(Error::NotReady);
            }
            // A first list is saved even when this link adds nothing to it.
            if stored
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
        self.directory.claim_provider(provider, subject, user).await
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
