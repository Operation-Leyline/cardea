//! The [`Directory`] over the DynamoDB table and the Cognito user pool.

use aws_sdk_cognitoidentityprovider::Client as Cognito;
use aws_sdk_dynamodb::Client as Dynamo;
use cardea_core::{Directory, EmailOwner, Error, Provider, User, person_key};
use tabulary::{MemberOf, MultiTable, ReadConsistency, ReadError, RecordKey};

use crate::record::{
    EmailRow, EmailRowKey, IdentityTable, ProviderRow, ProviderRowKey, ReadyRowKey,
};

mod claim;
pub mod config;
mod guard;
mod holder;
mod pool;
mod social;

pub use holder::{HolderReadError, mailbox_holder};

pub(crate) use claim::{Hold, now};
pub(crate) use pool::attribute;
pub(crate) use social::ORIGIN_METADATA;

/// The environment variable naming the directory table.
pub const TABLE_VARIABLE: &str = "IDENTITIES_TABLE";

/// The key of the directory row that owns a mailbox: keyed by the person
/// ([`person_key`]), so every alias of one mailbox reaches the same row.
pub fn email_key(email: &str) -> Result<EmailRowKey, Error> {
    EmailRowKey::new(person_key(email)?).map_err(|_| Error::Invalid)
}

/// The key of the row that binds a provider subject to its user.
pub fn provider_key(provider: Provider, subject: &str) -> Result<ProviderRowKey, Error> {
    ProviderRowKey::new(ProviderRow::provider_name(provider), subject.to_owned())
        .map_err(|_| Error::Invalid)
}

/// The directory of one user pool.
#[derive(Clone)]
pub struct AwsDirectory {
    ddb: Dynamo,
    cognito: Cognito,
    table: String,
    pool: String,
}

impl AwsDirectory {
    /// A directory over clients the caller built.
    pub fn new(ddb: Dynamo, cognito: Cognito, table: String, pool: String) -> Self {
        Self {
            ddb,
            cognito,
            table,
            pool,
        }
    }

    /// A directory over `config` ([`config::load`]), with both clients in the
    /// pool's region ([`config::in_pool_region`]): the table lives beside the
    /// pool, wherever the caller runs.
    pub fn from_config(config: &aws_config::SdkConfig, table: String, pool: String) -> Self {
        let config = config::in_pool_region(config, &pool);
        Self::new(Dynamo::new(&config), Cognito::new(&config), table, pool)
    }

    /// [`AwsDirectory::from_config`] with the table [`TABLE_VARIABLE`] names.
    pub fn from_env_with(config: &aws_config::SdkConfig, pool: String) -> Result<Self, Error> {
        Ok(Self::from_config(
            config,
            std::env::var(TABLE_VARIABLE).map_err(|_| Error::Unavailable)?,
            pool,
        ))
    }

    /// [`AwsDirectory::from_env_with`], loading the configuration too.
    pub async fn from_env(pool: String) -> Result<Self, Error> {
        Self::from_env_with(&config::load().await, pool)
    }

    /// The table this directory reads and writes.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// The user pool this directory manages.
    pub fn pool(&self) -> &str {
        &self.pool
    }

    /// The DynamoDB client.
    pub fn dynamodb(&self) -> &Dynamo {
        &self.ddb
    }

    /// The Cognito client.
    pub fn cognito(&self) -> &Cognito {
        &self.cognito
    }

    /// The typed table binding. The name is checked per request, which keeps a
    /// malformed name a request's error.
    pub fn rows(&self) -> Result<MultiTable<IdentityTable>, Error> {
        MultiTable::new(self.table.as_str()).map_err(|_| Error::Unavailable)
    }

    /// One row of `R`'s kind, read consistently: a claim reads back the winner
    /// after an ambiguous put. A row that does not decode is
    /// [`Error::Conflict`]: an owner nobody can read is nobody's to hand out.
    pub async fn row<R: MemberOf<IdentityTable>>(
        &self,
        key: impl RecordKey<R>,
    ) -> Result<Option<R>, Error> {
        let request = self
            .rows()?
            .get(key, ReadConsistency::Strong)
            .build()
            .map_err(|_| Error::Invalid)?;
        match request.decode(request.apply(self.ddb.get_item()).send().await) {
            Ok(read) => Ok(read.item),
            Err(ReadError::Decode(_)) => Err(Error::Conflict),
            Err(_) => Err(Error::Unavailable),
        }
    }

    /// Write `row` unless its key already holds one. The outcome is never
    /// trusted: the caller reads the winner back after every ambiguous write,
    /// including a transport timeout. Ownership is never released on
    /// timeout: Cognito might have committed its side effect.
    pub async fn put_new<R: MemberOf<IdentityTable>>(&self, row: &R) -> Result<(), Error> {
        let request = self
            .rows()?
            .put(row)
            .expect_new()
            .build()
            .map_err(|_| Error::Invalid)?;
        let _ = request.apply(self.ddb.put_item()).send().await;
        Ok(())
    }

    /// The whole row holding `email`'s mailbox, a lapsed claim included.
    /// [`Directory::email`] is the read that honours the lapse.
    pub async fn email_row(&self, email: &str) -> Result<Option<EmailRow>, Error> {
        self.row(email_key(email)?).await
    }
}

#[async_trait::async_trait]
impl Directory for AwsDirectory {
    async fn ready(&self) -> Result<(), Error> {
        let key = ReadyRowKey::new().map_err(|_| Error::Invalid)?;
        match self.row(key).await {
            Ok(Some(ready)) if ready.version == 1 => Ok(()),
            // Absent, another version, or a marker that does not decode.
            Ok(_) | Err(Error::Conflict) => Err(Error::NotReady),
            Err(error) => Err(error),
        }
    }

    async fn email(&self, email: &str) -> Result<Option<EmailOwner>, Error> {
        self.live_owner(email, claim::now()).await
    }

    async fn claim_email(&self, owner: &EmailOwner) -> Result<EmailOwner, Error> {
        self.claim_email_at(owner, Hold::Permanent, claim::now())
            .await
    }

    async fn provider(&self, provider: Provider, subject: &str) -> Result<Option<User>, Error> {
        Ok(self
            .row(provider_key(provider, subject)?)
            .await?
            .map(|row| row.record))
    }

    async fn awaits_confirmation(&self, username: &str) -> Result<bool, Error> {
        self.is_unconfirmed(username).await
    }

    async fn claim_provider(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<(), Error> {
        self.put_new(&ProviderRow {
            provider: ProviderRow::provider_name(provider),
            subject: subject.to_owned(),
            record: user.clone(),
        })
        .await?;
        let winner = self
            .provider(provider, subject)
            .await?
            .ok_or(Error::Unavailable)?;
        if winner == *user {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }

    async fn native_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        self.confirmed_user(owner).await
    }

    async fn create_social_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        self.find_or_create_social_user(owner).await
    }

    /// Refused with [`Error::NotReady`] while an unlink of the identity is
    /// unfinished.
    async fn link(&self, provider: Provider, subject: &str, user: &User) -> Result<(), Error> {
        self.admit_identity(user, provider, subject, None).await?;
        self.link_provider(provider, subject, user).await
    }
}

#[cfg(test)]
mod claim_tests;
#[cfg(test)]
mod guard_tests;
#[cfg(test)]
mod region_tests;
#[cfg(test)]
mod signup_tests;
#[cfg(test)]
mod social_tests;
