//! Accounts as the directory and the pool hold them, and a provider link made
//! the way a signed-in person makes one.

use aws_sdk_dynamodb::types::AttributeValue;
use cardea_core::{Directory, EmailOwner, Provider, Session, User};

use super::{
    Fixture,
    provider::{Proofs, client_id, token},
};
use crate::{
    OperationError,
    directory::now,
    link::{IdentityLinkChallenge, ProviderClients, complete_identity_link, create_identity_link},
};

/// Every provider under its test client id.
pub(crate) fn clients() -> ProviderClients {
    Provider::ALL
        .into_iter()
        .fold(ProviderClients::new(), |clients, provider| {
            clients.with(provider, client_id(provider))
        })
}

/// A session that signed in `age` seconds ago.
pub(crate) fn session(user: &User, age: i64) -> Session<'_> {
    Session {
        user,
        auth_time: now() - age,
        now: now(),
    }
}

impl Fixture {
    /// A confirmed, provisioned account of `{name}@example.com`, made by
    /// `origin` (`Cognito` for a password signup).
    pub async fn account(&self, name: &str, origin: &str) -> User {
        let user = User {
            user_id: format!("sub-of-{name}"),
            username: name.into(),
            email: format!("{name}@example.com"),
        };
        self.directory
            .claim_email(&EmailOwner {
                email: user.email.clone(),
                username: user.username.clone(),
                origin: origin.into(),
            })
            .await
            .unwrap();
        self.pool
            .add(&user.username, &user.user_id, &user.email, "CONFIRMED");
        user
    }

    /// An account whose password nobody was told.
    pub async fn passwordless(&self, name: &str) -> User {
        self.account(name, "Google").await
    }

    /// A challenge for `user` and `provider`.
    pub async fn challenge(&self, user: &User, provider: Provider) -> IdentityLinkChallenge {
        let client_token = uuid::Uuid::new_v4().to_string();
        create_identity_link(&self.directory, &clients(), user, provider, &client_token)
            .await
            .unwrap()
    }

    /// Link `subject` at `email` to `user` from a session just signed in.
    pub async fn try_link(
        &self,
        user: &User,
        provider: Provider,
        subject: &str,
        email: &str,
    ) -> Result<User, OperationError> {
        let challenge = self.challenge(user, provider).await;
        complete_identity_link(
            &self.directory,
            &Proofs::default(),
            &clients(),
            session(user, 0),
            &challenge.link_id,
            &token(provider, &challenge.nonce, subject, email),
        )
        .await
    }

    /// [`Fixture::try_link`] at the user's own address, expected to succeed.
    pub async fn link(&self, user: &User, provider: Provider, subject: &str) {
        self.try_link(user, provider, subject, &user.email)
            .await
            .unwrap();
    }

    /// Put an identity on a pool user without telling the directory.
    pub fn pool_link(&self, username: &str, provider: Provider, subject: &str) {
        self.pool
            .state()
            .users
            .get_mut(username)
            .unwrap()
            .identities
            .push((provider.rule().cognito_name.into(), subject.into()));
    }

    /// Take every identity off a pool user without telling the directory.
    pub fn pool_unlink_all(&self, username: &str) {
        self.pool
            .state()
            .users
            .get_mut(username)
            .unwrap()
            .identities
            .clear();
    }

    /// The identities the pool links onto `username`.
    pub fn identities(&self, username: &str) -> Vec<(String, String)> {
        self.pool.state().users[username].identities.clone()
    }

    /// Delete the stored item at `key`.
    pub async fn delete(&self, key: &str) {
        self.directory
            .dynamodb()
            .delete_item()
            .table_name(self.directory.table())
            .key("identityKey", AttributeValue::S(key.into()))
            .send()
            .await
            .unwrap();
    }
}
