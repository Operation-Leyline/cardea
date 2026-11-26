//! The user pool: reading accounts and linking providers onto them.

use aws_sdk_cognitoidentityprovider::{
    operation::admin_get_user::AdminGetUserOutput, types::ProviderUserIdentifierType,
};
use cardea_core::{EmailOwner, Error, NATIVE_ORIGIN, Provider, User, normalize_email, person_key};
use serde_json::Value;

use super::AwsDirectory;

/// The value of one attribute of a Cognito user.
fn attribute<'a>(raw: &'a AdminGetUserOutput, name: &str) -> Option<&'a str> {
    raw.user_attributes()
        .iter()
        .find(|a| a.name() == name)
        .and_then(|a| a.value())
}

/// Whether the account's `identities` attribute lists this provider subject.
fn linked(raw: &AdminGetUserOutput, provider: Provider, subject: &str) -> bool {
    let name = provider.rule().cognito_name;
    attribute(raw, "identities")
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|identities| {
            identities
                .iter()
                .any(|identity| identity["providerName"] == name && identity["userId"] == subject)
        })
}

/// `raw` as the account of `owner`'s mailbox: enabled, confirmed, its address
/// verified and reaching that mailbox.
fn checked_user(owner: &EmailOwner, raw: &AdminGetUserOutput) -> Result<User, Error> {
    if !raw.enabled()
        || raw.user_status().map(|s| s.as_str()) != Some("CONFIRMED")
        || attribute(raw, "email_verified") != Some("true")
    {
        return Err(Error::LinkRequired);
    }
    let email = attribute(raw, "email").ok_or(Error::Conflict)?.to_owned();
    if person_key(&email)? != person_key(&owner.email)? {
        return Err(Error::Conflict);
    }
    Ok(User {
        user_id: attribute(raw, "sub").ok_or(Error::Conflict)?.into(),
        username: raw.username().into(),
        email,
    })
}

impl AwsDirectory {
    /// The Cognito user at `username` (or at that email alias), if any.
    pub(super) async fn get_user(
        &self,
        username: &str,
    ) -> Result<Option<AdminGetUserOutput>, Error> {
        match self
            .cognito()
            .admin_get_user()
            .user_pool_id(self.pool())
            .username(username)
            .send()
            .await
        {
            Ok(user) => Ok(Some(user)),
            Err(e)
                if e.as_service_error()
                    .is_some_and(|e| e.is_user_not_found_exception()) =>
            {
                Ok(None)
            }
            Err(_) => Err(Error::Unavailable),
        }
    }

    pub(super) async fn is_unconfirmed(&self, username: &str) -> Result<bool, Error> {
        Ok(self.get_user(username).await?.is_some_and(|user| {
            user.user_status().map(|status| status.as_str()) == Some("UNCONFIRMED")
        }))
    }

    pub(super) async fn confirmed_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        checked_user(
            owner,
            &self
                .get_user(&owner.username)
                .await?
                .ok_or(Error::NotReady)?,
        )
    }

    /// `user`'s Cognito record, only while it still reads as exactly `user`.
    async fn same_user(&self, user: &User) -> Result<AdminGetUserOutput, Error> {
        let raw = self
            .get_user(&user.username)
            .await?
            .ok_or(Error::Conflict)?;
        let owner = EmailOwner {
            email: normalize_email(&user.email)?,
            username: user.username.clone(),
            origin: NATIVE_ORIGIN.into(),
        };
        if checked_user(&owner, &raw)? != *user {
            return Err(Error::Conflict);
        }
        Ok(raw)
    }

    /// Whether the pool already links this subject onto `user`.
    pub async fn is_linked(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<bool, Error> {
        Ok(linked(&self.same_user(user).await?, provider, subject))
    }

    pub(super) async fn link_provider(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<(), Error> {
        if linked(&self.same_user(user).await?, provider, subject) {
            return Ok(());
        }
        let source = ProviderUserIdentifierType::builder()
            .provider_name(provider.rule().cognito_name)
            .provider_attribute_name("Cognito_Subject")
            .provider_attribute_value(subject)
            .build();
        let destination = ProviderUserIdentifierType::builder()
            .provider_name("Cognito")
            .provider_attribute_value(&user.username)
            .build();
        let result = self
            .cognito()
            .admin_link_provider_for_user()
            .user_pool_id(self.pool())
            .source_user(source)
            .destination_user(destination)
            .send()
            .await;
        if result.is_ok() {
            return Ok(());
        }
        // The call may have committed although its answer was lost.
        if self
            .get_user(&user.username)
            .await?
            .is_some_and(|raw| linked(&raw, provider, subject))
        {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
}
