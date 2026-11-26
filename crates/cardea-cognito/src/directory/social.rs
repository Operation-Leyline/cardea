//! The password account behind a provider-claimed mailbox.

use aws_sdk_cognitoidentityprovider::{
    config::Builder as CognitoConfig,
    types::{AttributeType, MessageActionType},
};
use cardea_core::{Directory, EmailOwner, Error, Provider, User};
use tabulary::Update;

use super::{AwsDirectory, email_key};
use crate::record::EmailRowAttrs;

/// The client metadata key that tells the pre-signup trigger an account is the
/// library's own, made for a provider claim. Its value is the claim's origin.
pub(crate) const ORIGIN_METADATA: &str = "identityOrigin";

impl AwsDirectory {
    /// Elect `attempt` as the one password initialization of a mailbox's
    /// row, only while none is elected; or, with `elect` false, release it,
    /// only while `attempt` still holds it.
    async fn elect_initializer(
        &self,
        email: &str,
        attempt: &str,
        elect: bool,
    ) -> Result<(), Error> {
        let held = EmailRowAttrs::PASSWORD_INITIALIZATION;
        let (change, condition) = if elect {
            (held.set(attempt.to_owned()), held.not_exists())
        } else {
            (held.remove(), held.eq(attempt.to_owned()))
        };
        let request = self
            .rows()?
            .update(email_key(email)?)
            .changes(Update::new().and(change))
            .condition(condition)
            .build()
            .map_err(|_| Error::Invalid)?;
        request
            .decode(request.apply(self.dynamodb().update_item()).send().await)
            .map(|_| ())
            .map_err(|_| Error::Unavailable)
    }

    pub(super) async fn find_or_create_social_user(
        &self,
        owner: &EmailOwner,
    ) -> Result<User, Error> {
        if Provider::from_cognito_name(&owner.origin).is_none() {
            return Err(Error::Conflict);
        }
        let raw = match self.get_user(&owner.username).await? {
            Some(user) => user,
            None => {
                let attr = |name: &str, value: &str| {
                    AttributeType::builder()
                        .name(name)
                        .value(value)
                        .build()
                        .map_err(|_| Error::Invalid)
                };
                let created = self
                    .cognito()
                    .admin_create_user()
                    .user_pool_id(self.pool())
                    .username(&owner.username)
                    .user_attributes(attr("email", &owner.email)?)
                    .user_attributes(attr("email_verified", "true")?)
                    .client_metadata(ORIGIN_METADATA, &owner.origin)
                    .message_action(MessageActionType::Suppress)
                    .send()
                    .await;
                // The deterministic username is also Cognito's uniqueness guard.
                let _ = created;
                self.get_user(&owner.username)
                    .await?
                    .ok_or(Error::Unavailable)?
            }
        };
        if raw.user_status().map(|s| s.as_str()) == Some("FORCE_CHANGE_PASSWORD") {
            // A provider-made destination needs CONFIRMED status. The random
            // password is never returned or stored; mailbox recovery can add a
            // password later. Never reset a pre-existing native user's password.
            // Elect exactly one initializer. Otherwise an overlapping retry
            // could reset a password after the user has completed recovery.
            // An ambiguous/crashed initialization stays reserved for operator
            // reconciliation; it never creates a fallback user or resets again.
            let attempt = uuid::Uuid::new_v4().to_string();
            let acquired = self.elect_initializer(&owner.email, &attempt, true).await;
            if acquired.is_err() {
                return self.native_user(owner).await.map_err(|error| {
                    if error == Error::LinkRequired {
                        Error::NotReady
                    } else {
                        error
                    }
                });
            }
            let password = format!(
                "Aa1!{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            let result =
                self.cognito()
                    .admin_set_user_password()
                    .user_pool_id(self.pool())
                    .username(&owner.username)
                    .password(password)
                    .permanent(true)
                    .customize()
                    .config_override(CognitoConfig::new().retry_config(
                        aws_config::retry::RetryConfig::standard().with_max_attempts(1),
                    ))
                    .send()
                    .await;
            if let Err(error) = result {
                // These responses positively reject the operation before a
                // password change. Transport/server ambiguity never releases it.
                if error.as_service_error().is_some_and(|e| {
                    e.is_too_many_requests_exception() || e.is_not_authorized_exception()
                }) {
                    let _ = self.elect_initializer(&owner.email, &attempt, false).await;
                }
                return self
                    .native_user(owner)
                    .await
                    .map_err(|_| Error::Unavailable);
            }
        }
        self.native_user(owner).await
    }
}
