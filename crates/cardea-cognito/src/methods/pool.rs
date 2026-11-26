//! What the user pool says about a signed-in person's linked identities.

use aws_sdk_cognitoidentityprovider::types::ProviderUserIdentifierType;
use cardea_core::{Error, Provider, User};
use serde_json::Value;

use super::row::Identity;
use crate::directory::{AwsDirectory, attribute};

impl AwsDirectory {
    /// The identities the pool links onto `user`. Refused with
    /// [`Error::Conflict`] unless the pool's user of that name is enabled,
    /// confirmed and has the caller's id. A verified address is not asked for:
    /// an account an operator made may sign in without one, and may see and
    /// remove its methods. Linking still requires it.
    ///
    /// Providers this library does not know are left out: its triggers refuse
    /// their sign-ins, so they are no way in.
    pub(super) async fn pool_identities(&self, user: &User) -> Result<Vec<Identity>, Error> {
        let raw = self
            .get_user(&user.username)
            .await?
            .ok_or(Error::Conflict)?;
        if !raw.enabled()
            || raw.user_status().map(|status| status.as_str()) != Some("CONFIRMED")
            || attribute(&raw, "sub") != Some(user.user_id.as_str())
        {
            return Err(Error::Conflict);
        }
        let Some(value) = attribute(&raw, "identities") else {
            return Ok(Vec::new());
        };
        // An unreadable list is not an empty one.
        let listed: Vec<Value> = serde_json::from_str(value).map_err(|_| Error::Conflict)?;
        let mut identities: Vec<Identity> = listed
            .iter()
            .filter_map(|identity| {
                Some(Identity {
                    provider: Provider::from_cognito_name(identity["providerName"].as_str()?)?,
                    subject: identity["userId"].as_str()?.to_owned(),
                })
            })
            .collect();
        identities.sort_by_key(|i| Provider::ALL.iter().position(|p| *p == i.provider));
        Ok(identities)
    }

    /// Take `identity`, which the pool links onto `user`, off that user.
    pub(super) async fn disable_identity(
        &self,
        user: &User,
        identity: &Identity,
    ) -> Result<(), Error> {
        let named = ProviderUserIdentifierType::builder()
            .provider_name(identity.provider.rule().cognito_name)
            .provider_attribute_name("Cognito_Subject")
            .provider_attribute_value(&identity.subject)
            .build();
        let result = self
            .cognito()
            .admin_disable_provider_for_user()
            .user_pool_id(self.pool())
            .user(named)
            .send()
            .await;
        // The call may have committed although its answer was lost.
        if result.is_ok() || !self.pool_identities(user).await?.contains(identity) {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
}
