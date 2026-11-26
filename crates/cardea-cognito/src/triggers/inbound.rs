//! `InboundFederation_ExternalProvider`: resolve the provider identity, link
//! it onto its native user and answer with that user's address, so the first
//! linked sign-in already succeeds.

use cardea_core::{Error, Provider, ProviderIdentity, resolve};
use serde_json::{Value, json};

use super::TriggerError;
use crate::directory::AwsDirectory;

impl AwsDirectory {
    /// The inbound federation trigger.
    pub async fn inbound(&self, mut payload: Value) -> Result<Value, TriggerError> {
        let provider = payload["request"]["providerName"]
            .as_str()
            .and_then(Provider::from_cognito_name)
            .filter(|provider| payload["request"]["providerType"] == provider.rule().cognito_type)
            .ok_or(Error::Invalid)?;
        let identity = ProviderIdentity::from_verified_claims(
            provider,
            &payload["request"]["attributes"]["idToken"],
        )?;
        let user = resolve(self, &identity, None)
            .await
            .map_err(|error| match error {
                Error::LinkRequired => TriggerError::LinkRequired(provider.rule().display_name),
                error => error.into(),
            })?;
        // Cognito requires email on every federation response, including linked
        // users. Return the exact canonical value, never a changed provider
        // email. AdminUpdateUserAttributes is not a simulation of federation
        // mapping.
        payload["response"]["userAttributesToMap"] = json!({
            "sub": identity.subject, "email": user.email, "email_verified": "true"
        });
        Ok(payload)
    }
}
