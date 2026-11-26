//! `InboundFederation_ExternalProvider`: resolve the provider identity, link
//! it onto its native user and answer with that user's address, so the first
//! linked sign-in already succeeds.

use cardea_core::{Error, Provider, ProviderIdentity, resolve};
use serde_json::{Map, Value};

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
        let mut profile = provider_attributes(&payload);
        profile.insert("email".into(), user.email.into());
        payload["response"]["userAttributesToMap"] = Value::Object(profile);
        Ok(payload)
    }
}

/// Every attribute the event carries for this sign-in. Cognito stores only
/// what the answer names, so all of them go back.
///
/// Where two places name one attribute, the verified ID token wins over the
/// userinfo answer, and that over anything already in the response. An empty
/// value is left out, so that it never replaces a stored one: Apple sends a
/// name only on the first authorization.
fn provider_attributes(payload: &Value) -> Map<String, Value> {
    let attributes = &payload["request"]["attributes"];
    [
        &payload["response"]["userAttributesToMap"],
        &attributes["userInfo"],
        &attributes["idToken"],
    ]
    .into_iter()
    .filter_map(Value::as_object)
    .flatten()
    .filter_map(|(name, value)| Some((name.clone(), text(value)?.into())))
    .collect()
}

/// `value` as the string Cognito's attribute map holds: nothing for an empty
/// value, or for a list or object, which the map cannot hold.
fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        _ => None,
    }
}
