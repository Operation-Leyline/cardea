//! `PostConfirmation_*` and `TokenGeneration_*`: provision the account through
//! the product, record a chosen password, and add the product's claims.

use cardea_core::{Directory, Error, User};
use serde_json::{Value, json};

use super::{Claims, NewAccount, Product, TriggerError};
use crate::{cause::cause, directory::AwsDirectory, transact};

/// A string field every account event carries.
fn required(value: &Value, name: &'static str) -> Result<String, TriggerError> {
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or(TriggerError::MissingField(name))
}

/// The account a post-confirmation or token event is about.
pub(crate) fn account(payload: &Value) -> Result<NewAccount, TriggerError> {
    let attributes = &payload["request"]["userAttributes"];
    let user_id = required(&attributes["sub"], "sub")?;
    let email = required(&attributes["email"], "email")?;
    let username = required(&payload["userName"], "user name")?;
    let display_name = attributes["name"]
        .as_str()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or("User"))
        .to_owned();
    let email_verified = attributes["email_verified"].as_str() == Some("true");
    Ok(NewAccount {
        confirmed_signup: payload["triggerSource"] == "PostConfirmation_ConfirmSignUp"
            && email_verified,
        attributes: attributes.as_object().cloned().unwrap_or_default(),
        user_id,
        username,
        email,
        display_name,
        email_verified,
    })
}

/// Make sure the product holds the account and the mailbox is bound to it.
///
/// A new account goes to [`Product::provision`] with the guard; a known one
/// gets the guard alone. Existing sessions stay usable while the directory is
/// not ready.
pub(crate) async fn provision(
    directory: &AwsDirectory,
    product: &(impl Product + ?Sized),
    account: &NewAccount,
) -> Result<(), TriggerError> {
    let provisioned = product.is_provisioned(account).await?;
    if provisioned && directory.ready().await == Err(Error::NotReady) {
        return Ok(());
    }
    let guard = directory
        .profile_guard(&account.email, &account.username, &account.user_id)
        .await?;
    if provisioned {
        transact(directory.dynamodb(), vec![guard]).await?;
        return Ok(());
    }
    match product.provision(account, guard).await {
        Ok(()) => tracing::info!(user_id = %account.user_id, "provisioned"),
        Err(error) => {
            if !product.is_provisioned(account).await.unwrap_or(false) {
                tracing::error!(
                    cause = %cause(&error),
                    user_id = %account.user_id,
                    "provisioning failed"
                );
                return Err(error.into());
            }
            tracing::info!(user_id = %account.user_id, "already provisioned");
        }
    }
    Ok(())
}

/// Add `claims` to a token event's response, in the shape its version reads:
/// version 1 overrides the ID token; later versions name each token.
fn add_claims(payload: &mut Value, claims: Claims) {
    if claims.0.is_empty() {
        return;
    }
    let claims = json!(claims.0);
    if matches!(payload["version"].as_str(), Some("2" | "3")) {
        payload["response"]["claimsAndScopeOverrideDetails"] = json!({
            "idTokenGeneration": {"claimsToAddOrOverride": claims},
            "accessTokenGeneration": {"claimsToAddOrOverride": claims},
        });
    } else {
        payload["response"]["claimsOverrideDetails"] = json!({"claimsToAddOrOverride": claims});
    }
}

/// `TokenGeneration_*`: catches accounts no confirmation reached (an operator
/// made them), then adds the product's claims.
pub(crate) async fn token_generation(
    directory: &AwsDirectory,
    product: &(impl Product + ?Sized),
    mut payload: Value,
) -> Result<Value, TriggerError> {
    let account = account(&payload)?;
    provision(directory, product, &account).await?;
    let claims = product
        .token_claims(&User {
            user_id: account.user_id,
            username: account.username,
            email: account.email,
        })
        .await?;
    add_claims(&mut payload, claims);
    Ok(payload)
}

#[cfg(test)]
mod tests;
