//! The Lambda a product builds: it runs Cardea's handler with the product's
//! hooks.
//!
//! ```text
//! fn main() -> Result<(), lambda_runtime::Error> {
//!     cardea_cognito::triggers::run(MyProduct::from_env())
//! }
//! ```
//!
//! | Trigger | The library does |
//! |---|---|
//! | `PreSignUp_SignUp`, `PreSignUp_AdminCreateUser` | refuse disposable domains; claim the mailbox; never auto-confirm |
//! | `PreSignUp_ExternalProvider` | allow only a subject already bound and linked |
//! | `InboundFederation_ExternalProvider` | resolve, create the native user if needed, link, return the canonical email |
//! | `PostConfirmation_ConfirmSignUp` | provision through the product |
//! | `PostConfirmation_ConfirmForgotPassword` | set `passwordSet` |
//! | `TokenGeneration_*` | provision if not yet, then the product's claims |
//! | `TokenGeneration_ClientCredentials` | nothing: there is no person |
//! | `CustomMessage_UpdateUserAttribute`, `_VerifyUserAttribute` | refuse an address that is not the account's own mailbox; otherwise nothing |
//! | `CustomMessage_*`, any other | nothing |
//! | `CustomEmailSender_*` | refuse the same changed address; spend the mailbox's budget, decrypt, hand to the product (feature `email-sender`) |
//!
//! Changing a person's email is not supported. A pool must require
//! verification before an email update, and route either the custom message or
//! the custom email sender trigger here, so that the new address is never
//! verified.
//! The handler logs through `tracing`; the product installs the subscriber.
//!
//! The function reads `IDENTITIES_TABLE` (partition key `identityKey`) and
//! needs read and write on it, plus `cognito-idp:AdminGetUser`,
//! `AdminCreateUser`, `AdminSetUserPassword` and `AdminLinkProviderForUser` on
//! the pool. Mail events need what [`crate::mail`] lists.

use std::time::Duration;

use serde_json::Value;

use crate::directory::AwsDirectory;

mod account;
mod error;
mod inbound;
mod pre_signup;
mod product;
mod runtime;

pub use error::TriggerError;
pub use product::{Claims, NewAccount, Product, ProductError};
pub use runtime::{TriggerHandler, run, serve};

/// How long a directory trigger may take: Cognito gives up after five
/// seconds, and an answer just short of that is still readable.
const DEADLINE: Duration = Duration::from_millis(4500);

/// Answer one directory trigger: every trigger but the custom email sender's.
/// The result is the event Cognito gets back.
pub async fn handle(
    directory: &AwsDirectory,
    product: &(impl Product + ?Sized),
    payload: Value,
) -> Result<Value, TriggerError> {
    tokio::time::timeout(DEADLINE, dispatch(directory, product, payload))
        .await
        .map_err(|_| TriggerError::TimedOut)?
}

async fn dispatch(
    directory: &AwsDirectory,
    product: &(impl Product + ?Sized),
    payload: Value,
) -> Result<Value, TriggerError> {
    let source = payload["triggerSource"].as_str().unwrap_or_default();
    match source {
        "InboundFederation_ExternalProvider" => directory.inbound(payload).await,
        "PostConfirmation_ConfirmSignUp" => {
            let account = account::account(&payload)?;
            account::provision(directory, product, &account).await?;
            Ok(payload)
        }
        "PostConfirmation_ConfirmForgotPassword" => {
            let account = account::account(&payload)?;
            directory
                .record_password_set(&account.email, &account.username, &account.user_id)
                .await?;
            Ok(payload)
        }
        // The code that would complete an email change is withheld.
        "CustomMessage_UpdateUserAttribute" | "CustomMessage_VerifyUserAttribute" => {
            directory.check_verification_event(&payload).await?;
            Ok(payload)
        }
        // Every other message stays as Cognito wrote it.
        source if source.starts_with("CustomMessage_") => Ok(payload),
        // A machine client's token has no person behind it: no account to
        // provision and no user to add claims for.
        "TokenGeneration_ClientCredentials" => Ok(payload),
        source if source.starts_with("PreSignUp_") => Ok(directory.pre_signup(payload).await?),
        source if source.starts_with("TokenGeneration_") => {
            account::token_generation(directory, product, payload).await
        }
        _ => Err(TriggerError::Unsupported),
    }
}

#[cfg(test)]
mod tests;
