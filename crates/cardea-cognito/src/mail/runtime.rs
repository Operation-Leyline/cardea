//! The custom email sender as a Lambda function of its own.

use std::sync::Arc;

use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::Value;

use super::{EmailSender, KmsDecryptor, MailDelivery, MailError, SecretsManagerKey};

/// The environment variable naming the budget's table.
const TABLE_VARIABLE: &str = "MAIL_BUDGET_TABLE";
/// The environment variable naming the secret that holds the budget's key.
const SECRET_VARIABLE: &str = "MAIL_BUDGET_KEY_SECRET";
/// The environment variable naming the custom sender's KMS key.
const KEY_VARIABLE: &str = "COGNITO_EMAIL_KEY_ARN";

/// What the environment says about the sender.
#[derive(Debug, PartialEq, Eq)]
struct Settings {
    table: String,
    budget_key_secret: String,
    email_key: String,
}

impl Settings {
    /// The settings `variable` answers with. Each is required: an unset or
    /// empty one is refused by name.
    fn read(variable: impl Fn(&str) -> Option<String>) -> Result<Self, MailError> {
        let required = |name: &'static str| {
            variable(name)
                .filter(|value| !value.is_empty())
                .ok_or(MailError::Configuration(name))
        };
        Ok(Self {
            table: required(TABLE_VARIABLE)?,
            budget_key_secret: required(SECRET_VARIABLE)?,
            email_key: required(KEY_VARIABLE)?,
        })
    }
}

impl EmailSender {
    /// A sender from `MAIL_BUDGET_TABLE`, `MAIL_BUDGET_KEY_SECRET` and
    /// `COGNITO_EMAIL_KEY_ARN`, in the function's own region. The secret is
    /// read when the first message arrives.
    pub async fn from_env() -> Result<Self, MailError> {
        let settings = Settings::read(|name| std::env::var(name).ok())?;
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let decryptor =
            KmsDecryptor::new(aws_sdk_kms::Client::new(&config), settings.email_key).await?;
        let key = SecretsManagerKey::new(
            aws_sdk_secretsmanager::Client::new(&config),
            settings.budget_key_secret,
        );
        Ok(Self::new(
            aws_sdk_dynamodb::Client::new(&config),
            settings.table,
            key,
            decryptor,
        ))
    }
}

/// [`run`] on a Tokio runtime the caller already has.
pub async fn serve(delivery: impl MailDelivery) -> Result<(), lambda_runtime::Error> {
    let shared = Arc::new((EmailSender::from_env().await?, delivery));
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let shared = Arc::clone(&shared);
        async move {
            let (sender, delivery) = &*shared;
            sender
                .send(delivery, &event.payload, &event.context.request_id)
                .await
                .map_err(lambda_runtime::Error::from)
        }
    }))
    .await
}

/// Serve the custom email sender's events until Lambda stops the function.
pub fn run(delivery: impl MailDelivery) -> Result<(), lambda_runtime::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(delivery))
}

#[cfg(test)]
mod tests;
