//! The custom email sender as a Lambda function of its own.

use std::sync::Arc;

use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::Value;

use super::{EmailSender, KmsDecryptor, MailDelivery, MailError};
use crate::directory::{AwsDirectory, config};

/// The environment variable naming the budget's table.
const TABLE_VARIABLE: &str = "MAIL_BUDGET_TABLE";
/// The environment variable naming the custom sender's KMS key.
const KEY_VARIABLE: &str = "COGNITO_EMAIL_KEY_ARN";

impl EmailSender {
    /// A sender from `MAIL_BUDGET_TABLE` and `COGNITO_EMAIL_KEY_ARN`, in the
    /// function's own region.
    pub async fn from_env() -> Result<Self, MailError> {
        let table =
            std::env::var(TABLE_VARIABLE).map_err(|_| MailError::Configuration(TABLE_VARIABLE))?;
        let key =
            std::env::var(KEY_VARIABLE).map_err(|_| MailError::Configuration(KEY_VARIABLE))?;
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let decryptor = KmsDecryptor::new(aws_sdk_kms::Client::new(&config), key).await?;
        Ok(Self::new(
            aws_sdk_dynamodb::Client::new(&config),
            table,
            decryptor,
        ))
    }
}

/// [`run`] on a Tokio runtime the caller already has.
pub async fn serve(delivery: impl MailDelivery) -> Result<(), lambda_runtime::Error> {
    let shared = Arc::new((
        EmailSender::from_env().await?,
        delivery,
        config::load().await,
    ));
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let shared = Arc::clone(&shared);
        async move {
            let (sender, delivery, config) = &*shared;
            // Only attribute verification reads the directory, so a function
            // that has none configured still sends everything else.
            let directory = event.payload["userPoolId"]
                .as_str()
                .and_then(|pool| AwsDirectory::from_env_with(config, pool.into()).ok());
            sender
                .send(
                    directory.as_ref(),
                    delivery,
                    &event.payload,
                    &event.context.request_id,
                )
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
