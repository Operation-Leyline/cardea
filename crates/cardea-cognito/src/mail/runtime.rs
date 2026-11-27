//! The custom email sender as a Lambda function of its own.

use std::sync::Arc;

use aws_config::{BehaviorVersion, SdkConfig};
use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::Value;

use super::{
    BudgetKeySource, EmailSender, KmsDecryptor, MailDelivery, MailError, SecretsManagerKey,
};

/// The environment variable naming the budget's table.
const TABLE_VARIABLE: &str = "MAIL_BUDGET_TABLE";
/// The environment variable naming the secret that holds the budget's key.
const SECRET_VARIABLE: &str = "MAIL_BUDGET_KEY_SECRET";
/// The environment variable naming the custom sender's KMS key.
const KEY_VARIABLE: &str = "COGNITO_EMAIL_KEY_ARN";

/// Where a configured sender's budget key comes from.
enum KeyFrom {
    /// The secret `MAIL_BUDGET_KEY_SECRET` names, read once.
    Secret(String),
    /// The product's source, asked for every message.
    Product(Arc<dyn BudgetKeySource>),
}

/// What the environment says about the sender, whatever its key comes from.
#[derive(Debug, PartialEq, Eq)]
struct Settings {
    table: String,
    email_key: String,
}

/// The variable `name`'s value. An unset or empty one is refused by name.
fn required(
    variable: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, MailError> {
    variable(name)
        .filter(|value| !value.is_empty())
        .ok_or(MailError::Configuration(name))
}

impl Settings {
    /// The settings `variable` answers with. Each is required.
    fn read(variable: &impl Fn(&str) -> Option<String>) -> Result<Self, MailError> {
        Ok(Self {
            table: required(variable, TABLE_VARIABLE)?,
            email_key: required(variable, KEY_VARIABLE)?,
        })
    }
}

/// The process's environment.
pub(crate) fn environment(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The configuration the sender's clients run under.
pub(crate) async fn defaults() -> SdkConfig {
    aws_config::load_defaults(BehaviorVersion::latest()).await
}

impl EmailSender {
    /// A sender from `MAIL_BUDGET_TABLE`, `MAIL_BUDGET_KEY_SECRET` and
    /// `COGNITO_EMAIL_KEY_ARN`, in the function's own region. The secret is
    /// read when the first message arrives, and kept.
    pub async fn from_env() -> Result<Self, MailError> {
        Self::configured(environment, &defaults().await, None).await
    }

    /// [`EmailSender::from_env`] with the key from `source`, asked for every
    /// message ([`EmailSender::with_key_source`]). `MAIL_BUDGET_KEY_SECRET` is
    /// not read.
    pub async fn from_env_with_key_source(
        source: impl BudgetKeySource + 'static,
    ) -> Result<Self, MailError> {
        Self::configured(environment, &defaults().await, Some(Arc::new(source))).await
    }

    /// A sender from the variables `variable` answers with and clients under
    /// `config`. Without a `source` the key is the secret they name.
    pub(crate) async fn configured(
        variable: impl Fn(&str) -> Option<String>,
        config: &SdkConfig,
        source: Option<Arc<dyn BudgetKeySource>>,
    ) -> Result<Self, MailError> {
        let settings = Settings::read(&variable)?;
        let key = match source {
            Some(source) => KeyFrom::Product(source),
            None => KeyFrom::Secret(required(&variable, SECRET_VARIABLE)?),
        };
        let ddb = aws_sdk_dynamodb::Client::new(config);
        // Boxed: the Encryption SDK's setup future is deep enough to overflow
        // the default recursion limit of a product's own crate on Rust 1.97.1.
        let kms = aws_sdk_kms::Client::new(config);
        let decryptor = Box::pin(KmsDecryptor::new(kms, settings.email_key)).await?;
        Ok(match key {
            KeyFrom::Product(source) => {
                Self::with_key_source(ddb, settings.table, source, decryptor)
            }
            KeyFrom::Secret(name) => {
                let secrets = aws_sdk_secretsmanager::Client::new(config);
                let key = SecretsManagerKey::new(secrets, name);
                Self::new(ddb, settings.table, key, decryptor)
            }
        })
    }

    /// Serve the custom email sender's events with this sender until Lambda
    /// stops the function.
    pub async fn serve(self, delivery: impl MailDelivery) -> Result<(), lambda_runtime::Error> {
        let shared = Arc::new((self, delivery));
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
}

/// [`run`] on a Tokio runtime the caller already has.
pub async fn serve(delivery: impl MailDelivery) -> Result<(), lambda_runtime::Error> {
    EmailSender::from_env().await?.serve(delivery).await
}

/// Serve the custom email sender's events until Lambda stops the function. For
/// a key source of the product's own, build the sender with
/// [`EmailSender::from_env_with_key_source`] and call [`EmailSender::serve`].
pub fn run(delivery: impl MailDelivery) -> Result<(), lambda_runtime::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(delivery))
}

#[cfg(test)]
mod tests;
