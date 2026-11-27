//! The mail budget key as a Secrets Manager secret.

use async_trait::async_trait;
use aws_sdk_secretsmanager::Client;

use super::{BudgetKey, BudgetKeySource, KeyError};

/// Reads the key from the secret's current value (`AWSCURRENT`).
pub struct SecretsManagerKey {
    client: Client,
    secret: String,
}

impl SecretsManagerKey {
    /// The key in the secret named, or with the ARN, `secret`.
    pub fn new(client: Client, secret: impl Into<String>) -> Self {
        Self {
            client,
            secret: secret.into(),
        }
    }
}

#[async_trait]
impl BudgetKeySource for SecretsManagerKey {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        let output = self
            .client
            .get_secret_value()
            .secret_id(&self.secret)
            .send()
            .await
            .map_err(|error| KeyError::Read(Box::new(error)))?;
        BudgetKey::from_secret(output.secret_string().ok_or(KeyError::NoValue)?)
    }
}

#[cfg(test)]
mod tests;
