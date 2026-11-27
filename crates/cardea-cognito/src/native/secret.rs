//! The sign-in ticket key as a Secrets Manager secret.

use std::time::{Duration, Instant};

use aws_sdk_secretsmanager::Client;
use tokio::sync::Mutex;

use super::{TicketKey, TicketKeyError, TicketKeySource};

/// The variable naming the secret, by name or ARN.
pub const TICKET_KEY_VARIABLE: &str = "SIGN_IN_TICKET_KEY_SECRET";

/// How long a key read is used before the secret is read again. A changed key
/// is in use by every function this long after, with no deployment.
pub const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Reads the key from the secret's current value (`AWSCURRENT`) and keeps it
/// for [`KEY_REFRESH_INTERVAL`]. A read that fails gives no key.
pub struct SecretsManagerTicketKey {
    client: Client,
    secret: String,
    /// The key last read, and when that read began.
    held: Mutex<Option<(Instant, TicketKey)>>,
}

impl SecretsManagerTicketKey {
    /// The key in the secret named, or with the ARN, `secret`.
    pub fn new(client: Client, secret: impl Into<String>) -> Self {
        Self {
            client,
            secret: secret.into(),
            held: Mutex::new(None),
        }
    }

    /// The secret [`TICKET_KEY_VARIABLE`] names, read with `config`.
    pub fn from_env(config: &aws_config::SdkConfig) -> Result<Self, TicketKeyError> {
        Self::configured(|name| std::env::var(name).ok(), config)
    }

    /// [`SecretsManagerTicketKey::from_env`] over the variables `variable`
    /// answers with.
    pub(crate) fn configured(
        variable: impl Fn(&str) -> Option<String>,
        config: &aws_config::SdkConfig,
    ) -> Result<Self, TicketKeyError> {
        let secret = variable(TICKET_KEY_VARIABLE)
            .filter(|name| !name.is_empty())
            .ok_or(TicketKeyError::NoValue)?;
        Ok(Self::new(Client::new(config), secret))
    }

    async fn read(&self) -> Result<TicketKey, TicketKeyError> {
        let output = self
            .client
            .get_secret_value()
            .secret_id(&self.secret)
            .send()
            .await
            .map_err(|error| TicketKeyError::Read(Box::new(error)))?;
        TicketKey::from_secret(output.secret_string().ok_or(TicketKeyError::NoValue)?)
    }
}

#[async_trait::async_trait]
impl TicketKeySource for SecretsManagerTicketKey {
    async fn load(&self) -> Result<TicketKey, TicketKeyError> {
        let mut held = self.held.lock().await;
        let now = Instant::now();
        if let Some((read, key)) = held.as_ref()
            && now.duration_since(*read) < KEY_REFRESH_INTERVAL
        {
            return Ok(key.clone());
        }
        let key = self.read().await?;
        *held = Some((now, key.clone()));
        Ok(key)
    }
}

#[cfg(test)]
mod tests;
