//! One custom email sender event: budget, decrypt, deliver.

use async_trait::async_trait;
use aws_sdk_dynamodb::Client as Dynamo;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    BudgetKey, BudgetKeySource, Code, KeyError, MailDelivery, MailMessage, MessageKind, Refusal,
    Template, budget, once::ReadOnce,
};
use crate::{cause::cause, directory::now, email_change, triggers::ProductError};

/// The longest encrypted code accepted, in base64.
const MAX_CODE_BYTES: usize = 32_768;

/// Opens the envelope Cognito encrypts a code in.
#[async_trait]
pub trait CodeDecryptor: Send + Sync {
    /// The code in `ciphertext`, encrypted for the user pool `pool`.
    async fn decrypt(&self, ciphertext: Vec<u8>, pool: &str) -> Result<String, MailError>;
}

/// Why a message was not sent. Cognito quotes this text to the caller, and no
/// variant carries the code or the address.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// The event is not a version this sender reads.
    #[error("unsupported Cognito request version")]
    UnsupportedVersion,
    /// The trigger is not a mail trigger this sender knows.
    #[error("unsupported Cognito email source")]
    UnsupportedSource,
    /// The event lacks a field.
    #[error("missing {0}")]
    MissingField(&'static str),
    /// An identity rule refused the message.
    #[error(transparent)]
    Identity(#[from] cardea_core::Error),
    /// The budget refused the message.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// There is no budget key. It reads as [`Refusal::Unavailable`] does: the
    /// cause is for the log, not the caller.
    #[error("email service is unavailable; retry the same request")]
    BudgetKey(#[source] KeyError),
    /// The encrypted code is too large.
    #[error("Cognito ciphertext too large")]
    CodeTooLarge,
    /// The encrypted code is not base64.
    #[error("invalid Cognito ciphertext encoding")]
    CodeEncoding,
    /// The code could not be decrypted.
    #[error("Cognito code decryption failed")]
    Decryption,
    /// The decryptor could not be set up.
    #[error("Cognito email sender is not configured: {0}")]
    Configuration(&'static str),
    /// The product has no template for the message.
    #[error("Cognito email template is unavailable")]
    Template(#[source] ProductError),
    /// The product could not deliver it.
    #[error("Cognito email delivery failed")]
    Delivery(#[source] ProductError),
}

/// What a delivery needs besides the product: the budget's table and key, and
/// what opens Cognito's codes. Keep one for the life of the function, so that
/// a key it has read is not read for each message.
pub struct EmailSender {
    ddb: Dynamo,
    budget_table: String,
    key_source: Box<dyn BudgetKeySource>,
    decryptor: Box<dyn CodeDecryptor>,
}

fn required<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, MailError> {
    value[field]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or(MailError::MissingField(field))
}

/// Cognito HTML-escapes temporary passwords.
fn unescape_password(code: &str) -> String {
    code.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// The message's name across retries. It hashes the encrypted envelope, not
/// the low-entropy code; an event without a code is told apart by its
/// invocation.
fn delivery_key(event: &Value, template: &Template, request_id: &str) -> String {
    let identity = json!([
        event,
        template.id,
        template.version,
        if event["request"]["code"].is_string() {
            ""
        } else {
            request_id
        }
    ]);
    format!(
        "cognito:{}",
        hex::encode(Sha256::digest(identity.to_string().as_bytes()))
    )
}

impl EmailSender {
    /// A sender counting against `budget_table`, in rows named under the key
    /// `key` gives. It asks for the key when the first message needs it and
    /// keeps it; after a failure it asks again for the next message.
    pub fn new(
        ddb: Dynamo,
        budget_table: String,
        key: impl BudgetKeySource + 'static,
        decryptor: impl CodeDecryptor + 'static,
    ) -> Self {
        Self::with_key_source(ddb, budget_table, ReadOnce::new(key), decryptor)
    }

    /// A sender that asks `source` for the key for every message and keeps
    /// none itself. Caching is the source's: wrap one that reads a secret each
    /// time in a [`RefreshingKeySource`](super::RefreshingKeySource).
    pub fn with_key_source(
        ddb: Dynamo,
        budget_table: String,
        source: impl BudgetKeySource + 'static,
        decryptor: impl CodeDecryptor + 'static,
    ) -> Self {
        Self {
            ddb,
            budget_table,
            key_source: Box::new(source),
            decryptor: Box::new(decryptor),
        }
    }

    /// The key to count this message under.
    async fn budget_key(&self) -> Result<BudgetKey, MailError> {
        self.key_source.load().await.map_err(|error| {
            tracing::error!(cause = %cause(&error), "mail budget key unavailable");
            MailError::BudgetKey(error)
        })
    }

    /// Send the message a `CustomEmailSender_*` event asks for. The answer is
    /// empty: the encrypted event is never echoed.
    ///
    /// A code that could complete an email change is refused with
    /// [`Error::EmailChange`](cardea_core::Error::EmailChange), with nothing
    /// spent or sent: every `_UpdateUserAttribute`, and a
    /// `_VerifyUserAttribute` unless the event's `email_verified` is false.
    ///
    /// Without a budget key nothing is spent or sent either
    /// ([`MailError::BudgetKey`]), whatever the message.
    pub async fn send(
        &self,
        delivery: &dyn MailDelivery,
        event: &Value,
        request_id: &str,
    ) -> Result<Value, MailError> {
        self.send_at(delivery, event, request_id, now()).await
    }

    /// [`EmailSender::send`], counting in the UTC day that holds `time`.
    async fn send_at(
        &self,
        delivery: &dyn MailDelivery,
        event: &Value,
        request_id: &str,
        time: i64,
    ) -> Result<Value, MailError> {
        if required(&event["request"], "type")? != "customEmailSenderRequestV1" {
            return Err(MailError::UnsupportedVersion);
        }
        let source = required(event, "triggerSource")?;
        let kind = MessageKind::from_trigger(source).ok_or(MailError::UnsupportedSource)?;
        email_change::refuse(source, event)?;
        let recipient = required(&event["request"]["userAttributes"], "email")?;
        let template = delivery.template(kind).map_err(MailError::Template)?;
        let key = delivery_key(event, &template, request_id);
        let budget_key = self.budget_key().await?;
        // Spent before decrypting or sending anything, so a refused request
        // costs one transaction. The delivery key names the message: a retry
        // of one already counted spends nothing, so retries after a failed
        // send cannot drain a recipient's budget.
        if let Some(counter) = kind.counter() {
            budget::spend(
                &self.ddb,
                &self.budget_table,
                &budget_key,
                recipient,
                &key,
                counter,
                time,
            )
            .await?;
        }
        let code = match kind {
            MessageKind::SecurityAlert => None,
            _ => Some(self.code(kind, event).await?),
        };
        delivery
            .deliver(MailMessage {
                kind,
                recipient,
                code,
                template,
                delivery_key: &key,
            })
            .await
            .map_err(MailError::Delivery)?;
        Ok(json!({}))
    }

    async fn code(&self, kind: MessageKind, event: &Value) -> Result<Code, MailError> {
        let encoded = required(&event["request"], "code")?;
        if encoded.len() > MAX_CODE_BYTES {
            return Err(MailError::CodeTooLarge);
        }
        let ciphertext = STANDARD
            .decode(encoded)
            .map_err(|_| MailError::CodeEncoding)?;
        let code = self
            .decryptor
            .decrypt(ciphertext, required(event, "userPoolId")?)
            .await?;
        // Only temporary passwords are escaped. Decode once.
        Ok(Code::new(if kind == MessageKind::TemporaryPassword {
            unescape_password(&code)
        } else {
            code
        }))
    }
}

#[cfg(test)]
mod tests;
