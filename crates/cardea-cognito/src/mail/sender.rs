//! One custom email sender event: budget, decrypt, deliver.

use async_trait::async_trait;
use aws_sdk_dynamodb::Client as Dynamo;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Code, MailDelivery, MailMessage, MessageKind, Refusal, Template, budget};
use crate::{
    directory::{AwsDirectory, now},
    triggers::ProductError,
};

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
    /// An identity rule refused the message, or could not be checked.
    #[error(transparent)]
    Identity(#[from] cardea_core::Error),
    /// The budget refused the message.
    #[error(transparent)]
    Refused(#[from] Refusal),
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

/// What a delivery needs besides the product: the budget's table and the key
/// that opens Cognito's codes.
pub struct EmailSender {
    ddb: Dynamo,
    budget_table: String,
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
    /// A sender counting against `budget_table`.
    pub fn new(ddb: Dynamo, budget_table: String, decryptor: impl CodeDecryptor + 'static) -> Self {
        Self {
            ddb,
            budget_table,
            decryptor: Box::new(decryptor),
        }
    }

    /// Send the message a `CustomEmailSender_*` event asks for. The answer is
    /// empty: the encrypted event is never echoed.
    ///
    /// `directory` is that of the event's pool. A code that would verify any
    /// address but the one the account holds is refused
    /// ([`AwsDirectory::check_verification`]) with nothing spent or sent.
    pub async fn send(
        &self,
        directory: &AwsDirectory,
        delivery: &dyn MailDelivery,
        event: &Value,
        request_id: &str,
    ) -> Result<Value, MailError> {
        if required(&event["request"], "type")? != "customEmailSenderRequestV1" {
            return Err(MailError::UnsupportedVersion);
        }
        let kind = MessageKind::from_trigger(required(event, "triggerSource")?)
            .ok_or(MailError::UnsupportedSource)?;
        let recipient = required(&event["request"]["userAttributes"], "email")?;
        if kind == MessageKind::VerifyAttribute {
            directory.check_verification_event(event).await?;
        }
        let template = delivery.template(kind).map_err(MailError::Template)?;
        let key = delivery_key(event, &template, request_id);
        // Spent before decrypting or sending anything, so a refused request
        // costs one transaction. The delivery key names the message: a retry
        // of one already counted spends nothing, so retries after a failed
        // send cannot drain a recipient's budget.
        if let Some(counter) = kind.counter() {
            budget::spend(
                &self.ddb,
                &self.budget_table,
                recipient,
                &key,
                counter,
                now(),
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
