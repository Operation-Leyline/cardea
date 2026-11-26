//! The messages Cognito asks a custom sender to deliver.

use async_trait::async_trait;

use super::Counter;
use crate::triggers::ProductError;

/// What a message is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A signup's verification code, first or resent.
    VerifyEmail,
    /// A password reset code.
    PasswordReset,
    /// A code verifying a changed attribute.
    VerifyAttribute,
    /// A sign-in code.
    Authentication,
    /// An operator-created account's temporary password.
    TemporaryPassword,
    /// A notice that Cognito detected a possible account takeover.
    SecurityAlert,
}

impl MessageKind {
    /// The kind of a `CustomEmailSender_*` trigger.
    pub fn from_trigger(source: &str) -> Option<Self> {
        Some(match source {
            "CustomEmailSender_SignUp" | "CustomEmailSender_ResendCode" => Self::VerifyEmail,
            "CustomEmailSender_ForgotPassword" => Self::PasswordReset,
            "CustomEmailSender_UpdateUserAttribute" | "CustomEmailSender_VerifyUserAttribute" => {
                Self::VerifyAttribute
            }
            "CustomEmailSender_Authentication" => Self::Authentication,
            "CustomEmailSender_AdminCreateUser" => Self::TemporaryPassword,
            "CustomEmailSender_AccountTakeOverNotification" => Self::SecurityAlert,
            _ => return None,
        })
    }

    /// A stable name, such as `VERIFY_EMAIL`, for a product's configuration.
    pub fn name(self) -> &'static str {
        match self {
            Self::VerifyEmail => "VERIFY_EMAIL",
            Self::PasswordReset => "PASSWORD_RESET",
            Self::VerifyAttribute => "VERIFY_ATTRIBUTE",
            Self::Authentication => "AUTHENTICATION",
            Self::TemporaryPassword => "TEMPORARY_PASSWORD",
            Self::SecurityAlert => "SECURITY_ALERT",
        }
    }

    /// The daily budget the message draws on, if any. Everything a caller can
    /// request for someone else's address draws on one; a temporary password
    /// is an operator's act and a security alert follows a detection, so
    /// neither is something a stranger can aim at a victim, and a victim must
    /// always get the alert.
    pub fn counter(self) -> Option<Counter> {
        match self {
            Self::PasswordReset => Some(Counter::PasswordReset),
            Self::VerifyEmail | Self::VerifyAttribute | Self::Authentication => {
                Some(Counter::General)
            }
            Self::TemporaryPassword | Self::SecurityAlert => None,
        }
    }
}

/// The product's template for a kind of message. It is part of the delivery
/// key, so a new template version is a new message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// The product's id for the template.
    pub id: String,
    /// Its version.
    pub version: u64,
}

/// A decrypted code or temporary password. It prints as `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    pub(crate) fn new(code: String) -> Self {
        Self(code)
    }

    /// The secret itself, to put in the message.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One message to deliver. The recipient and code are not to be logged, which
/// is why this has no `Debug`.
pub struct MailMessage<'a> {
    /// What the message is for.
    pub kind: MessageKind,
    /// The address to deliver to.
    pub recipient: &'a str,
    /// The code; absent on a security alert.
    pub code: Option<Code>,
    /// What [`MailDelivery::template`] answered.
    pub template: Template,
    /// Names this message across retries: use it as the mail provider's
    /// idempotency key.
    pub delivery_key: &'a str,
}

/// How a product sends Cognito's mail.
#[async_trait]
pub trait MailDelivery: Send + Sync {
    /// The template for `kind`, asked before anything is spent, so a product
    /// missing one fails without using the recipient's budget. By default the
    /// kind's name at version 1.
    fn template(&self, kind: MessageKind) -> Result<Template, ProductError> {
        Ok(Template {
            id: kind.name().to_owned(),
            version: 1,
        })
    }

    /// Send the message.
    async fn deliver(&self, message: MailMessage<'_>) -> Result<(), ProductError>;
}
