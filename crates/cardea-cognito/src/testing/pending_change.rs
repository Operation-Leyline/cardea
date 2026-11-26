//! The events a live pool sent while a change from [`OLD`] to [`NEW`] waited
//! for its code, with example addresses.
//!
//! Observed: each event's `triggerSource` and its
//! `request.userAttributes.email` ([`OBSERVED`]), and that the stored account
//! still read `email_verified` "true". The capture did not record
//! `email_verified` as the events carried it, so its value here is assumed from
//! the stored account. The rest of each event follows AWS's documented shape.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(crate) const OLD: &str = "old@example.com";
pub(crate) const NEW: &str = "new@example.com";

/// `(triggerSource, request.userAttributes.email)`.
pub(crate) const OBSERVED: [(&str, &str); 4] = [
    ("CustomMessage_UpdateUserAttribute", OLD),
    ("CustomMessage_VerifyUserAttribute", OLD),
    ("CustomEmailSender_UpdateUserAttribute", NEW),
    ("CustomEmailSender_VerifyUserAttribute", OLD),
];

/// An event from `source` for `email`, carrying `email_verified` as given, or
/// not at all. A custom email sender event carries `code`, encrypted; a custom
/// message event carries its placeholder.
pub(crate) fn event(source: &str, email: &str, verified: Option<Value>, code: &str) -> Value {
    let mut attributes = json!({"sub":"native-sub","email":email});
    if let Some(verified) = verified {
        attributes["email_verified"] = verified;
    }
    let (request, response) = if source.starts_with("CustomEmailSender_") {
        (
            json!({"type":"customEmailSenderRequestV1","code":STANDARD.encode(code),
                "userAttributes":attributes}),
            json!({}),
        )
    } else {
        (
            json!({"userAttributes":attributes,"codeParameter":"{####}",
                "usernameParameter":null}),
            json!({"smsMessage":null,"emailMessage":null,"emailSubject":null}),
        )
    };
    json!({"version":"1","region":"us-east-1","userPoolId":"pool","userName":"internal",
        "callerContext":{"awsSdkVersion":"x","clientId":"c"},"triggerSource":source,
        "request":request,"response":response})
}
