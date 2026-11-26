//! Changing a person's email is not supported: mailbox ownership in the
//! directory would not follow it. A pool requires verification before a new
//! address replaces the old one, so a change completes only with a code, and
//! that code is never sent.
//!
//! The trigger source decides, not the address in the event: while a change is
//! pending, a live pool puts the old address in most of these events.

use cardea_core::Error;
use serde_json::Value;

/// Refuse, with [`Error::EmailChange`], a custom message or custom email
/// sender event whose code could complete an email change.
///
/// * `_UpdateUserAttribute` is always refused: with verification before update,
///   it only carries a change.
/// * `_VerifyUserAttribute` is allowed only when `email_verified` is false,
///   which is verifying the current address. When the current address is
///   already verified the code can only be for a pending change. A missing or
///   unreadable value is refused as if it were true.
///
/// Every other event passes. A pool that also verified phone numbers would have
/// those codes refused here too.
pub(crate) fn refuse(source: &str, event: &Value) -> Result<(), Error> {
    let allowed = match source {
        "CustomMessage_UpdateUserAttribute" | "CustomEmailSender_UpdateUserAttribute" => false,
        "CustomMessage_VerifyUserAttribute" | "CustomEmailSender_VerifyUserAttribute" => {
            let verified = &event["request"]["userAttributes"]["email_verified"];
            *verified == "false" || *verified == false
        }
        _ => true,
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::EmailChange)
    }
}
