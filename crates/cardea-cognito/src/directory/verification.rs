//! Changing a person's email is not supported, so a code that would verify a
//! new address is never sent. The pool applies a new address only once it is
//! verified, so withholding the code withholds the change.

use cardea_core::Error;
use serde_json::Value;

use super::AwsDirectory;

impl AwsDirectory {
    /// [`AwsDirectory::check_verification`] for a custom message or custom
    /// email sender event about a user attribute, whose `email` attribute is
    /// the address the code is for.
    pub(crate) async fn check_verification_event(&self, event: &Value) -> Result<(), Error> {
        let attributes = &event["request"]["userAttributes"];
        let field = |value: &Value| {
            value
                .as_str()
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .ok_or(Error::Invalid)
        };
        self.check_verification(
            &field(&attributes["email"])?,
            &field(&event["userName"])?,
            &field(&attributes["sub"])?,
        )
        .await
    }
}
