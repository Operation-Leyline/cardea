//! `PreSignUp_*`: native signups claim their mailbox, and a provider sign-up
//! is let through only for a subject already bound.

use cardea_core::{
    Directory, EmailOwner, Error, NATIVE_ORIGIN, Provider, disposable, normalize_email,
};
use serde_json::{Value, json};

use crate::directory::{AwsDirectory, Hold, ORIGIN_METADATA, now};

impl AwsDirectory {
    /// The pre-signup trigger: one ownership guard for self-signup and
    /// operator-created accounts, and the gate on provider sign-ups.
    pub async fn pre_signup(&self, payload: Value) -> Result<Value, Error> {
        self.pre_signup_at(payload, now()).await
    }

    /// [`AwsDirectory::pre_signup`] at `now`, in epoch seconds.
    pub(crate) async fn pre_signup_at(&self, mut payload: Value, now: i64) -> Result<Value, Error> {
        let source = payload["triggerSource"].as_str().ok_or(Error::Invalid)?;
        // Before any I/O: a throwaway domain reserves nothing.
        if source != "PreSignUp_ExternalProvider"
            && disposable::is_disposable(
                payload["request"]["userAttributes"]["email"]
                    .as_str()
                    .unwrap_or_default(),
            )
        {
            return Err(Error::DisposableDomain);
        }
        self.ready().await?;
        if source == "PreSignUp_ExternalProvider" {
            // Cognito may have selected this trigger before inbound linking.
            // Permit only the already-reserved, successfully linked subject.
            let (provider, subject) = payload["userName"]
                .as_str()
                .and_then(Provider::from_federated_username)
                .ok_or(Error::Invalid)?;
            let user = self
                .provider(provider, subject)
                .await?
                .ok_or(Error::Conflict)?;
            self.link(provider, subject, &user).await?;
            return Ok(payload);
        }
        if source != "PreSignUp_SignUp" && source != "PreSignUp_AdminCreateUser" {
            return Err(Error::Invalid);
        }
        // In an email-username pool Cognito generates a fresh internal UUID for
        // every failed signup attempt. Reserve the exact email alias instead:
        // it is stable across retries and Cognito enforces its uniqueness. The
        // directory row it lands on is the mailbox's, so a second alias of the
        // same mailbox loses the claim below.
        let username = payload["request"]["userAttributes"]["email"]
            .as_str()
            .ok_or(Error::Invalid)?;
        let proposed = EmailOwner {
            email: normalize_email(username)?,
            username: username.into(),
            origin: NATIVE_ORIGIN.into(),
        };
        // Only a self-signup waits on a confirmation that may never come; an
        // account an operator or a provider sign-in creates is meant to stay.
        let hold = if source == "PreSignUp_SignUp" {
            Hold::Unconfirmed
        } else {
            Hold::Permanent
        };
        let winner = self.claim_email_at(&proposed, hold, now).await?;
        let internal_create = source == "PreSignUp_AdminCreateUser"
            && Provider::from_cognito_name(&winner.origin).is_some()
            && payload["request"]["clientMetadata"][ORIGIN_METADATA] == winner.origin.as_str()
            && payload["request"]["userAttributes"]["email"] == winner.email.as_str();
        if winner != proposed && !internal_create {
            return Err(Error::Conflict);
        }
        // Never auto-confirm a native registration or mark its mailbox verified.
        payload["response"] =
            json!({"autoConfirmUser": false, "autoVerifyEmail": false, "autoVerifyPhone": false});
        Ok(payload)
    }
}
