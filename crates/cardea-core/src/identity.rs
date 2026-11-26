//! A person as a provider vouches for them.

use serde_json::Value;

use crate::{Error, Provider, normalize_email};

/// A verified sign-in from an external provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderIdentity {
    /// Who vouched.
    pub provider: Provider,
    /// The provider's permanent id for the person.
    pub subject: String,
    /// The verified address, normalized.
    pub email: String,
    /// Whether the provider owns the mailbox, so the sign-in may link without
    /// a signed-in session ([`crate::ProviderRule::owns_mailbox`]).
    pub authoritative: bool,
}

impl ProviderIdentity {
    /// The identity the claims describe. Refused without a subject, a usable
    /// address and `email_verified`.
    ///
    /// Only call with claims already validated by Cognito or a JWT verifier:
    /// nothing here checks a signature, issuer, audience or expiry.
    pub fn from_verified_claims(provider: Provider, claims: &Value) -> Result<Self, Error> {
        let subject = claims["sub"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 255)
            .ok_or(Error::Invalid)?
            .to_owned();
        let email = normalize_email(claims["email"].as_str().ok_or(Error::Invalid)?)?;
        let verified = claims["email_verified"] == true || claims["email_verified"] == "true";
        if !verified {
            return Err(Error::Invalid);
        }
        let domain = email.rsplit_once('@').ok_or(Error::Invalid)?.1;
        let authoritative = (provider.rule().owns_mailbox)(domain, claims);
        Ok(Self {
            provider,
            subject,
            email,
            authoritative,
        })
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
