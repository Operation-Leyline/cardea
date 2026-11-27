//! The checks on a signed ID token. They are the same for every provider; what
//! differs (issuer, keys, how the email claims read) is the provider's row.

use std::sync::Arc;

use async_trait::async_trait;
use cardea_core::{Error, Provider, ProviderIdentity};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

use super::{HttpKeyFetcher, KeyFetcher, ProofRequest, ProofVerifier, VerifiedProof, keys::Keys};
use crate::cause::cause;

/// How old a proof may be, counted from its `iat`.
pub const PROOF_MAX_AGE_SECONDS: i64 = 5 * 60;

/// How far ahead of this clock a proof's `iat` may be.
const ISSUED_AHEAD_SECONDS: i64 = 30;

/// Verifies provider ID tokens against each provider's published keys.
///
/// The keys are cached in the verifier: build one when the service starts and
/// share it between requests.
pub struct JwtVerifier {
    keys: [(Provider, Keys); Provider::ALL.len()],
    /// Who besides the client a proof may name in `azp`, per provider.
    authorized_parties: Vec<(Provider, String)>,
}

impl JwtVerifier {
    /// A verifier that fetches keys over HTTPS.
    pub fn new() -> Result<Self, super::KeyFetchError> {
        Ok(Self::with_fetcher(Arc::new(HttpKeyFetcher::new()?)))
    }

    /// A verifier that gets every key set through `fetcher`.
    pub fn with_fetcher(fetcher: Arc<dyn KeyFetcher>) -> Self {
        Self {
            keys: Provider::ALL.map(|provider| {
                let keys = Keys::new(provider.rule().keys_url, Arc::clone(&fetcher));
                (provider, keys)
            }),
            authorized_parties: Vec::new(),
        }
    }

    /// Also accept `provider`'s proofs whose `azp` (authorized party) is one of
    /// `parties`. Google names an Android app's own OAuth client there when the
    /// app asks for a token for the web client. The audience must still be the
    /// client id. There are none by default; a second call replaces the
    /// provider's list, and empty ids are ignored.
    pub fn with_authorized_parties<S: Into<String>>(
        mut self,
        provider: Provider,
        parties: impl IntoIterator<Item = S>,
    ) -> Self {
        self.authorized_parties.retain(|(of, _)| *of != provider);
        self.authorized_parties.extend(
            parties
                .into_iter()
                .map(Into::into)
                .filter(|party| !party.is_empty())
                .map(|party| (provider, party)),
        );
        self
    }

    /// The key `provider` publishes under `kid`.
    async fn key(&self, provider: Provider, kid: &str) -> Result<DecodingKey, Error> {
        let (_, keys) = self
            .keys
            .iter()
            .find(|(of, _)| *of == provider)
            .ok_or(Error::Invalid)?;
        keys.key(kid)
            .await
            .map_err(|error| {
                tracing::warn!(cause = %cause(&error), "provider keys are unavailable");
                Error::Unavailable
            })?
            .ok_or(Error::Invalid)
    }
}

#[async_trait]
impl ProofVerifier for JwtVerifier {
    async fn verify(&self, request: ProofRequest<'_>) -> Result<VerifiedProof, Error> {
        // The header is read before the signature only to pick the key.
        let header = jsonwebtoken::decode_header(request.token).map_err(|_| Error::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(Error::Invalid);
        }
        let kid = header.kid.ok_or(Error::Invalid)?;
        let key = self.key(request.provider, &kid).await?;
        verify_with_key(&request, &key, &self.authorized_parties)
    }
}

/// Signature, issuer, audience, authorized party, expiry, freshness, nonce and
/// a verified email.
fn verify_with_key(
    request: &ProofRequest<'_>,
    key: &DecodingKey,
    authorized_parties: &[(Provider, String)],
) -> Result<VerifiedProof, Error> {
    let ProofRequest {
        provider,
        token,
        client_id,
        nonce,
        now,
    } = *request;
    if client_id.is_empty() || nonce.is_empty() {
        return Err(Error::Invalid);
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(provider.rule().issuers);
    validation.set_audience(&[client_id]);
    validation.validate_nbf = true;
    validation.leeway = 0;
    let claims = jsonwebtoken::decode::<Value>(token, key, &validation)
        .map_err(|_| Error::Invalid)?
        .claims;
    let issued = claims["iat"].as_i64().ok_or(Error::Invalid)?;
    let authorized = |party: &Value| {
        party == client_id
            || authorized_parties
                .iter()
                .any(|(of, id)| *of == provider && party == id.as_str())
    };
    // One audience, this client: a token also made for someone else is refused,
    // and so is one asked for by a party the product has not named.
    if claims["nonce"] != nonce
        || claims["aud"] != client_id
        || claims.get("azp").is_some_and(|party| !authorized(party))
        || issued > now.saturating_add(ISSUED_AHEAD_SECONDS)
        || now.saturating_sub(issued) > PROOF_MAX_AGE_SECONDS
    {
        return Err(Error::Invalid);
    }
    let identity = ProviderIdentity::from_verified_claims(provider, &claims)?;
    let email = claims["email"].as_str().ok_or(Error::Invalid)?.to_owned();
    Ok(VerifiedProof { identity, email })
}

#[cfg(test)]
mod tests;
