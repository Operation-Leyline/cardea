//! Providers that sign real ID tokens with a test key and publish its public
//! half, so proofs are checked by the real verifier without a network.

use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use aws_lc_rs::{
    rand::SystemRandom,
    rsa::KeySize,
    signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cardea_core::{Error, Provider};
use serde_json::{Value, json};
use tokio::sync::Barrier;

use crate::{
    directory::now,
    proof::{JwtVerifier, KeyFetchError, KeyFetcher, ProofRequest, ProofVerifier, VerifiedProof},
};

/// The `kid` of the published key.
const KID: &str = "test";

/// The client id each test product configured.
pub(crate) fn client_id(provider: Provider) -> &'static str {
    match provider {
        Provider::Google => "google-client",
        Provider::Apple => "com.example.services",
    }
}

/// One key per test process: generating it is the slow part of a test, no test
/// depends on its value, and nothing needs a key committed to the tree.
pub(crate) fn signing_key() -> &'static RsaKeyPair {
    static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
    KEY.get_or_init(|| RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
}

/// `claims` as a token signed by `key`.
pub(crate) fn sign(key: &RsaKeyPair, claims: &Value) -> String {
    let header = json!({"alg": "RS256", "kid": KID});
    let text = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        text.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{text}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// The claims `provider` would sign now for `subject` at `email`.
pub(crate) fn claims(provider: Provider, nonce: &str, subject: &str, email: &str) -> Value {
    let time = now();
    json!({
        "iss": provider.rule().issuers[0],
        "aud": client_id(provider),
        "sub": subject,
        "iat": time,
        "exp": time + 3600,
        "nonce": nonce,
        "email": email,
        "email_verified": true,
    })
}

/// A token `provider` would sign now.
pub(crate) fn token(provider: Provider, nonce: &str, subject: &str, email: &str) -> String {
    sign(signing_key(), &claims(provider, nonce, subject, email))
}

/// Publishes the test key at every key URL.
struct Published;

#[async_trait]
impl KeyFetcher for Published {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, KeyFetchError> {
        let public = signing_key().public_key();
        let part = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
        Ok(json!({"keys": [{
            "kid": KID,
            "kty": "RSA",
            "n": part(public.modulus().big_endian_without_leading_zero()),
            "e": part(public.exponent().big_endian_without_leading_zero()),
        }]})
        .to_string()
        .into_bytes())
    }
}

/// The real verifier over the published test key.
pub(crate) fn verifier() -> JwtVerifier {
    JwtVerifier::with_fetcher(Arc::new(Published))
}

/// A stand-in verifier for the linking flow: it counts the checks and can hold
/// them until several are under way. The token checks are the real ones, over
/// the test key.
pub(crate) struct Proofs {
    inner: JwtVerifier,
    pub checks: AtomicUsize,
    barrier: Option<Barrier>,
}

impl Default for Proofs {
    fn default() -> Self {
        Self {
            inner: verifier(),
            checks: AtomicUsize::new(0),
            barrier: None,
        }
    }
}

impl Proofs {
    /// A verifier whose checks wait for each other, `count` at a time.
    pub fn waiting(count: usize) -> Self {
        Self {
            barrier: Some(Barrier::new(count)),
            ..Self::default()
        }
    }
}

#[async_trait]
impl ProofVerifier for Proofs {
    async fn verify(&self, request: ProofRequest<'_>) -> Result<VerifiedProof, Error> {
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        self.checks.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(request).await
    }
}
