//! The proof half of a native sign-in: a provider ID token in, a ticket out.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cardea_core::{Directory, Error, Provider, resolve};
use serde_json::Value;

use super::{
    NativeSignIn, load_key,
    nonce::spend_nonce,
    ticket::{Binding, mint},
    well_formed,
};
use crate::{
    OperationError,
    directory::{AwsDirectory, now},
    proof::{ProofRequest, ProofVerifier},
};

/// The longest ID token accepted.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// What the app takes to Cognito.
#[derive(Clone, PartialEq, Eq)]
pub struct SignInTicket {
    /// The account's username: `USERNAME` in the custom flow.
    pub username: String,
    /// The answer to the custom challenge, good once.
    pub ticket: String,
    /// Epoch seconds after which the ticket is refused.
    pub expires_at: u64,
}

/// Leaves the ticket and the username, which may be an address, out.
impl std::fmt::Debug for SignInTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignInTicket")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// The nonce `token` says it carries, only to look it up: the verifier then
/// requires the signed token to carry exactly this one.
fn claimed_nonce(token: &str) -> Option<String> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    let nonce = claims["nonce"].as_str()?;
    well_formed(nonce).then(|| nonce.to_owned())
}

/// Sign in the person `id_token` proves, on the app client `app_client`.
///
/// The token is checked as a link proof is (signature, issuer, audience,
/// authorized party, expiry, freshness and a verified email), and its nonce
/// must be one [`create_sign_in_nonce`](super::create_sign_in_nonce) issued and
/// nobody has used. The person is then resolved by the rules of a redirect
/// sign-in ([`resolve`] with no session), which makes their account if the
/// mailbox has none, and the ticket is bound to that account, `app_client` and
/// the provider identity.
///
/// A token is good for one call, whatever the call answers once the nonce is
/// spent: to try again, start with a new nonce.
///
/// Refusals are the redirect sign-in's, and say no more than it does:
///
/// * [`Error::Invalid`]: the token, its nonce or the app client does not check
///   out;
/// * [`Error::LinkRequired`] (`identityLinkRequired`): the person must sign in
///   to their account first and link the provider there;
/// * [`Error::DisposableDomain`], [`Error::Conflict`], [`Error::NotReady`] and
///   [`Error::Unavailable`] as in [`resolve`].
pub async fn begin_provider_sign_in(
    directory: &AwsDirectory,
    verifier: &(impl ProofVerifier + ?Sized),
    native: &NativeSignIn,
    provider: Provider,
    id_token: &str,
    app_client: &str,
) -> Result<SignInTicket, OperationError> {
    let client_id = native.client_id(provider)?;
    if !native.allows(app_client) || id_token.len() > MAX_TOKEN_BYTES {
        return Err(Error::Invalid.into());
    }
    let nonce = claimed_nonce(id_token).ok_or(Error::Invalid)?;
    directory.ready().await?;
    let time = now();
    let proof = verifier
        .verify(ProofRequest {
            provider,
            token: id_token,
            client_id,
            nonce: &nonce,
            now: time,
        })
        .await?;
    if proof.identity.provider != provider {
        return Err(Error::Invalid.into());
    }
    let key = load_key(&native.keys).await?;
    // Spent only for a token that checks out, and before anything is made.
    spend_nonce(directory, &key, &nonce, u64::try_from(time).unwrap_or(0)).await?;
    let recorder = directory.recording(Some(&proof.email));
    let user = resolve(&recorder, &proof.identity, None).await?;
    let binding = Binding {
        username: &user.username,
        user_id: &user.user_id,
        client_id: app_client,
    };
    let (ticket, expires_at) = mint(
        directory,
        &key,
        binding,
        provider,
        &proof.identity.subject,
        u64::try_from(now()).unwrap_or(0),
    )
    .await?;
    Ok(SignInTicket {
        username: user.username,
        ticket,
        expires_at,
    })
}
