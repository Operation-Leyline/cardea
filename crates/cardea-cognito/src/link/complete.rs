//! `CompleteIdentityLink`.

use cardea_core::{Directory, Error, Session, User, resolve};
use tabulary::{FailureKind, Update, WriteError};

use super::{ProviderClients, challenge_provider, digest, link_key};
use crate::{
    OperationError,
    directory::{AwsDirectory, now},
    proof::{ProofRequest, ProofVerifier},
    record::{LinkRow, LinkRowAttrs},
};

/// The longest ID token accepted.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Link the identity `id_token` proves to the signed-in caller, and return the
/// caller. Safe to repeat with the same input after a timeout.
///
/// Refusals say nothing about other accounts:
///
/// * [`Error::Invalid`]: no such challenge of this caller's, its nonce has
///   expired, or the proof does not check out;
/// * [`Error::ClientTokenMismatch`]: the challenge was given another proof;
/// * [`Error::RecentSignInRequired`]: a relay address and a sign-in that is
///   not recent;
/// * [`Error::Conflict`]: this identity cannot join this account.
///
/// Build `session` only from a verified session token.
pub async fn complete_identity_link(
    directory: &AwsDirectory,
    verifier: &(impl ProofVerifier + ?Sized),
    clients: &ProviderClients,
    session: Session<'_>,
    link_id: &str,
    id_token: &str,
) -> Result<User, OperationError> {
    directory.ready().await?;
    if link_id.len() != 64
        || !link_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid.into());
    }
    if id_token.is_empty() || id_token.len() > MAX_TOKEN_BYTES {
        return Err(Error::Invalid.into());
    }
    let user = session.user;
    let proof_digest = digest(id_token);
    let row: LinkRow = directory
        .row(link_key(&user.user_id, link_id)?)
        .await
        // A challenge nobody can read proves nothing.
        .map_err(|error| match error {
            Error::Conflict => Error::Invalid,
            error => error,
        })?
        .ok_or(Error::Invalid)?;
    let provider = challenge_provider(row.provider.as_deref())?;
    if let Some(previous) = &row.token_hash {
        if *previous != proof_digest {
            return Err(Error::ClientTokenMismatch.into());
        }
        if row.status.as_deref() == Some("complete") {
            return Ok(user.clone());
        }
        // The Cognito link may have committed while the receipt failed.
        // Reconcile that finished effect even after the nonce expires; never
        // perform a new link using expired proof.
        if let Some(subject) = &row.provider_subject
            && directory.provider(provider, subject).await?.as_ref() == Some(user)
            && directory.is_linked(provider, subject, user).await?
        {
            mark_complete(directory, user, link_id, &proof_digest).await?;
            return Ok(user.clone());
        }
    }
    let time = now();
    if u64::try_from(time).unwrap_or(0) >= row.deadline {
        return Err(Error::Invalid.into());
    }
    let client_id = clients
        .client_id(provider)
        .ok_or(OperationError::ProviderNotConfigured)?;
    let proof = verifier
        .verify(ProofRequest {
            provider,
            token: id_token,
            client_id,
            nonce: &row.nonce,
            now: time,
        })
        .await?;
    if proof.identity.provider != provider {
        return Err(Error::Invalid.into());
    }
    bind_proof(
        directory,
        user,
        link_id,
        &proof_digest,
        &proof.identity.subject,
    )
    .await?;
    let recorder = directory.recording(Some(&proof.email));
    let linked = resolve(&recorder, &proof.identity, Some(session)).await?;
    mark_complete(directory, user, link_id, &proof_digest).await?;
    Ok(linked)
}

/// Bind the challenge to the first proof presented: another token is refused.
async fn bind_proof(
    directory: &AwsDirectory,
    user: &User,
    link_id: &str,
    proof_digest: &str,
    subject: &str,
) -> Result<(), Error> {
    let hash = LinkRowAttrs::TOKEN_HASH;
    let request = directory
        .rows()?
        .update(link_key(&user.user_id, link_id)?)
        .changes(
            Update::new()
                .and(hash.set(proof_digest.to_owned()))
                .and(LinkRowAttrs::PROVIDER_SUBJECT.set(subject.to_owned())),
        )
        .condition(hash.not_exists().or(hash.eq(proof_digest.to_owned())))
        .build()
        .map_err(|_| Error::Invalid)?;
    match request.decode(
        request
            .apply(directory.dynamodb().update_item())
            .send()
            .await,
    ) {
        Ok(_) => Ok(()),
        Err(WriteError::Refused { failure, .. })
            if failure.kind == FailureKind::ConditionFailed =>
        {
            Err(Error::ClientTokenMismatch)
        }
        Err(_) => Err(Error::Unavailable),
    }
}

async fn mark_complete(
    directory: &AwsDirectory,
    user: &User,
    link_id: &str,
    proof_digest: &str,
) -> Result<(), Error> {
    let request = directory
        .rows()?
        .member::<LinkRow>()
        .update(link_key(&user.user_id, link_id)?)
        .changes(Update::new().and(LinkRowAttrs::STATUS.set("complete".to_owned())))
        .condition(LinkRowAttrs::TOKEN_HASH.eq(proof_digest.to_owned()))
        .build()
        .map_err(|_| Error::Invalid)?;
    request
        .decode(
            request
                .apply(directory.dynamodb().update_item())
                .send()
                .await,
        )
        .map_err(|_| Error::Unavailable)?;
    Ok(())
}
