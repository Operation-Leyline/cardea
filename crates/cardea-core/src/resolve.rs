//! Which account a provider sign-in is. External side effects always follow
//! durable ownership; retries reconcile instead of creating anew.

use crate::{
    Directory, EmailOwner, Error, Provider, ProviderIdentity, User, disposable, person_key,
};

/// The account `identity` signs in as, linking it there. `authenticated_user`
/// is the signed-in caller of a link request, or `None` for a sign-in.
///
/// * A subject already bound stays with its user, whatever its email says now.
/// * Without a session, only a provider that owns the mailbox may link, and a
///   mailbox nobody holds gets a new account.
/// * With a session, the identity's mailbox must be the caller's, and the
///   account must already exist.
pub async fn resolve(
    directory: &(impl Directory + ?Sized),
    identity: &ProviderIdentity,
    authenticated_user: Option<&User>,
) -> Result<User, Error> {
    let ProviderIdentity {
        provider,
        subject,
        email,
        authoritative,
    } = identity;
    directory.ready().await?;
    // A changed provider email can never move an established identity.
    if let Some(user) = directory.provider(*provider, subject).await? {
        if authenticated_user.is_some_and(|caller| caller.user_id != user.user_id) {
            return Err(Error::Conflict);
        }
        directory.link(*provider, subject, &user).await?;
        return Ok(user);
    }
    if let Some(caller) = authenticated_user {
        if person_key(&caller.email)? != person_key(email)? {
            return Err(Error::Conflict);
        }
    } else if !authoritative {
        return Err(Error::LinkRequired);
    }
    let owner = match directory.email(email).await? {
        Some(owner) => owner,
        None if authenticated_user.is_some() => return Err(Error::Conflict),
        None => {
            // Only a new claim is refused: someone who already holds an
            // account keeps signing in, whatever the list says today.
            if disposable::is_disposable(email) {
                return Err(Error::DisposableDomain);
            }
            // Cognito refuses the social account while an unconfirmed user holds
            // this exact address, and a claim that never lapses would then keep
            // every other alias out too. Take nothing.
            if directory.awaits_confirmation(email).await? {
                return Err(Error::LinkRequired);
            }
            directory
                .claim_email(&EmailOwner {
                    email: email.clone(),
                    username: email.clone(),
                    origin: provider.rule().cognito_name.into(),
                })
                .await?
        }
    };
    // A provider-made mailbox may still be waiting for its account, whichever
    // provider claimed it.
    let user = if Provider::from_cognito_name(&owner.origin).is_some() {
        directory.create_social_user(&owner).await?
    } else {
        directory.native_user(&owner).await?
    };
    if person_key(&user.email)? != person_key(email)?
        || authenticated_user.is_some_and(|caller| caller.user_id != user.user_id)
    {
        return Err(Error::Conflict);
    }
    directory.claim_provider(*provider, subject, &user).await?;
    directory.link(*provider, subject, &user).await?;
    Ok(user)
}

#[cfg(test)]
mod tests;
