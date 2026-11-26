//! Which account a provider sign-in is. External side effects always follow
//! durable ownership; retries reconcile instead of creating anew.

use crate::{
    Directory, EmailOwner, Error, Provider, ProviderIdentity, User, disposable, person_key,
};

/// How old a sign-in may be to link a private relay address.
pub const RECENT_SIGN_IN_SECONDS: i64 = 10 * 60;

/// How far a sign-in may appear to be in the future: the issuer's clock and
/// the caller's differ a little.
const CLOCK_SKEW_SECONDS: i64 = 60;

/// The signed-in caller of a link request. Build it only from a verified
/// session token.
#[derive(Clone, Copy, Debug)]
pub struct Session<'a> {
    /// Who is signed in.
    pub user: &'a User,
    /// The token's `auth_time`: when the person last signed in, in epoch
    /// seconds. A token refresh does not move it.
    pub auth_time: i64,
    /// The current time, in epoch seconds.
    pub now: i64,
}

impl Session<'_> {
    /// Whether the person signed in within [`RECENT_SIGN_IN_SECONDS`].
    fn is_recent(&self) -> bool {
        let age = self.now.saturating_sub(self.auth_time);
        (-CLOCK_SKEW_SECONDS..=RECENT_SIGN_IN_SECONDS).contains(&age)
    }
}

/// The account `identity` signs in as, linking it there. `session` is the
/// signed-in caller of a link request, or `None` for a sign-in.
///
/// * A subject already bound stays with its user, whatever its email says now.
/// * Without a session, only a provider that owns the mailbox may link, never
///   through a private relay, and a mailbox nobody holds gets a new account.
/// * With a session, the account must already exist, and the identity's
///   mailbox must be the caller's. A private relay address is the exception:
///   it links to the caller if the sign-in is recent, so that a long-lived
///   session cannot add a lasting way back in
///   ([`Error::RecentSignInRequired`] otherwise).
pub async fn resolve(
    directory: &(impl Directory + ?Sized),
    identity: &ProviderIdentity,
    session: Option<Session<'_>>,
) -> Result<User, Error> {
    let ProviderIdentity {
        provider,
        subject,
        email,
        authoritative,
        private_relay,
    } = identity;
    directory.ready().await?;
    // A changed provider email can never move an established identity.
    if let Some(user) = directory.provider(*provider, subject).await? {
        if session.is_some_and(|session| session.user.user_id != user.user_id) {
            return Err(Error::Conflict);
        }
        directory.link(*provider, subject, &user).await?;
        return Ok(user);
    }
    // The mailbox whose account this identity joins.
    let mailbox = match &session {
        Some(session) if person_key(&session.user.email)? == person_key(email)? => email,
        Some(session) if *private_relay => {
            if !session.is_recent() {
                return Err(Error::RecentSignInRequired);
            }
            &session.user.email
        }
        Some(_) => return Err(Error::Conflict),
        None if *authoritative && !private_relay => email,
        None => return Err(Error::LinkRequired),
    };
    let owner = match directory.email(mailbox).await? {
        Some(owner) => owner,
        None if session.is_some() => return Err(Error::Conflict),
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
    if person_key(&user.email)? != person_key(mailbox)?
        || session.is_some_and(|session| session.user.user_id != user.user_id)
    {
        return Err(Error::Conflict);
    }
    directory.claim_provider(*provider, subject, &user).await?;
    directory.link(*provider, subject, &user).await?;
    Ok(user)
}

#[cfg(test)]
mod tests;
