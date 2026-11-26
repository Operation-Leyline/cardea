//! Why an identity step was refused. The messages are generic on purpose: a
//! product may show them to the person signing in, so none of them says
//! anything about another account.

/// A refused or failed identity step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The proof, address or request is malformed or does not check out.
    #[error("identity proof is invalid")]
    Invalid,
    /// The provider's say-so is not enough: the person must sign in to the
    /// account first and link the provider from there.
    #[error("sign in with your existing method and link this provider from your profile")]
    LinkRequired,
    /// The link needs a sign-in no older than
    /// [`RECENT_SIGN_IN_SECONDS`](crate::RECENT_SIGN_IN_SECONDS). A product
    /// reports it as `recentSignInRequired`, and the person signs in again.
    #[error("sign in again, then link this provider")]
    RecentSignInRequired,
    /// The address to verify is not the account's own mailbox.
    #[error("changing your email address is not supported")]
    EmailChange,
    /// Ownership records disagree. Nothing was created.
    #[error("identity ownership requires recovery; no new account was created")]
    Conflict,
    /// A link challenge was already presented with another proof.
    #[error("client token was already used for a different identity proof")]
    ClientTokenMismatch,
    /// The directory, or an account being set up, is not ready yet.
    #[error("identity setup is in progress; try again later")]
    NotReady,
    /// A dependency failed; the same request may be repeated.
    #[error("identity service is unavailable; retry the same request")]
    Unavailable,
    /// The address is on the disposable-domain list. Cognito quotes a
    /// trigger's error text to the person verbatim.
    #[error("this email domain is not accepted; sign up with a permanent address")]
    DisposableDomain,
}
