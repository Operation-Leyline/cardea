//! Why a signed-in person's operation was refused.

/// A refused or failed linking or sign-in method operation. A product maps
/// each variant to its own API error. The messages are generic on purpose:
/// none of them says anything about another account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
    /// An identity rule refused it, or a dependency failed. Report
    /// [`RecentSignInRequired`](cardea_core::Error::RecentSignInRequired) as
    /// `recentSignInRequired`: the web package asks the person to sign in
    /// again on that name.
    #[error(transparent)]
    Identity(#[from] cardea_core::Error),
    /// The product configured no client id for this provider.
    #[error("this sign-in provider is not available")]
    ProviderNotConfigured,
    /// The unlink would leave the account no way to sign in.
    #[error("add another sign-in method before removing this one")]
    LastSignInMethod,
}
