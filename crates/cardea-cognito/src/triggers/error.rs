//! Why a trigger failed. Cognito quotes this text to the person.

use cardea_core::Error;

use super::ProductError;
use crate::TransactError;

/// A refused or failed trigger.
#[derive(Debug, thiserror::Error)]
pub enum TriggerError {
    /// An identity rule refused it.
    #[error(transparent)]
    Identity(#[from] Error),
    /// A provider sign-in that must first be linked from a signed-in session.
    #[error("sign in with your existing method and link {0} from your profile")]
    LinkRequired(&'static str),
    /// The event lacks a field every such event carries.
    #[error("provision event carried no {0}")]
    MissingField(&'static str),
    /// A trigger this handler does not serve.
    #[error("unsupported Cognito trigger")]
    Unsupported,
    /// A custom authentication step this library does not offer.
    #[error("this sign-in step is not offered")]
    UnexpectedChallenge,
    /// A product hook failed.
    #[error(transparent)]
    Product(#[from] ProductError),
    /// The guard could not be committed.
    #[error("identity ownership could not be recorded; retry the same request")]
    Guard(#[from] TransactError),
    /// The handler ran out of the time Cognito allows.
    #[error("identity service timed out; retry the same request")]
    TimedOut,
}
