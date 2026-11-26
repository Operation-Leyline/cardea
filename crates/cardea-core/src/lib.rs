//! The identity rules every product shares, with no AWS in them.
//!
//! One person is one account, whichever way they sign in. A person is a
//! mailbox ([`person_key`]); a [`Provider`] sign-in arrives as a
//! [`ProviderIdentity`] and [`resolve`] decides, against a [`Directory`],
//! which account it is.

mod directory;
pub mod disposable;
mod email;
mod error;
mod identity;
mod provider;
mod resolve;

pub use directory::{
    Directory, EmailOwner, NATIVE_ORIGIN, UNCONFIRMED_CLAIM_LIFETIME_SECONDS, User,
};
pub use email::{normalize_email, person_key, same_inbox, same_mailbox};
pub use error::Error;
pub use identity::ProviderIdentity;
pub use provider::{Provider, ProviderRule};
pub use resolve::{RECENT_SIGN_IN_SECONDS, Session, resolve};
