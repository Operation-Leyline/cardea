//! The directory table's row kinds as strict records.
//!
//! The partition key, `identityKey`, tells them apart: the readiness marker,
//! the row that owns a mailbox, the row that owns a provider subject, a link
//! challenge, the list of a user's linked identities, and the nonce and ticket
//! of a [native sign-in](crate::native). The first four are the wire format of
//! tables that earlier deployments wrote (a link challenge's `provider`, the
//! whole list and the two native sign-in rows are additions): attribute names,
//! types and key shapes are frozen by tests, and a row that carries anything
//! else fails to decode. The table's TTL attribute is `expiresAt`.

use std::marker::PhantomData;

use aws_sdk_dynamodb::types::AttributeValue;
use cardea_core::{EmailOwner, Provider, User};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tabulary::{
    Converter, DecodeContext, DecodeError, DecodeFault, EncodeContext, EncodeError, EncodeFault,
    MultiObject, Native, Record,
};

/// Every row the table may hold. The derive proves at compile time that the
/// key patterns are disjoint.
#[derive(Debug, MultiObject)]
#[tabulary(partition = "identityKey")]
pub enum IdentityTable {
    /// `SYSTEM#READY`.
    #[tabulary(partition(exact = "SYSTEM#READY"))]
    Ready(ReadyRow),
    /// `EMAIL#{personKey}`.
    #[tabulary(partition(prefix = "EMAIL#"))]
    Email(EmailRow),
    /// `PROVIDER#{provider}#{subject}`.
    #[tabulary(partition(prefix = "PROVIDER#"))]
    Provider(ProviderRow),
    /// `LINK#{userId}#{linkId}`.
    #[tabulary(partition(prefix = "LINK#"))]
    Link(LinkRow),
    /// `METHODS#{userId}`.
    #[tabulary(partition(prefix = "METHODS#"))]
    Methods(MethodsRow),
    /// `NONCE#{tag}`.
    #[tabulary(partition(prefix = "NONCE#"))]
    Nonce(NonceRow),
    /// `TICKET#{tag}`.
    #[tabulary(partition(prefix = "TICKET#"))]
    Ticket(TicketRow),
}

/// The directory's readiness marker. Signup is refused until it reads
/// version 1.
#[derive(Debug, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(name = "identityKey", template = "SYSTEM#READY")
)]
pub struct ReadyRow {
    /// The directory version.
    pub version: i64,
}

/// The row that owns a mailbox. Keyed by the person
/// ([`cardea_core::person_key`]), so every alias of one mailbox reaches the
/// same row; the owner is the JSON `record`.
#[derive(Debug, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(name = "identityKey", template = "EMAIL#{person:text}")
)]
pub struct EmailRow {
    /// The mailbox's person key.
    #[tabulary(key_only)]
    pub person: String,
    /// The mailbox's owner.
    #[tabulary(with = owner_json)]
    pub record: EmailOwner,
    /// The product's user the mailbox belongs to, once provisioned.
    pub user_id: Option<String>,
    /// Epoch seconds after which a native signup that never confirmed no
    /// longer holds the mailbox; absent on every claim that does not lapse.
    /// Not the table's TTL: a lapsed row stays until another claim replaces
    /// it, so its signup can still confirm.
    pub unconfirmed_expires_at: Option<i64>,
    /// The one attempt elected to set a provider-made user's first password.
    pub password_initialization: Option<String>,
    /// Whether password is a sign-in method, once something has settled it.
    /// Read it through [`EmailRow::has_password`], which applies the default.
    pub password_set: Option<bool>,
}

impl EmailRow {
    /// Whether password is a sign-in method of this account
    /// ([`EmailOwner::password_set`]).
    pub fn has_password(&self) -> bool {
        self.record.password_set(self.password_set)
    }
}

/// The row that owns a provider subject: the user it signs in as.
#[derive(Debug, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(
        name = "identityKey",
        template = "PROVIDER#{provider:text}#{subject:text}"
    )
)]
pub struct ProviderRow {
    /// The provider's Cognito name ([`ProviderRow::provider_name`]).
    #[tabulary(key_only)]
    pub provider: String,
    /// The provider's id for the person.
    #[tabulary(key_only)]
    pub subject: String,
    /// The user the subject signs in as.
    #[tabulary(with = user_json)]
    pub record: User,
}

impl ProviderRow {
    /// How `provider` is spelled in the key.
    pub fn provider_name(provider: Provider) -> String {
        provider.rule().cognito_name.to_owned()
    }
}

/// One identity-link challenge: the nonce a provider proof must carry, and,
/// once a proof was presented, which token and subject it was.
#[derive(Debug, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(name = "identityKey", template = "LINK#{user_id:text}#{link_id:text}")
)]
pub struct LinkRow {
    /// The user the challenge is bound to.
    #[tabulary(key_only)]
    pub user_id: String,
    /// SHA-256 of the client token, in hex.
    #[tabulary(key_only)]
    pub link_id: String,
    /// What the proof must carry.
    pub nonce: String,
    /// Epoch seconds after which the nonce proves nothing.
    pub deadline: u64,
    /// The table's TTL attribute, in epoch seconds.
    pub expires_at: u64,
    /// SHA-256 of the proof token presented first.
    pub token_hash: Option<String>,
    /// The subject that proof named.
    pub provider_subject: Option<String>,
    /// `complete` once the link and its receipt both finished.
    pub status: Option<String>,
    /// The Cognito name of the provider the challenge is for. A row without it
    /// was written before there was a choice, and is Google's.
    pub provider: Option<String>,
}

/// The identities linked onto one user, with the address each provider gave.
///
/// The user pool says which identities are linked; this row remembers what the
/// pool does not (the provider's address, and removals still under way), and
/// its `version` orders changes, so that two removals cannot both count on the
/// method the other is taking away. Every write is conditional on the version
/// it read. A user without the row has not been listed, linked or unlinked
/// since the row existed. Code older than the row never reads its key.
#[derive(Clone, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(name = "identityKey", template = "METHODS#{user_id:text}")
)]
pub struct MethodsRow {
    /// The user the identities are linked onto.
    #[tabulary(key_only)]
    pub user_id: String,
    /// One more than the version this write replaced; the first is 1.
    pub version: i64,
    /// The identities, as one JSON list.
    #[tabulary(with = identities_json)]
    pub identities: Vec<LinkedIdentity>,
    /// Addresses an erasure learned from the pool that its caller did not
    /// name, as one JSON list: kept so that a repeat, after the user is gone,
    /// still finds their mailbox rows. Absent unless there is one.
    #[tabulary(with = mailboxes_json)]
    pub erasing_mailboxes: Option<Vec<String>>,
}

/// Leaves the addresses out, so that printing a row cannot log them.
impl std::fmt::Debug for MethodsRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodsRow")
            .field("user_id", &self.user_id)
            .field("version", &self.version)
            .field("identities", &self.identities)
            .finish_non_exhaustive()
    }
}

/// One identity of a [`MethodsRow`]. Stored as JSON: field names and order are
/// part of the directory's wire format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedIdentity {
    /// The provider's Cognito name ([`ProviderRow::provider_name`]).
    pub provider: String,
    /// The provider's id for the person.
    pub subject: String,
    /// The address as the provider wrote it, once a link or sign-in showed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// An unlink has taken the identity away as a sign-in method and has yet
    /// to finish. It is not linked again until that is done.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removing: bool,
}

/// Leaves the address out, so that printing a row cannot log it.
impl std::fmt::Debug for LinkedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkedIdentity")
            .field("provider", &self.provider)
            .field("removing", &self.removing)
            .finish_non_exhaustive()
    }
}

/// A nonce issued for a native sign-in and not yet used. Deleting the row is
/// how the nonce is spent.
#[derive(Debug, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(name = "identityKey", template = "NONCE#{tag:text}")
)]
pub struct NonceRow {
    /// The nonce's HMAC under the product's sign-in ticket key. The nonce
    /// itself is not stored.
    #[tabulary(key_only)]
    pub tag: String,
    /// Epoch seconds after which the nonce is refused.
    pub deadline: u64,
    /// The table's TTL attribute, in epoch seconds.
    pub expires_at: u64,
}

/// A native sign-in's single-use ticket, not yet redeemed. Deleting the row is
/// how the ticket is spent.
#[derive(Clone, PartialEq, Record)]
#[tabulary(
    rename_all = "camelCase",
    partition(name = "identityKey", template = "TICKET#{tag:text}")
)]
pub struct TicketRow {
    /// HMAC, under the product's sign-in ticket key, of the ticket together
    /// with the pool, username, user and app client it is for. The ticket
    /// itself is not stored.
    #[tabulary(key_only)]
    pub tag: String,
    /// The user the ticket signs in.
    pub user_id: String,
    /// The app client the ticket signs in on.
    pub client_id: String,
    /// The Cognito name of the provider that proved the person.
    pub provider: String,
    /// The provider's id for the person.
    pub subject: String,
    /// Epoch seconds after which the ticket is refused.
    pub deadline: u64,
    /// The table's TTL attribute, in epoch seconds.
    pub expires_at: u64,
}

/// Leaves the provider subject out, so that printing a row cannot log it.
impl std::fmt::Debug for TicketRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketRow")
            .field("user_id", &self.user_id)
            .field("client_id", &self.client_id)
            .field("provider", &self.provider)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

/// A value stored as its compact JSON text (`serde_json::to_string`). Text
/// that does not parse is a decode fault, never a default.
pub struct JsonText<T>(PhantomData<fn() -> T>);

impl<T: Serialize + DeserializeOwned> Converter<T> for JsonText<T> {
    type Wire = tabulary::wire::String;

    fn encode(value: &T, cx: &mut EncodeContext) -> Result<AttributeValue, EncodeError> {
        let text = serde_json::to_string(value).map_err(|_| {
            cx.error(EncodeFault::Custom {
                code: "unencodable_json_record",
            })
        })?;
        <Native<String> as Converter<String>>::encode(&text, cx)
    }

    fn decode(value: &AttributeValue, cx: &mut DecodeContext) -> Result<T, DecodeError> {
        let text = <Native<String> as Converter<String>>::decode(value, cx)?;
        serde_json::from_str(&text).map_err(|_| {
            cx.error(DecodeFault::Custom {
                code: "invalid_json_record",
            })
        })
    }
}

mod owner_json {
    pub type Codec = super::JsonText<cardea_core::EmailOwner>;
}

mod user_json {
    pub type Codec = super::JsonText<cardea_core::User>;
}

mod identities_json {
    pub type Codec = super::JsonText<Vec<super::LinkedIdentity>>;
}

mod mailboxes_json {
    pub type Codec = super::JsonText<Vec<String>>;
}

#[cfg(test)]
mod tests;
