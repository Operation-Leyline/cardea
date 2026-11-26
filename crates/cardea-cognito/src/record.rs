//! The directory table's four row kinds as strict records.
//!
//! The partition key, `identityKey`, tells them apart: the readiness marker,
//! the row that owns a mailbox, the row that owns a provider subject, and a
//! link challenge. The records are the wire format of Leyline's live table:
//! attribute names, types and key shapes are frozen by tests, and a row that
//! carries anything else fails to decode. The table's TTL attribute is
//! `expiresAt`.

use std::marker::PhantomData;

use aws_sdk_dynamodb::types::AttributeValue;
use cardea_core::{EmailOwner, Provider, User};
use serde::{Serialize, de::DeserializeOwned};
use tabulary::{
    Converter, DecodeContext, DecodeError, DecodeFault, EncodeContext, EncodeError, EncodeFault,
    MultiObject, Native, Record,
};

/// Every row the table may hold. The derive proves at compile time that the
/// four key patterns are disjoint.
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

#[cfg(test)]
mod tests;
