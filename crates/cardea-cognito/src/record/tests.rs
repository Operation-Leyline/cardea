//! Wire freeze: the directory rows read and write exactly as Leyline's live
//! table holds them. The expected items are literals.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{EmailOwner, Provider, User};
use tabulary::RecordKey;

use super::*;
use crate::directory::{email_key, provider_key};
use crate::testing::ddb::Item;

fn item(pairs: &[(&str, Av)]) -> Item {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

fn s(value: &str) -> Av {
    Av::S(value.to_owned())
}

fn n(value: &str) -> Av {
    Av::N(value.to_owned())
}

const OWNER_JSON: &str = r#"{"email":"alice@example.com","username":"alice","origin":"Cognito"}"#;
const USER_JSON: &str = r#"{"user_id":"u1","username":"alice","email":"alice@example.com"}"#;
const LINK_ID: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn owner() -> EmailOwner {
    EmailOwner {
        email: "alice@example.com".into(),
        username: "alice".into(),
        origin: "Cognito".into(),
    }
}

fn user() -> User {
    User {
        user_id: "u1".into(),
        username: "alice".into(),
        email: "alice@example.com".into(),
    }
}

/// A mailbox row once provisioning set its user, as Leyline's table holds it.
fn email_item() -> Item {
    item(&[
        ("identityKey", s("EMAIL#alice@example.com")),
        ("record", s(OWNER_JSON)),
        ("userId", s("u1")),
    ])
}

fn email_row() -> EmailRow {
    EmailRow {
        person: "alice@example.com".into(),
        record: owner(),
        user_id: Some("u1".into()),
        password_initialization: None,
        unconfirmed_expires_at: None,
        password_set: None,
    }
}

#[test]
fn the_readiness_marker_is_its_literal_key_and_version() {
    let marker = item(&[("identityKey", s("SYSTEM#READY")), ("version", n("1"))]);
    assert_eq!(
        ReadyRow::from_item(&marker).unwrap(),
        ReadyRow { version: 1 }
    );
    assert_eq!(ReadyRow { version: 1 }.to_item().unwrap(), marker);
    assert_eq!(
        ReadyRowKey::new().unwrap().encode_key().unwrap(),
        item(&[("identityKey", s("SYSTEM#READY"))])
    );
}

#[test]
fn a_mailbox_row_is_its_person_key_and_the_owners_compact_json() {
    assert_eq!(EmailRow::from_item(&email_item()).unwrap(), email_row());
    assert_eq!(email_row().to_item().unwrap(), email_item());
    // An alias of the mailbox keys the same row.
    assert_eq!(
        email_key("Alice+news@Example.com")
            .unwrap()
            .encode_key()
            .unwrap(),
        item(&[("identityKey", s("EMAIL#alice@example.com"))])
    );
}

#[test]
fn every_optional_mailbox_attribute_keeps_its_name_and_type() {
    let row = EmailRow {
        unconfirmed_expires_at: Some(1_800_000_000),
        password_initialization: Some("attempt".into()),
        password_set: Some(true),
        ..email_row()
    };
    let mut stored = email_item();
    stored.insert("unconfirmedExpiresAt".into(), n("1800000000"));
    stored.insert("passwordInitialization".into(), s("attempt"));
    stored.insert("passwordSet".into(), Av::Bool(true));
    assert_eq!(row.to_item().unwrap(), stored);
    assert_eq!(EmailRow::from_item(&stored).unwrap(), row);
}

/// Rows written before `passwordSet` existed are read by their origin.
#[test]
fn a_row_without_password_set_is_read_by_its_origin() {
    assert!(EmailRow::from_item(&email_item()).unwrap().has_password());
    for provider in Provider::ALL {
        let mut stored = email_item();
        let name = provider.rule().cognito_name;
        stored.insert(
            "record".into(),
            s(&OWNER_JSON.replace(r#""Cognito""#, &format!(r#""{name}""#))),
        );
        assert!(!EmailRow::from_item(&stored).unwrap().has_password());
        stored.insert("passwordSet".into(), Av::Bool(true));
        assert!(EmailRow::from_item(&stored).unwrap().has_password());
    }
}

#[test]
fn a_provider_row_is_its_subject_and_the_users_compact_json() {
    for (provider, key) in [
        (Provider::Google, "PROVIDER#Google#google-1"),
        (Provider::Apple, "PROVIDER#SignInWithApple#google-1"),
    ] {
        let stored = item(&[("identityKey", s(key)), ("record", s(USER_JSON))]);
        let row = ProviderRow {
            provider: ProviderRow::provider_name(provider),
            subject: "google-1".into(),
            record: user(),
        };
        assert_eq!(ProviderRow::from_item(&stored).unwrap(), row);
        assert_eq!(row.to_item().unwrap(), stored);
        assert_eq!(
            provider_key(provider, "google-1")
                .unwrap()
                .encode_key()
                .unwrap(),
            item(&[("identityKey", s(key))])
        );
    }
}

#[test]
fn a_link_row_keys_its_user_and_link_id() {
    let stored = item(&[
        ("identityKey", s(&format!("LINK#u1#{LINK_ID}"))),
        ("nonce", s("nonce-1")),
        ("deadline", n("1800000300")),
        ("expiresAt", n("1800086400")),
        ("tokenHash", s("hash-1")),
        ("providerSubject", s("google-1")),
        ("status", s("complete")),
    ]);
    let row = LinkRow {
        user_id: "u1".into(),
        link_id: LINK_ID.into(),
        nonce: "nonce-1".into(),
        deadline: 1_800_000_300,
        expires_at: 1_800_086_400,
        token_hash: Some("hash-1".into()),
        provider_subject: Some("google-1".into()),
        status: Some("complete".into()),
        provider: None,
    };
    // A challenge Leyline wrote names no provider.
    assert_eq!(LinkRow::from_item(&stored).unwrap(), row);
    assert_eq!(row.to_item().unwrap(), stored);

    let mut named = stored;
    named.insert("provider".into(), s("SignInWithApple"));
    let row = LinkRow {
        provider: Some("SignInWithApple".into()),
        ..row
    };
    assert_eq!(LinkRow::from_item(&named).unwrap(), row);
    assert_eq!(row.to_item().unwrap(), named);
}

#[test]
fn a_methods_row_keys_its_user_and_lists_identities_as_compact_json() {
    let json = concat!(
        r#"[{"provider":"Google","subject":"google-1","email":"Alice@Example.com"},"#,
        r#"{"provider":"SignInWithApple","subject":"apple-1","removing":true}]"#
    );
    let stored = item(&[
        ("identityKey", s("METHODS#u1")),
        ("version", n("3")),
        ("identities", s(json)),
    ]);
    let row = MethodsRow {
        user_id: "u1".into(),
        version: 3,
        identities: vec![
            LinkedIdentity {
                provider: "Google".into(),
                subject: "google-1".into(),
                email: Some("Alice@Example.com".into()),
                removing: false,
            },
            LinkedIdentity {
                provider: "SignInWithApple".into(),
                subject: "apple-1".into(),
                email: None,
                removing: true,
            },
        ],
    };
    assert_eq!(MethodsRow::from_item(&stored).unwrap(), row);
    assert_eq!(row.to_item().unwrap(), stored);
    assert!(!format!("{row:?}").contains("Example.com"));
}

/// An owner record that is not the owner's JSON is refused, never read as
/// some default owner.
#[test]
fn a_mailbox_row_whose_record_is_not_json_does_not_decode() {
    let mut stored = email_item();
    stored.insert("record".into(), s("alice"));
    assert!(matches!(
        EmailRow::from_item(&stored).unwrap_err().kind,
        tabulary::DecodeFault::Custom {
            code: "invalid_json_record"
        }
    ));
}
