//! The guard, the writes beside it, and the rows they leave, on a real table.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, EmailOwner, Error};

use super::signup_tests::commit;
use super::{AwsDirectory, mailbox_holder};
use crate::record::LinkRow;
use crate::testing::{ddb::Item, fixture};

const KEY: &str = "EMAIL#alice@example.com";
const OWNER_JSON: &str = r#"{"email":"alice@example.com","username":"alice","origin":"Cognito"}"#;

fn item(pairs: &[(&str, Av)]) -> Item {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

fn s(value: &str) -> Av {
    Av::S(value.to_owned())
}

fn owner(origin: &str) -> EmailOwner {
    EmailOwner {
        email: "alice@example.com".into(),
        username: "alice".into(),
        origin: origin.into(),
    }
}

/// A claim writes exactly the key and the owner's JSON, and a second claim
/// for the same mailbox reads back the first owner instead of replacing it.
#[tokio::test]
async fn a_claim_writes_the_frozen_row_and_the_first_claim_wins() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    let first = owner("Cognito");
    assert_eq!(directory.claim_email(&first).await, Ok(first.clone()));
    assert_eq!(
        fixture.item(KEY).await,
        Some(item(&[("identityKey", s(KEY)), ("record", s(OWNER_JSON))]))
    );
    let rival = EmailOwner {
        username: "mallory".into(),
        ..first.clone()
    };
    assert_eq!(directory.claim_email(&rival).await, Ok(first));
}

/// Commit `profile_guard`'s item alone.
async fn guard(directory: &AwsDirectory, user_id: &str) -> Result<(), Error> {
    let guard = directory
        .profile_guard("alice@example.com", "alice", user_id)
        .await?;
    commit(directory, guard).await
}

/// The guard binds the mailbox to the first user it is committed for: the
/// same user again passes, and a second user is refused, so one mailbox
/// never becomes two product users.
#[tokio::test]
async fn the_profile_guard_binds_a_mailbox_to_one_user() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    directory.claim_email(&owner("Cognito")).await.unwrap();
    assert_eq!(guard(directory, "u1").await, Ok(()));
    assert_eq!(guard(directory, "u1").await, Ok(()));
    assert_eq!(
        fixture.item(KEY).await,
        Some(item(&[
            ("identityKey", s(KEY)),
            ("record", s(OWNER_JSON)),
            ("userId", s("u1")),
        ]))
    );
    // `native_user` would reach Cognito for another username, so the rival
    // owner is the same username with another user id.
    assert_eq!(guard(directory, "u2").await, Err(Error::Conflict));
}

#[tokio::test]
async fn the_profile_guard_refuses_a_mailbox_nobody_claimed() {
    let fixture = fixture().await;
    assert_eq!(guard(&fixture.directory, "u1").await, Err(Error::Conflict));
}

/// The holder read selects only the user: an address nobody holds, one that
/// does not normalize, and a row not yet provisioned all answer `None`.
#[tokio::test]
async fn the_mailbox_holder_is_the_rows_user() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    let holder =
        |email: &'static str| mailbox_holder(directory.dynamodb(), directory.table(), email);
    assert_eq!(holder("alice@example.com").await.unwrap(), None);
    directory.claim_email(&owner("Cognito")).await.unwrap();
    assert_eq!(holder("alice@example.com").await.unwrap(), None);
    guard(directory, "u1").await.unwrap();
    assert_eq!(
        holder("Alice+work@example.com").await.unwrap(),
        Some("u1".to_owned())
    );
    assert_eq!(holder("bob@example.com").await.unwrap(), None);
    assert_eq!(holder("not an address").await.unwrap(), None);
}

/// A new challenge writes exactly its key, nonce, deadline and TTL.
#[tokio::test]
async fn a_new_link_challenge_writes_the_frozen_attributes() {
    let fixture = fixture().await;
    fixture
        .directory
        .put_new(&LinkRow {
            user_id: "u1".into(),
            link_id: "link".into(),
            nonce: "nonce".into(),
            deadline: 1_800_000_300,
            expires_at: 1_800_086_400,
            token_hash: None,
            provider_subject: None,
            status: None,
            provider: None,
        })
        .await
        .unwrap();
    let row = fixture.item("LINK#u1#link").await.unwrap();
    let mut names = row.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, ["deadline", "expiresAt", "identityKey", "nonce"]);
}

#[tokio::test]
async fn a_chosen_password_is_recorded_on_the_users_own_row() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    // A provider-made account, provisioned as u1.
    directory.claim_email(&owner("Google")).await.unwrap();
    guard(directory, "u1").await.unwrap();
    let before = directory.email_row("alice@example.com").await.unwrap();
    assert!(!before.unwrap().has_password());

    // Another user's reset changes nothing.
    directory
        .record_password_set("alice@example.com", "alice", "u2")
        .await
        .unwrap();
    assert!(!fixture.item(KEY).await.unwrap().contains_key("passwordSet"));

    directory
        .record_password_set("Alice@example.com", "internal-username", "u1")
        .await
        .unwrap();
    assert_eq!(
        fixture.item(KEY).await.unwrap()["passwordSet"],
        Av::Bool(true)
    );
    let after = directory.email_row("alice@example.com").await.unwrap();
    assert!(after.unwrap().has_password());
    // The row is still the guard's and still decodes.
    assert_eq!(guard(directory, "u1").await, Ok(()));
}

/// Before provisioning, the pool says whose the mailbox is.
#[tokio::test]
async fn a_reset_before_provisioning_is_recorded_only_for_the_mailboxs_user() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    directory.claim_email(&owner("Google")).await.unwrap();
    fixture
        .pool
        .add("alice", "u1", "alice@example.com", "CONFIRMED");

    directory
        .record_password_set("alice@example.com", "other", "u2")
        .await
        .unwrap();
    assert!(!fixture.item(KEY).await.unwrap().contains_key("passwordSet"));
    directory
        .record_password_set("alice@example.com", "internal", "u1")
        .await
        .unwrap();
    assert_eq!(
        fixture.item(KEY).await.unwrap()["passwordSet"],
        Av::Bool(true)
    );
}

/// Another signup's claim on the mailbox must not fail this user's reset.
#[tokio::test]
async fn a_reset_over_someone_elses_unfinished_claim_writes_nothing() {
    for status in [None, Some("UNCONFIRMED")] {
        let fixture = fixture().await;
        let directory = &fixture.directory;
        directory.claim_email(&owner("Cognito")).await.unwrap();
        if let Some(status) = status {
            fixture
                .pool
                .add("alice", "other", "alice@example.com", status);
        }
        assert_eq!(
            directory
                .record_password_set("alice@example.com", "internal", "u1")
                .await,
            Ok(())
        );
        assert!(!fixture.item(KEY).await.unwrap().contains_key("passwordSet"));
    }
}

#[tokio::test]
async fn a_reset_for_a_mailbox_without_a_row_writes_nothing() {
    let fixture = fixture().await;
    fixture
        .directory
        .record_password_set("alice@example.com", "alice", "u1")
        .await
        .unwrap();
    assert_eq!(fixture.item(KEY).await, None);
}
