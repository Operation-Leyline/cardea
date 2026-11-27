//! Provider sign-ins through the triggers, before and after an unlink.

use serde_json::{Value, json};

use super::*;
use crate::triggers::TriggerError;

fn inbound(method: Provider, subject: &str, email: &str) -> Value {
    let rule = method.rule();
    json!({
        "triggerSource": "InboundFederation_ExternalProvider",
        "request": {
            "providerName": rule.cognito_name,
            "providerType": rule.cognito_type,
            "attributes": {"idToken": {
                "sub": subject, "email": email, "email_verified": true,
            }},
        },
        "response": {},
    })
}

fn external_sign_up(method: Provider, subject: &str) -> Value {
    json!({
        "triggerSource": "PreSignUp_ExternalProvider",
        "userName": format!("{}{subject}", method.rule().username_prefixes[0]),
        "request": {"userAttributes": {}},
        "response": {},
    })
}

/// The list is written when a sign-in links or shows a new spelling, and not
/// on every sign-in.
#[tokio::test]
async fn a_sign_in_writes_the_list_only_when_it_has_something_new() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.link(&alice, GOOGLE, "google-1").await;
    let before = stored(&f, &alice).await.unwrap();

    for _ in 0..2 {
        f.directory
            .inbound(inbound(GOOGLE, "google-1", "alice@example.com"))
            .await
            .unwrap();
        assert_eq!(stored(&f, &alice).await.unwrap(), before);
    }

    f.directory
        .inbound(inbound(GOOGLE, "google-1", "Alice@Example.com"))
        .await
        .unwrap();
    let after = stored(&f, &alice).await.unwrap();
    assert_eq!(after.0, before.0 + 1);
    assert!(after.1.contains("Alice@Example.com"));
}

/// The address of a link made before the list existed arrives with the next
/// sign-in.
#[tokio::test]
async fn a_sign_in_fills_in_a_missing_address() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool_link("alice", GOOGLE, "google-1");
    f.unlisted_binding(&alice, GOOGLE, "google-1").await;
    assert_eq!(list(&f, &alice).await[1], provider(GOOGLE, None));

    f.directory
        .inbound(inbound(GOOGLE, "google-1", "Alice@Example.com"))
        .await
        .unwrap();

    assert_eq!(
        list(&f, &alice).await[1],
        provider(GOOGLE, Some("Alice@Example.com"))
    );
}

/// An account from before the list existed, with two links: its first sign-in
/// starts the list with both.
#[tokio::test]
async fn a_first_sign_in_lists_every_identity_the_pool_links() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    for (method, subject) in [(GOOGLE, "google-1"), (APPLE, "apple-1")] {
        f.pool_link("alice", method, subject);
        f.unlisted_binding(&alice, method, subject).await;
    }

    f.directory
        .inbound(inbound(GOOGLE, "google-1", "Alice@Example.com"))
        .await
        .unwrap();

    assert_eq!(
        stored(&f, &alice).await.unwrap(),
        (
            1,
            concat!(
                r#"[{"provider":"Google","subject":"google-1","email":"Alice@Example.com"},"#,
                r#"{"provider":"SignInWithApple","subject":"apple-1"}]"#
            )
            .to_owned()
        )
    );
}

/// The pre-signup trigger links without an address; the first list is saved all
/// the same.
#[tokio::test]
async fn a_first_link_that_adds_nothing_still_saves_the_list() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool_link("alice", GOOGLE, "google-1");
    f.unlisted_binding(&alice, GOOGLE, "google-1").await;

    f.directory
        .pre_signup(external_sign_up(GOOGLE, "google-1"))
        .await
        .unwrap();

    let saved = (
        1,
        r#"[{"provider":"Google","subject":"google-1"}]"#.to_owned(),
    );
    assert_eq!(stored(&f, &alice).await, Some(saved.clone()));
    f.directory
        .pre_signup(external_sign_up(GOOGLE, "google-1"))
        .await
        .unwrap();
    assert_eq!(stored(&f, &alice).await, Some(saved));
}

#[tokio::test]
async fn an_unlinked_identity_no_longer_signs_in() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    let relay = "x7k2@privaterelay.appleid.com";
    f.try_link(&alice, APPLE, "apple-1", relay).await.unwrap();
    unlink(&f, &alice, APPLE).await.unwrap();

    assert!(matches!(
        f.directory.inbound(inbound(APPLE, "apple-1", relay)).await,
        Err(TriggerError::LinkRequired("Apple"))
    ));
    assert_eq!(
        f.directory
            .pre_signup(external_sign_up(APPLE, "apple-1"))
            .await,
        Err(Error::Conflict)
    );
    assert_eq!(f.identities("alice"), []);
}

/// The automatic rule still holds: a provider that owns the account's mailbox
/// links again when it signs in.
#[tokio::test]
async fn an_owner_of_the_mailbox_links_again_by_signing_in() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    let mut event = inbound(GOOGLE, "google-1", &alice.email);
    event["request"]["attributes"]["idToken"]["hd"] = json!("example.com");
    f.directory.inbound(event.clone()).await.unwrap();
    unlink(&f, &alice, GOOGLE).await.unwrap();

    f.directory.inbound(event).await.unwrap();

    assert_eq!(f.identities("alice").len(), 1);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice));
}

/// A sign-in that read the binding before an unlink must not undo it.
#[tokio::test]
async fn a_sign_in_during_an_unfinished_unlink_links_nothing() {
    let (f, alice) = password_and_google().await;
    f.pool.state().disable_failures = 1;
    assert!(unlink(&f, &alice, GOOGLE).await.is_err());
    f.pool_unlink_all("alice");

    assert!(matches!(
        f.directory
            .inbound(inbound(GOOGLE, "google-1", &alice.email))
            .await,
        Err(TriggerError::Identity(Error::NotReady))
    ));
    assert_eq!(f.identities("alice"), []);
}
