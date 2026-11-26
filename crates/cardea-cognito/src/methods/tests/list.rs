//! `ListSignInMethods`.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use serde_json::json;

use super::*;
use crate::{testing::product::FakeProduct, triggers};

#[tokio::test]
async fn password_and_each_provider_with_its_own_address() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    assert_eq!(list(&f, &alice).await, [SignInMethod::Password]);

    // Linked in the other order than they are listed.
    f.try_link(&alice, APPLE, "apple-1", "Alice+apple@Example.com")
        .await
        .unwrap();
    f.try_link(&alice, GOOGLE, "google-1", "ALICE@example.com")
        .await
        .unwrap();

    assert_eq!(
        list(&f, &alice).await,
        [
            SignInMethod::Password,
            provider(GOOGLE, Some("ALICE@example.com")),
            provider(APPLE, Some("Alice+apple@Example.com")),
        ]
    );
}

#[tokio::test]
async fn a_provider_made_account_has_no_password_until_it_chooses_one() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    let google = provider(GOOGLE, Some("alice@example.com"));
    assert_eq!(list(&f, &alice).await, std::slice::from_ref(&google));
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::LastSignInMethod)
    );

    // "Set a password" is the forgot-password flow; its confirmation sets
    // `passwordSet`.
    let product = FakeProduct::new(f.directory.dynamodb().clone());
    let confirmed = json!({
        "triggerSource": "PostConfirmation_ConfirmForgotPassword",
        "userName": alice.username,
        "request": {"userAttributes": {
            "sub": alice.user_id, "email": alice.email, "email_verified": "true",
        }},
        "response": {},
    });
    triggers::handle(&f.directory, &product, confirmed)
        .await
        .unwrap();

    let row = f.item("EMAIL#alice@example.com").await.unwrap();
    assert_eq!(row["passwordSet"], Av::Bool(true));
    assert_eq!(list(&f, &alice).await, [SignInMethod::Password, google]);
    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
}

/// Every account linked before the list existed: it is built from the pool on
/// first use, without addresses.
#[tokio::test]
async fn a_user_without_a_list_gets_one_from_the_pool() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool_link("alice", GOOGLE, "google-1");
    f.unlisted_binding(&alice, GOOGLE, "google-1").await;
    assert_eq!(stored(&f, &alice).await, None);

    let expected = [SignInMethod::Password, provider(GOOGLE, None)];
    assert_eq!(list(&f, &alice).await, expected);

    let written = stored(&f, &alice).await.unwrap();
    assert_eq!(
        written,
        (
            1,
            r#"[{"provider":"Google","subject":"google-1"}]"#.to_owned()
        )
    );
    // Nothing new, nothing written.
    assert_eq!(list(&f, &alice).await, expected);
    assert_eq!(stored(&f, &alice).await, Some(written));
}

#[tokio::test]
async fn a_user_with_no_provider_gets_an_empty_list() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    list(&f, &alice).await;
    assert_eq!(stored(&f, &alice).await, Some((1, "[]".to_owned())));
}

/// What a warning wrote.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn where_the_pool_and_directory_disagree_the_pool_is_followed() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, APPLE, "apple-1").await;
    // The pool drops Google (the list still has it), gains an identity nothing
    // in the directory knows, and Apple's binding is gone.
    f.pool_unlink_all("alice");
    f.pool_link("alice", APPLE, "apple-1");
    f.pool_link("alice", APPLE, "apple-2");
    f.delete("PROVIDER#SignInWithApple#apple-1").await;

    let log = Log::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let methods = list(&f, &alice).await;
    drop(guard);

    assert_eq!(
        methods,
        [
            SignInMethod::Password,
            provider(APPLE, Some("alice@example.com")),
            provider(APPLE, None),
        ]
    );
    let log = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    // apple-1 is unbound; apple-2 is unbound and unlisted; Google is listed
    // and not linked.
    assert!(log.contains("disagreements=3"), "{log}");
    assert!(!log.contains("example.com"), "{log}");
    // The identity the list lacked is added; nothing is dropped.
    let (_, identities) = stored(&f, &alice).await.unwrap();
    assert!(identities.contains("apple-2") && identities.contains("google-1"));
}

#[tokio::test]
async fn a_missing_mailbox_row_offers_no_password() {
    let (f, alice) = password_and_google().await;
    f.delete("EMAIL#alice@example.com").await;
    assert_eq!(
        list(&f, &alice).await,
        [provider(GOOGLE, Some("alice@example.com"))]
    );
}

#[tokio::test]
async fn a_caller_the_pool_does_not_agree_with_learns_nothing() {
    let (f, alice) = password_and_google().await;
    let impostor = User {
        user_id: "another-sub".into(),
        ..alice
    };
    assert_eq!(
        list_sign_in_methods(&f.directory, &impostor).await,
        Err(OperationError::Identity(Error::Conflict))
    );
}

#[test]
fn printing_a_method_shows_no_address() {
    let method = provider(GOOGLE, Some("alice@example.com"));
    assert!(!format!("{method:?}").contains("alice"));
}
