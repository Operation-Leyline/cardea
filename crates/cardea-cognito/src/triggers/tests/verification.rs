//! The custom message trigger: every message stays as Cognito wrote it, except
//! one whose code could complete an email change, which is refused.

use super::*;
use crate::testing::pending_change::{self, NEW, OBSERVED, OLD, VERIFIED};

const UPDATE: &str = "CustomMessage_UpdateUserAttribute";
const VERIFY: &str = "CustomMessage_VerifyUserAttribute";

fn message(source: &str, email: &str, verified: Option<Value>) -> Value {
    pending_change::event(source, email, verified, "")
}

async fn assert_unchanged(fixture: &Fixture, event: Value) {
    let sent = serde_json::to_vec(&event).unwrap();
    let answer = handle(&fixture.directory, &product(fixture), event.clone())
        .await
        .unwrap_or_else(|error| panic!("{error}: {event}"));
    assert_eq!(serde_json::to_vec(&answer).unwrap(), sent, "{event}");
}

async fn assert_refused(fixture: &Fixture, event: Value) {
    let error = handle(&fixture.directory, &product(fixture), event.clone())
        .await
        .expect_err(&event.to_string());
    assert!(
        matches!(error, TriggerError::Identity(Error::EmailChange)),
        "{error}: {event}"
    );
    assert_eq!(
        error.to_string(),
        "changing your email address is not supported"
    );
}

#[tokio::test]
async fn every_other_custom_message_is_returned_unchanged() {
    let fixture = fixture().await;
    for source in [
        "CustomMessage_SignUp",
        "CustomMessage_ResendCode",
        "CustomMessage_ForgotPassword",
        "CustomMessage_AdminCreateUser",
        "CustomMessage_Authentication",
    ] {
        for verified in [Some(json!("true")), Some(json!("false")), None] {
            assert_unchanged(&fixture, message(source, OLD, verified)).await;
        }
    }
}

/// The old address in the event does not make a pending change look harmless.
#[tokio::test]
async fn the_messages_a_pending_change_sends_are_refused() {
    let fixture = fixture().await;
    for (source, email) in OBSERVED {
        if source.starts_with("CustomMessage_") {
            assert_refused(&fixture, message(source, email, Some(json!(VERIFIED)))).await;
        }
    }
}

#[tokio::test]
async fn an_attribute_update_is_refused_whatever_it_says() {
    let fixture = fixture().await;
    for email in [OLD, NEW] {
        for verified in [Some(json!("true")), Some(json!("false")), None] {
            assert_refused(&fixture, message(UPDATE, email, verified)).await;
        }
    }
}

#[tokio::test]
async fn verifying_an_unverified_current_address_is_allowed() {
    let fixture = fixture().await;
    for verified in [json!("false"), json!(false)] {
        assert_unchanged(&fixture, message(VERIFY, OLD, Some(verified))).await;
    }
}

/// Only a clear "false" is one: anything else is read as already verified.
#[tokio::test]
async fn verification_is_refused_unless_the_address_is_clearly_unverified() {
    let fixture = fixture().await;
    for verified in [
        Some(json!("true")),
        Some(json!(true)),
        Some(json!("False")),
        Some(json!(" false")),
        Some(json!("")),
        Some(json!("no")),
        Some(json!(0)),
        Some(Value::Null),
        None,
    ] {
        assert_refused(&fixture, message(VERIFY, OLD, verified)).await;
    }
    assert_refused(&fixture, json!({"triggerSource":VERIFY})).await;
}

/// Why a change is refused. The directory and pool lookups use the signup
/// spelling, so this is what a pool that applied one, even to another spelling
/// of the same mailbox, would do to the account. If this stops failing, the
/// refusal can be reconsidered.
#[tokio::test]
async fn an_applied_change_would_break_the_account_so_its_code_is_withheld() {
    let second_subject = || {
        inbound(
            "Google",
            "g-2",
            json!({"email":"owner@gmail.com","email_verified":true}),
        )
    };

    // A password account, provisioned, with Google linked. Cognito gives its
    // user a name that is not the address.
    let native_account = fixture().await;
    let product_one = product(&native_account);
    native(&native_account, &product_one, "owner@gmail.com").await;
    let token = |email: &str| account_event("TokenGeneration_Authentication", "native-sub", email);
    for event in [token("owner@gmail.com"), google("owner@gmail.com")] {
        handle(&native_account.directory, &product_one, event)
            .await
            .unwrap();
    }
    for source in [UPDATE, VERIFY] {
        let event = message(source, "owner@gmail.com", Some(json!("true")));
        assert_refused(&native_account, event).await;
    }
    // Had the code been sent and used: no tokens, no linked sign-in, no new one.
    native_account
        .pool
        .state()
        .users
        .get_mut("internal")
        .unwrap()
        .email = "o.wner@gmail.com".into();
    for (event, expected) in [
        (token("o.wner@gmail.com"), Error::NotReady),
        (google("owner@gmail.com"), Error::Conflict),
        (second_subject(), Error::NotReady),
    ] {
        let error = handle(&native_account.directory, &product_one, event)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, TriggerError::Identity(refused) if *refused == expected),
            "{expected:?}: {error}"
        );
    }

    // A provider-made account: the old address finds nobody, so another pool
    // user is made for the same person.
    let social = fixture().await;
    let product_two = product(&social);
    handle(&social.directory, &product_two, google("owner@gmail.com"))
        .await
        .unwrap();
    {
        let mut pool = social.pool.state();
        let (_, mut account) = pool.users.pop_first().unwrap();
        account.email = "o.wner@gmail.com".into();
        pool.users.insert("internal".into(), account);
    }
    assert!(
        handle(&social.directory, &product_two, second_subject())
            .await
            .is_err()
    );
    assert_eq!(social.pool.state().users.len(), 2);
}
