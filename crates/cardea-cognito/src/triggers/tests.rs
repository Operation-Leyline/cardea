//! Every directory trigger through [`handle`], over a real table and a fake
//! pool.

use std::sync::atomic::Ordering;

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, Error};
use serde_json::{Value, json};

use super::*;
use crate::testing::{Fixture, cognito::SUB, fixture, product::FakeProduct};

mod inbound_attributes;
mod verification;

fn product(fixture: &Fixture) -> FakeProduct {
    FakeProduct::new(fixture.directory.dynamodb().clone())
}

fn inbound(provider: &str, subject: &str, claims: Value) -> Value {
    let mut token = claims;
    token["sub"] = json!(subject);
    json!({"triggerSource":"InboundFederation_ExternalProvider","userPoolId":"pool",
        "request":{"providerName":provider,"providerType":provider,
            "attributes":{"idToken":token}},
        "response":{}})
}

fn google(email: &str) -> Value {
    inbound(
        "Google",
        "g-1",
        json!({"email":email,"email_verified":true}),
    )
}

fn apple(email: &str, verified: Value, private: Value) -> Value {
    inbound(
        "SignInWithApple",
        "001.a.9",
        json!({"email":email,"email_verified":verified,"is_private_email":private}),
    )
}

fn external_sign_up(username: &str) -> Value {
    json!({"triggerSource":"PreSignUp_ExternalProvider","userName":username,
        "request":{"userAttributes":{}},"response":{}})
}

fn account_event(source: &str, sub: &str, email: &str) -> Value {
    json!({"triggerSource":source,"version":"1","userName":"internal",
        "request":{"userAttributes":{"sub":sub,"email":email,"email_verified":"true"}},
        "response":{}})
}

/// A confirmed native account: its signup claim and its pool user.
async fn native(fixture: &Fixture, product: &FakeProduct, email: &str) {
    let signup = json!({"triggerSource":"PreSignUp_SignUp","userName":"transient",
        "request":{"userAttributes":{"email":email}},"response":{}});
    let answer = handle(&fixture.directory, product, signup).await.unwrap();
    assert_eq!(
        answer["response"],
        json!({"autoConfirmUser":false,"autoVerifyEmail":false,"autoVerifyPhone":false})
    );
    fixture
        .pool
        .add("internal", "native-sub", email, "CONFIRMED");
}

/// The first linked sign-in succeeds, for either provider, and the pool is
/// then willing to let the federated sign-up through.
#[tokio::test]
async fn a_first_federated_sign_in_creates_links_and_succeeds() {
    for (event, username, email, key) in [
        (
            google("Owner@Gmail.com"),
            "google_g-1",
            "owner@gmail.com",
            "PROVIDER#Google#g-1",
        ),
        (
            apple("owner@icloud.com", json!("true"), json!("false")),
            "SignInWithApple_001.a.9",
            "owner@icloud.com",
            "PROVIDER#SignInWithApple#001.a.9",
        ),
        (
            apple("owner@me.com", json!(true), json!(false)),
            "signinwithapple_001.a.9",
            "owner@me.com",
            "PROVIDER#SignInWithApple#001.a.9",
        ),
    ] {
        let fixture = fixture().await;
        let product = product(&fixture);
        let subject = event["request"]["attributes"]["idToken"]["sub"].clone();
        let answer = handle(&fixture.directory, &product, event).await.unwrap();
        let profile = &answer["response"]["userAttributesToMap"];
        assert_eq!(
            (
                &profile["sub"],
                &profile["email"],
                &profile["email_verified"]
            ),
            (&subject, &json!(email), &json!("true"))
        );
        assert!(fixture.item(key).await.is_some(), "{key}");
        {
            let pool = fixture.pool.state();
            assert_eq!((pool.creates, pool.links), (1, 1));
        }
        let signup = external_sign_up(username);
        assert_eq!(
            handle(&fixture.directory, &product, signup.clone())
                .await
                .unwrap(),
            signup
        );
        assert_eq!(fixture.pool.state().links, 1);
    }
}

/// A later sign-in answers the account's address, not the provider's new one.
#[tokio::test]
async fn a_linked_sign_in_returns_the_canonical_email() {
    let fixture = fixture().await;
    let product = product(&fixture);
    handle(&fixture.directory, &product, google("first@gmail.com"))
        .await
        .unwrap();
    let answer = handle(&fixture.directory, &product, google("second@gmail.com"))
        .await
        .unwrap();
    assert_eq!(
        answer["response"]["userAttributesToMap"]["email"],
        "first@gmail.com"
    );
    assert_eq!(fixture.pool.state().creates, 1);
}

/// The pool's internal operator-style create passes the signup guard.
#[tokio::test]
async fn the_librarys_own_create_passes_pre_signup_and_a_stranger_does_not() {
    let fixture = fixture().await;
    let product = product(&fixture);
    handle(&fixture.directory, &product, google("owner@gmail.com"))
        .await
        .unwrap();
    let create = |origin: &str| {
        json!({"triggerSource":"PreSignUp_AdminCreateUser","userName":"internal",
            "request":{"userAttributes":{"email":"owner@gmail.com"},
                "clientMetadata":{"identityOrigin":origin}},
            "response":{}})
    };
    assert!(
        handle(&fixture.directory, &product, create("Google"))
            .await
            .is_ok()
    );
    for origin in ["SignInWithApple", "Cognito", ""] {
        assert!(
            matches!(
                handle(&fixture.directory, &product, create(origin)).await,
                Err(TriggerError::Identity(Error::Conflict))
            ),
            "{origin}"
        );
    }
}

#[tokio::test]
async fn an_address_apple_does_not_own_asks_for_a_signed_in_link() {
    for event in [
        apple("x@privaterelay.appleid.com", json!("true"), json!("true")),
        apple("owner@icloud.com", json!(true), json!(true)),
        apple("owner@gmail.com", json!("true"), json!("false")),
    ] {
        let fixture = fixture().await;
        let product = product(&fixture);
        let error = handle(&fixture.directory, &product, event)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "sign in with your existing method and link Apple from your profile"
        );
        assert_eq!(fixture.pool.state().creates, 0);
    }
    let fixture = fixture().await;
    let error = handle(
        &fixture.directory,
        &product(&fixture),
        google("owner@example.com"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "sign in with your existing method and link Google from your profile"
    );
}

#[tokio::test]
async fn inbound_refuses_unknown_or_mismatched_providers_and_unverified_mail() {
    let fixture = fixture().await;
    let product = product(&fixture);
    let mut mismatched = google("owner@gmail.com");
    mismatched["request"]["providerType"] = json!("OIDC");
    for event in [
        mismatched,
        inbound(
            "Microsoft",
            "m",
            json!({"email":"a@outlook.com","email_verified":true}),
        ),
        apple("owner@icloud.com", json!("false"), json!("false")),
    ] {
        assert!(matches!(
            handle(&fixture.directory, &product, event).await,
            Err(TriggerError::Identity(Error::Invalid))
        ));
    }
}

#[tokio::test]
async fn a_federated_sign_up_for_an_unbound_subject_is_refused() {
    let fixture = fixture().await;
    let product = product(&fixture);
    for (username, expected) in [
        ("Google_unknown", Error::Conflict),
        ("SignInWithApple_unknown", Error::Conflict),
        ("Google_", Error::Invalid),
        ("Facebook_1", Error::Invalid),
    ] {
        let error = handle(&fixture.directory, &product, external_sign_up(username))
            .await
            .unwrap_err();
        assert!(
            matches!(error, TriggerError::Identity(found) if found == expected),
            "{username}"
        );
    }
}

#[tokio::test]
async fn confirmation_provisions_once_through_the_product() {
    let fixture = fixture().await;
    let product = product(&fixture);
    native(&fixture, &product, "pat@example.com").await;
    let event = account_event(
        "PostConfirmation_ConfirmSignUp",
        "native-sub",
        "pat@example.com",
    );
    for _ in 0..2 {
        assert_eq!(
            handle(&fixture.directory, &product, event.clone())
                .await
                .unwrap(),
            event
        );
    }
    {
        let accounts = product.accounts.lock().unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].confirmed_signup);
    }
    let row = fixture.item("EMAIL#pat@example.com").await.unwrap();
    assert_eq!(row["userId"], Av::S("native-sub".into()));
    assert!(!row.contains_key("unconfirmedExpiresAt"));
}

/// A second `sub` for a bound mailbox gets no product account.
#[tokio::test]
async fn another_user_cannot_be_provisioned_onto_a_bound_mailbox() {
    let fixture = fixture().await;
    let product = product(&fixture);
    native(&fixture, &product, "pat@example.com").await;
    let confirm =
        |sub: &str| account_event("TokenGeneration_Authentication", sub, "pat@example.com");
    handle(&fixture.directory, &product, confirm("native-sub"))
        .await
        .unwrap();
    assert!(matches!(
        handle(&fixture.directory, &product, confirm("intruder")).await,
        Err(TriggerError::Identity(Error::Conflict))
    ));
    assert_eq!(product.accounts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn token_generation_provisions_an_operator_account_then_adds_claims() {
    let fixture = fixture().await;
    let mut product = product(&fixture);
    product
        .claims
        .0
        .insert("custom:tenantId".into(), "ws_1".into());
    native(&fixture, &product, "pat@example.com").await;
    for source in [
        "TokenGeneration_NewPasswordChallenge",
        "TokenGeneration_RefreshTokens",
    ] {
        let answer = handle(
            &fixture.directory,
            &product,
            account_event(source, "native-sub", "pat@example.com"),
        )
        .await
        .unwrap();
        assert_eq!(
            answer["response"]["claimsOverrideDetails"]["claimsToAddOrOverride"]["custom:tenantId"],
            "ws_1"
        );
    }
    let accounts = product.accounts.lock().unwrap();
    assert_eq!(accounts.len(), 1);
    assert!(!accounts[0].confirmed_signup);
}

#[tokio::test]
async fn a_failed_provision_fails_the_trigger_unless_the_account_exists() {
    let fixture = fixture().await;
    let product = product(&fixture);
    native(&fixture, &product, "pat@example.com").await;
    let event = account_event(
        "PostConfirmation_ConfirmSignUp",
        "native-sub",
        "pat@example.com",
    );
    product.fail_provision.store(true, Ordering::SeqCst);
    assert!(matches!(
        handle(&fixture.directory, &product, event.clone()).await,
        Err(TriggerError::Product(_))
    ));
    // A concurrent winner: the writes are there although this call failed.
    product.lose_provision.store(true, Ordering::SeqCst);
    assert!(handle(&fixture.directory, &product, event).await.is_ok());
}

/// While the directory is being filled, existing accounts keep their sessions
/// and nothing new is provisioned.
#[tokio::test]
async fn only_existing_accounts_pass_while_the_directory_is_not_ready() {
    let fixture = fixture().await;
    let product = product(&fixture);
    native(&fixture, &product, "pat@example.com").await;
    let event = account_event(
        "TokenGeneration_Authentication",
        "native-sub",
        "pat@example.com",
    );
    handle(&fixture.directory, &product, event.clone())
        .await
        .unwrap();
    fixture
        .directory
        .dynamodb()
        .delete_item()
        .table_name(fixture.directory.table())
        .key("identityKey", Av::S("SYSTEM#READY".into()))
        .send()
        .await
        .unwrap();
    assert_eq!(fixture.directory.ready().await, Err(Error::NotReady));
    assert!(handle(&fixture.directory, &product, event).await.is_ok());
    assert!(matches!(
        handle(
            &fixture.directory,
            &product,
            account_event("TokenGeneration_Authentication", "new", "new@example.com"),
        )
        .await,
        Err(TriggerError::Identity(Error::NotReady))
    ));
}

#[tokio::test]
async fn a_confirmed_reset_records_the_password_and_provisions_nothing() {
    let fixture = fixture().await;
    let product = product(&fixture);
    handle(&fixture.directory, &product, google("owner@gmail.com"))
        .await
        .unwrap();
    let event = account_event(
        "PostConfirmation_ConfirmForgotPassword",
        SUB,
        "owner@gmail.com",
    );
    assert_eq!(
        handle(&fixture.directory, &product, event.clone())
            .await
            .unwrap(),
        event
    );
    let row = fixture.item("EMAIL#owner@gmail.com").await.unwrap();
    assert_eq!(row["passwordSet"], Av::Bool(true));
    assert!(product.accounts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_machine_clients_token_is_left_as_it_is() {
    let fixture = fixture().await;
    let mut product = product(&fixture);
    product
        .claims
        .0
        .insert("custom:tenantId".into(), "ws_1".into());
    let event = json!({"triggerSource":"TokenGeneration_ClientCredentials","version":"3",
        "request":{"userAttributes":{}},"response":{}});
    assert_eq!(
        handle(&fixture.directory, &product, event.clone())
            .await
            .unwrap(),
        event
    );
    assert!(product.accounts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unknown_trigger_is_refused() {
    let fixture = fixture().await;
    let product = product(&fixture);
    for source in [
        "PreAuthentication_Authentication",
        "NoSuchTrigger_SignUp",
        "CustomMessage",
        "",
    ] {
        assert!(matches!(
            handle(
                &fixture.directory,
                &product,
                json!({"triggerSource":source})
            )
            .await,
            Err(TriggerError::Unsupported)
        ));
    }
}
