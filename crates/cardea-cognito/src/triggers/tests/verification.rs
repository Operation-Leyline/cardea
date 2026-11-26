//! The custom message trigger: every message stays as Cognito wrote it, except
//! the code that would verify a new address, which is refused.

use super::*;

const CHANGING: [&str; 2] = [
    "CustomMessage_UpdateUserAttribute",
    "CustomMessage_VerifyUserAttribute",
];

/// A message event for the account `native` makes, about `email`.
fn message(source: &str, email: &str) -> Value {
    json!({"version":"1","region":"us-east-1","userPoolId":"pool","userName":"internal",
        "callerContext":{"awsSdkVersion":"x","clientId":"c"},"triggerSource":source,
        "request":{"userAttributes":{"sub":"native-sub","email":email,"email_verified":"true"},
            "codeParameter":"{####}","usernameParameter":null},
        "response":{"smsMessage":null,"emailMessage":null,"emailSubject":null}})
}

/// A confirmed account at `owner@gmail.com`, and another person's.
async fn accounts(fixture: &Fixture, product: &FakeProduct) {
    native(fixture, product, "owner@gmail.com").await;
    let theirs = json!({"triggerSource":"PreSignUp_SignUp","userName":"other",
        "request":{"userAttributes":{"email":"taken@example.com"}},"response":{}});
    handle(&fixture.directory, product, theirs).await.unwrap();
    fixture
        .pool
        .add("other", "other-sub", "taken@example.com", "CONFIRMED");
}

async fn assert_unchanged(fixture: &Fixture, product: &FakeProduct, event: Value) {
    let sent = serde_json::to_vec(&event).unwrap();
    let answer = handle(&fixture.directory, product, event.clone())
        .await
        .unwrap_or_else(|error| panic!("{error}: {event}"));
    assert_eq!(serde_json::to_vec(&answer).unwrap(), sent, "{event}");
}

#[tokio::test]
async fn every_other_custom_message_is_returned_unchanged() {
    let fixture = fixture().await;
    let product = product(&fixture);
    accounts(&fixture, &product).await;
    // Whoever the address belongs to: these messages change nothing.
    for source in [
        "CustomMessage_SignUp",
        "CustomMessage_ResendCode",
        "CustomMessage_ForgotPassword",
        "CustomMessage_AdminCreateUser",
        "CustomMessage_Authentication",
    ] {
        for email in ["owner@gmail.com", "stranger@example.com"] {
            assert_unchanged(&fixture, &product, message(source, email)).await;
        }
    }
}

/// The account's own address, and any other spelling of the same mailbox.
#[tokio::test]
async fn verifying_the_persons_own_mailbox_is_allowed() {
    let fixture = fixture().await;
    let product = product(&fixture);
    accounts(&fixture, &product).await;
    for source in CHANGING {
        for email in [
            "owner@gmail.com",
            "Owner@Gmail.com",
            "o.wner+new@googlemail.com",
        ] {
            assert_unchanged(&fixture, &product, message(source, email)).await;
        }
    }
}

#[tokio::test]
async fn verifying_a_different_mailbox_is_refused() {
    let fixture = fixture().await;
    let product = product(&fixture);
    accounts(&fixture, &product).await;
    // Nobody's, another person's, and not an address at all.
    for source in CHANGING {
        for email in ["new@example.com", "taken@example.com"] {
            let error = handle(&fixture.directory, &product, message(source, email))
                .await
                .unwrap_err();
            assert!(
                matches!(error, TriggerError::Identity(Error::EmailChange)),
                "{source} {email}: {error}"
            );
            assert_eq!(
                error.to_string(),
                "changing your email address is not supported"
            );
        }
        for event in [
            message(source, "not-an-address"),
            message(source, ""),
            json!({"triggerSource":source,"request":{"userAttributes":{}}}),
        ] {
            assert!(matches!(
                handle(&fixture.directory, &product, event).await,
                Err(TriggerError::Identity(Error::Invalid))
            ));
        }
    }
}

/// Once provisioned, the row names its user, whoever asks under that name.
#[tokio::test]
async fn a_bound_mailbox_is_only_its_users_to_verify() {
    let fixture = fixture().await;
    let product = product(&fixture);
    accounts(&fixture, &product).await;
    let confirm = account_event(
        "PostConfirmation_ConfirmSignUp",
        "native-sub",
        "owner@gmail.com",
    );
    handle(&fixture.directory, &product, confirm).await.unwrap();
    let source = "CustomMessage_VerifyUserAttribute";
    assert_unchanged(&fixture, &product, message(source, "owner@gmail.com")).await;
    let mut intruder = message(source, "owner@gmail.com");
    intruder["request"]["userAttributes"]["sub"] = json!("other-sub");
    assert!(matches!(
        handle(&fixture.directory, &product, intruder).await,
        Err(TriggerError::Identity(Error::EmailChange))
    ));
}
