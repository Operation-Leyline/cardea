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

#[tokio::test]
async fn re_verifying_the_accounts_own_address_is_allowed() {
    let fixture = fixture().await;
    let product = product(&fixture);
    accounts(&fixture, &product).await;
    for source in CHANGING {
        for email in ["owner@gmail.com", "Owner@Gmail.com", " owner@gmail.com "] {
            assert_unchanged(&fixture, &product, message(source, email)).await;
        }
    }
}

#[tokio::test]
async fn verifying_any_other_address_is_refused() {
    let fixture = fixture().await;
    let product = product(&fixture);
    accounts(&fixture, &product).await;
    // Nobody's, another person's, and other spellings of the same mailbox.
    for source in CHANGING {
        for email in [
            "new@example.com",
            "taken@example.com",
            "o.wner@gmail.com",
            "owner+new@gmail.com",
            "owner@googlemail.com",
        ] {
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

/// Why an alias is refused. The directory and pool lookups use the signup
/// spelling, so this is what a pool that applied one would do to the account.
/// If this stops failing, the refusal can be reconsidered.
#[tokio::test]
async fn an_applied_alias_would_break_the_account_so_its_code_is_withheld() {
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
    for source in CHANGING {
        assert!(matches!(
            handle(
                &native_account.directory,
                &product_one,
                message(source, "o.wner@gmail.com")
            )
            .await,
            Err(TriggerError::Identity(Error::EmailChange))
        ));
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
