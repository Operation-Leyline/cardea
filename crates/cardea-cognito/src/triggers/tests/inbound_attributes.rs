//! What the inbound federation answer keeps: Cognito stores only what it
//! names.

use super::*;

/// The attributes the handler answers an inbound event with.
async fn profile(fixture: &Fixture, mut event: Value, user_info: Value) -> Value {
    event["request"]["attributes"]["userInfo"] = user_info;
    let product = product(fixture);
    let answer = handle(&fixture.directory, &product, event).await.unwrap();
    answer["response"]["userAttributesToMap"].clone()
}

/// Apple names the person only on the first authorization. The flat fields
/// here are an assumed shape: where a real pool puts Apple's name has not been
/// observed.
#[tokio::test]
async fn apples_first_sign_in_keeps_the_name() {
    let fixture = fixture().await;
    let event = apple("owner@icloud.com", json!("true"), json!("false"));
    let first = profile(
        &fixture,
        event,
        json!({"name":"Ada Lovelace","firstName":"Ada","lastName":"Lovelace"}),
    )
    .await;
    assert_eq!(
        first,
        json!({"sub":"001.a.9","email":"owner@icloud.com","email_verified":"true",
            "is_private_email":"false","name":"Ada Lovelace",
            "firstName":"Ada","lastName":"Lovelace"})
    );
}

/// An empty value would replace the name the first sign-in stored.
#[tokio::test]
async fn a_later_apple_sign_in_sends_no_empty_name() {
    let fixture = fixture().await;
    for user_info in [
        Value::Null,
        json!({}),
        json!({"name":"","firstName":null,"lastName":""}),
    ] {
        let event = apple("owner@icloud.com", json!(true), json!(false));
        assert_eq!(
            profile(&fixture, event, user_info.clone()).await,
            json!({"sub":"001.a.9","email":"owner@icloud.com","email_verified":"true",
                "is_private_email":"false"}),
            "{user_info}"
        );
    }
}

#[tokio::test]
async fn google_attributes_all_return_with_the_accounts_own_address() {
    let fixture = fixture().await;
    let event = inbound(
        "Google",
        "g-1",
        json!({"email":"Owner+g@Gmail.com","email_verified":true,"name":"Grace Hopper",
            "picture":"https://example.com/g.png","exp":1_800_000_000,"locale":""}),
    );
    // The ID token wins over userinfo, unless it has nothing to say.
    let answer = profile(
        &fixture,
        event,
        json!({"sub":"someone-else","email":"other@gmail.com","name":"Other",
            "locale":"en","given_name":"Grace","groups":["a"]}),
    )
    .await;
    assert_eq!(
        answer,
        json!({"sub":"g-1","email":"owner+g@gmail.com","email_verified":"true",
            "name":"Grace Hopper","given_name":"Grace","locale":"en",
            "picture":"https://example.com/g.png","exp":"1800000000"})
    );
}

/// Anything already in the response stays, below what the provider sent.
#[tokio::test]
async fn attributes_already_in_the_response_are_kept() {
    let fixture = fixture().await;
    let mut event = google("owner@gmail.com");
    event["response"]["userAttributesToMap"] =
        json!({"custom:kept":"yes","sub":"stale","email":"stale@example.com"});
    assert_eq!(
        profile(&fixture, event, Value::Null).await,
        json!({"custom:kept":"yes","sub":"g-1","email":"owner@gmail.com","email_verified":"true"})
    );
}
