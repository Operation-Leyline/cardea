//! What can be done with a mailbox and an identity once their account is gone.

use super::*;

fn sign_up(email: &str) -> Value {
    json!({
        "triggerSource": "PreSignUp_SignUp",
        "request": {"userAttributes": {"email": email}},
        "response": {},
    })
}

fn google_sign_in(subject: &str, email: &str) -> Value {
    json!({
        "triggerSource": "InboundFederation_ExternalProvider",
        "request": {
            "providerName": "Google",
            "providerType": "Google",
            "attributes": {"idToken": {
                "sub": subject, "email": email, "email_verified": true, "hd": "example.com",
            }},
        },
        "response": {},
    })
}

#[tokio::test]
async fn the_mailbox_can_sign_up_again() {
    let (f, alice) = linked_account().await;
    // Without erasure the deleted account keeps its mailbox.
    assert_eq!(
        f.directory
            .pre_signup(sign_up("alice+new@example.com"))
            .await,
        Err(Error::Conflict)
    );

    delete_account(&f, &alice).await;

    f.directory
        .pre_signup(sign_up("alice@example.com"))
        .await
        .unwrap();
    let claim = f.directory.email("alice@example.com").await.unwrap();
    assert_eq!(claim.unwrap().username, "alice@example.com");
}

#[tokio::test]
async fn the_same_google_subject_signs_in_to_a_fresh_account() {
    let (f, alice) = linked_account().await;
    delete_account(&f, &alice).await;

    let answer = f
        .directory
        .inbound(google_sign_in("google-1", "alice@example.com"))
        .await
        .unwrap();

    assert_eq!(
        answer["response"]["userAttributesToMap"]["email"],
        "alice@example.com"
    );
    assert_eq!(f.pool.state().creates, 1);
    let fresh = f
        .directory
        .provider(GOOGLE, "google-1")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(fresh.user_id, alice.user_id);
}
