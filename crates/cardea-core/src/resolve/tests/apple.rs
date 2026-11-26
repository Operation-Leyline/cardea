//! Apple sign-ins through the same resolution, built from claims so the
//! provider's linking rule is part of what is tested.

use super::*;
use serde_json::json;

fn apple(subject: &str, email: &str, private: bool) -> ProviderIdentity {
    ProviderIdentity::from_verified_claims(
        Provider::Apple,
        &json!({"sub":subject, "email":email, "email_verified":"true",
            "is_private_email":private.to_string()}),
    )
    .unwrap()
}

fn untouched(directory: &Mock) {
    let state = directory.0.lock().unwrap();
    assert!(state.providers.is_empty() && state.links.is_empty());
    assert_eq!(state.creates, 0);
}

#[tokio::test]
async fn a_relay_address_never_links_automatically() {
    // Even one on an Apple domain, and even when an account holds it.
    for email in ["x1y2@privaterelay.appleid.com", "owner@icloud.com"] {
        let directory = Mock::default();
        native(&directory, email);
        assert_eq!(
            resolve(&directory, &apple("a", email, true), None).await,
            Err(Error::LinkRequired),
            "{email}"
        );
        untouched(&directory);
    }
    let empty = Mock::default();
    assert_eq!(
        resolve(
            &empty,
            &apple("a", "x1y2@privaterelay.appleid.com", true),
            None
        )
        .await,
        Err(Error::LinkRequired)
    );
    assert!(empty.0.lock().unwrap().emails.is_empty());
}

#[tokio::test]
async fn a_verified_icloud_address_links_automatically() {
    for domain in ["icloud.com", "me.com", "mac.com"] {
        let email = format!("owner@{domain}");
        let directory = Mock::default();
        let original = native(&directory, &email);
        assert_eq!(
            resolve(&directory, &apple("a", &email, false), None).await,
            Ok(original),
            "{domain}"
        );
        let state = directory.0.lock().unwrap();
        assert_eq!(state.links[&(Provider::Apple, "a".into())], "existing-sub");
        assert_eq!(state.creates, 0);
    }
}

#[tokio::test]
async fn an_apple_first_person_gets_one_account_claimed_as_apples() {
    let directory = Mock::default();
    let identity = apple("a", "owner@icloud.com", false);
    let first = resolve(&directory, &identity, None).await.unwrap();
    assert_eq!(resolve(&directory, &identity, None).await, Ok(first));
    let state = directory.0.lock().unwrap();
    assert_eq!(state.creates, 1);
    assert_eq!(state.emails["owner@icloud.com"].origin, "SignInWithApple");
}

#[tokio::test]
async fn another_verified_domain_needs_a_session_link() {
    let directory = Mock::default();
    let user = native(&directory, "owner@gmail.com");
    let identity = apple("a", "owner@gmail.com", false);
    assert_eq!(
        resolve(&directory, &identity, None).await,
        Err(Error::LinkRequired)
    );
    untouched(&directory);
    assert_eq!(
        resolve(&directory, &identity, Some(signed_in(&user, 0))).await,
        Ok(user.clone())
    );
    // Once linked from the session, Apple signs in on its own.
    assert_eq!(resolve(&directory, &identity, None).await, Ok(user));
}

#[tokio::test]
async fn google_and_apple_share_one_account_and_keep_separate_bindings() {
    let directory = Mock::default();
    let google_first = resolve(&directory, &google("owner@gmail.com"), None)
        .await
        .unwrap();
    // The same subject text under another provider is another identity.
    let identity = apple("stable-subject", "owner@gmail.com", false);
    assert_eq!(
        resolve(&directory, &identity, Some(signed_in(&google_first, 0))).await,
        Ok(google_first)
    );
    let state = directory.0.lock().unwrap();
    assert_eq!((state.creates, state.providers.len()), (1, 2));
}

/// A claim whose account was never finished is completed by whichever
/// authoritative provider signs in next.
#[tokio::test]
async fn another_provider_finishes_an_unfinished_provider_claim() {
    let directory = Mock::default();
    directory.0.lock().unwrap().emails.insert(
        "owner@icloud.com".into(),
        EmailOwner {
            email: "owner@icloud.com".into(),
            username: "owner@icloud.com".into(),
            origin: "Google".into(),
        },
    );
    resolve(&directory, &apple("a", "owner@icloud.com", false), None)
        .await
        .unwrap();
    assert_eq!(directory.0.lock().unwrap().creates, 1);
}
