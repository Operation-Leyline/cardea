//! Which identities a signed-in person may link: their own mailbox, or a
//! private relay address after a recent sign-in.

use super::*;
use crate::RECENT_SIGN_IN_SECONDS;
use serde_json::{Value, json};

const RELAY: &str = "x1y2@privaterelay.appleid.com";

fn apple(email: &str, private: Value) -> ProviderIdentity {
    ProviderIdentity::from_verified_claims(
        Provider::Apple,
        &json!({"sub":"a", "email":email, "email_verified":"true", "is_private_email":private}),
    )
    .unwrap()
}

/// Each way Apple marks a relay: the flag in either form, or the domain alone.
fn relays() -> [ProviderIdentity; 4] {
    [
        apple(RELAY, json!("true")),
        apple(RELAY, json!(null)),
        apple("hidden@example.net", json!(true)),
        apple("hidden@icloud.com", json!("true")),
    ]
}

fn unbound(directory: &Mock) {
    let state = directory.0.lock().unwrap();
    assert!(state.providers.is_empty() && state.links.is_empty());
    assert_eq!(state.creates, 0);
}

#[tokio::test]
async fn a_relay_links_to_a_freshly_signed_in_caller() {
    for identity in relays() {
        for age in [-30, 0, RECENT_SIGN_IN_SECONDS] {
            let directory = Mock::default();
            let user = native(&directory, "owner@example.com");
            assert_eq!(
                resolve(&directory, &identity, Some(signed_in(&user, age))).await,
                Ok(user.clone()),
                "{} {age}",
                identity.email
            );
            // It signs in to that account from then on, and claims no mailbox.
            assert_eq!(resolve(&directory, &identity, None).await, Ok(user));
            let state = directory.0.lock().unwrap();
            assert_eq!(state.links[&(Provider::Apple, "a".into())], "existing-sub");
            assert_eq!((state.emails.len(), state.creates), (1, 0));
        }
    }
}

#[tokio::test]
async fn a_relay_with_a_stale_sign_in_asks_for_a_new_one() {
    for identity in relays() {
        for age in [RECENT_SIGN_IN_SECONDS + 1, 86_400, -3_600] {
            let directory = Mock::default();
            let user = native(&directory, "owner@example.com");
            assert_eq!(
                resolve(&directory, &identity, Some(signed_in(&user, age))).await,
                Err(Error::RecentSignInRequired),
                "{} {age}",
                identity.email
            );
            unbound(&directory);
        }
    }
}

/// However recent the sign-in, another address that is not a relay is refused.
#[tokio::test]
async fn another_address_that_is_not_a_relay_is_refused() {
    let directory = Mock::default();
    let user = native(&directory, "owner@example.com");
    for identity in [
        apple("other@example.com", json!("false")),
        apple("other@icloud.com", json!(null)),
        // An unclear flag is evidence of nothing.
        apple("other@example.com", json!("TRUE")),
        google("other@gmail.com"),
    ] {
        assert_eq!(
            resolve(&directory, &identity, Some(signed_in(&user, 0))).await,
            Err(Error::Conflict),
            "{}",
            identity.email
        );
    }
    unbound(&directory);
}

/// The account's own mailbox needs no recent sign-in, relay or not.
#[tokio::test]
async fn a_relay_that_is_the_accounts_own_address_links_as_any_mailbox_does() {
    let directory = Mock::default();
    let user = native(&directory, RELAY);
    assert_eq!(
        resolve(
            &directory,
            &apple(RELAY, json!("true")),
            Some(signed_in(&user, 86_400))
        )
        .await,
        Ok(user)
    );
}

#[tokio::test]
async fn a_relay_is_never_linked_without_a_session_whatever_it_claims() {
    let directory = Mock::default();
    native(&directory, RELAY);
    let mut identity = apple(RELAY, json!("true"));
    // Even a hand-built identity that calls itself authoritative.
    identity.authoritative = true;
    assert_eq!(
        resolve(&directory, &identity, None).await,
        Err(Error::LinkRequired)
    );
    unbound(&directory);
}

#[tokio::test]
async fn a_relay_cannot_join_a_caller_the_directory_does_not_hold() {
    let directory = Mock::default();
    let stranger = User {
        user_id: "stranger".into(),
        username: "stranger".into(),
        email: "stranger@example.com".into(),
    };
    assert_eq!(
        resolve(
            &directory,
            &apple(RELAY, json!("true")),
            Some(signed_in(&stranger, 0))
        )
        .await,
        Err(Error::Conflict)
    );
    unbound(&directory);
}

/// A bound relay never moves, however recent the other caller's sign-in.
#[tokio::test]
async fn a_bound_relay_cannot_be_taken_by_another_account() {
    let directory = Mock::default();
    let first = native(&directory, "owner@example.com");
    let identity = apple(RELAY, json!("true"));
    resolve(&directory, &identity, Some(signed_in(&first, 0)))
        .await
        .unwrap();
    let other = User {
        user_id: "other-user".into(),
        username: "other".into(),
        email: "other@example.com".into(),
    };
    assert_eq!(
        resolve(&directory, &identity, Some(signed_in(&other, 0))).await,
        Err(Error::Conflict)
    );
}
