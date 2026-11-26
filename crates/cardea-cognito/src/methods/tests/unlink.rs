//! `UnlinkSignInMethod`.

use std::{sync::Arc, time::Duration};

use super::*;

#[tokio::test]
async fn the_last_method_is_refused_and_nothing_changes() {
    for method in Provider::ALL {
        let f = fixture().await;
        let alice = f.passwordless("alice").await;
        f.link(&alice, method, "subject-1").await;
        let before = stored(&f, &alice).await;

        assert_eq!(
            unlink(&f, &alice, method).await,
            Err(OperationError::LastSignInMethod)
        );

        assert_eq!(f.identities("alice").len(), 1);
        assert_eq!(bound(&f, method, "subject-1").await, Some(alice.clone()));
        assert_eq!(stored(&f, &alice).await, before);
        assert_eq!(f.pool.state().disables, 0);
    }
}

#[tokio::test]
async fn google_comes_off_an_account_with_a_password() {
    let (f, alice) = password_and_google().await;

    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));

    assert_eq!(f.identities("alice"), []);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(list(&f, &alice).await, [SignInMethod::Password]);
    assert_eq!(stored(&f, &alice).await.unwrap().1, "[]");
    // The account stays.
    assert!(f.item("EMAIL#alice@example.com").await.is_some());
}

#[tokio::test]
async fn without_a_password_one_provider_must_stay() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, APPLE, "apple-1").await;

    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
    assert_eq!(
        unlink(&f, &alice, APPLE).await,
        Err(OperationError::LastSignInMethod)
    );
    assert_eq!(
        list(&f, &alice).await,
        [provider(APPLE, Some("alice@example.com"))]
    );
}

/// The pool links it, but a sign-in through it could be refused.
#[tokio::test]
async fn an_unbound_identity_does_not_count_as_a_method() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.pool_link("alice", APPLE, "apple-1");

    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::LastSignInMethod)
    );

    // Nor one bound to someone else.
    let bob = f.account("bob", "Cognito").await;
    f.directory
        .claim_provider(APPLE, "apple-1", &bob)
        .await
        .unwrap();
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::LastSignInMethod)
    );
    assert_eq!(f.pool.state().disables, 0);
}

/// An account an operator made, whose address nobody verified.
#[tokio::test]
async fn an_unverified_address_does_not_hide_or_hold_the_methods() {
    let (f, alice) = password_and_google().await;
    f.pool.state().users.get_mut("alice").unwrap().unverified = true;

    assert_eq!(list(&f, &alice).await.len(), 2);
    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
    // Linking still needs the verified address.
    assert_eq!(
        f.try_link(&alice, GOOGLE, "google-1", &alice.email).await,
        Err(OperationError::Identity(Error::LinkRequired))
    );
}

/// No provider signs in to an account with an unverified address, so without a
/// password there is no other way in to count on.
#[tokio::test]
async fn an_unverified_passwordless_account_keeps_every_provider_it_has() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, APPLE, "apple-1").await;
    f.pool.state().users.get_mut("alice").unwrap().unverified = true;
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::LastSignInMethod)
    );
    assert_eq!(f.identities("alice").len(), 2);
}

#[tokio::test]
async fn an_unconfirmed_user_changes_nothing() {
    let (f, alice) = password_and_google().await;
    f.pool.state().users.get_mut("alice").unwrap().status = "UNCONFIRMED";
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::Identity(Error::Conflict))
    );
    assert_eq!(f.identities("alice").len(), 1);
}

/// Both removals read the list and the pool before either writes: the second
/// write is refused, and counting again it finds nothing would be left.
#[tokio::test]
async fn two_removals_at_once_cannot_take_both_methods() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, APPLE, "apple-1").await;
    f.pool.state().read_barrier = Some((Arc::new(tokio::sync::Barrier::new(2)), 2));

    let (google, apple) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(unlink(&f, &alice, GOOGLE), unlink(&f, &alice, APPLE))
    })
    .await
    .expect("both removals read the pool");

    let answers = [google, apple];
    assert!(answers.contains(&Ok(())), "{answers:?}");
    assert!(
        answers.contains(&Err(OperationError::LastSignInMethod)),
        "{answers:?}"
    );
    assert_eq!(f.identities("alice").len(), 1);
}

#[tokio::test]
async fn unlinking_what_is_not_linked_succeeds() {
    let (f, alice) = password_and_google().await;
    assert_eq!(unlink(&f, &alice, APPLE).await, Ok(()));
    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
    assert_eq!(f.pool.state().disables, 1);

    // Even for an account whose only method is another provider.
    let bob = f.passwordless("bob").await;
    f.link(&bob, GOOGLE, "google-2").await;
    assert_eq!(unlink(&f, &bob, APPLE).await, Ok(()));
}

#[tokio::test]
async fn every_identity_of_the_provider_comes_off() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, GOOGLE, "google-2").await;
    f.link(&alice, APPLE, "apple-1").await;

    unlink(&f, &alice, GOOGLE).await.unwrap();

    assert_eq!(f.identities("alice").len(), 1);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(bound(&f, GOOGLE, "google-2").await, None);
    assert_eq!(bound(&f, APPLE, "apple-1").await, Some(alice));
}

/// A link made before the list existed.
#[tokio::test]
async fn a_user_without_a_list_can_unlink() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool_link("alice", GOOGLE, "google-1");
    f.directory
        .claim_provider(GOOGLE, "google-1", &alice)
        .await
        .unwrap();

    unlink(&f, &alice, GOOGLE).await.unwrap();

    assert_eq!(f.identities("alice"), []);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(stored(&f, &alice).await.unwrap().1, "[]");
}

#[tokio::test]
async fn a_user_without_a_list_keeps_the_last_method() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.pool_link("alice", GOOGLE, "google-1");
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::LastSignInMethod)
    );
}

#[tokio::test]
async fn an_unlinked_identity_may_join_another_account() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    let bob = f.account("bob", "Cognito").await;
    // A relay address, which belongs to no account's mailbox.
    let relay = "x7k2@privaterelay.appleid.com";
    f.try_link(&alice, APPLE, "apple-1", relay).await.unwrap();
    assert_eq!(
        f.try_link(&bob, APPLE, "apple-1", relay).await,
        Err(OperationError::Identity(Error::Conflict))
    );

    unlink(&f, &alice, APPLE).await.unwrap();

    assert_eq!(
        f.try_link(&bob, APPLE, "apple-1", relay).await,
        Ok(bob.clone())
    );
    assert_eq!(bound(&f, APPLE, "apple-1").await, Some(bob));
    assert_eq!(f.identities("alice"), []);
}

/// A claim whose pool link never happened holds the identity until an unlink
/// releases it.
#[tokio::test]
async fn a_link_that_never_reached_the_pool_can_be_released() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool.state().link_failures = 1;
    assert!(
        f.try_link(&alice, GOOGLE, "google-1", &alice.email)
            .await
            .is_err()
    );
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice.clone()));
    assert_eq!(list(&f, &alice).await, [SignInMethod::Password]);

    // Nothing in the pool, so nothing counts against the remaining methods.
    unlink(&f, &alice, GOOGLE).await.unwrap();

    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(f.pool.state().disables, 0);
}

/// An identity the pool links nowhere is no remaining method.
#[tokio::test]
async fn a_listed_identity_the_pool_lacks_does_not_count_as_a_method() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.pool.state().link_failures = 1;
    assert!(
        f.try_link(&alice, APPLE, "apple-1", &alice.email)
            .await
            .is_err()
    );
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::LastSignInMethod)
    );
}
