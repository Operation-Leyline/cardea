//! An unlink that stopped part-way.

use super::*;

const KEY: &str = "METHODS#sub-of-alice";

#[tokio::test]
async fn a_failed_pool_call_is_finished_by_a_repeat() {
    let (f, alice) = password_and_google().await;
    f.pool.state().disable_failures = 1;

    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::Identity(Error::Unavailable))
    );
    // Still linked, and shown, so the person can ask again; the mark is kept.
    assert_eq!(f.identities("alice").len(), 1);
    assert!(stored(&f, &alice).await.unwrap().1.contains("removing"));
    assert_eq!(list(&f, &alice).await.len(), 2);

    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
    assert_eq!(f.identities("alice"), []);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(stored(&f, &alice).await.unwrap().1, "[]");
}

#[tokio::test]
async fn a_lost_answer_from_the_pool_is_success() {
    let (f, alice) = password_and_google().await;
    f.pool.state().lost_disables = 1;
    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
}

/// The pool let go and the process stopped there: the binding is still held,
/// and only the list remembers which one.
async fn stopped_after_the_pool() -> (Fixture, User) {
    let (f, alice) = password_and_google().await;
    f.pool.state().disable_failures = 1;
    assert!(unlink(&f, &alice, GOOGLE).await.is_err());
    f.pool_unlink_all("alice");
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice.clone()));
    (f, alice)
}

#[tokio::test]
async fn a_binding_left_behind_is_released_by_a_repeat() {
    let (f, alice) = stopped_after_the_pool().await;

    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));

    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(stored(&f, &alice).await.unwrap().1, "[]");
    // Free for another account.
    let bob = f.account("bob", "Cognito").await;
    f.link(&bob, GOOGLE, "google-1").await;
}

#[tokio::test]
async fn a_new_link_finishes_an_unlink_the_pool_completed() {
    let (f, alice) = stopped_after_the_pool().await;

    // The first attempt finishes the removal and links nothing.
    assert_eq!(
        f.try_link(&alice, GOOGLE, "google-1", &alice.email).await,
        Err(OperationError::Identity(Error::NotReady))
    );
    assert_eq!(f.identities("alice"), []);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);

    f.link(&alice, GOOGLE, "google-1").await;
    assert_eq!(f.identities("alice").len(), 1);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice));
}

#[tokio::test]
async fn an_identity_still_in_the_pool_waits_for_its_unlink() {
    let (f, alice) = password_and_google().await;
    f.pool.state().disable_failures = 1;
    assert!(unlink(&f, &alice, GOOGLE).await.is_err());

    assert_eq!(
        f.try_link(&alice, GOOGLE, "google-1", &alice.email).await,
        Err(OperationError::Identity(Error::NotReady))
    );
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice.clone()));
    // A direct link, as the pre-signup trigger makes, is held off too.
    assert_eq!(
        f.directory.link(GOOGLE, "google-1", &alice).await,
        Err(Error::NotReady)
    );
}

#[tokio::test]
async fn an_unfinished_removal_does_not_count_as_a_method() {
    let f = fixture().await;
    let alice = f.passwordless("alice").await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, APPLE, "apple-1").await;
    f.pool.state().disable_failures = 1;
    assert!(unlink(&f, &alice, GOOGLE).await.is_err());

    assert_eq!(
        unlink(&f, &alice, APPLE).await,
        Err(OperationError::LastSignInMethod)
    );
    // The removal already counted may be repeated.
    assert_eq!(unlink(&f, &alice, GOOGLE).await, Ok(()));
}

/// A removal that another caller already finished touches nothing: the binding
/// there now is a newer link's.
#[tokio::test]
async fn a_late_finish_leaves_a_newer_link_alone() {
    let (f, alice) = password_and_google().await;
    let removed = row::Identity {
        provider: GOOGLE,
        subject: "google-1".into(),
    };
    f.directory
        .finish_removal(&alice, std::slice::from_ref(&removed))
        .await
        .unwrap();
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice.clone()));
    assert!(stored(&f, &alice).await.unwrap().1.contains("google-1"));
}

#[tokio::test]
async fn another_users_binding_is_left_alone() {
    let (f, alice) = stopped_after_the_pool().await;
    let bob = f.account("bob", "Cognito").await;
    f.delete("PROVIDER#Google#google-1").await;
    f.directory
        .claim_provider(GOOGLE, "google-1", &bob)
        .await
        .unwrap();

    unlink(&f, &alice, GOOGLE).await.unwrap();

    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(bob));
}

#[tokio::test]
async fn a_list_that_does_not_decode_stops_every_change() {
    let (f, alice) = password_and_google().await;
    f.directory
        .dynamodb()
        .update_item()
        .table_name(f.directory.table())
        .key("identityKey", Av::S(KEY.into()))
        .update_expression("SET identities = :value")
        .expression_attribute_values(":value", Av::S("junk".into()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unlink(&f, &alice, GOOGLE).await,
        Err(OperationError::Identity(Error::Conflict))
    );
    assert_eq!(f.identities("alice").len(), 1);
}
