//! Links that stopped, or ran, around an account's deletion.

use super::*;

/// The directory bound the subject and the process stopped there: the pool
/// never linked it, and no repeat came.
#[tokio::test]
async fn a_link_that_stopped_after_the_binding_is_erased() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.directory
        .claim_provider(GOOGLE, "google-1", &alice)
        .await
        .unwrap();
    assert_eq!(f.identities("alice"), []);

    assert_eq!(delete_account(&f, &alice).await, counts(1, 1, 1, 0));
    assert!(!present(&f, BINDING).await);
}

#[tokio::test]
async fn a_link_the_pool_refused_is_erased() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool.state().link_failures = 1;
    assert!(
        f.try_link(&alice, GOOGLE, "google-1", &alice.email)
            .await
            .is_err()
    );

    assert_eq!(delete_account(&f, &alice).await, counts(1, 1, 1, 0));
    assert!(!present(&f, BINDING).await);
}

/// A link already under way binds between the plan and the erasure.
#[tokio::test]
async fn a_binding_made_after_the_plan_is_erased() {
    let (f, alice) = linked_account().await;
    let planned = plan(&f, &alice).await;
    f.directory
        .claim_provider(GOOGLE, "google-late", &alice)
        .await
        .unwrap();
    f.pool.remove("alice");

    assert_eq!(erase(&f, &planned).await, counts(1, 3, 1, 0));
    assert!(!present(&f, "PROVIDER#Google#google-late").await);
}

/// A link that starts once the user is gone binds nothing.
#[tokio::test]
async fn nothing_binds_to_an_erased_user() {
    let (f, alice) = linked_account().await;
    delete_account(&f, &alice).await;

    assert_eq!(
        f.directory
            .claim_provider(GOOGLE, "google-late", &alice)
            .await,
        Err(Error::Conflict)
    );
    assert!(!present(&f, "PROVIDER#Google#google-late").await);
    assert!(!present(&f, LIST).await);
}
