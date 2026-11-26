//! Repeats after a stop part-way, and rows that changed hands meanwhile.

use super::*;

/// The first attempt stopped after the pool deletion: the plan is lost, the
/// pool can say nothing, and the rows lead to everything.
#[tokio::test]
async fn a_repeat_after_the_pool_deletion_needs_no_kept_plan() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    // Linked in the pool only, and a claim nothing ever bound.
    f.pool_link("alice", GOOGLE, "google-1");
    f.unlisted_binding(&alice, GOOGLE, "google-1").await;
    drop(plan(&f, &alice).await);
    f.pool.remove("alice");

    let again = plan(&f, &alice).await;
    assert_eq!(erase(&f, &again).await, counts(1, 1, 1, 0));

    // And once more, with nothing left.
    let done = plan(&f, &alice).await;
    assert_eq!(erase(&f, &done).await, counts(0, 0, 0, 0));
    assert!(!present(&f, LIST).await);
}

#[tokio::test]
async fn a_failure_part_way_keeps_the_list_and_a_repeat_finishes() {
    let (f, alice) = linked_account().await;
    let planned = plan(&f, &alice).await;
    f.pool.remove("alice");
    // The mailbox's row cannot be read, so the erasure stops after the bindings.
    let good = f.item(EMAIL).await.unwrap();
    let mut bad = good.clone();
    bad.insert("record".into(), Av::S("not json".into()));
    put(&f, bad).await;

    assert_eq!(
        erase_user(&f.directory, &planned).await,
        Err(ErasureError::Identity(Error::Conflict))
    );
    assert!(!present(&f, BINDING).await);
    assert!(present(&f, LIST).await);

    put(&f, good).await;
    assert_eq!(erase(&f, &planned).await, counts(1, 0, 1, 0));
    assert!(!present(&f, EMAIL).await);
}

/// The caller's saved address is not the one the pool and the directory hold,
/// and the first attempt stopped after the pool deletion.
#[tokio::test]
async fn an_address_only_the_pool_knew_survives_a_lost_plan() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    provision(&f, &alice).await;
    let saved = User {
        email: "old@example.com".into(),
        ..alice
    };
    drop(plan(&f, &saved).await);
    f.pool.remove("alice");

    let again = plan(&f, &saved).await;

    assert_eq!(erase(&f, &again).await, counts(1, 0, 1, 0));
    assert!(!present(&f, EMAIL).await);
    assert!(!present(&f, LIST).await);
}

#[tokio::test]
async fn rows_someone_else_has_claimed_since_stay() {
    let (f, alice) = linked_account().await;
    let planned = plan(&f, &alice).await;
    f.pool.remove("alice");
    // Between the two steps the mailbox and one identity change hands.
    f.delete(EMAIL).await;
    f.delete(BINDING).await;
    let carol = User {
        user_id: "sub-of-carol".into(),
        username: "alice".into(),
        email: "alice@example.com".into(),
    };
    f.pool
        .add("alice", &carol.user_id, &carol.email, "CONFIRMED");
    f.directory
        .claim_email(&EmailOwner {
            email: carol.email.clone(),
            username: carol.username.clone(),
            origin: "Cognito".into(),
        })
        .await
        .unwrap();
    provision(&f, &carol).await;
    f.directory
        .claim_provider(GOOGLE, "google-1", &carol)
        .await
        .unwrap();

    // The username is another account's now, which is not this one remaining.
    assert_eq!(erase(&f, &planned).await, counts(0, 1, 1, 2));

    assert_eq!(
        f.directory.provider(GOOGLE, "google-1").await.unwrap(),
        Some(carol)
    );
    assert_eq!(
        f.item(EMAIL).await.unwrap()["userId"],
        Av::S("sub-of-carol".into())
    );
}

/// A newcomer's unbound claim of the freed mailbox is not the old user's, even
/// when a repeat plans again.
#[tokio::test]
async fn a_new_unconfirmed_claim_is_left_alone() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool.remove("alice");
    f.pool.add(
        "alice",
        "sub-of-newcomer",
        "alice@example.com",
        "UNCONFIRMED",
    );

    let planned = plan(&f, &alice).await;

    assert_eq!(erase(&f, &planned).await, counts(0, 0, 0, 1));
    assert!(!f.item(EMAIL).await.unwrap().contains_key("userId"));
}

async fn put(f: &Fixture, item: crate::testing::ddb::Item) {
    f.directory
        .dynamodb()
        .put_item()
        .table_name(f.directory.table())
        .set_item(Some(item))
        .send()
        .await
        .unwrap();
}
