//! Erasure over an in-process DynamoDB and a fake pool.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, EmailOwner, Error, Provider, User};
use serde_json::{Value, json};

use super::*;
use crate::{
    testing::{Fixture, fixture},
    transact,
};

mod interrupted;
mod retry;
mod reuse;

const GOOGLE: Provider = Provider::Google;
const APPLE: Provider = Provider::Apple;

const EMAIL: &str = "EMAIL#alice@example.com";
const BINDING: &str = "PROVIDER#Google#google-1";
const LIST: &str = "METHODS#sub-of-alice";

/// Give the user's mailbox row its `userId`, as provisioning does.
async fn provision(f: &Fixture, user: &User) {
    let guard = f
        .directory
        .profile_guard(&user.email, &user.username, &user.user_id)
        .await
        .unwrap();
    transact(f.directory.dynamodb(), vec![guard]).await.unwrap();
}

/// A provisioned account with Google and Apple linked.
async fn linked_account() -> (Fixture, User) {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    provision(&f, &alice).await;
    f.link(&alice, GOOGLE, "google-1").await;
    f.link(&alice, APPLE, "apple-1").await;
    (f, alice)
}

async fn plan(f: &Fixture, user: &User) -> ErasurePlan {
    plan_erasure(&f.directory, user).await.unwrap()
}

async fn erase(f: &Fixture, plan: &ErasurePlan) -> ErasureReport {
    erase_user(&f.directory, plan).await.unwrap()
}

/// The whole sequence: plan, delete from the pool, erase.
async fn delete_account(f: &Fixture, user: &User) -> ErasureReport {
    let plan = plan(f, user).await;
    f.pool.remove(&user.username);
    erase(f, &plan).await
}

async fn present(f: &Fixture, key: &str) -> bool {
    f.item(key).await.is_some()
}

fn counts(emails: usize, providers: usize, methods: usize, kept: usize) -> ErasureReport {
    ErasureReport {
        emails,
        providers,
        methods,
        kept,
    }
}

#[tokio::test]
async fn every_row_of_the_user_goes_and_no_one_elses() {
    let (f, alice) = linked_account().await;
    let bob = f.account("bob", "Cognito").await;
    provision(&f, &bob).await;
    f.link(&bob, GOOGLE, "google-2").await;

    assert_eq!(delete_account(&f, &alice).await, counts(1, 2, 1, 0));

    for key in [EMAIL, BINDING, "PROVIDER#SignInWithApple#apple-1", LIST] {
        assert!(!present(&f, key).await, "{key}");
    }
    for key in [
        "EMAIL#bob@example.com",
        "PROVIDER#Google#google-2",
        "METHODS#sub-of-bob",
        "SYSTEM#READY",
    ] {
        assert!(present(&f, key).await, "{key}");
    }
}

/// An account from before the pool used Cardea: the pool and the bindings know
/// its identity, and there is no list.
#[tokio::test]
async fn an_identity_only_the_pool_lists_is_recorded_then_erased() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    provision(&f, &alice).await;
    f.pool_link("alice", GOOGLE, "google-1");
    f.unlisted_binding(&alice, GOOGLE, "google-1").await;
    assert!(!present(&f, LIST).await);

    let planned = plan(&f, &alice).await;
    assert!(present(&f, LIST).await, "a repeat can find the binding");
    f.pool.remove("alice");

    assert_eq!(erase(&f, &planned).await, counts(1, 1, 1, 0));
}

/// No provisioning ever named the user on the mailbox's row, and the account is
/// disabled, as a deletion worker leaves it.
#[tokio::test]
async fn an_unbound_claim_the_pool_proves_is_the_users_goes() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool.state().users.get_mut("alice").unwrap().disabled = true;
    assert!(!f.item(EMAIL).await.unwrap().contains_key("userId"));

    assert_eq!(delete_account(&f, &alice).await, counts(1, 0, 0, 0));
    assert!(!present(&f, EMAIL).await);
}

/// A provider-made account: its claim's username is the address, and the pool's
/// own username is another.
#[tokio::test]
async fn a_claim_made_under_the_address_is_found_through_the_alias() {
    let f = fixture().await;
    f.directory
        .claim_email(&EmailOwner {
            email: "alice@example.com".into(),
            username: "alice@example.com".into(),
            origin: "Google".into(),
        })
        .await
        .unwrap();
    f.pool
        .add("uuid-1", "sub-of-alice", "alice@example.com", "CONFIRMED");
    let alice = User {
        user_id: "sub-of-alice".into(),
        username: "uuid-1".into(),
        email: "alice@example.com".into(),
    };

    assert_eq!(delete_account(&f, &alice).await, counts(1, 0, 0, 0));
}

#[tokio::test]
async fn nothing_is_erased_while_the_pool_holds_the_user() {
    let (f, alice) = linked_account().await;
    let planned = plan(&f, &alice).await;

    assert_eq!(
        erase_user(&f.directory, &planned).await,
        Err(ErasureError::UserStillExists)
    );
    for key in [EMAIL, BINDING, LIST] {
        assert!(present(&f, key).await, "{key}");
    }
}

#[tokio::test]
async fn a_directory_that_is_not_ready_refuses_both_steps() {
    let (f, alice) = linked_account().await;
    let planned = plan(&f, &alice).await;
    f.pool.remove("alice");
    f.delete("SYSTEM#READY").await;

    assert_eq!(
        plan_erasure(&f.directory, &alice).await.map(|_| ()),
        Err(Error::NotReady)
    );
    assert_eq!(
        erase_user(&f.directory, &planned).await,
        Err(ErasureError::Identity(Error::NotReady))
    );
    assert!(present(&f, EMAIL).await);
}

#[tokio::test]
async fn printing_a_plan_shows_no_address_or_subject() {
    let (f, alice) = linked_account().await;
    let text = format!("{:?}", plan(&f, &alice).await);
    assert!(text.contains("sub-of-alice"));
    for private in ["example.com", "google-1", "apple-1"] {
        assert!(!text.contains(private), "{private}");
    }
}
