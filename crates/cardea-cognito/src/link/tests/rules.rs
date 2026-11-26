//! What the generic operations add: the provider on the challenge, malformed
//! requests, who may link, and failures part-way.

use cardea_core::{Error, Provider};

use super::*;
use crate::testing::{accounts::session, provider::token};

#[tokio::test]
async fn a_client_token_stays_with_its_first_provider() {
    let f = Link::new(Provider::Google).await;
    f.create(&f.alice, "client-token").await.unwrap();
    let other = create_identity_link(
        &f.fixture.directory,
        &clients(),
        &f.alice,
        Provider::Apple,
        "client-token",
    )
    .await;
    assert_eq!(
        other,
        Err(OperationError::Identity(Error::ClientTokenMismatch))
    );
}

#[tokio::test]
async fn a_provider_without_a_client_id_is_not_offered() {
    let f = Link::new(Provider::Apple).await;
    let google_only = ProviderClients::new()
        .with(Provider::Google, "google-client")
        .with(Provider::Apple, "");
    assert_eq!(
        create_identity_link(
            &f.fixture.directory,
            &google_only,
            &f.alice,
            Provider::Apple,
            "client-token",
        )
        .await,
        Err(OperationError::ProviderNotConfigured)
    );
    // One configured when the challenge was made, and since withdrawn.
    let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
    assert_eq!(
        complete_identity_link(
            &f.fixture.directory,
            &f.proofs,
            &google_only,
            session(&f.alice, 0),
            &challenge.link_id,
            &proof,
        )
        .await,
        Err(OperationError::ProviderNotConfigured)
    );
}

#[tokio::test]
async fn malformed_requests_are_invalid() {
    let f = Link::new(Provider::Google).await;
    for client_token in ["", "has space", "é", &"x".repeat(129)] {
        assert_eq!(
            f.create(&f.alice, client_token).await,
            Err(OperationError::Identity(Error::Invalid))
        );
    }
    let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
    for id in ["", "short", &"A".repeat(64), &"a".repeat(65)] {
        assert_eq!(
            f.complete(&f.alice, id, &proof).await,
            identity(Error::Invalid)
        );
    }
    for token in ["", &"x".repeat(16 * 1024 + 1)] {
        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, token).await,
            identity(Error::Invalid)
        );
    }
    assert_eq!(f.checks(), 0);
}

#[tokio::test]
async fn nothing_is_linked_before_the_directory_is_ready() {
    let f = Link::new(Provider::Google).await;
    let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
    f.fixture.delete("SYSTEM#READY").await;
    assert_eq!(
        f.create(&f.alice, "another").await,
        Err(OperationError::Identity(Error::NotReady))
    );
    assert_eq!(
        f.complete(&f.alice, &challenge.link_id, &proof).await,
        identity(Error::NotReady)
    );
}

#[tokio::test]
async fn a_challenge_that_does_not_decode_proves_nothing() {
    let f = Link::new(Provider::Google).await;
    let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
    f.update(
        &f.alice,
        &challenge.link_id,
        "SET deadline = :value",
        Some(Av::S("soon".into())),
    )
    .await;
    assert_eq!(
        f.complete(&f.alice, &challenge.link_id, &proof).await,
        identity(Error::Invalid)
    );
}

#[tokio::test]
async fn another_mailbox_that_is_no_relay_is_refused() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let challenge = f.create(&f.alice, "client-token").await.unwrap();
        let proof = token(provider, &challenge.nonce, SUBJECT, "other@example.com");
        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, &proof).await,
            identity(Error::Conflict)
        );
        assert_eq!(f.links(), 0);
        assert_eq!(f.bound(SUBJECT).await, None);
    }
}

#[tokio::test]
async fn an_alias_of_the_accounts_mailbox_links_and_keeps_its_spelling() {
    let f = Link::new(Provider::Google).await;
    f.fixture
        .try_link(
            &f.alice,
            Provider::Google,
            SUBJECT,
            "Alice+work@Example.com",
        )
        .await
        .unwrap();
    let list = f.fixture.item("METHODS#sub-of-alice").await.unwrap();
    assert!(
        list["identities"]
            .as_s()
            .unwrap()
            .contains("Alice+work@Example.com")
    );
}

/// A link the pool refused is finished by repeating the same request.
#[tokio::test]
async fn a_failed_pool_link_is_finished_by_a_repeat() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        f.fixture.pool.state().link_failures = 1;
        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, &proof).await,
            identity(Error::Unavailable)
        );
        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, &proof).await,
            Ok(f.alice.clone())
        );
        assert_eq!(f.links(), 1);
    }
}
