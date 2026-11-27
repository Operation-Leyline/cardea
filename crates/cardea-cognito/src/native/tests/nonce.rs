//! The nonce: issued by the server, carried by the token, spent once.

use super::*;
use crate::native::nonce::spend_nonce;

#[tokio::test]
async fn a_nonce_names_the_google_client_and_expires() {
    let fixture = fixture().await;
    let before = u64::try_from(now()).unwrap();
    let issued = create_sign_in_nonce(&fixture.directory, &native(), Provider::Google)
        .await
        .unwrap();
    assert_eq!(issued.client_id, client_id(Provider::Google));
    assert!(well_formed(&issued.nonce));
    assert!(issued.expires_at >= before + NONCE_LIFETIME_SECONDS);
    assert!(!format!("{issued:?}").contains(&issued.nonce));
    let rows = fixture.rows_under("NONCE#").await;
    assert_eq!(rows.len(), 1);
    // The table holds the nonce's HMAC, never the nonce.
    assert!(!format!("{rows:?}").contains(&issued.nonce));
    assert_eq!(rows[0]["expiresAt"], Av::N(issued.expires_at.to_string()));
}

#[tokio::test]
async fn two_nonces_differ() {
    let fixture = fixture().await;
    assert_ne!(fixture.nonce().await, fixture.nonce().await);
}

#[tokio::test]
async fn a_nonce_is_spent_once_even_by_another_identity() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    fixture.begin(&google(&nonce), WEB).await.unwrap();
    for replay in [
        google(&nonce),
        token(Provider::Google, &nonce, "g-subject-2", "other@gmail.com"),
    ] {
        assert_eq!(
            fixture.begin(&replay, WEB).await.unwrap_err(),
            refused(Error::Invalid)
        );
    }
    assert_eq!(fixture.rows_under("TICKET#").await.len(), 1);
    assert_eq!(fixture.pool.state().creates, 1);
}

#[tokio::test]
async fn concurrent_uses_of_one_nonce_yield_one_ticket() {
    let fixture = fixture().await;
    let token = google(&fixture.nonce().await);
    let (first, second) = tokio::join!(fixture.begin(&token, WEB), fixture.begin(&token, WEB));
    assert_eq!(
        usize::from(first.is_ok()) + usize::from(second.is_ok()),
        1,
        "{first:?} {second:?}"
    );
    assert_eq!(fixture.rows_under("TICKET#").await.len(), 1);
}

/// A token without a nonce, with one the server never issued, or with one of
/// another shape.
#[tokio::test]
async fn a_token_without_an_issued_nonce_is_refused_and_makes_nothing() {
    let fixture = fixture().await;
    let issued = fixture.nonce().await;
    for token in [
        google_with(&issued, "nonce", Value::Null),
        google_with(&issued, "nonce", json!(7)),
        google(""),
        google("chosen-by-the-caller"),
        google(&"0".repeat(64)),
    ] {
        assert_eq!(
            fixture.begin(&token, WEB).await.unwrap_err(),
            refused(Error::Invalid)
        );
    }
    assert_eq!(fixture.pool.state().creates, 0);
    // The issued one is still good.
    assert!(fixture.begin(&google(&issued), WEB).await.is_ok());
}

/// A linking challenge's nonce is not a sign-in nonce.
#[tokio::test]
async fn a_link_challenges_nonce_does_not_sign_in() {
    let fixture = fixture().await;
    let alice = fixture.account("alice", "Cognito").await;
    let link = fixture.challenge(&alice, Provider::Google).await;
    assert_eq!(
        fixture.begin(&google(&link.nonce), WEB).await.unwrap_err(),
        refused(Error::Invalid)
    );
}

#[tokio::test]
async fn a_nonce_lapses() {
    let fixture = fixture().await;
    let key = ticket_key("a1");
    let nonce = fixture.nonce().await;
    let later = u64::try_from(now()).unwrap() + NONCE_LIFETIME_SECONDS + 1;
    assert_eq!(
        spend_nonce(&fixture.directory, &key, &nonce, later).await,
        Err(Error::Invalid)
    );
    let sooner = u64::try_from(now()).unwrap();
    assert_eq!(
        spend_nonce(&fixture.directory, &key, &nonce, sooner).await,
        Ok(())
    );
}

#[tokio::test]
async fn a_nonce_issued_under_another_key_is_unknown() {
    let fixture = fixture().await;
    let other = NativeSignIn::new(clients(), [WEB], ticket_key("b2"));
    let nonce = create_sign_in_nonce(&fixture.directory, &other, Provider::Google)
        .await
        .unwrap()
        .nonce;
    assert_eq!(
        fixture.begin(&google(&nonce), WEB).await.unwrap_err(),
        refused(Error::Invalid)
    );
}

#[tokio::test]
async fn only_a_configured_google_offers_a_nonce() {
    let fixture = fixture().await;
    // Apple is configured for linking, and still not offered natively.
    let apple = create_sign_in_nonce(&fixture.directory, &native(), Provider::Apple).await;
    assert_eq!(apple.unwrap_err(), OperationError::ProviderNotConfigured);
    let none = NativeSignIn::new(ProviderClients::new(), [WEB], ticket_key("a1"));
    let google = create_sign_in_nonce(&fixture.directory, &none, Provider::Google).await;
    assert_eq!(google.unwrap_err(), OperationError::ProviderNotConfigured);
    assert!(fixture.rows_under("NONCE#").await.is_empty());
}

#[tokio::test]
async fn without_a_key_or_an_open_directory_nothing_is_issued() {
    let fixture = fixture().await;
    let keyless = NativeSignIn::new(clients(), [WEB], NoKey);
    let result = create_sign_in_nonce(&fixture.directory, &keyless, Provider::Google).await;
    assert_eq!(result.unwrap_err(), refused(Error::Unavailable));
    fixture.delete("SYSTEM#READY").await;
    let result = create_sign_in_nonce(&fixture.directory, &native(), Provider::Google).await;
    assert_eq!(result.unwrap_err(), refused(Error::NotReady));
    assert!(fixture.rows_under("NONCE#").await.is_empty());
}
