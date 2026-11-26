//! Linking with Apple proofs: the claim checks, and the relay address's need
//! for a recent sign-in.

use cardea_core::{Error, Provider, RECENT_SIGN_IN_SECONDS};
use serde_json::{Value, json};

use super::*;
use crate::testing::provider::{claims, sign, signing_key};

const RELAY: &str = "x7k2@privaterelay.appleid.com";

/// Claims Apple would sign for `email`, flags as strings.
fn apple(nonce: &str, email: &str, private: bool) -> Value {
    let mut claims = claims(Provider::Apple, nonce, SUBJECT, email);
    claims["email_verified"] = json!("true");
    claims["is_private_email"] = json!(private.to_string());
    claims
}

async fn complete_aged(
    f: &Link,
    link_id: &str,
    token: &str,
    age: i64,
) -> Result<User, OperationError> {
    complete_identity_link(
        &f.fixture.directory,
        &f.proofs,
        &clients(),
        session(&f.alice, age),
        link_id,
        token,
    )
    .await
}

#[tokio::test]
async fn a_good_apple_proof_of_the_accounts_mailbox_links() {
    let f = Link::new(Provider::Apple).await;
    let challenge = f.create(&f.alice, "client-token").await.unwrap();
    let token = sign(
        signing_key(),
        &apple(&challenge.nonce, &f.alice.email, false),
    );
    // The same mailbox needs no recent sign-in.
    assert_eq!(
        complete_aged(&f, &challenge.link_id, &token, 30 * 24 * 3600).await,
        Ok(f.alice.clone())
    );
    assert_eq!(f.bound(SUBJECT).await.as_ref(), Some(&f.alice));
}

#[tokio::test]
async fn a_bad_apple_proof_links_nothing() {
    for (case, field, value) in [
        ("wrong issuer", "iss", json!("https://accounts.google.com")),
        ("wrong audience", "aud", json!("com.example.other")),
        ("wrong nonce", "nonce", json!("another-challenge")),
        ("expired", "exp", json!(now() - 1)),
    ] {
        let f = Link::new(Provider::Apple).await;
        let challenge = f.create(&f.alice, "client-token").await.unwrap();
        let mut claims = apple(&challenge.nonce, &f.alice.email, false);
        claims[field] = value;
        let token = sign(signing_key(), &claims);

        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, &token).await,
            identity(Error::Invalid),
            "{case}"
        );
        assert_eq!(f.links(), 0, "{case}");
        assert_eq!(f.bound(SUBJECT).await, None, "{case}");
        let row = f.row(&f.alice, &challenge.link_id).await;
        assert_eq!(row.token_hash, None, "{case}");
    }
}

#[tokio::test]
async fn a_relay_address_links_from_a_fresh_session() {
    let f = Link::new(Provider::Apple).await;
    let challenge = f.create(&f.alice, "client-token").await.unwrap();
    let token = sign(signing_key(), &apple(&challenge.nonce, RELAY, true));
    assert_eq!(
        complete_aged(&f, &challenge.link_id, &token, RECENT_SIGN_IN_SECONDS - 30).await,
        Ok(f.alice.clone())
    );
    assert_eq!(f.bound(SUBJECT).await.as_ref(), Some(&f.alice));
    assert_eq!(f.links(), 1);
}

#[tokio::test]
async fn a_relay_address_needs_a_recent_sign_in() {
    let f = Link::new(Provider::Apple).await;
    let challenge = f.create(&f.alice, "client-token").await.unwrap();
    let token = sign(signing_key(), &apple(&challenge.nonce, RELAY, true));

    assert_eq!(
        complete_aged(&f, &challenge.link_id, &token, RECENT_SIGN_IN_SECONDS + 1).await,
        identity(Error::RecentSignInRequired)
    );
    assert_eq!(f.links(), 0);
    assert_eq!(f.bound(SUBJECT).await, None);

    // Signed in again, the same request goes through.
    assert_eq!(
        complete_aged(&f, &challenge.link_id, &token, 0).await,
        Ok(f.alice.clone())
    );
}
