//! Challenges written by earlier deployments, before provider names were
//! stored: no `provider` attribute.

use cardea_core::{Error, Provider};

use super::*;

const NONCE: &str = "earlier-nonce";

/// Write a row as an earlier deployment's `CreateGoogleIdentityLink` does.
async fn unnamed_challenge(f: &Link, extra: &[(&str, &str)]) -> String {
    let link_id = digest("earlier-client-token");
    let time = now();
    let mut request = f
        .fixture
        .directory
        .dynamodb()
        .put_item()
        .table_name(f.fixture.directory.table())
        .item(
            "identityKey",
            Av::S(format!("LINK#{}#{link_id}", f.alice.user_id)),
        )
        .item("nonce", Av::S(NONCE.into()))
        .item("deadline", Av::N((time + 300).to_string()))
        .item("expiresAt", Av::N((time + 86400).to_string()));
    for (name, value) in extra {
        request = request.item(*name, Av::S((*value).into()));
    }
    request.send().await.unwrap();
    link_id
}

#[tokio::test]
async fn a_challenge_without_a_provider_completes_as_googles() {
    let f = Link::new(Provider::Google).await;
    let link_id = unnamed_challenge(&f, &[]).await;
    let proof = f.token(NONCE, SUBJECT);

    assert_eq!(
        f.complete(&f.alice, &link_id, &proof).await,
        Ok(f.alice.clone())
    );
    assert_eq!(f.bound(SUBJECT).await.as_ref(), Some(&f.alice));
    let row = f.row(&f.alice, &link_id).await;
    assert_eq!(row.status.as_deref(), Some("complete"));
    assert_eq!(row.provider, None, "the row keeps its wire format");
}

#[tokio::test]
async fn a_challenge_without_a_provider_takes_no_other_providers_proof() {
    let f = Link::new(Provider::Apple).await;
    let link_id = unnamed_challenge(&f, &[]).await;
    let proof = f.token(NONCE, SUBJECT);
    assert_eq!(
        f.complete(&f.alice, &link_id, &proof).await,
        identity(Error::Invalid)
    );
    assert_eq!(f.links(), 0);
}

#[tokio::test]
async fn a_receipt_without_a_provider_replays() {
    let f = Link::new(Provider::Google).await;
    let proof = f.token(NONCE, SUBJECT);
    let hash = digest(&proof);
    let link_id = unnamed_challenge(
        &f,
        &[
            ("tokenHash", &hash),
            ("providerSubject", SUBJECT),
            ("status", "complete"),
        ],
    )
    .await;
    assert_eq!(
        f.complete(&f.alice, &link_id, &proof).await,
        Ok(f.alice.clone())
    );
    assert_eq!((f.links(), f.checks()), (0, 0));
}

#[tokio::test]
async fn a_challenge_for_an_unknown_provider_is_invalid() {
    let f = Link::new(Provider::Google).await;
    let link_id = unnamed_challenge(&f, &[("provider", "Unknown")]).await;
    let proof = f.token(NONCE, SUBJECT);
    assert_eq!(
        f.complete(&f.alice, &link_id, &proof).await,
        identity(Error::Invalid)
    );
    assert_eq!(f.checks(), 0);
}
