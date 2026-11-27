//! The link flow, over an in-process DynamoDB for the challenge and ownership
//! rows and a fake pool. Only the providers' signing keys are replaced: each
//! proof is a real signed token checked by the real verifier.
//!
//! The first group is the Google link flow's cases, run for every provider.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, Error, Provider, User};
use tabulary::RecordKey;

use super::*;
use crate::{
    OperationError,
    directory::now,
    proof::ProofVerifier,
    record::LinkRow,
    testing::{
        Fixture,
        accounts::{clients, session},
        fixture,
        provider::{Proofs, client_id, token},
    },
};

mod apple;
mod legacy;
mod rules;

const SUBJECT: &str = "provider-subject-1";

pub(super) struct Link {
    pub fixture: Fixture,
    pub alice: User,
    pub proofs: Proofs,
    pub provider: Provider,
}

impl Link {
    pub async fn new(provider: Provider) -> Self {
        let fixture = fixture().await;
        let alice = fixture.account("alice", "Cognito").await;
        Self {
            fixture,
            alice,
            proofs: Proofs::default(),
            provider,
        }
    }

    pub fn links(&self) -> usize {
        self.fixture.pool.state().links
    }

    pub fn checks(&self) -> usize {
        self.proofs.checks.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A token the provider would sign for `nonce`, valid right now.
    pub fn token(&self, nonce: &str, subject: &str) -> String {
        token(self.provider, nonce, subject, &self.alice.email)
    }

    pub async fn complete_with(
        &self,
        verifier: &dyn ProofVerifier,
        user: &User,
        link_id: &str,
        token: &str,
    ) -> Result<User, OperationError> {
        complete_identity_link(
            &self.fixture.directory,
            verifier,
            &clients(),
            session(user, 0),
            link_id,
            token,
        )
        .await
    }

    pub async fn complete(
        &self,
        user: &User,
        link_id: &str,
        token: &str,
    ) -> Result<User, OperationError> {
        self.complete_with(&self.proofs, user, link_id, token).await
    }

    pub async fn create(
        &self,
        user: &User,
        client_token: &str,
    ) -> Result<IdentityLinkChallenge, OperationError> {
        create_identity_link(
            &self.fixture.directory,
            &clients(),
            user,
            self.provider,
            client_token,
        )
        .await
    }

    /// A challenge for `client_token` and a valid proof of it.
    pub async fn challenge(
        &self,
        user: &User,
        client_token: &str,
    ) -> (IdentityLinkChallenge, String) {
        let challenge = self.create(user, client_token).await.unwrap();
        let proof = self.token(&challenge.nonce, SUBJECT);
        (challenge, proof)
    }

    fn row_key(user: &User, link_id: &str) -> String {
        format!("LINK#{}#{link_id}", user.user_id)
    }

    pub async fn row(&self, user: &User, link_id: &str) -> LinkRow {
        self.fixture
            .directory
            .row(link_key(&user.user_id, link_id).unwrap())
            .await
            .unwrap()
            .expect("the challenge row exists")
    }

    async fn update(&self, user: &User, link_id: &str, expression: &str, value: Option<Av>) {
        let mut request = self
            .fixture
            .directory
            .dynamodb()
            .update_item()
            .table_name(self.fixture.directory.table())
            .key("identityKey", Av::S(Self::row_key(user, link_id)))
            .update_expression(expression);
        match value {
            Some(value) => request = request.expression_attribute_values(":value", value),
            None => request = request.expression_attribute_names("#status", "status"),
        }
        request.send().await.unwrap();
    }

    /// Moves the challenge's deadline into the past.
    pub async fn expire(&self, user: &User, link_id: &str) {
        self.update(
            user,
            link_id,
            "SET deadline = :value",
            Some(Av::N("1".into())),
        )
        .await;
    }

    /// Undoes the receipt, as if only that write had failed.
    pub async fn lose_receipt(&self, user: &User, link_id: &str) {
        self.update(user, link_id, "REMOVE #status", None).await;
    }

    pub async fn bound(&self, subject: &str) -> Option<User> {
        self.fixture
            .directory
            .provider(self.provider, subject)
            .await
            .unwrap()
    }
}

fn identity(error: Error) -> Result<User, OperationError> {
    Err(OperationError::Identity(error))
}

#[tokio::test]
async fn a_challenge_names_the_client_and_lasts_five_minutes() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let before = u64::try_from(now()).unwrap();
        let challenge = f.create(&f.alice, "client-token").await.unwrap();

        assert_eq!(challenge.client_id, client_id(provider));
        assert_eq!(challenge.link_id, digest("client-token"));
        assert_eq!(challenge.nonce.len(), 64);
        assert!((before + 300..=before + 302).contains(&challenge.expires_at));
        let row = f.row(&f.alice, &challenge.link_id).await;
        assert_eq!(row.expires_at, challenge.expires_at - 300 + 86400);
        assert_eq!(row.provider.as_deref(), Some(provider.rule().cognito_name));
        let item = f
            .fixture
            .item(&Link::row_key(&f.alice, &challenge.link_id))
            .await
            .unwrap();
        let mut names = item.keys().map(String::as_str).collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(
            names,
            ["deadline", "expiresAt", "identityKey", "nonce", "provider"]
        );

        assert_eq!(f.create(&f.alice, "client-token").await, Ok(challenge));
    }
}

#[tokio::test]
async fn a_valid_proof_links_the_caller_and_records_the_receipt() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;

        let linked = f
            .complete(&f.alice, &challenge.link_id, &proof)
            .await
            .unwrap();

        assert_eq!(linked, f.alice);
        assert_eq!(f.links(), 1);
        assert_eq!(
            f.fixture.identities("alice"),
            [(provider.rule().cognito_name.to_owned(), SUBJECT.to_owned())]
        );
        let row = f.row(&f.alice, &challenge.link_id).await;
        assert_eq!(row.status.as_deref(), Some("complete"));
        assert_eq!(row.token_hash.as_deref(), Some(digest(&proof).as_str()));
        assert_eq!(row.provider_subject.as_deref(), Some(SUBJECT));
        assert_eq!(f.bound(SUBJECT).await.as_ref(), Some(&f.alice));
    }
}

/// A repeat of the same request answers the same, whatever the clock says about
/// the nonce, and checks no proof again.
#[tokio::test]
async fn the_same_token_replays_without_new_proof() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        f.complete(&f.alice, &challenge.link_id, &proof)
            .await
            .unwrap();
        f.expire(&f.alice, &challenge.link_id).await;

        let again = f.complete(&f.alice, &challenge.link_id, &proof).await;

        assert_eq!(again, Ok(f.alice.clone()));
        assert_eq!((f.links(), f.checks()), (1, 1));
    }
}

#[tokio::test]
async fn a_different_token_on_a_used_link_is_a_client_token_mismatch() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        f.complete(&f.alice, &challenge.link_id, &proof)
            .await
            .unwrap();

        // A fresh proof of the same nonce is still not the token the link was
        // bound to.
        let other = f.token(&challenge.nonce, "another-subject");
        assert_ne!(other, proof);
        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, &other).await,
            identity(Error::ClientTokenMismatch)
        );
        assert_eq!(f.links(), 1);
        assert_eq!(f.bound("another-subject").await, None);
    }
}

#[tokio::test]
async fn two_tokens_racing_for_one_link_have_exactly_one_winner() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, first) = f.challenge(&f.alice, "client-token").await;
        let second = f.token(&challenge.nonce, "another-subject");
        let id = &challenge.link_id;

        // Both attempts read the unbound row before either writes, so the loser
        // is turned away by the database condition. An attempt that never
        // reaches the barrier fails the test rather than hanging it.
        let proofs = Proofs::waiting(2);
        let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                f.complete_with(&proofs, &f.alice, id, &first),
                f.complete_with(&proofs, &f.alice, id, &second)
            )
        })
        .await
        .expect("both attempts reached the proof check");
        let answers = [a, b];
        assert_eq!(
            answers.iter().filter(|answer| answer.is_ok()).count(),
            1,
            "{answers:?}"
        );
        assert!(
            answers.contains(&identity(Error::ClientTokenMismatch)),
            "{answers:?}"
        );
        assert_eq!(f.links(), 1, "one proof linked, once");
    }
}

#[tokio::test]
async fn another_users_link_id_and_proof_complete_nothing() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        let bob = f.fixture.account("bob", "Cognito").await;

        assert_eq!(
            f.complete(&bob, &challenge.link_id, &proof).await,
            identity(Error::Invalid),
            "the challenge row is the owner's"
        );
        assert_eq!((f.links(), f.checks()), (0, 0));
        let row = f.row(&f.alice, &challenge.link_id).await;
        assert_eq!(row.token_hash, None, "the owner's row is untouched");
        assert_ne!(
            link_key("one", &digest("token")).unwrap().encode_key(),
            link_key("two", &digest("token")).unwrap().encode_key()
        );
    }
}

#[tokio::test]
async fn an_identity_bound_to_one_user_cannot_be_linked_by_another() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        f.complete(&f.alice, &challenge.link_id, &proof)
            .await
            .unwrap();

        let bob = f.fixture.account("bob", "Cognito").await;
        let (bobs, bobs_proof) = f.challenge(&bob, "client-token").await;
        assert_ne!(
            bobs.nonce, challenge.nonce,
            "one client token, two users, two challenges"
        );
        assert_eq!(
            f.complete(&bob, &bobs.link_id, &bobs_proof).await,
            identity(Error::Conflict)
        );
        assert_eq!(f.links(), 1);
        let row = f.row(&bob, &bobs.link_id).await;
        assert_ne!(row.status.as_deref(), Some("complete"));
        assert_eq!(f.bound(SUBJECT).await.as_ref(), Some(&f.alice));
    }
}

#[tokio::test]
async fn an_expired_nonce_cannot_complete_and_checks_no_proof() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        f.expire(&f.alice, &challenge.link_id).await;

        assert_eq!(
            f.complete(&f.alice, &challenge.link_id, &proof).await,
            identity(Error::Invalid)
        );

        assert_eq!((f.links(), f.checks()), (0, 0));
        let row = f.row(&f.alice, &challenge.link_id).await;
        assert_eq!(row.token_hash, None);
    }
}

#[tokio::test]
async fn asking_again_does_not_renew_an_expired_nonce() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, _) = f.challenge(&f.alice, "client-token").await;
        f.expire(&f.alice, &challenge.link_id).await;

        assert_eq!(
            f.create(&f.alice, "client-token").await,
            Err(OperationError::Identity(Error::Invalid))
        );
    }
}

#[tokio::test]
async fn a_proof_for_another_nonce_is_refused_and_binds_nothing() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, _) = f.challenge(&f.alice, "client-token").await;
        let id = &challenge.link_id;
        let stale = f.token("a-nonce-from-another-challenge", SUBJECT);

        assert_eq!(
            f.complete(&f.alice, id, &stale).await,
            identity(Error::Invalid)
        );

        assert_eq!(f.links(), 0);
        let row = f.row(&f.alice, id).await;
        assert_eq!(row.token_hash, None, "no token was recorded");
    }
}

#[tokio::test]
async fn a_link_id_with_no_challenge_is_invalid() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (_, proof) = f.challenge(&f.alice, "client-token").await;

        assert_eq!(
            f.complete(&f.alice, &"a".repeat(64), &proof).await,
            identity(Error::Invalid)
        );
        assert_eq!(f.checks(), 0);
    }
}

/// The pool linked and the receipt did not finish: the retry completes the
/// receipt from what happened, even after the nonce is gone.
#[tokio::test]
async fn a_retry_after_the_link_landed_finishes_the_receipt_without_new_proof() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        let id = &challenge.link_id;
        f.complete(&f.alice, id, &proof).await.unwrap();

        f.lose_receipt(&f.alice, id).await;
        f.expire(&f.alice, id).await;

        assert_eq!(f.complete(&f.alice, id, &proof).await, Ok(f.alice.clone()));
        assert_eq!((f.links(), f.checks()), (1, 1));
        let row = f.row(&f.alice, id).await;
        assert_eq!(row.status.as_deref(), Some("complete"));
    }
}

/// The same retry, but nothing was linked: an expired nonce is not revived to
/// do it now.
#[tokio::test]
async fn an_expired_retry_that_never_linked_does_not_link() {
    for provider in Provider::ALL {
        let f = Link::new(provider).await;
        let (challenge, proof) = f.challenge(&f.alice, "client-token").await;
        let id = &challenge.link_id;
        f.complete(&f.alice, id, &proof).await.unwrap();

        f.lose_receipt(&f.alice, id).await;
        f.fixture.pool_unlink_all("alice");
        f.expire(&f.alice, id).await;

        assert_eq!(
            f.complete(&f.alice, id, &proof).await,
            identity(Error::Invalid)
        );
        assert_eq!((f.links(), f.checks()), (1, 1), "no second link");
        let row = f.row(&f.alice, id).await;
        assert_ne!(row.status.as_deref(), Some("complete"));
    }
}
