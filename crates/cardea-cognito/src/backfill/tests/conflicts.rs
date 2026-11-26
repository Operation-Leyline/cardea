//! What is reported and left for an operator.

use cardea_core::{Directory, EmailOwner};

use super::*;
use crate::record::EmailRow;

async fn claim(f: &Fixture, email: &str, username: &str) {
    f.directory
        .claim_email(&EmailOwner {
            email: email.into(),
            username: username.into(),
            origin: "Cognito".into(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn two_users_of_one_mailbox_get_nothing() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    user(&f, "other", "CONFIRMED");
    change(&f, "other", |a| a.email = "alice+two@example.com".into());
    f.pool_link("other", GOOGLE, "google-1");
    user(&f, "bob", "CONFIRMED");

    let report = run(&f, Mode::Apply).await;

    let shares = |with: &str| Problem::SharedMailbox {
        with: vec![format!("sub-of-{with}")],
    };
    assert_eq!(
        report.findings,
        [
            finding("alice", shares("other")),
            finding("other", shares("alice")),
        ]
    );
    assert!(report.needs_attention());
    assert_eq!(report.written, counts(1, 0, 0));
    assert!(!present(&f, "EMAIL#alice@example.com").await);
    assert!(!present(&f, "PROVIDER#Google#google-1").await);
    assert!(present(&f, "EMAIL#bob@example.com").await);
}

#[tokio::test]
async fn a_subject_bound_elsewhere_is_reported_and_kept() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    f.pool_link("alice", GOOGLE, "google-1");
    f.pool_link("alice", APPLE, "apple-1");
    let carol = User {
        user_id: "sub-of-carol".into(),
        username: "carol".into(),
        email: "carol@example.com".into(),
    };
    f.unlisted_binding(&carol, GOOGLE, "google-1").await;

    let report = run(&f, Mode::Apply).await;

    assert_eq!(
        report.findings,
        [finding(
            "alice",
            Problem::SubjectBound {
                provider: GOOGLE,
                holder: carol.user_id.clone(),
            }
        )]
    );
    assert_eq!(report.written, counts(1, 1, 1));
    assert_eq!(
        f.directory.provider(GOOGLE, "google-1").await.unwrap(),
        Some(carol)
    );
}

#[tokio::test]
async fn a_binding_with_an_old_address_is_reported() {
    let f = closed().await;
    let alice = user(&f, "alice", "CONFIRMED");
    f.pool_link("alice", GOOGLE, "google-1");
    let old = User {
        email: "old@example.com".into(),
        ..alice
    };
    f.unlisted_binding(&old, GOOGLE, "google-1").await;

    let report = run(&f, Mode::Apply).await;

    let stale = Problem::StaleBinding { provider: GOOGLE };
    assert_eq!(report.findings, [finding("alice", stale)]);
}

#[tokio::test]
async fn a_mailbox_held_by_another_claim_is_left_as_it_is() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    f.pool_link("alice", GOOGLE, "google-1");
    claim(&f, "alice@example.com", "somebody").await;
    let before = f.item("EMAIL#alice@example.com").await;

    let report = run(&f, Mode::Apply).await;

    let held = Problem::MailboxHeld { holder: None };
    assert_eq!(report.findings, [finding("alice", held)]);
    assert_eq!(report.written, counts(0, 0, 0));
    assert_eq!(f.item("EMAIL#alice@example.com").await, before);
}

/// The row names the user, but a sign-in looks its username up and finds
/// nobody.
#[tokio::test]
async fn a_claim_under_a_username_the_pool_dropped_blocks() {
    let f = closed().await;
    let alice = user(&f, "alice", "CONFIRMED");
    f.directory
        .put_new(&EmailRow {
            person: "alice@example.com".into(),
            record: EmailOwner {
                email: "alice+old@example.com".into(),
                username: "alice+old@example.com".into(),
                origin: "Cognito".into(),
            },
            user_id: Some(alice.user_id),
            unconfirmed_expires_at: None,
            password_initialization: None,
            password_set: None,
        })
        .await
        .unwrap();

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::ActivationRefused);
    assert_eq!(report.findings, [finding("alice", Problem::StaleClaim)]);
}

#[tokio::test]
async fn a_lapsing_claim_of_a_confirmed_user_is_not_cover() {
    let f = closed().await;
    user(&f, "alice", "UNCONFIRMED");
    run(&f, Mode::Apply).await;
    change(&f, "alice", |a| a.status = "CONFIRMED");

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::ActivationRefused);
    assert_eq!(report.findings, [finding("alice", Problem::LapsingClaim)]);
}

#[tokio::test]
async fn unreadable_users_and_rows_block() {
    let f = closed().await;
    f.pool.add("anon", "sub-of-anon", "", "CONFIRMED");
    f.pool
        .add("bad", "sub-of-bad", "not an address", "CONFIRMED");
    user(&f, "torn", "CONFIRMED");
    claim(&f, "torn@example.com", "torn").await;
    let mut item = f.item("EMAIL#torn@example.com").await.unwrap();
    item.insert("record".into(), Av::S("not json".into()));
    f.directory
        .dynamodb()
        .put_item()
        .table_name(f.directory.table())
        .set_item(Some(item))
        .send()
        .await
        .unwrap();

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::ActivationRefused);
    let row = RowKind::Email;
    assert_eq!(
        report.findings,
        [
            finding("anon", Problem::NoUsableEmail),
            finding("bad", Problem::NoUsableEmail),
            finding("torn", Problem::UnreadableRow { row }),
        ]
    );
}

#[tokio::test]
async fn notes_do_not_block() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    change(&f, "alice", |a| {
        a.unverified = true;
        a.identities.push(("Facebook".into(), "fb-1".into()));
    });

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::Activated);
    assert_eq!(
        report.findings,
        [
            finding("alice", Problem::UnverifiedEmail),
            finding("alice", Problem::UnsupportedProvider),
        ]
    );
    assert_eq!(report.written, counts(1, 0, 0));
}
