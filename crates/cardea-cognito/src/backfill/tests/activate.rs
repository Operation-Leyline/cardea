//! Opening the directory.

use super::*;

#[tokio::test]
async fn a_covered_pool_is_opened() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::Activated);
    let marker = f.item("SYSTEM#READY").await.unwrap();
    assert_eq!(marker["version"], Av::N("1".into()));
}

#[tokio::test]
async fn an_empty_pool_is_opened() {
    let f = closed().await;
    assert_eq!(
        run(&f, Mode::ApplyAndActivate).await.outcome,
        Outcome::Activated
    );
}

#[tokio::test]
async fn apply_alone_never_opens() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    run(&f, Mode::Apply).await;
    assert!(!present(&f, "SYSTEM#READY").await);
}

#[tokio::test]
async fn a_user_who_arrives_between_the_passes_refuses_activation() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    f.pool.state().arrives_late = Some((
        "late".into(),
        Account::new("sub-of-late", "late@example.com", "CONFIRMED"),
    ));

    let refused = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(refused.outcome, Outcome::ActivationRefused);
    assert_eq!(refused.users, 2);
    assert_eq!(refused.missing, counts(1, 0, 0));
    assert!(!present(&f, "SYSTEM#READY").await);
    assert_eq!(
        run(&f, Mode::ApplyAndActivate).await.outcome,
        Outcome::Activated
    );
}

#[tokio::test]
async fn an_open_directory_is_only_read() {
    let f = fixture().await;
    user(&f, "alice", "CONFIRMED");

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::AlreadyActive);
    assert_eq!(report.missing, counts(1, 0, 0));
    assert!(report.needs_attention());
    assert_eq!(table_size(&f).await, 1);
}

#[tokio::test]
async fn an_unknown_marker_is_refused() {
    let f = closed().await;
    f.directory
        .dynamodb()
        .put_item()
        .table_name(f.directory.table())
        .item("identityKey", Av::S("SYSTEM#READY".into()))
        .item("version", Av::N("2".into()))
        .send()
        .await
        .unwrap();

    let refused = backfill(&f.directory, Mode::Apply).await;

    assert!(matches!(refused, Err(BackfillError::UnknownMarker)));
}

#[tokio::test]
async fn a_listing_that_fails_names_the_error_and_writes_nothing() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    f.pool.state().list_failures = 1;

    let failed = backfill(&f.directory, Mode::ApplyAndActivate).await;

    assert!(matches!(
        failed,
        Err(BackfillError::ListUsers(code)) if code == "TooManyRequestsException"
    ));
    assert_eq!(table_size(&f).await, 0);
}
