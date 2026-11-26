//! The rows each kind of user gets.

use cardea_core::Directory;
use serde_json::json;

use super::*;

#[tokio::test]
async fn a_dry_run_counts_and_writes_nothing() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    user(&f, "bob", "CONFIRMED");
    f.pool_link("alice", GOOGLE, "google-1");
    f.pool_link("alice", APPLE, "apple-1");

    let report = run(&f, Mode::DryRun).await;

    assert_eq!(report.outcome, Outcome::DryRun);
    assert_eq!(report.users, 2);
    assert_eq!(report.missing, counts(2, 2, 1));
    assert_eq!(report.written, counts(0, 0, 0));
    assert_eq!(report.findings, []);
    assert!(!report.needs_attention());
    assert_eq!(table_size(&f).await, 0);
}

#[tokio::test]
async fn a_native_user_gets_a_claim_bindings_and_a_list() {
    let f = closed().await;
    let alice = user(&f, "alice", "CONFIRMED");
    change(&f, "alice", |a| a.email = "A.lice+x@Example.com".into());
    f.pool_link("alice", GOOGLE, "google-1");

    let report = run(&f, Mode::Apply).await;

    assert_eq!(report.outcome, Outcome::Applied);
    assert_eq!(report.written, counts(1, 1, 1));
    assert_eq!(report.missing, counts(0, 0, 0));
    let claim = f.item("EMAIL#a.lice@example.com").await.unwrap();
    assert_eq!(
        claim["record"],
        Av::S(r#"{"email":"a.lice+x@example.com","username":"alice","origin":"Cognito"}"#.into())
    );
    assert_eq!(claim["userId"], Av::S(alice.user_id.clone()));
    assert_eq!(claim["passwordSet"], Av::Bool(true));
    assert!(!claim.contains_key("unconfirmedExpiresAt"));
    // The binding holds the user as a sign-in compares it: the pool's spelling.
    let bound = f.directory.provider(GOOGLE, "google-1").await.unwrap();
    assert_eq!(bound.unwrap().email, "A.lice+x@Example.com");
    let list = f.item("METHODS#sub-of-alice").await.unwrap();
    assert_eq!(list["version"], Av::N("1".into()));
    assert_eq!(
        list["identities"],
        Av::S(r#"[{"provider":"Google","subject":"google-1"}]"#.into())
    );
    assert!(!present(&f, "SYSTEM#READY").await);
}

#[tokio::test]
async fn a_federated_user_is_bound_where_they_are_and_noted() {
    let f = closed().await;
    f.pool.add(
        "google_google-1",
        "sub-of-gina",
        "gina@example.com",
        "EXTERNAL_PROVIDER",
    );
    f.pool_link("google_google-1", GOOGLE, "google-1");

    let report = run(&f, Mode::ApplyAndActivate).await;

    assert_eq!(report.outcome, Outcome::Activated);
    assert_eq!(report.findings, [finding("gina", Problem::FederatedOnly)]);
    let claim = f.item("EMAIL#gina@example.com").await.unwrap();
    assert!(
        claim["record"]
            .as_s()
            .unwrap()
            .contains(r#""origin":"Google""#)
    );
    assert_eq!(claim["passwordSet"], Av::Bool(false));
    let bound = f.directory.provider(GOOGLE, "google-1").await.unwrap();
    assert_eq!(bound.unwrap().username, "google_google-1");
}

#[tokio::test]
async fn the_status_decides_the_password_and_whether_the_claim_lapses() {
    let f = closed().await;
    user(&f, "pending", "UNCONFIRMED");
    change(&f, "pending", |a| a.unverified = true);
    user(&f, "invited", "FORCE_CHANGE_PASSWORD");
    user(&f, "reset", "RESET_REQUIRED");

    let report = run(&f, Mode::Apply).await;

    assert_eq!(report.findings, []);
    let pending = f.item("EMAIL#pending@example.com").await.unwrap();
    assert!(pending.contains_key("unconfirmedExpiresAt"));
    assert!(!pending.contains_key("userId"));
    assert!(!pending.contains_key("passwordSet"));
    for name in ["invited", "reset"] {
        let claim = f.item(&format!("EMAIL#{name}@example.com")).await.unwrap();
        assert_eq!(claim["passwordSet"], Av::Bool(false), "{name}");
        assert!(claim.contains_key("userId"), "{name}");
    }
}

/// `ListUsers` shows a linked identity's own profile beside the user, whether
/// or not that profile carries a list of its own.
#[tokio::test]
async fn a_linked_identitys_own_profile_is_not_a_second_user() {
    for profile_lists_itself in [false, true] {
        let f = closed().await;
        let alice = user(&f, "alice", "CONFIRMED");
        f.pool_link("alice", GOOGLE, "google-1");
        f.pool_link("alice", APPLE, "apple-1");
        f.pool.add(
            "google_google-1",
            "sub-of-profile",
            "alice@example.com",
            "EXTERNAL_PROVIDER",
        );
        f.pool.add(
            "SignInWithApple_apple-1",
            "sub-of-other-profile",
            "relay@privaterelay.appleid.com",
            "EXTERNAL_PROVIDER",
        );
        if profile_lists_itself {
            f.pool_link("google_google-1", GOOGLE, "google-1");
        }
        f.pool.state().page_size = 1;

        let report = run(&f, Mode::ApplyAndActivate).await;

        assert_eq!(report.outcome, Outcome::Activated);
        assert_eq!(report.users, 1);
        assert_eq!(report.findings, []);
        assert_eq!(report.written, counts(1, 2, 1));
        assert!(!present(&f, "EMAIL#relay@privaterelay.appleid.com").await);
        assert_eq!(
            f.directory.provider(GOOGLE, "google-1").await.unwrap(),
            Some(alice)
        );
    }
}

#[tokio::test]
async fn every_page_is_read_and_a_repeat_writes_nothing() {
    let f = closed().await;
    for name in ["a", "b", "c", "d", "e"] {
        user(&f, name, "CONFIRMED");
    }
    f.pool.state().page_size = 2;

    let first = run(&f, Mode::Apply).await;
    assert_eq!(first.users, 5);
    assert_eq!(first.written, counts(5, 0, 0));
    // Three pages in each of the two passes.
    assert_eq!(f.pool.state().pages, 6);

    let again = run(&f, Mode::Apply).await;
    assert_eq!(again.present, counts(5, 0, 0));
    assert_eq!(again.written, counts(0, 0, 0));
    assert!(!again.needs_attention());
}

/// A row a trigger wrote names the user by the address, not the pool's
/// username.
#[tokio::test]
async fn a_claim_made_at_signup_counts_as_covered() {
    let f = closed().await;
    user(&f, "alice", "UNCONFIRMED");
    f.directory
        .claim_email_at(
            &cardea_core::EmailOwner {
                email: "alice@example.com".into(),
                username: "Alice@Example.com".into(),
                origin: "Cognito".into(),
            },
            crate::directory::Hold::Unconfirmed,
            crate::directory::now(),
        )
        .await
        .unwrap();

    let report = run(&f, Mode::Apply).await;

    assert_eq!(report.present, counts(1, 0, 0));
    assert!(!report.needs_attention());
}

#[tokio::test]
async fn backfilled_people_sign_in_to_their_own_accounts() {
    let f = closed().await;
    let alice = user(&f, "alice", "CONFIRMED");
    f.pool_link("alice", GOOGLE, "google-1");
    run(&f, Mode::ApplyAndActivate).await;

    f.directory
        .inbound(json!({
            "triggerSource": "InboundFederation_ExternalProvider",
            "request": {
                "providerName": "Google",
                "providerType": "Google",
                "attributes": {"idToken": {
                    "sub": "google-1", "email": "alice@example.com", "email_verified": true,
                }},
            },
            "response": {},
        }))
        .await
        .unwrap();
    // The mailbox is taken: no second account under an alias of it.
    let second = f
        .directory
        .pre_signup(json!({
            "triggerSource": "PreSignUp_SignUp",
            "request": {"userAttributes": {"email": "alice+2@example.com"}},
            "response": {},
        }))
        .await;

    assert_eq!(second, Err(cardea_core::Error::Conflict));
    assert_eq!(f.pool.state().creates, 0);
    assert_eq!(
        f.directory.provider(GOOGLE, "google-1").await.unwrap(),
        Some(alice)
    );
}

#[tokio::test]
async fn a_report_prints_ids_and_counts_but_no_address_username_or_subject() {
    let f = closed().await;
    user(&f, "alice", "CONFIRMED");
    f.pool.add(
        "google_secret-subject",
        "sub-of-gina",
        "alice+g@example.com",
        "EXTERNAL_PROVIDER",
    );
    f.pool_link("google_secret-subject", GOOGLE, "secret-subject");

    let text = run(&f, Mode::DryRun).await.to_string();

    assert!(text.contains("pool users: 2"), "{text}");
    assert!(text.contains("user sub-of-alice shares one mailbox with sub-of-gina"));
    for private in ["@", "example.com", "secret-subject", "google_"] {
        assert!(!text.contains(private), "{private}: {text}");
    }
}
