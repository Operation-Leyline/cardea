//! How long a claim holds its mailbox, on real conditional writes. Signups are
//! given their time; only provider sign-in reads the clock, so its claims are
//! placed far enough from now.
use aws_sdk_dynamodb::Client as Ddb;
use aws_sdk_dynamodb::config::interceptors::BeforeTransmitInterceptorContextRef;
use aws_sdk_dynamodb::config::{ConfigBag, Intercept, RuntimeComponents};
use aws_sdk_dynamodb::error::BoxError;
use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, EmailOwner, Error, Provider, ProviderIdentity, resolve};
use serde_json::json;

use super::signup_tests::{commit, signup};
use super::{AwsDirectory, now};
use crate::testing::{Fixture, cognito::SUB as POOL_SUB, ddb::Item, fixture};

/// The documented life of an unconfirmed claim: 24 hours.
const DAY: i64 = 86_400;
const THEN: i64 = 1_800_000_000;
const TYPO: &str = "a.b+typo@gmail.com";
const ALIAS: &str = "ab@gmail.com";
const KEY: &str = "EMAIL#ab@gmail.com";
const SUB: &str = "11111111-1111-4111-8111-111111111111";

async fn signup_at(directory: &AwsDirectory, email: &str, at: i64) -> Result<(), Error> {
    directory
        .pre_signup_at(signup(email, "transient"), at)
        .await
        .map(|_| ())
}

async fn row(directory: &AwsDirectory) -> Item {
    directory
        .dynamodb()
        .get_item()
        .table_name(directory.table())
        .key("identityKey", Av::S(KEY.into()))
        .consistent_read(true)
        .send()
        .await
        .unwrap()
        .item
        .expect("the mailbox row")
}

/// The owner record a native signup of `email` writes.
fn record(email: &str) -> Av {
    Av::S(format!(
        r#"{{"email":"{email}","username":"{email}","origin":"Cognito"}}"#
    ))
}

/// Provisioning's guard for the signup of `email`, committed.
async fn confirm(directory: &AwsDirectory, email: &str) -> Result<(), Error> {
    let guard = directory.profile_guard(email, email, SUB).await?;
    commit(directory, guard).await
}

#[tokio::test]
async fn an_unconfirmed_claim_blocks_other_aliases_until_it_lapses() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();

    assert_eq!(
        signup_at(directory, ALIAS, THEN + DAY - 1).await,
        Err(Error::Conflict)
    );

    let row = row(directory).await;
    assert_eq!(row.len(), 3, "{row:?}");
    assert_eq!(row["record"], record(TYPO));
    assert_eq!(row["unconfirmedExpiresAt"], Av::N((THEN + DAY).to_string()));
}

/// Used to be: the claim had no expiry, so a typo kept the mailbox's owner
/// out for good.
#[tokio::test]
async fn another_alias_takes_a_lapsed_claim() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();

    signup_at(directory, ALIAS, THEN + DAY).await.unwrap();

    let row = row(directory).await;
    assert_eq!(row["record"], record(ALIAS));
    assert_eq!(
        row["unconfirmedExpiresAt"],
        Av::N((THEN + 2 * DAY).to_string())
    );
}

#[tokio::test]
async fn two_signups_racing_for_a_lapsed_claim_have_exactly_one_winner() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();

    // Fixed two signups race for the one lapsed row.
    let (left, right) = tokio::join!(
        signup_at(directory, ALIAS, THEN + DAY),
        signup_at(directory, "a.b@gmail.com", THEN + DAY),
    );

    let mut answers = [left, right];
    answers.sort_by_key(Result::is_err);
    assert_eq!(answers, [Ok(()), Err(Error::Conflict)]);
}

#[tokio::test]
async fn a_confirmed_mailbox_never_lapses() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();
    confirm(directory, TYPO).await.unwrap();

    assert_eq!(
        signup_at(directory, ALIAS, THEN + 400 * DAY).await,
        Err(Error::Conflict)
    );

    let row = row(directory).await;
    assert_eq!(row["userId"], Av::S(SUB.into()));
    assert!(!row.contains_key("unconfirmedExpiresAt"), "{row:?}");
}

/// A row that names a user is theirs whatever else it carries, so a writer
/// that bound the user and left the expiry cannot lose the account.
#[tokio::test]
async fn a_row_naming_a_user_is_never_taken_whatever_expiry_it_keeps() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();
    directory
        .dynamodb()
        .update_item()
        .table_name(directory.table())
        .key("identityKey", Av::S(KEY.into()))
        .update_expression("SET userId = :user")
        .expression_attribute_values(":user", Av::S(SUB.into()))
        .send()
        .await
        .unwrap();

    assert_eq!(
        signup_at(directory, ALIAS, THEN + 400 * DAY).await,
        Err(Error::Conflict)
    );
    assert_eq!(row(directory).await["record"], record(TYPO));
}

#[tokio::test]
async fn a_google_claim_never_lapses() {
    let Fixture { directory, .. } = &fixture().await;
    let google = EmailOwner {
        email: ALIAS.into(),
        username: ALIAS.into(),
        origin: "Google".into(),
    };
    assert_eq!(directory.claim_email(&google).await, Ok(google.clone()));

    assert_eq!(
        signup_at(directory, TYPO, i64::from(u32::MAX)).await,
        Err(Error::Conflict)
    );
    assert!(!row(directory).await.contains_key("unconfirmedExpiresAt"));
}

#[tokio::test]
async fn an_operator_created_account_never_lapses() {
    let Fixture { directory, .. } = &fixture().await;
    let mut created = signup(TYPO, "transient");
    created["triggerSource"] = json!("PreSignUp_AdminCreateUser");
    directory.pre_signup_at(created, THEN).await.unwrap();

    assert_eq!(
        signup_at(directory, ALIAS, THEN + 400 * DAY).await,
        Err(Error::Conflict)
    );
}

/// The operator's account is the signup's own address, so its claim stops
/// lapsing.
#[tokio::test]
async fn an_operator_creating_a_signed_up_address_ends_its_lapse() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();
    let mut created = signup(TYPO, "transient");
    created["triggerSource"] = json!("PreSignUp_AdminCreateUser");

    directory.pre_signup_at(created, THEN + 1).await.unwrap();

    assert!(!row(directory).await.contains_key("unconfirmedExpiresAt"));
    assert_eq!(
        signup_at(directory, ALIAS, THEN + 400 * DAY).await,
        Err(Error::Conflict)
    );
}

/// Refuses every `PutItem` before it is sent; reads still answer.
#[derive(Debug)]
struct RefusesPuts;

impl Intercept for RefusesPuts {
    fn name(&self) -> &'static str {
        "RefusesPuts"
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let put = context
            .request()
            .headers()
            .get("x-amz-target")
            .is_some_and(|target| target.ends_with(".PutItem"));
        if put {
            return Err("injected put failure".into());
        }
        Ok(())
    }
}

/// Used to be: the read back named the same owner, so an operator was told the
/// account was theirs while its claim still lapsed.
#[tokio::test]
async fn an_operator_creation_whose_write_fails_is_not_reported_as_kept() {
    let mut fixture = fixture().await;
    let directory = &mut fixture.directory;
    signup_at(directory, TYPO, THEN).await.unwrap();
    let refusing = directory.ddb.config().to_builder().interceptor(RefusesPuts);
    directory.ddb = Ddb::from_conf(refusing.build());
    let mut created = signup(TYPO, "transient");
    created["triggerSource"] = json!("PreSignUp_AdminCreateUser");

    let answer = directory.pre_signup_at(created, THEN + 1).await;

    assert_eq!(answer.map(|_| ()), Err(Error::Unavailable));
}

/// A code resent after the claim lapsed still confirms, while nobody else has
/// taken the mailbox.
#[tokio::test]
async fn a_lapsed_signup_nobody_displaced_can_still_confirm() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, 0).await.unwrap();

    assert_eq!(confirm(directory, TYPO).await, Ok(()));

    assert_eq!(row(directory).await["userId"], Av::S(SUB.into()));
}

/// The guard was built while the claim was still the old signup's and commits
/// after another took it: the commit's own condition refuses.
#[tokio::test]
async fn a_signup_displaced_before_its_guard_commits_cannot_confirm() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, THEN).await.unwrap();
    let guard = directory.profile_guard(TYPO, TYPO, SUB).await.unwrap();
    signup_at(directory, ALIAS, THEN + DAY).await.unwrap();

    assert_eq!(commit(directory, guard).await, Err(Error::Conflict));

    assert!(!row(directory).await.contains_key("userId"));
}

fn google() -> ProviderIdentity {
    ProviderIdentity {
        provider: Provider::Google,
        subject: "google-subject".into(),
        email: ALIAS.into(),
        authoritative: true,
        private_relay: false,
    }
}

#[tokio::test]
async fn google_sign_in_waits_on_a_fresh_native_claim() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, now()).await.unwrap();

    assert_eq!(
        resolve(directory, &google(), None).await,
        Err(Error::NotReady)
    );
    assert_eq!(row(directory).await["record"], record(TYPO));
}

#[tokio::test]
async fn google_sign_in_takes_a_lapsed_native_claim() {
    let Fixture { directory, .. } = &fixture().await;
    signup_at(directory, TYPO, 0).await.unwrap();

    let user = resolve(directory, &google(), None).await.unwrap();

    assert_eq!(
        (user.user_id.as_str(), user.email.as_str()),
        (POOL_SUB, ALIAS)
    );
    let row = row(directory).await;
    assert_eq!(
        row["record"],
        Av::S(format!(
            r#"{{"email":"{ALIAS}","username":"{ALIAS}","origin":"Google"}}"#
        ))
    );
    assert!(!row.contains_key("unconfirmedExpiresAt"), "{row:?}");
}

/// Used to be: the claim was taken for good before Cognito refused the social
/// account, so no alias of the mailbox could sign up again.
#[tokio::test]
async fn google_leaves_a_lapsed_claim_whose_cognito_user_is_unconfirmed() {
    let Fixture {
        directory, pool, ..
    } = &fixture().await;
    pool.add(ALIAS, SUB, ALIAS, "UNCONFIRMED");
    signup_at(directory, ALIAS, 0).await.unwrap();

    assert_eq!(
        resolve(directory, &google(), None).await,
        Err(Error::LinkRequired)
    );

    assert_eq!(row(directory).await["record"], record(ALIAS));
    assert_eq!(signup_at(directory, TYPO, THEN).await, Ok(()));
}
