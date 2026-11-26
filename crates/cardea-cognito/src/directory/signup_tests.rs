//! Native signup against real directory rows. The pre-signup trigger never
//! calls Cognito.
use aws_sdk_dynamodb::types::TransactWriteItem;
use cardea_core::{Directory, Error};
use serde_json::{Value, json};

use super::AwsDirectory;
use crate::testing::{Fixture, fixture};

pub(super) fn signup(email: &str, transient: &str) -> Value {
    json!({"userPoolId":"pool","userName":transient,"triggerSource":"PreSignUp_SignUp",
        "request":{"userAttributes":{"email":email}},"response":{}})
}

/// Commit a guard alone, as a provisioning transaction does among its other
/// writes.
pub(super) async fn commit(
    directory: &AwsDirectory,
    guard: TransactWriteItem,
) -> Result<(), Error> {
    crate::transact(directory.dynamodb(), vec![guard])
        .await
        .map_err(|error| {
            let refused = error
                .0
                .as_service_error()
                .is_some_and(|error| error.is_transaction_canceled_exception());
            if refused {
                Error::Conflict
            } else {
                Error::Unavailable
            }
        })
}

/// Used to be: only case folded, so `a.b+1@gmail.com`, `a.b+2@gmail.com` and
/// `ab@gmail.com` each claimed their own directory row and became three users.
#[tokio::test]
async fn plus_and_dot_aliases_of_one_gmail_mailbox_are_one_person() {
    let Fixture { directory, .. } = &fixture().await;
    assert!(
        directory
            .pre_signup(signup("A.B+1@Gmail.com", "transient-1"))
            .await
            .is_ok()
    );
    // A retry of the same alias is the same signup.
    assert!(
        directory
            .pre_signup(signup("A.B+1@Gmail.com", "transient-2"))
            .await
            .is_ok()
    );
    for alias in ["ab@gmail.com", "a.b+2@gmail.com", "AB+x@googlemail.com"] {
        assert_eq!(
            directory.pre_signup(signup(alias, "transient-3")).await,
            Err(Error::Conflict),
            "{alias}"
        );
    }
    // The directory answers any alias with the one owner, whose delivery
    // address is the first spelling, never the folded key.
    for alias in ["ab@gmail.com", "a.b+9@googlemail.com"] {
        let owner = directory.email(alias).await.unwrap().unwrap();
        assert_eq!(owner.email, "a.b+1@gmail.com");
        assert_eq!(owner.username, "A.B+1@Gmail.com");
    }
    // Another mailbox is another person.
    assert!(
        directory
            .pre_signup(signup("c.d@gmail.com", "transient-4"))
            .await
            .is_ok()
    );
    // The same dots and tag mean nothing on a domain that is not Gmail,
    // except the tag, which every domain folds.
    assert!(
        directory
            .pre_signup(signup("a.b@example.com", "transient-5"))
            .await
            .is_ok()
    );
    assert!(
        directory
            .pre_signup(signup("ab@example.com", "transient-6"))
            .await
            .is_ok()
    );
    assert_eq!(
        directory
            .pre_signup(signup("ab+tag@example.com", "transient-7"))
            .await,
        Err(Error::Conflict)
    );
}

/// Used to be: nothing looked at the domain, so a throwaway mailbox opened a
/// free account. The refusal precedes every directory read and write.
#[tokio::test]
async fn a_disposable_domain_is_refused_at_signup() {
    // Offline: the trigger decides before it reads the directory, so an
    // unreachable table cannot turn the refusal into an outage.
    let config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .endpoint_url("http://127.0.0.1:9")
        .build();
    let directory = AwsDirectory::from_config(&config, "identities".into(), "pool".into());
    for email in [
        "someone@mailinator.com",
        "Someone+tag@Guerrillamail.COM",
        "x@team.yopmail.com",
    ] {
        for trigger in ["PreSignUp_SignUp", "PreSignUp_AdminCreateUser"] {
            let mut payload = signup(email, "transient");
            payload["triggerSource"] = json!(trigger);
            assert_eq!(
                directory.pre_signup(payload).await,
                Err(Error::DisposableDomain),
                "{email} {trigger}"
            );
        }
    }
    assert_eq!(
        Error::DisposableDomain.to_string(),
        "this email domain is not accepted; sign up with a permanent address"
    );
}
