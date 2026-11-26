//! The password account behind a provider claim, and provider linking.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, EmailOwner, Error, Provider, User};

use crate::testing::{Fixture, fixture};

const EMAIL: &str = "owner@icloud.com";
const KEY: &str = "EMAIL#owner@icloud.com";

async fn claimed(fixture: &Fixture, provider: Provider) -> EmailOwner {
    let owner = EmailOwner {
        email: EMAIL.into(),
        username: EMAIL.into(),
        origin: provider.rule().cognito_name.into(),
    };
    fixture.directory.claim_email(&owner).await.unwrap()
}

#[tokio::test]
async fn a_provider_claim_gets_one_confirmed_password_account() {
    for provider in Provider::ALL {
        let fixture = fixture().await;
        let owner = claimed(&fixture, provider).await;
        let first = fixture.directory.create_social_user(&owner).await.unwrap();
        let again = fixture.directory.create_social_user(&owner).await.unwrap();
        assert_eq!(first, again);
        {
            let pool = fixture.pool.state();
            assert_eq!((pool.creates, pool.passwords), (1, 1));
            assert_eq!(
                pool.create_metadata["identityOrigin"],
                provider.rule().cognito_name
            );
        }
        let row = fixture.item(KEY).await.unwrap();
        assert!(row.contains_key("passwordInitialization"));
        // A random password nobody was told is not a sign-in method.
        assert!(!row.contains_key("passwordSet"));
    }
}

#[tokio::test]
async fn a_native_claim_is_never_given_a_social_account() {
    let fixture = fixture().await;
    let owner = EmailOwner {
        email: EMAIL.into(),
        username: EMAIL.into(),
        origin: "Cognito".into(),
    };
    assert_eq!(
        fixture.directory.create_social_user(&owner).await,
        Err(Error::Conflict)
    );
    assert_eq!(fixture.pool.state().creates, 0);
}

/// A rejected password change releases the election, so a retry finishes.
#[tokio::test]
async fn a_rejected_password_change_can_be_retried() {
    for refusal in ["TooManyRequestsException", "NotAuthorizedException"] {
        let fixture = fixture().await;
        let owner = claimed(&fixture, Provider::Apple).await;
        fixture.pool.state().password_error = Some(refusal);
        assert_eq!(
            fixture.directory.create_social_user(&owner).await,
            Err(Error::Unavailable)
        );
        let row = fixture.item(KEY).await.unwrap();
        assert!(!row.contains_key("passwordInitialization"), "{refusal}");
        assert!(fixture.directory.create_social_user(&owner).await.is_ok());
        assert_eq!(fixture.pool.state().passwords, 1);
    }
}

/// An ambiguous failure keeps the election: nothing resets the password again.
#[tokio::test]
async fn an_ambiguous_password_change_is_never_repeated() {
    let fixture = fixture().await;
    let owner = claimed(&fixture, Provider::Google).await;
    fixture.pool.state().password_error = Some("InternalErrorException");
    assert_eq!(
        fixture.directory.create_social_user(&owner).await,
        Err(Error::Unavailable)
    );
    assert_eq!(
        fixture.directory.create_social_user(&owner).await,
        Err(Error::NotReady)
    );
    assert_eq!(fixture.pool.state().passwords, 0);
}

#[tokio::test]
async fn someone_elses_initialization_is_waited_on() {
    let fixture = fixture().await;
    let owner = claimed(&fixture, Provider::Google).await;
    fixture
        .pool
        .add(EMAIL, "sub", EMAIL, "FORCE_CHANGE_PASSWORD");
    fixture
        .directory
        .dynamodb()
        .update_item()
        .table_name(fixture.directory.table())
        .key("identityKey", Av::S(KEY.into()))
        .update_expression("SET passwordInitialization = :attempt")
        .expression_attribute_values(":attempt", Av::S("other".into()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        fixture.directory.create_social_user(&owner).await,
        Err(Error::NotReady)
    );
    assert_eq!(fixture.pool.state().passwords, 0);
}

fn user() -> User {
    User {
        user_id: "sub".into(),
        username: "internal".into(),
        email: EMAIL.into(),
    }
}

#[tokio::test]
async fn each_provider_links_once_under_its_cognito_name() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    fixture.pool.add("internal", "sub", EMAIL, "CONFIRMED");
    for provider in Provider::ALL {
        assert!(!directory.is_linked(provider, "s", &user()).await.unwrap());
        directory.link(provider, "s", &user()).await.unwrap();
        directory.link(provider, "s", &user()).await.unwrap();
        assert!(directory.is_linked(provider, "s", &user()).await.unwrap());
    }
    let pool = fixture.pool.state();
    assert_eq!(pool.links, 2);
    assert_eq!(
        pool.users["internal"].identities,
        [
            ("Google".to_owned(), "s".to_owned()),
            ("SignInWithApple".to_owned(), "s".to_owned())
        ]
    );
}

#[tokio::test]
async fn a_failed_link_reports_it_and_a_lost_answer_succeeds() {
    let fixture = fixture().await;
    let directory = &fixture.directory;
    fixture.pool.add("internal", "sub", EMAIL, "CONFIRMED");
    fixture.pool.state().link_failures = 1;
    assert_eq!(
        directory.link(Provider::Apple, "s", &user()).await,
        Err(Error::Unavailable)
    );
    fixture.pool.state().lost_links = 1;
    assert_eq!(directory.link(Provider::Apple, "s", &user()).await, Ok(()));
}

#[tokio::test]
async fn a_user_the_pool_no_longer_agrees_with_is_not_linked() {
    let fixture = fixture().await;
    fixture
        .pool
        .add("internal", "another-sub", EMAIL, "CONFIRMED");
    assert_eq!(
        fixture.directory.link(Provider::Google, "s", &user()).await,
        Err(Error::Conflict)
    );
    assert_eq!(fixture.pool.state().links, 0);
}
