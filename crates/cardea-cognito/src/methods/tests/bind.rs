//! A binding and its place on the list are one write.

use super::*;

async fn claim(f: &Fixture, user: &User, method: Provider, subject: &str) -> Result<(), Error> {
    f.directory.claim_provider(method, subject, user).await
}

#[tokio::test]
async fn a_new_binding_is_listed_with_what_the_pool_already_links() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.pool_link("alice", GOOGLE, "google-1");

    claim(&f, &alice, APPLE, "apple-1").await.unwrap();
    // A repeat finds the binding and writes nothing.
    claim(&f, &alice, APPLE, "apple-1").await.unwrap();

    let (version, list) = stored(&f, &alice).await.unwrap();
    assert_eq!(version, 1);
    assert!(list.contains("google-1") && list.contains("apple-1"));
    assert_eq!(bound(&f, APPLE, "apple-1").await, Some(alice));
}

#[tokio::test]
async fn anothers_subject_goes_on_no_list() {
    let (f, alice) = password_and_google().await;
    let bob = f.account("bob", "Cognito").await;

    assert_eq!(
        claim(&f, &bob, GOOGLE, "google-1").await,
        Err(Error::Conflict)
    );

    assert_eq!(stored(&f, &bob).await, None);
    assert_eq!(bound(&f, GOOGLE, "google-1").await, Some(alice));
}

#[tokio::test]
async fn bindings_made_together_are_all_listed() {
    let (f, alice) = password_and_google().await;

    let (first, second) = tokio::join!(
        claim(&f, &alice, GOOGLE, "google-2"),
        claim(&f, &alice, APPLE, "apple-1"),
    );

    assert_eq!((first, second), (Ok(()), Ok(())));
    let list = stored(&f, &alice).await.unwrap().1;
    for subject in ["google-1", "google-2", "apple-1"] {
        assert!(list.contains(subject), "{subject}");
    }
}

/// The binding is gone and the unlink has yet to drop the entry: it is not
/// bound anew until that is done.
#[tokio::test]
async fn nothing_is_bound_while_its_unlink_is_unfinished() {
    let (f, alice) = password_and_google().await;
    f.pool.state().disable_failures = 1;
    assert!(unlink(&f, &alice, GOOGLE).await.is_err());
    f.delete("PROVIDER#Google#google-1").await;

    assert_eq!(
        claim(&f, &alice, GOOGLE, "google-1").await,
        Err(Error::NotReady)
    );
    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
}

/// A link that stopped after the binding can be removed like any other.
#[tokio::test]
async fn an_unlink_releases_a_binding_the_pool_never_linked() {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    claim(&f, &alice, GOOGLE, "google-1").await.unwrap();

    unlink(&f, &alice, GOOGLE).await.unwrap();

    assert_eq!(bound(&f, GOOGLE, "google-1").await, None);
    assert_eq!(stored(&f, &alice).await.unwrap().1, "[]");
}
