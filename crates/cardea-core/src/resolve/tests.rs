use super::*;
use crate::{normalize_email, resolve};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    emails: HashMap<String, EmailOwner>,
    providers: HashMap<(Provider, String), User>,
    users: HashMap<String, User>,
    unconfirmed: bool,
    link_failures: usize,
    lost_creates: usize,
    creates: usize,
    links: HashMap<(Provider, String), String>,
}
#[derive(Clone, Default)]
struct Mock(Arc<Mutex<State>>);
#[async_trait]
impl Directory for Mock {
    async fn ready(&self) -> Result<(), Error> {
        Ok(())
    }
    // Keyed by the person, as the real directory's rows are.
    async fn email(&self, email: &str) -> Result<Option<EmailOwner>, Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .emails
            .get(&person_key(email)?)
            .cloned())
    }
    async fn claim_email(&self, owner: &EmailOwner) -> Result<EmailOwner, Error> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .emails
            .entry(person_key(&owner.email)?)
            .or_insert_with(|| owner.clone())
            .clone())
    }
    async fn provider(&self, provider: Provider, subject: &str) -> Result<Option<User>, Error> {
        let key = (provider, subject.to_owned());
        Ok(self.0.lock().unwrap().providers.get(&key).cloned())
    }
    async fn claim_provider(
        &self,
        provider: Provider,
        subject: &str,
        user: &User,
    ) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap();
        let owner = state
            .providers
            .entry((provider, subject.into()))
            .or_insert_with(|| user.clone());
        if owner == user {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
    async fn awaits_confirmation(&self, _username: &str) -> Result<bool, Error> {
        Ok(self.0.lock().unwrap().unconfirmed)
    }
    async fn native_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        let state = self.0.lock().unwrap();
        if state.unconfirmed {
            return Err(Error::LinkRequired);
        }
        state
            .users
            .get(&owner.username)
            .cloned()
            .ok_or(Error::NotReady)
    }
    async fn create_social_user(&self, owner: &EmailOwner) -> Result<User, Error> {
        // Yield between the durable reservation and external service call to
        // exercise overlapping sign-ins, not only sequential idempotency.
        tokio::task::yield_now().await;
        let mut state = self.0.lock().unwrap();
        if let Some(user) = state.users.get(&owner.username) {
            return Ok(user.clone());
        }
        let user = User {
            user_id: format!("canonical-{}", state.creates),
            username: owner.username.clone(),
            email: owner.email.clone(),
        };
        state.creates += 1;
        state.users.insert(owner.username.clone(), user.clone());
        if state.lost_creates > 0 {
            state.lost_creates -= 1;
            return Err(Error::Unavailable);
        }
        Ok(user)
    }
    async fn link(&self, provider: Provider, subject: &str, user: &User) -> Result<(), Error> {
        let mut state = self.0.lock().unwrap();
        if state.link_failures > 0 {
            state.link_failures -= 1;
            return Err(Error::Unavailable);
        }
        let owner = state
            .links
            .entry((provider, subject.into()))
            .or_insert_with(|| user.user_id.clone());
        if owner == &user.user_id {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
}
fn google(email: &str) -> ProviderIdentity {
    ProviderIdentity {
        provider: Provider::Google,
        subject: "stable-subject".into(),
        email: email.into(),
        authoritative: true,
    }
}
fn google_link(subject: &str) -> (Provider, String) {
    (Provider::Google, subject.into())
}
fn native(directory: &Mock, email: &str) -> User {
    let user = User {
        user_id: "existing-sub".into(),
        username: "existing-username".into(),
        email: email.into(),
    };
    let owner = EmailOwner {
        email: normalize_email(email).unwrap(),
        username: user.username.clone(),
        origin: "Cognito".into(),
    };
    let mut state = directory.0.lock().unwrap();
    state.emails.insert(person_key(email).unwrap(), owner);
    state.users.insert(user.username.clone(), user.clone());
    user
}

#[tokio::test]
async fn native_first_preserves_canonical_id_and_immutable_email_case() {
    let directory = Mock::default();
    let original = native(&directory, "Owner@Gmail.com");
    for _ in 0..5 {
        assert_eq!(
            resolve(&directory, &google("owner@gmail.com"), None).await,
            Ok(original.clone())
        );
    }
    let state = directory.0.lock().unwrap();
    assert_eq!(state.users.len(), 1);
    assert_eq!(state.creates, 0);
    assert_eq!(state.links[&google_link("stable-subject")], "existing-sub");
}

/// Used to be: the directory knew only lowercase, so a Google sign-in for
/// `ownername@gmail.com` did not find the native account `Owner.Name+shop@…`
/// and made a second user, a second personal organization and a second free
/// tier for one mailbox.
#[tokio::test]
async fn google_and_native_sign_in_with_the_same_mailbox_reconcile_to_one_person() {
    for google_email in [
        "ownername@gmail.com",
        "owner.name@gmail.com",
        "OwnerName+g@googlemail.com",
    ] {
        let directory = Mock::default();
        let original = native(&directory, "Owner.Name+shop@Gmail.com");
        assert_eq!(
            resolve(&directory, &google(google_email), None).await,
            Ok(original.clone()),
            "{google_email}"
        );
        // An authenticated link from the native session names the same person.
        assert_eq!(
            resolve(&directory, &google(google_email), Some(&original)).await,
            Ok(original.clone()),
            "{google_email}"
        );
        let state = directory.0.lock().unwrap();
        assert_eq!((state.users.len(), state.creates), (1, 0));
        assert_eq!(state.links[&google_link("stable-subject")], "existing-sub");
        // The native account's delivery address is untouched by the fold.
        assert_eq!(
            state.users["existing-username"].email,
            "Owner.Name+shop@Gmail.com"
        );
    }
}

#[tokio::test]
async fn google_first_then_native_alias_is_the_same_account() {
    let directory = Mock::default();
    let first = resolve(&directory, &google("owner.name@gmail.com"), None)
        .await
        .unwrap();
    // The directory answers any alias of the mailbox with its one owner.
    let owner = directory.email("OwnerName+x@googlemail.com").await.unwrap();
    assert_eq!(owner.map(|o| o.email), Some("owner.name@gmail.com".into()));
    let other_device = ProviderIdentity {
        subject: "second-subject".into(),
        ..google("ownername+y@gmail.com")
    };
    assert_eq!(
        resolve(&directory, &other_device, None).await.unwrap(),
        first
    );
    assert_eq!(directory.0.lock().unwrap().creates, 1);
}

/// Used to be: any domain could claim a mailbox, so a throwaway address was a
/// free account.
#[tokio::test]
async fn a_disposable_google_domain_cannot_claim_a_new_mailbox() {
    let directory = Mock::default();
    assert_eq!(
        resolve(&directory, &google("anyone@mailinator.com"), None).await,
        Err(Error::DisposableDomain)
    );
    let state = directory.0.lock().unwrap();
    assert!(state.emails.is_empty() && state.providers.is_empty() && state.users.is_empty());
}

#[tokio::test]
async fn concurrent_google_first_signins_create_one_user() {
    let directory = Mock::default();
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let directory = directory.clone();
        tasks.push(tokio::spawn(async move {
            resolve(&directory, &google("owner@gmail.com"), None).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap().user_id, "canonical-0");
    }
    let state = directory.0.lock().unwrap();
    assert_eq!(state.creates, 1);
    assert_eq!(state.emails.len(), 1);
    assert_eq!(state.providers.len(), 1);
}

#[tokio::test]
async fn lost_create_response_and_failed_link_retry_without_fallback() {
    let directory = Mock::default();
    {
        let mut s = directory.0.lock().unwrap();
        s.lost_creates = 1;
        s.link_failures = 1;
    }
    let google = google("owner@gmail.com");
    assert_eq!(
        resolve(&directory, &google, None).await,
        Err(Error::Unavailable)
    );
    assert_eq!(
        resolve(&directory, &google, None).await,
        Err(Error::Unavailable)
    );
    assert_eq!(
        resolve(&directory, &google, None).await.unwrap().user_id,
        "canonical-0"
    );
    assert_eq!(directory.0.lock().unwrap().creates, 1);
}

#[tokio::test]
async fn pending_native_signup_and_preregistration_cannot_be_taken_over() {
    let directory = Mock::default();
    let user = native(&directory, "owner@gmail.com");
    directory.0.lock().unwrap().unconfirmed = true;
    assert_eq!(
        resolve(&directory, &google(&user.email), None).await,
        Err(Error::LinkRequired)
    );
    directory.0.lock().unwrap().users.clear();
    directory.0.lock().unwrap().unconfirmed = false;
    assert_eq!(
        resolve(&directory, &google(&user.email), None).await,
        Err(Error::NotReady)
    );
    assert!(directory.0.lock().unwrap().providers.is_empty());
    assert_eq!(directory.0.lock().unwrap().creates, 0);
}

#[tokio::test]
async fn external_email_requires_authenticated_same_account() {
    let directory = Mock::default();
    let user = native(&directory, "owner@example.com");
    let mut google = google(&user.email);
    google.authoritative = false;
    assert_eq!(
        resolve(&directory, &google, None).await,
        Err(Error::LinkRequired)
    );
    let mut wrong = user.clone();
    wrong.user_id = "other-user".into();
    assert_eq!(
        resolve(&directory, &google, Some(&wrong)).await,
        Err(Error::Conflict)
    );
    assert!(directory.0.lock().unwrap().providers.is_empty());
    assert_eq!(resolve(&directory, &google, Some(&user)).await, Ok(user));
}

#[tokio::test]
async fn provider_email_change_never_moves_identity() {
    let directory = Mock::default();
    let original = native(&directory, "first@gmail.com");
    resolve(&directory, &google(&original.email), None)
        .await
        .unwrap();
    let other = User {
        user_id: "other-user".into(),
        username: "other".into(),
        email: "second@gmail.com".into(),
    };
    assert_eq!(
        resolve(&directory, &google(&other.email), None).await,
        Ok(original)
    );
    assert_eq!(
        resolve(&directory, &google(&other.email), Some(&other)).await,
        Err(Error::Conflict)
    );
    assert_eq!(directory.0.lock().unwrap().creates, 0);
}

mod apple;
