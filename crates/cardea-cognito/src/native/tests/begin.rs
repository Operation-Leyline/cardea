//! Beginning a sign-in: the token checks, and resolution with the redirect
//! sign-in's rules and refusals.

use super::*;

async fn begin_with(
    fixture: &Fixture,
    verifier: &JwtVerifier,
    token: &str,
) -> Result<SignInTicket, OperationError> {
    begin_provider_sign_in(
        &fixture.directory,
        verifier,
        &native(),
        Provider::Google,
        token,
        WEB,
    )
    .await
}

#[tokio::test]
async fn a_new_person_gets_one_account_linked_and_a_ticket_for_it() {
    let fixture = fixture().await;
    let answer = fixture.google_ticket(SUBJECT, EMAIL).await.unwrap();
    assert_eq!(answer.username, EMAIL);
    assert!(well_formed(&answer.ticket));
    assert!(answer.expires_at <= u64::try_from(now()).unwrap() + TICKET_LIFETIME_SECONDS);
    let printed = format!("{answer:?}");
    assert!(!printed.contains(&answer.ticket) && !printed.contains(EMAIL));
    assert!(fixture.item("PROVIDER#Google#g-subject-1").await.is_some());
    assert!(fixture.item("EMAIL#owner@gmail.com").await.is_some());
    let pool = fixture.pool.state();
    assert_eq!((pool.creates, pool.passwords, pool.links), (1, 1, 1));
}

#[tokio::test]
async fn a_returning_person_reaches_the_same_account() {
    let fixture = fixture().await;
    let first = fixture.google_ticket(SUBJECT, EMAIL).await.unwrap();
    // A changed provider address never moves an established identity.
    let second = fixture
        .google_ticket(SUBJECT, "renamed@gmail.com")
        .await
        .unwrap();
    assert_eq!(first.username, second.username);
    assert_ne!(first.ticket, second.ticket);
    assert_eq!(fixture.pool.state().creates, 1);
}

#[tokio::test]
async fn a_gmail_owner_joins_their_password_account() {
    let fixture = fixture().await;
    fixture
        .directory
        .claim_email(&cardea_core::EmailOwner {
            email: EMAIL.into(),
            username: "alice".into(),
            origin: "Cognito".into(),
        })
        .await
        .unwrap();
    fixture
        .pool
        .add("alice", "sub-of-alice", EMAIL, "CONFIRMED");
    let answer = fixture.google_ticket(SUBJECT, EMAIL).await.unwrap();
    assert_eq!(answer.username, "alice");
    assert_eq!(fixture.pool.state().creates, 0);
}

/// A provider that does not own the mailbox: the same refusal whether or not
/// anyone holds it.
#[tokio::test]
async fn a_non_authoritative_address_must_be_linked_from_a_session() {
    let fixture = fixture().await;
    fixture.account("alice", "Cognito").await;
    for email in ["alice@example.com", "nobody@example.com"] {
        assert_eq!(
            fixture.google_ticket(SUBJECT, email).await.unwrap_err(),
            refused(Error::LinkRequired),
            "{email}"
        );
    }
    assert!(fixture.rows_under("TICKET#").await.is_empty());
    assert_eq!(fixture.pool.state().links, 0);
}

#[tokio::test]
async fn a_disposable_domain_makes_no_account() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    // A Workspace token, so that only the domain stands in the way.
    let token = {
        let mut claims = claims(Provider::Google, &nonce, SUBJECT, "a@mailinator.com");
        claims["hd"] = json!("mailinator.com");
        sign(signing_key(), &claims)
    };
    assert_eq!(
        fixture.begin(&token, WEB).await.unwrap_err(),
        refused(Error::DisposableDomain)
    );
    assert_eq!(fixture.pool.state().creates, 0);
    assert!(fixture.rows_under("TICKET#").await.is_empty());
}

#[tokio::test]
async fn an_unconfirmed_signup_of_the_address_is_not_taken_over() {
    let fixture = fixture().await;
    fixture.pool.add(EMAIL, "pending", EMAIL, "UNCONFIRMED");
    assert_eq!(
        fixture.google_ticket(SUBJECT, EMAIL).await.unwrap_err(),
        refused(Error::LinkRequired)
    );
}

#[tokio::test]
async fn a_disabled_account_gets_no_ticket() {
    let fixture = fixture().await;
    fixture.google_ticket(SUBJECT, EMAIL).await.unwrap();
    fixture.pool.state().users.get_mut(EMAIL).unwrap().disabled = true;
    assert!(fixture.google_ticket(SUBJECT, EMAIL).await.is_err());
    assert_eq!(fixture.rows_under("TICKET#").await.len(), 1);
}

#[tokio::test]
async fn a_token_that_does_not_check_out_is_refused_and_spends_nothing() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    let time = now();
    let foreign = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let bad = [
        sign(&foreign, &claims(Provider::Google, &nonce, SUBJECT, EMAIL)),
        google_with(&nonce, "iss", json!("https://accounts.google.test")),
        google_with(&nonce, "aud", json!("another-client")),
        google_with(&nonce, "aud", json!([client_id(Provider::Google), "other"])),
        google_with(&nonce, "azp", json!("unlisted-android-client")),
        google_with(&nonce, "exp", json!(time - 1)),
        google_with(&nonce, "iat", json!(time - 301)),
        google_with(&nonce, "iat", Value::Null),
        google_with(&nonce, "email_verified", json!(false)),
        google_with(&nonce, "email", Value::Null),
        format!("{}x", google(&nonce)),
        "not.a.token".to_owned(),
        "a".repeat(20_000),
    ];
    for (index, token) in bad.iter().enumerate() {
        assert_eq!(
            fixture.begin(token, WEB).await.unwrap_err(),
            refused(Error::Invalid),
            "case {index}"
        );
    }
    assert_eq!(fixture.pool.state().creates, 0);
    assert!(fixture.begin(&google(&nonce), WEB).await.is_ok());
}

/// An Android app's token names the app's own client in `azp`.
#[tokio::test]
async fn a_listed_authorized_party_may_ask_for_the_token() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    let token = google_with(&nonce, "azp", json!("android-google-client"));
    let verifier = verifier().with_authorized_parties(Provider::Google, ["android-google-client"]);
    assert!(begin_with(&fixture, &verifier, &token).await.is_ok());
}

#[tokio::test]
async fn an_app_client_that_was_not_chosen_is_refused_and_spends_nothing() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    for client in ["", "other-app-client"] {
        assert_eq!(
            fixture.begin(&google(&nonce), client).await.unwrap_err(),
            refused(Error::Invalid)
        );
    }
    assert!(fixture.begin(&google(&nonce), ANDROID).await.is_ok());
}

#[tokio::test]
async fn apple_has_no_native_sign_in() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    let result = begin_provider_sign_in(
        &fixture.directory,
        &verifier(),
        &native(),
        Provider::Apple,
        &token(Provider::Apple, &nonce, "001.a", "a@icloud.com"),
        WEB,
    )
    .await;
    assert_eq!(result.unwrap_err(), OperationError::ProviderNotConfigured);
}

#[tokio::test]
async fn a_directory_that_is_not_ready_spends_nothing() {
    let fixture = fixture().await;
    let nonce = fixture.nonce().await;
    fixture.delete("SYSTEM#READY").await;
    assert_eq!(
        fixture.begin(&google(&nonce), WEB).await.unwrap_err(),
        refused(Error::NotReady)
    );
    assert_eq!(fixture.rows_under("NONCE#").await.len(), 1);
}

#[tokio::test]
async fn an_unfinished_unlink_refuses_the_identity() {
    let fixture = fixture().await;
    let alice = fixture.account("alice", "Cognito").await;
    fixture.link(&alice, Provider::Google, SUBJECT).await;
    fixture.pool.state().disable_failures = 1;
    assert!(
        crate::methods::unlink_sign_in_method(&fixture.directory, &alice, Provider::Google)
            .await
            .is_err()
    );
    let result = fixture.google_ticket(SUBJECT, "alice@example.com").await;
    assert_eq!(result.unwrap_err(), refused(Error::NotReady));
}

/// The account's `sub` the ticket was bound to, for the first user the pool
/// made.
#[tokio::test]
async fn the_ticket_row_is_bound_and_holds_no_ticket() {
    let fixture = fixture().await;
    let answer = fixture.google_ticket(SUBJECT, EMAIL).await.unwrap();
    let rows = fixture.rows_under("TICKET#").await;
    let row = &rows[0];
    for (name, value) in [
        ("userId", SUB),
        ("clientId", WEB),
        ("provider", "Google"),
        ("subject", SUBJECT),
    ] {
        assert_eq!(row[name], Av::S(value.into()), "{name}");
    }
    assert_eq!(row["expiresAt"], Av::N(answer.expires_at.to_string()));
    assert!(!format!("{rows:?}").contains(&answer.ticket));
}
