//! Signed tokens against the real checks.

use aws_lc_rs::{rsa::KeySize, signature::RsaKeyPair};
use cardea_core::{Error, Provider};
use serde_json::{Value, json};

use super::*;
use crate::{
    directory::now,
    testing::provider::{claims, client_id, sign, signing_key, verifier},
};

const NONCE: &str = "challenge";

async fn check(provider: Provider, token: &str) -> Result<VerifiedProof, Error> {
    verifier()
        .verify(ProofRequest {
            provider,
            token,
            client_id: client_id(provider),
            nonce: NONCE,
            now: now(),
        })
        .await
}

fn good(provider: Provider) -> Value {
    claims(provider, NONCE, "subject", "User@Example.com")
}

#[tokio::test]
async fn a_good_proof_names_the_subject_and_keeps_the_email_as_written() {
    for provider in Provider::ALL {
        let proof = check(provider, &sign(signing_key(), &good(provider)))
            .await
            .unwrap();
        assert_eq!(proof.identity.provider, provider);
        assert_eq!(proof.identity.subject, "subject");
        assert_eq!(proof.identity.email, "user@example.com");
        assert_eq!(proof.email, "User@Example.com");
    }
}

#[tokio::test]
async fn google_accepts_its_bare_issuer() {
    let mut claims = good(Provider::Google);
    claims["iss"] = json!("accounts.google.com");
    assert!(
        check(Provider::Google, &sign(signing_key(), &claims))
            .await
            .is_ok()
    );
}

/// Leyline's `fresh_signed_proof_is_bound_to_google_client_nonce_and_mailbox`,
/// for every provider.
#[tokio::test]
async fn a_proof_is_bound_to_its_issuer_client_nonce_mailbox_and_time() {
    for provider in Provider::ALL {
        let time = now();
        for (field, value) in [
            ("iss", json!("https://attacker.test")),
            ("aud", json!("other-client")),
            ("aud", json!([client_id(provider), "other-client"])),
            ("azp", json!("other-client")),
            ("nonce", json!("other-challenge")),
            ("email_verified", json!(false)),
            ("email_verified", json!("false")),
            ("email", Value::Null),
            ("sub", json!("")),
            ("iat", json!(time - 301)),
            ("iat", json!(time + 31)),
            ("iat", Value::Null),
            ("exp", json!(time - 1)),
            ("nbf", json!(time + 60)),
        ] {
            let mut bad = good(provider);
            bad[field] = value.clone();
            assert_eq!(
                check(provider, &sign(signing_key(), &bad))
                    .await
                    .map(|_| ()),
                Err(Error::Invalid),
                "{provider:?} {field} {value}"
            );
        }
    }
}

const APP_CLIENT: &str = "android-app-client";

/// Whether `verifier` takes a Google proof with `changes` made to it.
async fn takes(verifier: &JwtVerifier, changes: &[(&str, Value)]) -> bool {
    let mut claims = good(Provider::Google);
    for (field, value) in changes {
        claims[*field] = value.clone();
    }
    let token = sign(signing_key(), &claims);
    let answer = verifier
        .verify(ProofRequest {
            provider: Provider::Google,
            token: &token,
            client_id: client_id(Provider::Google),
            nonce: NONCE,
            now: now(),
        })
        .await;
    match answer {
        Ok(_) => true,
        Err(error) => {
            assert_eq!(error, Error::Invalid);
            false
        }
    }
}

/// A token an Android app asks for: the web client's, naming the app in `azp`.
#[tokio::test]
async fn a_listed_authorized_party_is_accepted() {
    let verifier = verifier().with_authorized_parties(Provider::Google, ["other", APP_CLIENT]);
    assert!(takes(&verifier, &[("azp", json!(APP_CLIENT))]).await);
    assert!(takes(&verifier, &[("azp", json!(client_id(Provider::Google)))]).await);
    assert!(takes(&verifier, &[]).await);
}

#[tokio::test]
async fn an_unlisted_authorized_party_is_refused() {
    let verifier = verifier().with_authorized_parties(Provider::Google, [APP_CLIENT, ""]);
    for party in [
        json!("another-app"),
        json!(""),
        Value::Null,
        json!([APP_CLIENT]),
    ] {
        assert!(
            !takes(&verifier, &[("azp", party.clone())]).await,
            "{party}"
        );
    }
}

#[tokio::test]
async fn a_listed_authorized_party_does_not_stand_in_for_the_audience() {
    let verifier = verifier().with_authorized_parties(Provider::Google, [APP_CLIENT]);
    for audience in [
        json!(APP_CLIENT),
        json!("other-client"),
        json!([client_id(Provider::Google), APP_CLIENT]),
    ] {
        let changes = [("aud", audience.clone()), ("azp", json!(APP_CLIENT))];
        assert!(!takes(&verifier, &changes).await, "{audience}");
    }
}

#[tokio::test]
async fn by_default_only_the_client_may_be_the_authorized_party() {
    for verifier in [
        verifier(),
        // Another provider's list says nothing about Google.
        verifier().with_authorized_parties(Provider::Apple, [APP_CLIENT]),
        // A second call replaces the list.
        verifier()
            .with_authorized_parties(Provider::Google, [APP_CLIENT])
            .with_authorized_parties(Provider::Google, Vec::<String>::new()),
    ] {
        assert!(!takes(&verifier, &[("azp", json!(APP_CLIENT))]).await);
        assert!(takes(&verifier, &[("azp", json!(client_id(Provider::Google)))]).await);
        assert!(takes(&verifier, &[]).await);
    }
}

#[tokio::test]
async fn one_providers_token_is_not_anothers_proof() {
    for (signed, asked) in [
        (Provider::Google, Provider::Apple),
        (Provider::Apple, Provider::Google),
    ] {
        let mut claims = good(signed);
        // Even for the other provider's client, the issuer gives it away.
        claims["aud"] = json!(client_id(asked));
        assert_eq!(
            check(asked, &sign(signing_key(), &claims))
                .await
                .map(|_| ()),
            Err(Error::Invalid)
        );
    }
}

#[tokio::test]
async fn another_keys_signature_and_junk_are_refused() {
    let other = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    for token in [
        sign(&other, &good(Provider::Google)),
        "not-a-token".into(),
        String::new(),
    ] {
        assert_eq!(
            check(Provider::Google, &token).await.map(|_| ()),
            Err(Error::Invalid)
        );
    }
}

#[tokio::test]
async fn an_empty_client_or_nonce_proves_nothing() {
    for (client_id, nonce) in [("", NONCE), (client_id(Provider::Google), "")] {
        let mut claims = good(Provider::Google);
        claims["aud"] = json!(client_id);
        claims["nonce"] = json!(nonce);
        let token = sign(signing_key(), &claims);
        let refused = verifier()
            .verify(ProofRequest {
                provider: Provider::Google,
                token: &token,
                client_id,
                nonce,
                now: now(),
            })
            .await;
        assert_eq!(refused.map(|_| ()), Err(Error::Invalid));
    }
}

/// Apple sends both flags as strings or booleans.
#[tokio::test]
async fn apple_flags_are_read_as_strings_or_booleans() {
    for (verified, private) in [
        (json!(true), json!(true)),
        (json!("true"), json!("true")),
        (json!(true), json!("true")),
        (json!("true"), json!(true)),
    ] {
        let mut claims = good(Provider::Apple);
        claims["email"] = json!("x1@privaterelay.appleid.com");
        claims["email_verified"] = verified;
        claims["is_private_email"] = private;
        let proof = check(Provider::Apple, &sign(signing_key(), &claims))
            .await
            .unwrap();
        assert!(proof.identity.private_relay);
        assert!(!proof.identity.authoritative);
    }
    for private in [json!(false), json!("false")] {
        let mut claims = good(Provider::Apple);
        claims["email"] = json!("owner@icloud.com");
        claims["is_private_email"] = private;
        let proof = check(Provider::Apple, &sign(signing_key(), &claims))
            .await
            .unwrap();
        assert!(!proof.identity.private_relay);
        assert!(proof.identity.authoritative);
    }
}

#[tokio::test]
async fn keys_that_cannot_be_fetched_are_unavailable_not_invalid() {
    use crate::proof::{KeyFetchError, KeyFetcher};

    struct Down;
    #[async_trait::async_trait]
    impl KeyFetcher for Down {
        async fn fetch(&self, _: &str) -> Result<Vec<u8>, KeyFetchError> {
            Err(KeyFetchError::TooLarge)
        }
    }
    let token = sign(signing_key(), &good(Provider::Apple));
    let refused = JwtVerifier::with_fetcher(std::sync::Arc::new(Down))
        .verify(ProofRequest {
            provider: Provider::Apple,
            token: &token,
            client_id: client_id(Provider::Apple),
            nonce: NONCE,
            now: now(),
        })
        .await;
    assert_eq!(refused.map(|_| ()), Err(Error::Unavailable));
}

#[test]
fn each_provider_reads_its_own_key_set() {
    assert_eq!(
        Provider::Apple.rule().keys_url,
        "https://appleid.apple.com/auth/keys"
    );
    assert_eq!(
        Provider::Google.rule().keys_url,
        "https://www.googleapis.com/oauth2/v3/certs"
    );
}
