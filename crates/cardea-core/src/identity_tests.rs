use super::*;
use serde_json::json;

fn authoritative(provider: Provider, claims: Value) -> Option<bool> {
    ProviderIdentity::from_verified_claims(provider, &claims)
        .ok()
        .map(|identity| identity.authoritative)
}

#[test]
fn trust_only_authoritative_google_mailboxes_and_validate_claims() {
    for (email, hd, verified, expected) in [
        ("a@gmail.com", "", true, Some(true)),
        ("a@googlemail.com", "", true, Some(true)),
        ("a@company.com", "company.com", true, Some(true)),
        ("a@example.com", "", true, Some(false)),
        ("a@example.com", "  ", true, Some(false)),
        ("a@gmail.com", "", false, None),
        ("a@gmail.com.evil.test", "", true, Some(false)),
    ] {
        let claims = json!({"sub":"subject", "email":email, "email_verified":verified, "hd":hd});
        assert_eq!(authoritative(Provider::Google, claims), expected, "{email}");
    }
    assert!(
        ProviderIdentity::from_verified_claims(
            Provider::Google,
            &json!({"email":"a@gmail.com", "email_verified":true})
        )
        .is_err()
    );
}

#[test]
fn a_subject_is_present_and_bounded_for_every_provider() {
    for provider in Provider::ALL {
        for subject in [json!(null), json!(""), json!("s".repeat(256)), json!(1)] {
            let claims = json!({"sub":subject, "email":"a@example.com", "email_verified":true});
            assert_eq!(authoritative(provider, claims), None);
        }
    }
}

/// Apple sends both booleans as booleans or as strings.
#[test]
fn apple_owns_only_its_own_mailboxes_when_they_are_not_relays() {
    for domain in ["icloud.com", "me.com", "mac.com"] {
        for (private, expected) in [
            (json!(null), true),
            (json!(false), true),
            (json!("false"), true),
            (json!(true), false),
            (json!("true"), false),
            (json!("TRUE"), false),
            (json!(0), false),
        ] {
            for verified in [json!(true), json!("true")] {
                let claims = json!({"sub":"s", "email":format!("a@{domain}"),
                    "email_verified":verified, "is_private_email":private});
                assert_eq!(
                    authoritative(Provider::Apple, claims),
                    Some(expected),
                    "{domain} {private}"
                );
            }
        }
    }
}

#[test]
fn other_verified_domains_are_not_apples_to_vouch_for() {
    for email in [
        "a@gmail.com",
        "a@company.com",
        "a@privaterelay.appleid.com",
        "a@icloud.com.evil.test",
        "a@sub.icloud.com",
    ] {
        // `hd` is Google's claim and means nothing from Apple.
        let claims = json!({"sub":"s", "email":email, "email_verified":"true", "hd":"company.com"});
        assert_eq!(
            authoritative(Provider::Apple, claims),
            Some(false),
            "{email}"
        );
    }
}

#[test]
fn an_unverified_apple_address_is_refused() {
    for verified in [json!(false), json!("false"), json!(null)] {
        let claims = json!({"sub":"s", "email":"a@icloud.com", "email_verified":verified});
        assert_eq!(authoritative(Provider::Apple, claims), None);
    }
}
