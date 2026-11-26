use serde_json::json;

use super::*;

fn event(source: &str, verified: &str) -> Value {
    json!({"triggerSource": source, "userName": "internal",
        "request": {"userAttributes": {"sub": "sub", "email": "pat@example.com",
            "email_verified": verified}}})
}

#[test]
fn only_a_verified_signup_is_a_confirmed_signup() {
    for (source, verified, expected) in [
        ("PostConfirmation_ConfirmSignUp", "true", true),
        ("PostConfirmation_ConfirmSignUp", "false", false),
        ("PostConfirmation_ConfirmForgotPassword", "true", false),
        ("TokenGeneration_Authentication", "true", false),
        ("TokenGeneration_RefreshTokens", "true", false),
    ] {
        let account = account(&event(source, verified)).unwrap();
        assert_eq!(account.confirmed_signup, expected, "{source} {verified}");
    }
    assert!(account(&Value::Null).is_err());
}

#[test]
fn an_account_needs_a_sub_an_email_and_a_user_name() {
    for pointer in [
        "/request/userAttributes/sub",
        "/request/userAttributes/email",
        "/userName",
    ] {
        let mut payload = event("TokenGeneration_Authentication", "true");
        *payload.pointer_mut(pointer).unwrap() = json!("");
        assert!(account(&payload).is_err(), "{pointer}");
    }
}

#[test]
fn the_display_name_falls_back_to_the_local_part() {
    let mut payload = event("PostConfirmation_ConfirmSignUp", "true");
    assert_eq!(account(&payload).unwrap().display_name, "pat");
    payload["request"]["userAttributes"]["name"] = json!("  ");
    assert_eq!(account(&payload).unwrap().display_name, "pat");
    payload["request"]["userAttributes"]["name"] = json!("Pat Smith");
    assert_eq!(account(&payload).unwrap().display_name, "Pat Smith");
}

#[test]
fn claims_take_the_shape_the_event_version_reads() {
    let claims = Claims([("custom:tenantId".to_owned(), "ws_1".to_owned())].into());
    let expected = json!({"custom:tenantId":"ws_1"});

    let mut first = json!({"version":"1","response":{}});
    add_claims(&mut first, claims.clone());
    assert_eq!(
        first["response"]["claimsOverrideDetails"]["claimsToAddOrOverride"],
        expected
    );

    let mut second = json!({"version":"2","response":{}});
    add_claims(&mut second, claims);
    let details = &second["response"]["claimsAndScopeOverrideDetails"];
    for token in ["idTokenGeneration", "accessTokenGeneration"] {
        assert_eq!(details[token]["claimsToAddOrOverride"], expected);
    }

    let mut none = json!({"version":"1","response":{}});
    add_claims(&mut none, Claims::default());
    assert_eq!(none["response"], json!({}));
}
