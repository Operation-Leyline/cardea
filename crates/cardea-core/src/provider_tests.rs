use super::*;

#[test]
fn each_row_is_the_designs_table() {
    let google = Provider::Google.rule();
    assert_eq!(
        (google.cognito_name, google.cognito_type),
        ("Google", "Google")
    );
    assert_eq!(
        google.issuers,
        ["https://accounts.google.com", "accounts.google.com"]
    );
    assert_eq!(
        google.keys_url,
        "https://www.googleapis.com/oauth2/v3/certs"
    );
    let apple = Provider::Apple.rule();
    assert_eq!(
        (apple.cognito_name, apple.cognito_type),
        ("SignInWithApple", "SignInWithApple")
    );
    assert_eq!(apple.issuers, ["https://appleid.apple.com"]);
    assert_eq!(apple.keys_url, "https://appleid.apple.com/auth/keys");
    for provider in Provider::ALL {
        let name = provider.rule().cognito_name;
        assert_eq!(Provider::from_cognito_name(name), Some(provider));
    }
    for name in ["google", "Apple", "Microsoft", "Cognito", ""] {
        assert_eq!(Provider::from_cognito_name(name), None, "{name}");
    }
}

#[test]
fn a_federated_username_names_its_provider_and_subject_in_both_cases() {
    for (username, provider, subject) in [
        ("Google_123", Provider::Google, "123"),
        ("google_123", Provider::Google, "123"),
        ("SignInWithApple_001.ab_c.9", Provider::Apple, "001.ab_c.9"),
        ("signinwithapple_001.abc.9", Provider::Apple, "001.abc.9"),
    ] {
        assert_eq!(
            Provider::from_federated_username(username),
            Some((provider, subject))
        );
    }
    for username in [
        "Google_",
        "SignInWithApple_",
        "GOOGLE_123",
        "Apple_123",
        "123",
        "someone@example.com",
    ] {
        assert_eq!(Provider::from_federated_username(username), None);
    }
}
