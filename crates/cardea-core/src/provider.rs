//! The external identity providers. A provider is a row of facts, not a branch
//! in the code: adding one is a variant plus its row.

use serde_json::Value;

/// An external identity provider a person may sign in with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// Sign in with Google.
    Google,
    /// Sign in with Apple.
    Apple,
}

/// What differs between providers.
#[derive(Debug)]
pub struct ProviderRule {
    /// The name a person reads.
    pub display_name: &'static str,
    /// Cognito's identity provider name. It also names the provider in the
    /// directory table's keys and in a claim's origin.
    pub cognito_name: &'static str,
    /// Cognito's identity provider type.
    pub cognito_type: &'static str,
    /// The prefixes of a Cognito federated username, which Cognito writes in
    /// either case. What follows is the provider's subject.
    pub username_prefixes: [&'static str; 2],
    /// The `iss` values a proof from this provider may carry.
    pub issuers: &'static [&'static str],
    /// Where the provider publishes the keys that sign its proofs.
    pub keys_url: &'static str,
    /// Whether the provider owns the mailbox, so that its say-so alone proves
    /// the person holds it and the sign-in may link automatically. Called
    /// only for an address the claims already mark verified, with its
    /// lowercased domain.
    pub owns_mailbox: fn(domain: &str, claims: &Value) -> bool,
}

static GOOGLE: ProviderRule = ProviderRule {
    display_name: "Google",
    cognito_name: "Google",
    cognito_type: "Google",
    username_prefixes: ["Google_", "google_"],
    issuers: &["https://accounts.google.com", "accounts.google.com"],
    keys_url: "https://www.googleapis.com/oauth2/v3/certs",
    owns_mailbox: google_owns,
};

static APPLE: ProviderRule = ProviderRule {
    display_name: "Apple",
    cognito_name: "SignInWithApple",
    cognito_type: "SignInWithApple",
    username_prefixes: ["SignInWithApple_", "signinwithapple_"],
    issuers: &["https://appleid.apple.com"],
    keys_url: "https://appleid.apple.com/auth/keys",
    owns_mailbox: apple_owns,
};

/// Gmail, or a Google Workspace account (`hd`).
fn google_owns(domain: &str, claims: &Value) -> bool {
    domain == "gmail.com"
        || domain == "googlemail.com"
        || claims["hd"].as_str().is_some_and(|s| !s.trim().is_empty())
}

/// An Apple mailbox that is not a private relay. Apple sends
/// `is_private_email` as a boolean or a string; any value other than a clear
/// "no" counts as a relay.
fn apple_owns(domain: &str, claims: &Value) -> bool {
    let relay = !match &claims["is_private_email"] {
        Value::Null => true,
        Value::Bool(private) => !private,
        Value::String(private) => private == "false",
        _ => false,
    };
    !relay && matches!(domain, "icloud.com" | "me.com" | "mac.com")
}

impl Provider {
    /// Every provider.
    pub const ALL: [Provider; 2] = [Provider::Google, Provider::Apple];

    /// This provider's row.
    pub fn rule(self) -> &'static ProviderRule {
        match self {
            Self::Google => &GOOGLE,
            Self::Apple => &APPLE,
        }
    }

    /// The provider Cognito calls `name`.
    pub fn from_cognito_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.rule().cognito_name == name)
    }

    /// The provider and subject a Cognito federated username names.
    pub fn from_federated_username(username: &str) -> Option<(Self, &str)> {
        Self::ALL.into_iter().find_map(|provider| {
            provider
                .rule()
                .username_prefixes
                .iter()
                .find_map(|prefix| username.strip_prefix(prefix))
                .filter(|subject| !subject.is_empty())
                .map(|subject| (provider, subject))
        })
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
