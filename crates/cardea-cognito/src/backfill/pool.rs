//! Every user of the pool, as the backfill reads them.

use std::collections::HashSet;

use aws_sdk_cognitoidentityprovider::{error::ProvideErrorMetadata, types::UserType};
use serde_json::Value;

use super::BackfillError;
use crate::{
    directory::{AwsDirectory, value_of},
    methods::{pool::identities_of, row::Identity},
};

/// The most users one `ListUsers` page may ask for.
const PAGE: i32 = 60;

/// What a user's status says about how they sign in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Standing {
    /// A native user who chose a password.
    Confirmed,
    /// A native signup nobody has confirmed.
    Unconfirmed,
    /// A user that exists only behind a provider sign-in.
    Federated,
    /// A native user with no password of their own in force: made by an
    /// operator, or told to reset it.
    NoPassword,
}

/// One user of the pool.
pub(super) struct PoolAccount {
    /// The `sub`.
    pub user_id: Option<String>,
    pub username: String,
    /// The address as the pool holds it.
    pub email: Option<String>,
    pub email_verified: bool,
    pub standing: Standing,
    /// The linked identities of providers this library knows; `None` when the
    /// list cannot be read.
    pub identities: Option<Vec<Identity>>,
    /// Every `(providerName, subject)` the pool lists on the user, known
    /// provider or not.
    listed: Vec<(String, String)>,
}

impl PoolAccount {
    fn read(user: &UserType) -> Self {
        let attributes = user.attributes();
        let text = |name| {
            value_of(attributes, name)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let entries: Vec<Value> = value_of(attributes, "identities")
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default();
        let listed = entries
            .iter()
            .filter_map(|identity| {
                Some((
                    identity["providerName"].as_str()?.to_owned(),
                    identity["userId"].as_str()?.to_owned(),
                ))
            })
            .collect();
        Self {
            user_id: text("sub"),
            username: user.username().unwrap_or_default().to_owned(),
            email: text("email"),
            email_verified: value_of(attributes, "email_verified") == Some("true"),
            standing: match user.user_status().map(|status| status.as_str()) {
                Some("CONFIRMED") => Standing::Confirmed,
                Some("UNCONFIRMED") => Standing::Unconfirmed,
                Some("EXTERNAL_PROVIDER") => Standing::Federated,
                _ => Standing::NoPassword,
            },
            identities: identities_of(attributes).ok(),
            listed,
        }
    }

    /// The first provider the pool lists, known or not.
    pub fn first_provider(&self) -> Option<&str> {
        self.listed.first().map(|(provider, _)| provider.as_str())
    }

    /// Whether the list names a provider this library does not know.
    pub fn has_unsupported_provider(&self) -> bool {
        self.identities
            .as_ref()
            .is_some_and(|known| known.len() < self.listed.len())
    }
}

/// The username Cognito gives an identity's own profile: the provider's name,
/// `_`, the subject. Compared in lowercase, as Cognito writes either case.
fn profile_name(provider: &str, subject: &str) -> String {
    format!("{provider}_{subject}").to_ascii_lowercase()
}

/// Leave out the profiles of linked identities. `ListUsers` shows such a profile
/// beside the user the identity is linked to; it is that person's sign-in, not
/// another user.
///
/// Only a provider's profile (`EXTERNAL_PROVIDER`) is one, named for an
/// identity another user lists, and listing no identity but such ones. A
/// native user stays whatever its name, and so does a federated-only user.
fn without_linked_profiles(mut accounts: Vec<PoolAccount>) -> Vec<PoolAccount> {
    // What users link besides themselves, and the names of those profiles.
    let (names, linked): (HashSet<String>, HashSet<(String, String)>) = accounts
        .iter()
        .flat_map(|account| {
            let own = account.username.to_ascii_lowercase();
            account.listed.iter().filter_map(move |identity| {
                let name = profile_name(&identity.0, &identity.1);
                (name != own).then(|| (name, identity.clone()))
            })
        })
        .unzip();
    accounts.retain(|account| {
        !(account.standing == Standing::Federated
            && names.contains(&account.username.to_ascii_lowercase())
            && account
                .listed
                .iter()
                .all(|identity| linked.contains(identity)))
    });
    accounts
}

impl AwsDirectory {
    /// Every user of the pool, page by page, linked identities' own profiles
    /// apart.
    pub(super) async fn all_accounts(&self) -> Result<Vec<PoolAccount>, BackfillError> {
        let mut accounts = Vec::new();
        let mut token = None;
        loop {
            let page = self
                .cognito()
                .list_users()
                .user_pool_id(self.pool())
                .limit(PAGE)
                .set_pagination_token(token)
                .send()
                .await
                .map_err(|error| {
                    BackfillError::ListUsers(error.code().unwrap_or("no answer").to_owned())
                })?;
            accounts.extend(page.users().iter().map(PoolAccount::read));
            token = page.pagination_token().map(str::to_owned);
            if token.is_none() {
                return Ok(without_linked_profiles(accounts));
            }
        }
    }
}
