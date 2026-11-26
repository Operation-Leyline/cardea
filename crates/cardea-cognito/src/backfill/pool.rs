//! Every user of the pool, as the backfill reads them.

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
    /// The first provider the pool lists, known or not.
    pub first_provider: Option<String>,
    /// Whether the list names a provider this library does not know.
    pub unsupported_provider: bool,
}

impl PoolAccount {
    fn read(user: &UserType) -> Self {
        let attributes = user.attributes();
        let text = |name| {
            value_of(attributes, name)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let listed: Vec<Value> = value_of(attributes, "identities")
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default();
        let identities = identities_of(attributes).ok();
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
            first_provider: listed
                .first()
                .and_then(|identity| identity["providerName"].as_str())
                .map(str::to_owned),
            unsupported_provider: identities
                .as_ref()
                .is_some_and(|known| known.len() < listed.len()),
            identities,
        }
    }
}

impl AwsDirectory {
    /// Every user of the pool, page by page.
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
                return Ok(accounts);
            }
        }
    }
}
