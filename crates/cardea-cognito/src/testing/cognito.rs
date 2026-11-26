//! A fake user pool: the five admin calls the library makes, on loopback.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use aws_sdk_cognitoidentityprovider::{
    Client,
    config::{Credentials, Region, retry::RetryConfig},
};
use axum::{
    Json, Router, body::Bytes, extract::State, http::HeaderMap, http::StatusCode, routing::post,
};
use serde_json::{Value, json};
use tokio::sync::Barrier;

use super::loopback::{Loopback, serve};

/// The `sub` of the first user the pool creates.
pub(crate) const SUB: &str = "sub-0";

#[derive(Clone)]
pub(crate) struct Account {
    pub sub: String,
    pub email: String,
    pub status: &'static str,
    /// `(providerName, subject)`.
    pub identities: Vec<(String, String)>,
    /// Report `email_verified` as false.
    pub unverified: bool,
}

#[derive(Default)]
pub(crate) struct PoolState {
    /// Keyed by the username the account was made with.
    pub users: BTreeMap<String, Account>,
    pub creates: usize,
    pub passwords: usize,
    pub links: usize,
    /// The `clientMetadata` of the last created user.
    pub create_metadata: Value,
    /// An error type the next password change answers with.
    pub password_error: Option<&'static str>,
    /// Link calls that fail without linking.
    pub link_failures: usize,
    /// Link calls that link and then answer with a failure.
    pub lost_links: usize,
    /// Calls that take a provider off a user, counted when they do it.
    pub disables: usize,
    /// Disable calls that fail without unlinking.
    pub disable_failures: usize,
    /// Disable calls that unlink and then answer with a failure.
    pub lost_disables: usize,
    /// The next calls reading a user wait here for each other first.
    pub read_barrier: Option<(Arc<Barrier>, usize)>,
}

#[derive(Clone, Default)]
pub(crate) struct Pool(Arc<Mutex<PoolState>>);

impl Pool {
    pub fn state(&self) -> MutexGuard<'_, PoolState> {
        self.0.lock().unwrap()
    }

    /// Put an account in the pool.
    pub fn add(&self, username: &str, sub: &str, email: &str, status: &'static str) {
        self.state().users.insert(
            username.into(),
            Account {
                sub: sub.into(),
                email: email.into(),
                status,
                identities: Vec::new(),
                unverified: false,
            },
        );
    }

    pub(super) async fn serve(&self) -> Loopback {
        serve(
            Router::new()
                .route("/", post(answer))
                .with_state(self.clone()),
        )
        .await
    }
}

/// A client for a fake pool, which answers each call once.
pub(super) fn client(endpoint: &str) -> Client {
    Client::from_conf(
        aws_sdk_cognitoidentityprovider::Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .credentials_provider(Credentials::new("test", "test", None, None, "local"))
            .build(),
    )
}

fn refusal(kind: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"__type": kind, "message": "refused"})),
    )
}

async fn answer(
    State(pool): State<Pool>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let target = headers["x-amz-target"].to_str().unwrap();
    let operation = target.rsplit_once('.').unwrap().1;
    let request: Value = serde_json::from_slice(&body).unwrap();
    if operation == "AdminGetUser" {
        let barrier = match &mut pool.state().read_barrier {
            Some((barrier, waiting)) if *waiting > 0 => {
                *waiting -= 1;
                Some(Arc::clone(barrier))
            }
            _ => None,
        };
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
    }
    let mut state = pool.state();
    let ok = (StatusCode::OK, Json(json!({})));
    if operation == "AdminLinkProviderForUser" {
        if state.link_failures > 0 {
            state.link_failures -= 1;
            return refusal("InternalErrorException");
        }
        let name = request["DestinationUser"]["ProviderAttributeValue"]
            .as_str()
            .unwrap();
        let source = &request["SourceUser"];
        assert_eq!(source["ProviderAttributeName"], "Cognito_Subject");
        let identity = (
            source["ProviderName"].as_str().unwrap().to_owned(),
            source["ProviderAttributeValue"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        // An identity signs in as one user only.
        if state
            .users
            .iter()
            .any(|(other, user)| other != name && user.identities.contains(&identity))
        {
            return refusal("InvalidParameterException");
        }
        state.links += 1;
        state
            .users
            .get_mut(name)
            .expect("a link names a user")
            .identities
            .push(identity);
        if state.lost_links > 0 {
            state.lost_links -= 1;
            return refusal("InternalErrorException");
        }
        return ok;
    }
    if operation == "AdminDisableProviderForUser" {
        if state.disable_failures > 0 {
            state.disable_failures -= 1;
            return refusal("InternalErrorException");
        }
        let named = &request["User"];
        assert_eq!(named["ProviderAttributeName"], "Cognito_Subject");
        let identity = (
            named["ProviderName"].as_str().unwrap().to_owned(),
            named["ProviderAttributeValue"].as_str().unwrap().to_owned(),
        );
        let Some(user) = state
            .users
            .values_mut()
            .find(|user| user.identities.contains(&identity))
        else {
            return refusal("UserNotFoundException");
        };
        user.identities.retain(|linked| *linked != identity);
        state.disables += 1;
        if state.lost_disables > 0 {
            state.lost_disables -= 1;
            return refusal("InternalErrorException");
        }
        return ok;
    }
    let username = request["Username"].as_str().unwrap().to_owned();
    // A user is found by its username or by its email alias, in any case.
    let found = state
        .users
        .iter()
        .find(|(name, user)| **name == username || user.email.eq_ignore_ascii_case(&username))
        .map(|(name, user)| (name.clone(), user.clone()));
    match operation {
        "AdminGetUser" => match found {
            None => refusal("UserNotFoundException"),
            Some((name, user)) => {
                let mut attributes = vec![
                    json!({"Name":"sub","Value":user.sub}),
                    json!({"Name":"email","Value":user.email}),
                    json!({"Name":"email_verified","Value":(!user.unverified).to_string()}),
                ];
                if !user.identities.is_empty() {
                    let identities: Vec<Value> = user
                        .identities
                        .iter()
                        .map(
                            |(provider, subject)| json!({"providerName":provider,"userId":subject}),
                        )
                        .collect();
                    attributes.push(json!({"Name":"identities",
                        "Value":Value::from(identities).to_string()}));
                }
                (
                    StatusCode::OK,
                    Json(
                        json!({"Username":name,"Enabled":true,"UserStatus":user.status,
                        "UserAttributes":attributes}),
                    ),
                )
            }
        },
        "AdminCreateUser" => {
            if found.is_some() {
                return refusal("UsernameExistsException");
            }
            let sub = format!("sub-{}", state.creates);
            state.creates += 1;
            state.create_metadata = request["ClientMetadata"].clone();
            let email = request["UserAttributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["Name"] == "email")
                .unwrap()["Value"]
                .as_str()
                .unwrap()
                .to_owned();
            state.users.insert(
                username,
                Account {
                    sub,
                    email,
                    status: "FORCE_CHANGE_PASSWORD",
                    identities: Vec::new(),
                    unverified: false,
                },
            );
            ok
        }
        "AdminSetUserPassword" => {
            if let Some(error) = state.password_error.take() {
                return refusal(error);
            }
            state.passwords += 1;
            let (name, _) = found.expect("a password names a user");
            state.users.get_mut(&name).unwrap().status = "CONFIRMED";
            ok
        }
        other => panic!("unexpected Cognito call {other}"),
    }
}
