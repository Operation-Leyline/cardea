//! Listing and unlinking, over an in-process DynamoDB and a fake pool.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, Error, Provider, User};

use super::*;
use crate::{
    OperationError,
    testing::{Fixture, fixture},
};

mod bind;
mod list;
mod partial;
mod sign_in;
mod unlink;

const GOOGLE: Provider = Provider::Google;
const APPLE: Provider = Provider::Apple;

fn provider(provider: Provider, email: Option<&str>) -> SignInMethod {
    SignInMethod::Provider {
        provider,
        email: email.map(str::to_owned),
    }
}

async fn list(f: &Fixture, user: &User) -> Vec<SignInMethod> {
    list_sign_in_methods(&f.directory, user).await.unwrap()
}

async fn unlink(f: &Fixture, user: &User, provider: Provider) -> Result<(), OperationError> {
    unlink_sign_in_method(&f.directory, user, provider).await
}

async fn bound(f: &Fixture, provider: Provider, subject: &str) -> Option<User> {
    f.directory.provider(provider, subject).await.unwrap()
}

/// The stored list of `user`: its version and JSON.
async fn stored(f: &Fixture, user: &User) -> Option<(i64, String)> {
    let item = f.item(&format!("METHODS#{}", user.user_id)).await?;
    Some((
        item["version"].as_n().unwrap().parse().unwrap(),
        item["identities"].as_s().unwrap().clone(),
    ))
}

/// An account with a chosen password and a linked Google identity.
async fn password_and_google() -> (Fixture, User) {
    let f = fixture().await;
    let alice = f.account("alice", "Cognito").await;
    f.link(&alice, GOOGLE, "google-1").await;
    (f, alice)
}
