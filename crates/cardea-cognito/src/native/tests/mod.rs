//! Native sign-in over an in-process DynamoDB and a fake pool. Google's tokens
//! are real signed tokens checked by the real verifier; only the signing keys
//! are replaced.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Directory, Error, Provider};
use serde_json::{Value, json};

use super::*;
use crate::{
    OperationError,
    directory::now,
    proof::JwtVerifier,
    testing::{
        Fixture,
        accounts::clients,
        cognito::SUB,
        fixture,
        native::{ANDROID, WEB, native, ticket_key},
        provider::{claims, client_id, sign, signing_key, token, verifier},
    },
};

mod begin;
mod nonce;
mod ticket;

const SUBJECT: &str = "g-subject-1";
const EMAIL: &str = "owner@gmail.com";

fn google(nonce: &str) -> String {
    token(Provider::Google, nonce, SUBJECT, EMAIL)
}

/// A Google token with one claim replaced, or removed by `null`.
fn google_with(nonce: &str, name: &str, value: Value) -> String {
    let mut claims = claims(Provider::Google, nonce, SUBJECT, EMAIL);
    if value.is_null() {
        claims.as_object_mut().unwrap().remove(name);
    } else {
        claims[name] = value;
    }
    sign(signing_key(), &claims)
}

fn refused(error: Error) -> OperationError {
    OperationError::Identity(error)
}

/// A key source that never has a key.
struct NoKey;

#[async_trait::async_trait]
impl TicketKeySource for NoKey {
    async fn load(&self) -> Result<TicketKey, TicketKeyError> {
        Err(TicketKeyError::NoValue)
    }
}
