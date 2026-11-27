use std::sync::{Arc, Mutex};

use aws_sdk_secretsmanager::config::{Credentials, Region, retry::RetryConfig};
use axum::{Json, Router, body::Bytes, http::StatusCode, routing::post};
use serde_json::{Value, json};

use super::*;
use crate::{
    cause::cause,
    testing::loopback::{self, Loopback},
};

/// A Secrets Manager that gives every request one answer and remembers what was
/// asked.
async fn secrets(status: StatusCode, answer: Value) -> (Client, Loopback, Arc<Mutex<Vec<Value>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&asked);
    let server = loopback::serve(Router::new().route(
        "/",
        post(move |body: Bytes| async move {
            seen.lock()
                .unwrap()
                .push(serde_json::from_slice(&body).unwrap());
            (status, Json(answer))
        }),
    ))
    .await;
    let client = Client::from_conf(
        aws_sdk_secretsmanager::Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("local", "local", None, None, "test"))
            .endpoint_url(server.endpoint())
            .retry_config(RetryConfig::disabled())
            .build(),
    );
    (client, server, asked)
}

async fn load(status: StatusCode, answer: Value) -> Result<BudgetKey, KeyError> {
    let (client, _server, _) = secrets(status, answer).await;
    SecretsManagerKey::new(client, "product/mail-budget-key")
        .load()
        .await
}

#[tokio::test]
async fn reads_the_key_from_the_named_secret() {
    let text = "ab".repeat(32);
    let (client, _server, asked) = secrets(StatusCode::OK, json!({"SecretString": text})).await;
    let key = SecretsManagerKey::new(client, "product/mail-budget-key")
        .load()
        .await
        .unwrap();
    assert_eq!(
        key.tag("name"),
        BudgetKey::from_secret(&text).unwrap().tag("name")
    );
    // The current value: no version or stage is named.
    assert_eq!(
        *asked.lock().unwrap(),
        [json!({"SecretId": "product/mail-budget-key"})]
    );
}

#[tokio::test]
async fn a_missing_or_forbidden_secret_is_no_key() {
    for kind in ["ResourceNotFoundException", "AccessDeniedException"] {
        let error = load(
            StatusCode::BAD_REQUEST,
            json!({"__type": kind, "Message": "refused"}),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, KeyError::Read(_)), "{kind}: {error:?}");
        // The log line says which.
        assert!(cause(&error).contains("refused"), "{}", cause(&error));
    }
}

#[tokio::test]
async fn a_secret_that_holds_no_key_is_refused_without_quoting_it() {
    for answer in [
        json!({}),
        json!({"SecretBinary": "q83vq83vq83vq83vq83vq83vq83vq83vq83vq83vq80="}),
    ] {
        assert!(matches!(
            load(StatusCode::OK, answer).await,
            Err(KeyError::NoValue)
        ));
    }
    let error = load(StatusCode::OK, json!({"SecretString": "hunter2"}))
        .await
        .unwrap_err();
    assert!(matches!(error, KeyError::Format));
    assert!(!format!("{error:?} {}", cause(&error)).contains("hunter2"));
}
