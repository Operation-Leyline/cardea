use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use aws_sdk_secretsmanager::config::{Credentials, Region, retry::RetryConfig};
use axum::{Json, Router, http::StatusCode, routing::post};
use serde_json::{Value, json};

use super::*;
use crate::testing::loopback::{self, Loopback};

/// A Secrets Manager that gives every request one answer and counts them.
async fn secrets(status: StatusCode, answer: Value) -> (Client, Loopback, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&reads);
    let server = loopback::serve(Router::new().route(
        "/",
        post(move || async move {
            seen.fetch_add(1, Ordering::SeqCst);
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
    (client, server, reads)
}

#[tokio::test]
async fn a_key_read_is_kept_for_a_while() {
    let text = "ab".repeat(32);
    let (client, _server, reads) = secrets(StatusCode::OK, json!({"SecretString": text})).await;
    let source = SecretsManagerTicketKey::new(client, "product/sign-in-ticket-key");
    for _ in 0..3 {
        let key = source.load().await.unwrap();
        assert_eq!(
            key.tag(&["x"]),
            TicketKey::from_secret(&text).unwrap().tag(&["x"])
        );
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_read_gives_no_key_and_is_tried_again() {
    let refusal = json!({"__type": "AccessDeniedException", "Message": "refused"});
    let (client, _server, reads) = secrets(StatusCode::BAD_REQUEST, refusal).await;
    let source = SecretsManagerTicketKey::new(client, "product/sign-in-ticket-key");
    for _ in 0..2 {
        assert!(matches!(source.load().await, Err(TicketKeyError::Read(_))));
    }
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn the_secret_must_be_named() {
    let config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .build();
    for value in [None, Some(String::new())] {
        let source = SecretsManagerTicketKey::configured(|_| value.clone(), &config);
        assert!(matches!(source, Err(TicketKeyError::NoValue)));
    }
}
