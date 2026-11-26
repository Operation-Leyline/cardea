//! The directory and the pool are reached in the pool's region, wherever the
//! caller runs.

use std::sync::{Arc, Mutex};

use axum::{Json, Router, body::Bytes, extract::State, http::HeaderMap, routing::post};
use cardea_core::Directory;
use serde_json::{Value, json};

use super::{AwsDirectory, config::in_pool_region};
use crate::testing::loopback::serve;

async fn peer(
    State(calls): State<Arc<Mutex<Vec<String>>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    let target = headers["x-amz-target"].to_str().unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    let signing_service = if target.ends_with(".GetItem") {
        assert_eq!(request["TableName"], "identities");
        assert_eq!(request["ConsistentRead"], true);
        "dynamodb"
    } else {
        assert!(target.ends_with(".AdminGetUser"));
        assert_eq!(request["UserPoolId"], "us-east-1_fixture");
        "cognito-idp"
    };
    assert!(
        headers["authorization"]
            .to_str()
            .unwrap()
            .contains(&format!("/us-east-1/{signing_service}/aws4_request"))
    );
    calls.lock().unwrap().push(signing_service.into());
    Json(if signing_service == "dynamodb" {
        json!({"Item":{"identityKey":{"S":"SYSTEM#READY"},"version":{"N":"1"}}})
    } else {
        json!({"Username":"alice","Enabled":true,"UserStatus":"CONFIRMED","UserAttributes":[]})
    })
}

#[tokio::test]
async fn a_caller_in_ireland_uses_the_pools_region() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = serve(
        Router::new()
            .route("/", post(peer))
            .with_state(calls.clone()),
    )
    .await;
    let config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("eu-west-1"))
        .credentials_provider(aws_sdk_dynamodb::config::SharedCredentialsProvider::new(
            aws_sdk_dynamodb::config::Credentials::new("test", "test", None, None, "local"),
        ))
        .endpoint_url(server.endpoint())
        .retry_config(aws_config::retry::RetryConfig::standard().with_max_attempts(1))
        .build();
    let directory =
        AwsDirectory::from_config(&config, "identities".into(), "us-east-1_fixture".into());
    assert_eq!(directory.ready().await, Ok(()));
    directory
        .cognito()
        .admin_get_user()
        .user_pool_id(directory.pool())
        .username("alice")
        .send()
        .await
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), ["dynamodb", "cognito-idp"]);
    assert_eq!(config.region().unwrap().as_ref(), "eu-west-1");
}

#[test]
fn only_the_region_changes_and_an_unreadable_pool_id_changes_nothing() {
    let config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("eu-west-1"))
        .endpoint_url("http://127.0.0.1:9")
        .retry_config(aws_config::retry::RetryConfig::standard().with_max_attempts(2))
        .build();
    let moved = in_pool_region(&config, "us-east-2_AbC");
    assert_eq!(moved.region().unwrap().as_ref(), "us-east-2");
    assert_eq!(moved.endpoint_url(), config.endpoint_url());
    assert_eq!(moved.retry_config().unwrap().max_attempts(), 2);
    for pool in ["pool", "not_a_region", ""] {
        let kept = in_pool_region(&config, pool);
        assert_eq!(kept.region().unwrap().as_ref(), "eu-west-1", "{pool}");
    }
}
