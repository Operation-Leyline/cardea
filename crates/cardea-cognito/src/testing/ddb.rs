//! One in-memory dynoxide server per test process, on its own thread so that
//! it outlives each test's runtime.

use std::{
    collections::HashMap,
    sync::{OnceLock, mpsc},
    time::Duration,
};

use aws_sdk_dynamodb::{
    Client,
    config::{Credentials, Region},
    types::{
        AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType,
        ScalarAttributeType,
    },
};

/// One DynamoDB item as the SDK returns it.
pub(crate) type Item = HashMap<String, AttributeValue>;

fn endpoint() -> &'static str {
    static ENDPOINT: OnceLock<String> = OnceLock::new();
    ENDPOINT.get_or_init(|| {
        let (ready, started) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a dynoxide server runtime");
            runtime.block_on(async {
                let database =
                    dynoxide::Database::memory().expect("an in-memory DynamoDB database");
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind dynoxide to a loopback port");
                let address = listener.local_addr().expect("a bound dynoxide listener");
                ready
                    .send(format!("http://{address}"))
                    .expect("the test waits for dynoxide");
                dynoxide::server::serve_on(listener, database).await;
            });
        });
        // A failed startup must not hang every test waiting for the endpoint.
        started
            .recv_timeout(Duration::from_secs(30))
            .expect("dynoxide must start within 30 seconds")
    })
}

/// A client for the emulator.
pub(crate) fn client() -> Client {
    Client::from_conf(
        aws_sdk_dynamodb::Config::builder()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("local", "local", None, None, "test"))
            .endpoint_url(endpoint())
            .build(),
    )
}

/// A new table with string keys; its name is unique to the caller.
pub(crate) async fn table(client: &Client, partition: &str, sort: Option<&str>) -> String {
    let name = format!("cardea-{}", uuid::Uuid::new_v4().simple());
    let mut request = client
        .create_table()
        .table_name(&name)
        .billing_mode(BillingMode::PayPerRequest);
    for (attribute, kind) in [(Some(partition), KeyType::Hash), (sort, KeyType::Range)] {
        let Some(attribute) = attribute else { continue };
        request = request
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(attribute)
                    .key_type(kind)
                    .build()
                    .unwrap(),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(attribute)
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .unwrap(),
            );
    }
    request.send().await.expect("create a test table");
    name
}
