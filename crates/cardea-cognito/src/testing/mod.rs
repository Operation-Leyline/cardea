//! Test fixtures: an in-process DynamoDB, a fake user pool that speaks
//! Cognito's wire protocol on loopback, and a directory over both. No test
//! reaches AWS.

pub(crate) mod accounts;
pub(crate) mod cognito;
pub(crate) mod ddb;
pub(crate) mod loopback;
pub(crate) mod pending_change;
pub(crate) mod product;
pub(crate) mod provider;
#[cfg(feature = "email-sender")]
pub(crate) mod sender;

use aws_sdk_dynamodb::types::AttributeValue;

use crate::directory::AwsDirectory;

/// A ready directory, its pool, and the server standing in for Cognito.
pub(crate) struct Fixture {
    pub directory: AwsDirectory,
    pub pool: cognito::Pool,
    _server: loopback::Loopback,
}

/// A directory over a fresh table that is ready for signup, and an empty pool.
pub(crate) async fn fixture() -> Fixture {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "identityKey", None).await;
    ddb.put_item()
        .table_name(&table)
        .item("identityKey", AttributeValue::S("SYSTEM#READY".into()))
        .item("version", AttributeValue::N("1".into()))
        .send()
        .await
        .unwrap();
    let pool = cognito::Pool::default();
    let server = pool.serve().await;
    let directory = AwsDirectory::new(
        ddb,
        cognito::client(server.endpoint()),
        table,
        "pool".into(),
    );
    Fixture {
        directory,
        pool,
        _server: server,
    }
}

impl Fixture {
    /// The stored item at `key`.
    pub async fn item(&self, key: &str) -> Option<ddb::Item> {
        self.directory
            .dynamodb()
            .get_item()
            .table_name(self.directory.table())
            .key("identityKey", AttributeValue::S(key.into()))
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .item
    }
}
