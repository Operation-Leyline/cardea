use async_trait::async_trait;
use aws_sdk_dynamodb::types::TransactWriteItem;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use tokio::sync::OnceCell;

use super::*;
use crate::{
    mail::{CodeDecryptor, EmailSender, MailError},
    testing::{
        ddb,
        product::Outbox,
        sender::{self, Counted, SecretStore},
    },
    triggers::{NewAccount, ProductError},
};

/// A product that only delivers mail.
struct Mailer(Outbox);

#[async_trait]
impl Product for Mailer {
    async fn is_provisioned(&self, _: &NewAccount) -> Result<bool, ProductError> {
        unreachable!("a mail event provisions nothing")
    }

    async fn provision(&self, _: &NewAccount, _: TransactWriteItem) -> Result<(), ProductError> {
        unreachable!("a mail event provisions nothing")
    }

    fn mail(&self) -> Option<&dyn crate::mail::MailDelivery> {
        Some(&self.0)
    }
}

struct Fixed;

#[async_trait]
impl CodeDecryptor for Fixed {
    async fn decrypt(&self, _: Vec<u8>, _: &str) -> Result<String, MailError> {
        Ok("012345".into())
    }
}

/// The function's invocations share one sender, so a cold start reads the
/// budget key once however many messages it sends.
#[tokio::test]
async fn invocations_share_the_sender_and_its_key() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let key = Counted::default();
    let sender = EmailSender::new(ddb, table, key.clone(), Fixed);
    let outbox = Outbox::default();
    let handler = TriggerHandler {
        sender: OnceCell::new_with(Some(sender)),
        ..handler(outbox.clone())
    };
    for code in ["first", "second"] {
        let event = json!({"userPoolId":"pool","triggerSource":"CustomEmailSender_SignUp",
            "request":{"type":"customEmailSenderRequestV1","code":STANDARD.encode(code),
                "userAttributes":{"email":"victim@example.com"}}});
        handler.invoke(event, "r").await.unwrap();
    }
    assert_eq!(outbox.sent.lock().unwrap().len(), 2);
    assert_eq!(key.reads(), 1);
}

fn handler(outbox: Outbox) -> TriggerHandler<Mailer> {
    TriggerHandler {
        product: Mailer(outbox),
        config: SdkConfig::builder().build(),
        key_source: None,
        sender: OnceCell::new(),
    }
}

/// A message that needs neither the table nor the decryptor.
fn alert() -> serde_json::Value {
    json!({"userPoolId":"pool",
        "triggerSource":"CustomEmailSender_AccountTakeOverNotification",
        "request":{"type":"customEmailSenderRequestV1",
            "userAttributes":{"email":"victim@example.com"}}})
}

/// The handler's own sender asks the product's source for every mail event and
/// needs no secret.
#[tokio::test]
async fn a_given_source_serves_the_mail_events() {
    let store = SecretStore::serve().await;
    let key = Counted::default();
    let outbox = Outbox::default();
    let handler = handler(outbox.clone()).with_budget_key_source(key.clone());
    let without_secret =
        |name: &str| sender::variable(name).filter(|_| name != "MAIL_BUDGET_KEY_SECRET");
    handler
        .sender(without_secret, || async { store.config() })
        .await
        .unwrap();
    for _ in 0..2 {
        handler.invoke(alert(), "r").await.unwrap();
    }
    assert_eq!(outbox.sent.lock().unwrap().len(), 2);
    assert_eq!(key.reads(), 2);
    assert!(store.asked().is_empty());
}

#[tokio::test]
async fn without_a_source_the_handler_reads_the_secret_once() {
    let store = SecretStore::serve().await;
    let outbox = Outbox::default();
    let handler = handler(outbox.clone());
    handler
        .sender(sender::variable, || async { store.config() })
        .await
        .unwrap();
    for _ in 0..2 {
        handler.invoke(alert(), "r").await.unwrap();
    }
    assert_eq!(outbox.sent.lock().unwrap().len(), 2);
    assert_eq!(store.asked(), [json!({"SecretId": sender::SECRET})]);
}
