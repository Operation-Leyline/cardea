use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use aws_sdk_dynamodb::types::TransactWriteItem;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use tokio::sync::OnceCell;

use super::*;
use crate::{
    mail::{BudgetKey, BudgetKeySource, CodeDecryptor, EmailSender, KeyError, MailError},
    testing::{ddb, product::Outbox},
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

/// Counts how often the key is asked for.
struct Counted(Arc<AtomicUsize>);

#[async_trait]
impl BudgetKeySource for Counted {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BudgetKey::from_secret(&"01".repeat(32))
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
    let reads = Arc::new(AtomicUsize::new(0));
    let sender = EmailSender::new(ddb, table, Counted(Arc::clone(&reads)), Fixed);
    let outbox = Outbox::default();
    let handler = TriggerHandler {
        product: Mailer(outbox.clone()),
        config: SdkConfig::builder().build(),
        sender: OnceCell::new_with(Some(sender)),
    };
    for code in ["first", "second"] {
        let event = json!({"userPoolId":"pool","triggerSource":"CustomEmailSender_SignUp",
            "request":{"type":"customEmailSenderRequestV1","code":STANDARD.encode(code),
                "userAttributes":{"email":"victim@example.com"}}});
        handler.invoke(event, "r").await.unwrap();
    }
    assert_eq!(outbox.sent.lock().unwrap().len(), 2);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}
