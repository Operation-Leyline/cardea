use serde_json::json;

use super::*;
use crate::testing::{
    product::Outbox,
    sender::{self, SecretStore},
};

fn environment(without: &str, empty: &str) -> impl Fn(&str) -> Option<String> {
    move |name| match name {
        name if name == without => None,
        name if name == empty => Some(String::new()),
        name => sender::variable(name),
    }
}

#[test]
fn reads_each_setting_from_its_variable() {
    assert_eq!(
        Settings::read(&sender::variable).unwrap(),
        Settings {
            table: "budget-table".into(),
            email_key: sender::EMAIL_KEY.into(),
        }
    );
}

/// No secret named is no sender, so nothing can be sent.
#[tokio::test]
async fn an_unset_or_empty_variable_is_refused_by_name() {
    let store = SecretStore::serve().await;
    for name in [TABLE_VARIABLE, SECRET_VARIABLE, KEY_VARIABLE] {
        for variables in [environment(name, ""), environment("", name)] {
            assert!(matches!(
                EmailSender::configured(variables, &store.config(), None).await,
                Err(MailError::Configuration(missing)) if missing == name
            ));
        }
    }
}

/// Sends a message that needs neither the table nor the decryptor.
async fn alert(sender: &EmailSender) {
    let event = json!({"userPoolId":"pool",
        "triggerSource":"CustomEmailSender_AccountTakeOverNotification",
        "request":{"type":"customEmailSenderRequestV1",
            "userAttributes":{"email":"victim@example.com"}}});
    sender.send(&Outbox::default(), &event, "r").await.unwrap();
}

#[tokio::test]
async fn without_a_source_the_named_secret_is_read_once() {
    let store = SecretStore::serve().await;
    let sender = EmailSender::configured(sender::variable, &store.config(), None)
        .await
        .unwrap();
    assert!(store.asked().is_empty());
    alert(&sender).await;
    alert(&sender).await;
    assert_eq!(store.asked(), [json!({"SecretId": sender::SECRET})]);
}

/// The secret's variable is not needed, and the secret is not read.
#[tokio::test]
async fn a_given_source_replaces_the_secret() {
    let store = SecretStore::serve().await;
    let source = sender::Counted::default();
    let sender = EmailSender::configured(
        environment(SECRET_VARIABLE, ""),
        &store.config(),
        Some(Arc::new(source.clone())),
    )
    .await
    .unwrap();
    alert(&sender).await;
    alert(&sender).await;
    assert_eq!(source.reads(), 2);
    assert!(store.asked().is_empty());
}
