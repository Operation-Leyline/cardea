use aws_sdk_dynamodb::types::AttributeValue as Av;

use super::*;
use crate::mail::{Counter, DAILY_CAP, RESET_DAILY_CAP};
use crate::testing::{Fixture, ddb, fixture, product::Outbox};
use cardea_core::{Directory, EmailOwner, Error};

/// "Decrypts" by reading the bytes as text, and remembers the pool.
struct Plain;

#[async_trait]
impl CodeDecryptor for Plain {
    async fn decrypt(&self, ciphertext: Vec<u8>, pool: &str) -> Result<String, MailError> {
        assert_eq!(pool, "pool");
        String::from_utf8(ciphertext).map_err(|_| MailError::Decryption)
    }
}

/// A sender, and a directory in which `victim@example.com` is the account
/// the events are about.
struct Sender {
    sender: EmailSender,
    directory: Fixture,
    ddb: Dynamo,
    table: String,
}

impl Sender {
    async fn send(&self, outbox: &Outbox, event: &Value) -> Result<Value, MailError> {
        self.sender
            .send(&self.directory.directory, outbox, event, "r")
            .await
    }
}

async fn sender() -> Sender {
    let client = ddb::client();
    let table = ddb::table(&client, "partitionKey", Some("sortKey")).await;
    let directory = fixture().await;
    directory
        .directory
        .claim_email(&EmailOwner {
            email: "victim@example.com".into(),
            username: "victim".into(),
            origin: "Cognito".into(),
        })
        .await
        .unwrap();
    Sender {
        sender: EmailSender::new(client.clone(), table.clone(), Plain),
        directory,
        ddb: client,
        table,
    }
}

fn event(source: &str, code: &str) -> Value {
    json!({"userPoolId":"pool","userName":"victim",
        "triggerSource":format!("CustomEmailSender_{source}"),
        "request":{"type":"customEmailSenderRequestV1","code":STANDARD.encode(code),
            "userAttributes":{"sub":"victim-sub","email":"victim@example.com"}}})
}

async fn rows(ddb: &Dynamo, table: &str) -> Vec<std::collections::HashMap<String, Av>> {
    ddb.scan()
        .table_name(table)
        .consistent_read(true)
        .send()
        .await
        .unwrap()
        .items
        .unwrap_or_default()
}

#[test]
fn temporary_password_entities_are_decoded_exactly_once() {
    assert_eq!(
        unescape_password("Pass&lt;&gt;&amp;lt;123"),
        "Pass<>&lt;123"
    );
}

#[test]
fn routes_every_documented_source_and_rejects_unknown_sources() {
    for (source, name) in [
        ("SignUp", "VERIFY_EMAIL"),
        ("ResendCode", "VERIFY_EMAIL"),
        ("ForgotPassword", "PASSWORD_RESET"),
        ("UpdateUserAttribute", "VERIFY_ATTRIBUTE"),
        ("VerifyUserAttribute", "VERIFY_ATTRIBUTE"),
        ("Authentication", "AUTHENTICATION"),
        ("AdminCreateUser", "TEMPORARY_PASSWORD"),
        ("AccountTakeOverNotification", "SECURITY_ALERT"),
    ] {
        assert_eq!(
            MessageKind::from_trigger(&format!("CustomEmailSender_{source}"))
                .map(MessageKind::name),
            Some(name)
        );
    }
    assert_eq!(MessageKind::from_trigger("CustomEmailSender_Unknown"), None);
}

#[test]
fn only_requests_a_stranger_can_aim_at_a_victim_spend_the_budget() {
    for (kind, counter) in [
        (MessageKind::VerifyEmail, Some(Counter::General)),
        (MessageKind::PasswordReset, Some(Counter::PasswordReset)),
        (MessageKind::VerifyAttribute, Some(Counter::General)),
        (MessageKind::Authentication, Some(Counter::General)),
        (MessageKind::TemporaryPassword, None),
        (MessageKind::SecurityAlert, None),
    ] {
        assert_eq!(kind.counter(), counter, "{kind:?}");
    }
}

#[test]
fn retries_reuse_the_key_but_new_codes_and_payloads_do_not() {
    let template = |version| Template {
        id: "tpl".into(),
        version,
    };
    let event = json!({"request":{"code":"encrypted-envelope"}});
    let key = delivery_key(&event, &template(1), "request-one");
    assert_eq!(key, delivery_key(&event, &template(1), "request-two"));
    assert_ne!(key, delivery_key(&event, &template(2), "request-one"));
    assert_ne!(
        key,
        delivery_key(
            &json!({"request":{"code":"new-envelope"}}),
            &template(1),
            "request-one"
        )
    );
    assert!(!key.contains("encrypted"));
    // Without a code, the invocation is what tells messages apart.
    let alert = json!({"request":{}});
    assert_ne!(
        delivery_key(&alert, &template(1), "request-one"),
        delivery_key(&alert, &template(1), "request-two")
    );
}

/// The key's spelling is what delivery markers already in a table hash.
#[test]
fn the_delivery_key_keeps_its_spelling() {
    let event = json!({"request":{"code":"c"}});
    let template = Template {
        id: "tpl".into(),
        version: 1,
    };
    assert_eq!(
        delivery_key(&event, &template, "r"),
        format!(
            "cognito:{}",
            hex::encode(Sha256::digest(br#"[{"request":{"code":"c"}},"tpl",1,""]"#))
        )
    );
}

#[tokio::test]
async fn a_message_is_counted_decrypted_and_delivered() {
    let fixture = sender().await;
    let outbox = Outbox::default();
    assert_eq!(
        fixture
            .send(&outbox, &event("SignUp", "012345"))
            .await
            .unwrap(),
        json!({})
    );
    let sent = outbox.sent.lock().unwrap().clone();
    let (kind, recipient, code, key) = &sent[0];
    assert_eq!(*kind, MessageKind::VerifyEmail);
    assert_eq!(recipient, "victim@example.com");
    assert_eq!(code.as_deref(), Some("012345"));
    assert!(key.starts_with("cognito:"));
    // The delivery marker and the counter.
    assert_eq!(rows(&fixture.ddb, &fixture.table).await.len(), 2);
}

#[tokio::test]
async fn the_cap_refuses_before_delivery() {
    let fixture = sender().await;
    let outbox = Outbox::default();
    for (source, cap) in [
        ("ForgotPassword", RESET_DAILY_CAP),
        // Spent resets leave every other code its whole budget.
        ("Authentication", DAILY_CAP),
    ] {
        for n in 0..cap {
            fixture
                .send(&outbox, &event(source, &n.to_string()))
                .await
                .unwrap();
        }
        assert!(matches!(
            fixture.send(&outbox, &event(source, "over")).await,
            Err(MailError::Refused(Refusal::CapReached))
        ));
    }
    assert_eq!(
        outbox.sent.lock().unwrap().len(),
        (RESET_DAILY_CAP + DAILY_CAP) as usize
    );
}

#[tokio::test]
async fn temporary_passwords_and_alerts_are_uncounted() {
    let fixture = sender().await;
    let outbox = Outbox::default();
    fixture
        .send(&outbox, &event("AdminCreateUser", "a&amp;b"))
        .await
        .unwrap();
    let mut alert = event("AccountTakeOverNotification", "");
    alert["request"].as_object_mut().unwrap().remove("code");
    fixture.send(&outbox, &alert).await.unwrap();
    let sent = outbox.sent.lock().unwrap().clone();
    assert_eq!(sent[0].2.as_deref(), Some("a&b"));
    assert_eq!(sent[1].2, None);
    assert!(rows(&fixture.ddb, &fixture.table).await.is_empty());
}

const CHANGING: [&str; 2] = ["UpdateUserAttribute", "VerifyUserAttribute"];

#[tokio::test]
async fn a_code_for_the_accounts_own_address_is_sent() {
    let fixture = sender().await;
    let outbox = Outbox::default();
    for source in CHANGING {
        for email in ["victim@example.com", "Victim@Example.com"] {
            let mut event = event(source, &format!("{source}{email}"));
            event["request"]["userAttributes"]["email"] = json!(email);
            fixture.send(&outbox, &event).await.unwrap();
        }
    }
    assert_eq!(outbox.sent.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn a_code_for_any_other_address_is_neither_sent_nor_counted() {
    let fixture = sender().await;
    let outbox = Outbox::default();
    for source in CHANGING {
        let mut changed = event(source, "1");
        changed["request"]["userAttributes"]["email"] = json!("new@example.com");
        // Another spelling of the account's mailbox.
        let mut alias = event(source, "2");
        alias["request"]["userAttributes"]["email"] = json!("victim+new@example.com");
        // The account's address, asked for by someone else.
        let mut intruder = event(source, "3");
        intruder["userName"] = json!("intruder");
        for event in [changed, alias, intruder] {
            assert!(matches!(
                fixture.send(&outbox, &event).await,
                Err(MailError::Identity(Error::EmailChange))
            ));
        }
    }
    assert!(outbox.sent.lock().unwrap().is_empty());
    assert!(rows(&fixture.ddb, &fixture.table).await.is_empty());
}

#[tokio::test]
async fn a_missing_template_or_a_bad_event_spends_nothing() {
    let fixture = sender().await;
    let outbox = Outbox {
        no_templates: true,
        ..Outbox::default()
    };
    assert!(matches!(
        fixture.send(&outbox, &event("SignUp", "1")).await,
        Err(MailError::Template(_))
    ));
    let mut version = event("SignUp", "1");
    version["request"]["type"] = json!("customEmailSenderRequestV2");
    assert!(matches!(
        fixture.send(&outbox, &version).await,
        Err(MailError::UnsupportedVersion)
    ));
    assert!(matches!(
        fixture.send(&outbox, &event("Unknown", "1")).await,
        Err(MailError::UnsupportedSource)
    ));
    assert!(rows(&fixture.ddb, &fixture.table).await.is_empty());
}

#[test]
fn a_code_never_prints() {
    assert_eq!(format!("{:?}", Code::new("012345".into())), "<redacted>");
}
