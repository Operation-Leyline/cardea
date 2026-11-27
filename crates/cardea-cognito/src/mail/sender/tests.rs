use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use aws_sdk_dynamodb::types::AttributeValue as Av;

use super::*;
use crate::mail::{Counter, DAILY_CAP, RESET_DAILY_CAP, RefreshingKeySource};
use crate::testing::{
    ddb,
    pending_change::{self, NEW, OBSERVED, OLD, VERIFIED},
    product::Outbox,
};
use cardea_core::Error;

/// "Decrypts" by reading the bytes as text, and remembers the pool.
struct Plain;

#[async_trait]
impl CodeDecryptor for Plain {
    async fn decrypt(&self, ciphertext: Vec<u8>, pool: &str) -> Result<String, MailError> {
        assert_eq!(pool, "pool");
        String::from_utf8(ciphertext).map_err(|_| MailError::Decryption)
    }
}

/// A fixed time, so that a test counting to a cap cannot straddle two days.
const NOON: i64 = 1_790_000_000;

/// A budget key whose bytes are all `byte`.
fn budget_key_of(byte: u8) -> BudgetKey {
    BudgetKey::from_secret(&hex::encode([byte; 32])).unwrap()
}

async fn sender() -> (EmailSender, Dynamo, String) {
    let client = ddb::client();
    let table = ddb::table(&client, "partitionKey", Some("sortKey")).await;
    (
        EmailSender::new(client.clone(), table.clone(), budget_key_of(1), Plain),
        client,
        table,
    )
}

fn event(source: &str, code: &str) -> Value {
    json!({"userPoolId":"pool","triggerSource":format!("CustomEmailSender_{source}"),
        "request":{"type":"customEmailSenderRequestV1","code":STANDARD.encode(code),
            "userAttributes":{"email":"victim@example.com"}}})
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

/// The product's mail provider knows a message by this key, so a release must
/// not spell it anew.
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
    let (sender, ddb, table) = sender().await;
    let outbox = Outbox::default();
    assert_eq!(
        sender
            .send(&outbox, &event("SignUp", "012345"), "r")
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
    assert_eq!(rows(&ddb, &table).await.len(), 2);
}

#[tokio::test]
async fn the_cap_refuses_before_delivery() {
    let (sender, ..) = sender().await;
    let outbox = Outbox::default();
    for (source, cap) in [
        ("ForgotPassword", RESET_DAILY_CAP),
        // Spent resets leave every other code its whole budget.
        ("Authentication", DAILY_CAP),
    ] {
        for n in 0..cap {
            sender
                .send_at(&outbox, &event(source, &n.to_string()), "r", NOON)
                .await
                .unwrap();
        }
        assert!(matches!(
            sender
                .send_at(&outbox, &event(source, "over"), "r", NOON)
                .await,
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
    let (sender, ddb, table) = sender().await;
    let outbox = Outbox::default();
    sender
        .send(&outbox, &event("AdminCreateUser", "a&amp;b"), "r")
        .await
        .unwrap();
    let mut alert = event("AccountTakeOverNotification", "");
    alert["request"].as_object_mut().unwrap().remove("code");
    sender.send(&outbox, &alert, "r").await.unwrap();
    let sent = outbox.sent.lock().unwrap().clone();
    assert_eq!(sent[0].2.as_deref(), Some("a&b"));
    assert_eq!(sent[1].2, None);
    assert!(rows(&ddb, &table).await.is_empty());
}

const UPDATE: &str = "CustomEmailSender_UpdateUserAttribute";
const VERIFY: &str = "CustomEmailSender_VerifyUserAttribute";

/// Each event is refused as an email change, with nothing sent or counted.
async fn assert_refused(events: impl IntoIterator<Item = Value>) {
    let (sender, ddb, table) = sender().await;
    let outbox = Outbox::default();
    for event in events {
        let result = sender.send(&outbox, &event, "r").await;
        assert!(
            matches!(result, Err(MailError::Identity(Error::EmailChange))),
            "{event}: {result:?}"
        );
    }
    assert!(outbox.sent.lock().unwrap().is_empty());
    assert!(rows(&ddb, &table).await.is_empty());
}

/// One goes to the new address and one to the old; neither is sent.
#[tokio::test]
async fn the_codes_a_pending_change_sends_are_refused() {
    assert_refused(
        OBSERVED
            .into_iter()
            .filter(|(source, _)| source.starts_with("CustomEmailSender_"))
            .map(|(source, email)| {
                pending_change::event(source, email, Some(json!(VERIFIED)), "012345")
            }),
    )
    .await;
}

#[tokio::test]
async fn an_attribute_update_is_refused_whatever_it_says() {
    let mut events = Vec::new();
    for email in [OLD, NEW] {
        for verified in [Some(json!("true")), Some(json!("false")), None] {
            events.push(pending_change::event(UPDATE, email, verified, "1"));
        }
    }
    assert_refused(events).await;
}

#[tokio::test]
async fn verification_is_refused_unless_the_address_is_clearly_unverified() {
    assert_refused(
        [
            Some(json!("true")),
            Some(json!(true)),
            Some(json!("False")),
            Some(json!("")),
            Some(json!(0)),
            Some(Value::Null),
            None,
        ]
        .map(|verified| pending_change::event(VERIFY, OLD, verified, "1")),
    )
    .await;
}

#[tokio::test]
async fn verifying_an_unverified_current_address_is_sent_and_counted() {
    let (sender, ddb, table) = sender().await;
    let outbox = Outbox::default();
    for (code, verified) in [("111", json!("false")), ("222", json!(false))] {
        let event = pending_change::event(VERIFY, OLD, Some(verified), code);
        sender.send(&outbox, &event, "r").await.unwrap();
    }
    let sent = outbox.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, recipient, ..)| recipient == OLD));
    // Two delivery markers and the day's counter.
    assert_eq!(rows(&ddb, &table).await.len(), 3);
}

#[tokio::test]
async fn a_missing_template_or_a_bad_event_spends_nothing() {
    let (sender, ddb, table) = sender().await;
    let outbox = Outbox {
        no_templates: true,
        ..Outbox::default()
    };
    assert!(matches!(
        sender.send(&outbox, &event("SignUp", "1"), "r").await,
        Err(MailError::Template(_))
    ));
    let mut version = event("SignUp", "1");
    version["request"]["type"] = json!("customEmailSenderRequestV2");
    assert!(matches!(
        sender.send(&outbox, &version, "r").await,
        Err(MailError::UnsupportedVersion)
    ));
    assert!(matches!(
        sender.send(&outbox, &event("Unknown", "1"), "r").await,
        Err(MailError::UnsupportedSource)
    ));
    assert!(rows(&ddb, &table).await.is_empty());
}

/// A secret that answers each read with what a test put there, and counts the
/// reads. `None` is a secret that cannot be read.
#[derive(Clone, Default)]
struct Secret {
    value: Arc<std::sync::Mutex<Option<u8>>>,
    reads: Arc<AtomicUsize>,
}

impl Secret {
    fn holding(byte: u8) -> Self {
        let secret = Self::default();
        secret.set(byte);
        secret
    }

    fn set(&self, byte: u8) {
        *self.value.lock().unwrap() = Some(byte);
    }

    fn fail(&self) {
        *self.value.lock().unwrap() = None;
    }
}

#[async_trait]
impl BudgetKeySource for Secret {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let byte = *self.value.lock().unwrap();
        byte.map(budget_key_of)
            .ok_or_else(|| KeyError::Read("secret not found".into()))
    }
}

/// A decryptor that must not be reached.
struct Untouched;

#[async_trait]
impl CodeDecryptor for Untouched {
    async fn decrypt(&self, _: Vec<u8>, _: &str) -> Result<String, MailError> {
        panic!("decrypted a code without a budget key")
    }
}

/// Every message is refused, the uncounted ones too, with nothing decrypted,
/// counted or delivered.
#[tokio::test]
async fn without_a_budget_key_nothing_is_sent() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let sender = EmailSender::new(ddb.clone(), table.clone(), Secret::default(), Untouched);
    let outbox = Outbox::default();
    for source in [
        "SignUp",
        "ResendCode",
        "ForgotPassword",
        "Authentication",
        "AdminCreateUser",
        "AccountTakeOverNotification",
    ] {
        let error = sender
            .send(&outbox, &event(source, "1"), "r")
            .await
            .unwrap_err();
        assert!(
            matches!(error, MailError::BudgetKey(KeyError::Read(_))),
            "{source}: {error:?}"
        );
        assert_eq!(error.to_string(), Refusal::Unavailable.to_string());
    }
    assert!(outbox.sent.lock().unwrap().is_empty());
    assert!(rows(&ddb, &table).await.is_empty());
}

#[tokio::test]
async fn the_key_is_read_again_after_a_failure_and_once_after_a_success() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let secret = Secret::default();
    let sender = EmailSender::new(ddb, table, secret.clone(), Plain);
    let outbox = Outbox::default();
    assert!(
        sender
            .send(&outbox, &event("SignUp", "1"), "r")
            .await
            .is_err()
    );
    secret.set(1);
    for code in ["1", "2", "3"] {
        sender
            .send(&outbox, &event("SignUp", code), "r")
            .await
            .unwrap();
    }
    assert_eq!(outbox.sent.lock().unwrap().len(), 3);
    assert_eq!(secret.reads.load(Ordering::SeqCst), 2);
}

/// Rotating the secret resets the day's counters, one function instance at a
/// time: a running one keeps the key it read, and one started afterwards counts
/// from nothing.
#[tokio::test]
async fn a_rotated_key_takes_effect_in_a_new_sender_with_fresh_counters() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let secret = Secret::holding(1);
    let running = EmailSender::new(ddb.clone(), table.clone(), secret.clone(), Plain);
    let outbox = Outbox::default();
    for n in 0..DAILY_CAP {
        running
            .send_at(&outbox, &event("SignUp", &n.to_string()), "r", NOON)
            .await
            .unwrap();
    }

    secret.set(2);
    assert!(matches!(
        running
            .send_at(&outbox, &event("SignUp", "over"), "r", NOON)
            .await,
        Err(MailError::Refused(Refusal::CapReached))
    ));

    let started = EmailSender::new(ddb, table, secret, Plain);
    for n in 0..DAILY_CAP {
        started
            .send_at(&outbox, &event("SignUp", &format!("new{n}")), "r", NOON)
            .await
            .unwrap();
    }
    assert!(matches!(
        started
            .send_at(&outbox, &event("SignUp", "new-over"), "r", NOON)
            .await,
        Err(MailError::Refused(Refusal::CapReached))
    ));
}

/// A source given as one is asked for every message, so a running sender takes
/// up a changed key, and the new key's rows start from nothing.
#[tokio::test]
async fn a_given_source_is_asked_for_every_message() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let secret = Secret::holding(1);
    let sender = EmailSender::with_key_source(ddb, table, secret.clone(), Plain);
    let outbox = Outbox::default();
    for n in 0..DAILY_CAP {
        sender
            .send_at(&outbox, &event("SignUp", &n.to_string()), "r", NOON)
            .await
            .unwrap();
    }
    assert!(matches!(
        sender
            .send_at(&outbox, &event("SignUp", "over"), "r", NOON)
            .await,
        Err(MailError::Refused(Refusal::CapReached))
    ));
    secret.set(2);
    sender
        .send_at(&outbox, &event("SignUp", "over"), "r", NOON)
        .await
        .unwrap();
    assert_eq!(
        secret.reads.load(Ordering::SeqCst),
        usize::try_from(DAILY_CAP).unwrap() + 2
    );
}

/// An interval of nothing reads the secret for every message.
#[tokio::test]
async fn a_refresh_takes_up_a_new_key_in_a_running_sender() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let secret = Secret::holding(1);
    let source = RefreshingKeySource::new(secret.clone(), Duration::ZERO);
    let sender = EmailSender::with_key_source(ddb.clone(), table.clone(), source, Plain);
    let outbox = Outbox::default();
    for byte in [1, 2] {
        secret.set(byte);
        sender
            .send_at(&outbox, &event("SignUp", "1"), "r", NOON)
            .await
            .unwrap();
    }
    // The same message under two keys: a marker and a counter for each.
    assert_eq!(rows(&ddb, &table).await.len(), 4);
}

#[tokio::test]
async fn a_failed_refresh_sends_with_the_last_key() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let secret = Secret::holding(1);
    let source = RefreshingKeySource::new(secret.clone(), Duration::ZERO);
    let sender = EmailSender::with_key_source(ddb.clone(), table.clone(), source, Plain);
    let outbox = Outbox::default();
    sender
        .send_at(&outbox, &event("SignUp", "1"), "r", NOON)
        .await
        .unwrap();
    secret.fail();
    sender
        .send_at(&outbox, &event("SignUp", "2"), "r", NOON)
        .await
        .unwrap();
    assert_eq!(secret.reads.load(Ordering::SeqCst), 2);
    // Both counted on the one key's rows: two markers and the counter.
    assert_eq!(rows(&ddb, &table).await.len(), 3);
}

/// A maximum age of nothing lets no key outlive the call that read it.
#[tokio::test]
async fn past_the_bound_nothing_is_sent() {
    let ddb = ddb::client();
    let table = ddb::table(&ddb, "partitionKey", Some("sortKey")).await;
    let secret = Secret::holding(1);
    let source =
        RefreshingKeySource::new(secret.clone(), Duration::ZERO).with_max_age(Duration::ZERO);
    let sender = EmailSender::with_key_source(ddb.clone(), table.clone(), source, Plain);
    let outbox = Outbox::default();
    sender
        .send(&outbox, &event("SignUp", "1"), "r")
        .await
        .unwrap();
    secret.fail();
    let error = sender
        .send(&outbox, &event("SignUp", "2"), "r")
        .await
        .unwrap_err();
    assert!(
        matches!(error, MailError::BudgetKey(KeyError::Read(_))),
        "{error:?}"
    );
    assert_eq!(outbox.sent.lock().unwrap().len(), 1);
    assert_eq!(rows(&ddb, &table).await.len(), 2);
}

#[test]
fn a_code_never_prints() {
    assert_eq!(format!("{:?}", Code::new("012345".into())), "<redacted>");
}
