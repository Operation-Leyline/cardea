use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Json, Router, http::StatusCode, routing::post};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::testing::{ddb, loopback};

const NOON: i64 = 1_790_000_000;

/// A budget key whose bytes are all `byte`.
fn key_of(byte: u8) -> BudgetKey {
    BudgetKey::from_secret(&hex::encode([byte; 32])).unwrap()
}

/// The key the tests count under.
fn key() -> BudgetKey {
    key_of(1)
}

async fn table() -> (Client, String) {
    let client = ddb::client();
    let name = ddb::table(&client, "partitionKey", Some("sortKey")).await;
    (client, name)
}

/// One new message to `recipient`, named `delivery`.
async fn send(
    ddb: &Client,
    table: &str,
    recipient: &str,
    delivery: &str,
    now: i64,
) -> Result<(), Refusal> {
    spend(
        ddb,
        table,
        &key(),
        recipient,
        delivery,
        Counter::General,
        now,
    )
    .await
}

/// One new password reset message.
async fn reset(
    ddb: &Client,
    table: &str,
    recipient: &str,
    delivery: &str,
    now: i64,
) -> Result<(), Refusal> {
    spend(
        ddb,
        table,
        &key(),
        recipient,
        delivery,
        Counter::PasswordReset,
        now,
    )
    .await
}

/// The recipient's count for the day, read back from the table.
async fn count(ddb: &Client, table: &str, recipient: &str, now: i64) -> Option<i64> {
    let (partition, sort) = row_names(&key(), recipient, Counter::General, now).unwrap();
    ddb.get_item()
        .table_name(table)
        .key("partitionKey", Av::S(partition))
        .key("sortKey", Av::S(sort))
        .consistent_read(true)
        .send()
        .await
        .unwrap()
        .item
        .map(|item| item["count"].as_n().unwrap().parse().unwrap())
}

/// Used to be: nothing counted the messages, so one recipient could be
/// sent as many verification mails as an attacker could request.
#[tokio::test]
async fn verification_mail_to_one_recipient_stops_at_the_daily_cap() {
    let (ddb, table) = table().await;
    for n in 0..DAILY_CAP {
        assert_eq!(
            send(&ddb, &table, "Victim@example.com", &format!("m{n}"), NOON).await,
            Ok(())
        );
    }
    assert_eq!(
        send(&ddb, &table, "victim@example.com", "over", NOON).await,
        Err(Refusal::CapReached)
    );
    // Aliases of the same mailbox share the budget.
    assert_eq!(
        send(&ddb, &table, "victim+news@example.com", "alias", NOON + 60).await,
        Err(Refusal::CapReached)
    );
    // A refusal is not counted, and another mailbox has its own budget.
    assert_eq!(
        count(&ddb, &table, "victim@example.com", NOON).await,
        Some(DAILY_CAP)
    );
    assert_eq!(
        send(&ddb, &table, "other@example.com", "m0", NOON).await,
        Ok(())
    );
    // The next UTC day starts a fresh budget.
    assert_eq!(
        send(
            &ddb,
            &table,
            "victim@example.com",
            "tomorrow",
            NOON + DAY_SECONDS
        )
        .await,
        Ok(())
    );
}

/// Used to be: nothing named a message, so a retry of one delivery (the
/// same idempotency key) would have spent a slot each time.
#[tokio::test]
async fn a_retried_message_is_counted_once_even_at_the_cap() {
    let (ddb, table) = table().await;
    for _ in 0..5 {
        assert_eq!(
            send(&ddb, &table, "victim@example.com", "same-delivery", NOON).await,
            Ok(())
        );
    }
    assert_eq!(
        count(&ddb, &table, "victim@example.com", NOON).await,
        Some(1)
    );
    for n in 1..DAILY_CAP {
        send(&ddb, &table, "victim@example.com", &format!("m{n}"), NOON)
            .await
            .unwrap();
    }
    // The budget is spent, so a new message is refused, but the retry of
    // one already sent is not.
    assert_eq!(
        send(&ddb, &table, "victim@example.com", "new", NOON).await,
        Err(Refusal::CapReached)
    );
    assert_eq!(
        send(&ddb, &table, "victim@example.com", "same-delivery", NOON).await,
        Ok(())
    );
    assert_eq!(
        send(&ddb, &table, "victim@example.com", "m3", NOON).await,
        Ok(())
    );
    assert_eq!(
        count(&ddb, &table, "victim@example.com", NOON).await,
        Some(DAILY_CAP)
    );
}

#[tokio::test]
async fn concurrent_requests_cannot_overshoot_the_cap() {
    let (ddb, table) = table().await;
    let mut tasks = Vec::new();
    for n in 0..(DAILY_CAP * 3) {
        let (ddb, table) = (ddb.clone(), table.clone());
        tasks.push(tokio::spawn(async move {
            send(&ddb, &table, "victim@example.com", &format!("m{n}"), NOON).await
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            allowed += 1;
        }
    }
    assert_eq!(allowed, DAILY_CAP);
}

/// A DynamoDB that cancels its first `conflicts` transactions because another
/// one held the counter, then accepts. The in-process emulator runs
/// transactions one at a time, so it never answers this way.
async fn contended(conflicts: usize) -> (Client, loopback::Loopback, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let server = loopback::serve(Router::new().route(
        "/",
        post(move || async move {
            if seen.fetch_add(1, Ordering::SeqCst) >= conflicts {
                return (StatusCode::OK, Json(json!({})));
            }
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "__type": "com.amazonaws.dynamodb.v20120810#TransactionCanceledException",
                    "message": "cancelled",
                    "CancellationReasons": [{"Code": "None"}, {"Code": "TransactionConflict"}],
                })),
            )
        }),
    ))
    .await;
    let config = ddb::client()
        .config()
        .to_builder()
        .endpoint_url(server.endpoint())
        .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
        .build();
    (Client::from_conf(config), server, calls)
}

/// Two sends for one mailbox at once, such as a signup code and a quick
/// resend, collide on the counter: the loser goes again and is sent.
#[tokio::test]
async fn a_send_that_lost_a_race_for_the_counter_goes_again() {
    let (ddb, _server, calls) = contended(2).await;
    assert_eq!(
        send(&ddb, "budget", "victim@example.com", "m", NOON).await,
        Ok(())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

/// Contention that does not clear is refused rather than sent unmetered.
#[tokio::test]
async fn a_counter_that_stays_contended_refuses() {
    let (ddb, _server, calls) = contended(usize::MAX).await;
    assert_eq!(
        send(&ddb, "budget", "victim@example.com", "m", NOON).await,
        Err(Refusal::Unavailable)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

/// The key whose bytes count from 0 to 31.
fn counting_key() -> BudgetKey {
    BudgetKey::from_secret("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .unwrap()
}

/// The HMACs below were computed independently of this crate.
#[test]
fn the_rows_are_named_by_hmac_never_by_the_address() {
    let key = counting_key();
    let general = |recipient| row_names(&key, recipient, Counter::General, NOON);
    let (partition, sort) = general("Vic.Tim+x@Gmail.com").unwrap();
    assert_eq!(
        partition,
        "MAILK#4c4b53e6b24e1861941d9e538a46a468e2cee07fefe4ff0a96ff5f771e686c82"
    );
    assert_eq!(general("victim@googlemail.com").unwrap().0, partition);
    assert_eq!(sort, format!("SEND#{}", NOON / DAY_SECONDS));
    assert_eq!(
        row_names(&key, "victim@gmail.com", Counter::PasswordReset, NOON).unwrap(),
        (partition, format!("RESET#{}", NOON / DAY_SECONDS))
    );
    assert_eq!(
        marker_name(&key, "cognito:example"),
        "DELIVERYK#980953fdda416d7586096d59bc2ba5e5725b8d773a618c7e8b3699293e5bd615"
    );
    assert_eq!(general("not-an-address"), Err(Refusal::Invalid));
}

#[test]
fn another_key_names_other_rows() {
    let names = |key: &BudgetKey| {
        (
            row_names(key, "victim@example.com", Counter::General, NOON)
                .unwrap()
                .0,
            marker_name(key, "m"),
        )
    };
    let (one, two) = (names(&key_of(1)), names(&key_of(2)));
    assert_ne!(one.0, two.0);
    assert_ne!(one.1, two.1);
}

/// What `spend` writes, read back whole: the two keyed rows and nothing that
/// holds the address or the delivery's name.
#[tokio::test]
async fn the_table_holds_only_keyed_rows() {
    let (ddb, table) = table().await;
    send(&ddb, &table, "victim@example.com", "delivery-name", NOON)
        .await
        .unwrap();
    let items = ddb
        .scan()
        .table_name(&table)
        .consistent_read(true)
        .send()
        .await
        .unwrap()
        .items
        .unwrap();
    let partition = row_names(&key(), "victim@example.com", Counter::General, NOON)
        .unwrap()
        .0;
    let mut sorts: Vec<&str> = items
        .iter()
        .map(|item| {
            assert_eq!(item["partitionKey"].as_s().unwrap(), &partition);
            item["sortKey"].as_s().unwrap().as_str()
        })
        .collect();
    sorts.sort_unstable();
    assert_eq!(
        sorts,
        [
            marker_name(&key(), "delivery-name"),
            format!("SEND#{}", NOON / DAY_SECONDS)
        ]
    );
    let stored = format!("{items:?}");
    assert!(!stored.contains("victim") && !stored.contains("delivery-name"));
}

/// Rotating the key resets the day's counters: the new key reads none of the
/// old rows, so a spent mailbox has a whole budget and a counted delivery is
/// counted again. Each key still stops at its cap, and the old rows stay.
#[tokio::test]
async fn a_new_key_starts_the_days_counters_again() {
    let (ddb, table) = table().await;
    let victim = "victim@example.com";
    for n in 0..DAILY_CAP {
        send(&ddb, &table, victim, &format!("m{n}"), NOON)
            .await
            .unwrap();
    }
    let rotated = key_of(2);
    let after = async |delivery: &str| {
        spend(
            &ddb,
            &table,
            &rotated,
            victim,
            delivery,
            Counter::General,
            NOON,
        )
        .await
    };
    assert_eq!(after("m0").await, Ok(()));
    for n in 1..DAILY_CAP {
        assert_eq!(after(&format!("n{n}")).await, Ok(()));
    }
    assert_eq!(after("over").await, Err(Refusal::CapReached));
    assert_eq!(count(&ddb, &table, victim, NOON).await, Some(DAILY_CAP));
}

/// A row under the unkeyed name of an earlier deployment is another row: it
/// neither counts against the mailbox nor changes.
#[tokio::test]
async fn unkeyed_rows_are_left_alone() {
    let (ddb, table) = table().await;
    let hash = hex::encode(Sha256::digest("victim@example.com"));
    let old = [
        ("partitionKey", Av::S(format!("MAIL#{hash}"))),
        ("sortKey", Av::S(format!("SEND#{}", NOON / DAY_SECONDS))),
    ];
    let mut put = ddb
        .put_item()
        .table_name(&table)
        .item("count", Av::N(DAILY_CAP.to_string()));
    for (name, value) in old.clone() {
        put = put.item(name, value);
    }
    put.send().await.unwrap();
    assert_eq!(
        send(&ddb, &table, "victim@example.com", "m", NOON).await,
        Ok(())
    );
    assert_eq!(
        count(&ddb, &table, "victim@example.com", NOON).await,
        Some(1)
    );
    let mut get = ddb.get_item().table_name(&table).consistent_read(true);
    for (name, value) in old {
        get = get.key(name, value);
    }
    let item = get.send().await.unwrap().item.unwrap();
    assert_eq!(item["count"].as_n().unwrap(), &DAILY_CAP.to_string());
}

/// Anyone can request a reset for any address, so resets are counted apart:
/// running either counter out leaves the other's budget whole.
#[tokio::test]
async fn password_resets_and_other_codes_cannot_drain_each_other() {
    let (ddb, table) = table().await;
    let victim = "victim@example.com";
    for n in 0..RESET_DAILY_CAP {
        assert_eq!(
            reset(&ddb, &table, victim, &format!("r{n}"), NOON).await,
            Ok(())
        );
    }
    assert_eq!(
        reset(&ddb, &table, "victim+x@example.com", "over", NOON).await,
        Err(Refusal::CapReached)
    );
    // Every other code still has its whole budget.
    for n in 0..DAILY_CAP {
        assert_eq!(
            send(&ddb, &table, victim, &format!("m{n}"), NOON).await,
            Ok(())
        );
    }
    assert_eq!(
        send(&ddb, &table, victim, "over-general", NOON).await,
        Err(Refusal::CapReached)
    );
    // A retry of a counted reset is still allowed, and the next day is fresh.
    assert_eq!(reset(&ddb, &table, victim, "r0", NOON).await, Ok(()));
    assert_eq!(
        reset(&ddb, &table, victim, "tomorrow", NOON + DAY_SECONDS).await,
        Ok(())
    );
}

/// A spent general budget leaves password recovery open.
#[tokio::test]
async fn a_spent_general_budget_leaves_resets() {
    let (ddb, table) = table().await;
    for n in 0..DAILY_CAP {
        send(&ddb, &table, "victim@example.com", &format!("m{n}"), NOON)
            .await
            .unwrap();
    }
    assert_eq!(
        reset(&ddb, &table, "victim@example.com", "r", NOON).await,
        Ok(())
    );
}
