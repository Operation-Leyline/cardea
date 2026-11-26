use super::*;
use crate::testing::ddb;

const NOON: i64 = 1_790_000_000;

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
    spend(ddb, table, recipient, delivery, now, DAILY_CAP).await
}

/// The recipient's count for the day, read back from the table.
async fn count(ddb: &Client, table: &str, recipient: &str, now: i64) -> Option<i64> {
    let (partition, sort) = key(recipient, now).unwrap();
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

#[test]
fn the_row_names_the_mailbox_by_hash_never_the_address() {
    let (partition, sort) = key("Vic.Tim+x@Gmail.com", NOON).unwrap();
    assert_eq!(key("victim@googlemail.com", NOON).unwrap().0, partition);
    assert!(partition.starts_with("MAIL#") && !partition.contains("victim"));
    assert_eq!(sort, format!("SEND#{}", NOON / DAY_SECONDS));
    assert_eq!(key("not-an-address", NOON), Err(Refusal::Invalid));
}
