//! The backfill over an in-process DynamoDB and a fake pool.

use aws_sdk_dynamodb::types::AttributeValue as Av;
use cardea_core::{Provider, User};

use super::*;
use crate::testing::{Fixture, cognito::Account, fixture};

mod activate;
mod conflicts;
mod rows;

const GOOGLE: Provider = Provider::Google;
const APPLE: Provider = Provider::Apple;

/// A pool with no directory yet: the table is empty.
async fn closed() -> Fixture {
    let f = fixture().await;
    f.delete("SYSTEM#READY").await;
    f
}

/// Put a user in the pool: `sub-of-{name}` at `{name}@example.com`, under the
/// username `{name}`.
fn user(f: &Fixture, name: &str, status: &'static str) -> User {
    let user = User {
        user_id: format!("sub-of-{name}"),
        username: name.into(),
        email: format!("{name}@example.com"),
    };
    f.pool.add(name, &user.user_id, &user.email, status);
    user
}

fn change(f: &Fixture, username: &str, change: impl FnOnce(&mut Account)) {
    change(f.pool.state().users.get_mut(username).unwrap());
}

async fn run(f: &Fixture, mode: Mode) -> BackfillReport {
    backfill(&f.directory, mode).await.unwrap()
}

fn counts(emails: usize, providers: usize, methods: usize) -> RowCounts {
    RowCounts {
        emails,
        providers,
        methods,
    }
}

fn finding(user: &str, problem: Problem) -> Finding {
    Finding {
        user: format!("sub-of-{user}"),
        problem,
    }
}

async fn present(f: &Fixture, key: &str) -> bool {
    f.item(key).await.is_some()
}

/// Every item the table holds.
async fn table_size(f: &Fixture) -> usize {
    f.directory
        .dynamodb()
        .scan()
        .table_name(f.directory.table())
        .consistent_read(true)
        .send()
        .await
        .unwrap()
        .items()
        .len()
}
