//! The ticket: bound to one account and app client, short-lived, good once.

use std::collections::HashMap;

use cardea_core::User;

use crate::native::ticket::{Binding, redeem};

use super::*;

/// A ticket as the trigger sees it: everything its event would name.
struct Issued {
    fixture: Fixture,
    answer: SignInTicket,
}

async fn issued() -> Issued {
    let fixture = fixture().await;
    let answer = fixture.google_ticket(SUBJECT, EMAIL).await.unwrap();
    Issued { fixture, answer }
}

impl Issued {
    fn binding(&self) -> Binding<'_> {
        Binding {
            username: &self.answer.username,
            user_id: SUB,
            client_id: WEB,
        }
    }

    async fn redeem_as(&self, binding: Binding<'_>, ticket: &str, at: u64) -> Result<bool, Error> {
        let key = ticket_key("a1");
        redeem(&self.fixture.directory, &key, binding, ticket, at).await
    }

    async fn redeem(&self) -> Result<bool, Error> {
        let at = u64::try_from(now()).unwrap();
        self.redeem_as(self.binding(), &self.answer.ticket, at)
            .await
    }
}

#[tokio::test]
async fn a_ticket_is_good_once() {
    let issued = issued().await;
    assert_eq!(issued.redeem().await, Ok(true));
    assert_eq!(issued.redeem().await, Ok(false));
    assert!(issued.fixture.rows_under("TICKET#").await.is_empty());
}

#[tokio::test]
async fn concurrent_redemptions_succeed_once() {
    let issued = issued().await;
    let (a, b, c) = tokio::join!(issued.redeem(), issued.redeem(), issued.redeem());
    let wins = [a, b, c]
        .into_iter()
        .filter(|answer| *answer == Ok(true))
        .count();
    assert_eq!(wins, 1);
}

#[tokio::test]
async fn a_ticket_lapses() {
    let issued = issued().await;
    for at in [issued.answer.expires_at, issued.answer.expires_at + 60] {
        let answer = issued
            .redeem_as(issued.binding(), &issued.answer.ticket, at)
            .await;
        assert_eq!(answer, Ok(false));
    }
    assert_eq!(issued.redeem().await, Ok(true));
}

/// Presented for anyone or anywhere else, it is refused and stays good for its
/// owner.
#[tokio::test]
async fn a_ticket_is_bound_to_its_user_and_app_client() {
    let issued = issued().await;
    let right = issued.binding();
    let wrong = [
        Binding {
            username: "someone-else",
            ..right
        },
        Binding {
            user_id: "another-sub",
            ..right
        },
        Binding {
            user_id: "",
            ..right
        },
        Binding {
            client_id: ANDROID,
            ..right
        },
    ];
    let at = u64::try_from(now()).unwrap();
    for binding in wrong {
        let answer = issued.redeem_as(binding, &issued.answer.ticket, at).await;
        assert_eq!(answer, Ok(false));
    }
    assert_eq!(issued.redeem().await, Ok(true));
}

#[tokio::test]
async fn a_wrong_ticket_or_another_key_is_refused() {
    let issued = issued().await;
    let at = u64::try_from(now()).unwrap();
    for ticket in [
        "",
        "short",
        &"0".repeat(64),
        &issued.answer.ticket.to_uppercase(),
        &format!("{} ", issued.answer.ticket),
    ] {
        let answer = issued.redeem_as(issued.binding(), ticket, at).await;
        assert_eq!(answer, Ok(false), "{ticket}");
    }
    let other = redeem(
        &issued.fixture.directory,
        &ticket_key("b2"),
        issued.binding(),
        &issued.answer.ticket,
        at,
    )
    .await;
    assert_eq!(other, Ok(false));
    assert_eq!(issued.redeem().await, Ok(true));
}

#[tokio::test]
async fn without_a_key_redemption_fails_closed() {
    let issued = issued().await;
    let at = u64::try_from(now()).unwrap();
    let answer = redeem(
        &issued.fixture.directory,
        &NoKey,
        issued.binding(),
        &issued.answer.ticket,
        at,
    )
    .await;
    assert_eq!(answer, Err(Error::Unavailable));
}

/// Rewriting a row does not move a ticket: its name holds the binding, and the
/// row must agree.
#[tokio::test]
async fn a_rewritten_row_signs_nobody_else_in() {
    let issued = issued().await;
    let row = issued.fixture.rows_under("TICKET#").await.remove(0);
    let put = |changed: HashMap<String, Av>| {
        issued
            .fixture
            .directory
            .dynamodb()
            .put_item()
            .table_name(issued.fixture.directory.table())
            .set_item(Some(changed))
            .send()
    };
    for (name, value) in [("userId", "victim-sub"), ("clientId", ANDROID)] {
        let mut changed = row.clone();
        changed.insert(name.into(), Av::S(value.into()));
        put(changed).await.unwrap();
        let mut binding = issued.binding();
        if name == "userId" {
            binding.user_id = value;
        } else {
            binding.client_id = value;
        }
        let at = u64::try_from(now()).unwrap();
        let moved = issued.redeem_as(binding, &issued.answer.ticket, at).await;
        assert_eq!(moved, Ok(false), "{name}");
        assert_eq!(issued.redeem().await, Ok(false), "{name}");
    }
}

#[tokio::test]
async fn a_ticket_dies_with_the_identitys_binding() {
    let issued = issued().await;
    issued.fixture.delete("PROVIDER#Google#g-subject-1").await;
    assert_eq!(issued.redeem().await, Ok(false));
}

/// What a redemption sees when an unlink runs to its end between its reads: a
/// binding still there, and a list that no longer holds the identity.
#[tokio::test]
async fn an_identity_off_the_users_list_ends_the_ticket() {
    for whole_list in [false, true] {
        let issued = issued().await;
        if whole_list {
            issued.fixture.delete(&format!("METHODS#{SUB}")).await;
        } else {
            let user = User {
                user_id: SUB.into(),
                username: EMAIL.into(),
                email: EMAIL.into(),
            };
            let directory = &issued.fixture.directory;
            let mut list = directory.methods_row(&user).await.unwrap().unwrap();
            list.identities.clear();
            let version = list.version;
            assert!(directory.replace_methods_row(version, list).await.unwrap());
        }
        let binding = issued.fixture.item("PROVIDER#Google#g-subject-1").await;
        assert!(binding.is_some());
        assert_eq!(issued.redeem().await, Ok(false), "{whole_list}");
    }
}

#[tokio::test]
async fn an_unlink_under_way_ends_the_ticket() {
    let issued = issued().await;
    let user = User {
        user_id: SUB.into(),
        username: EMAIL.into(),
        email: EMAIL.into(),
    };
    let mut list = issued
        .fixture
        .directory
        .methods_row(&user)
        .await
        .unwrap()
        .unwrap();
    list.identities[0].removing = true;
    let version = list.version;
    assert!(
        issued
            .fixture
            .directory
            .replace_methods_row(version, list)
            .await
            .unwrap()
    );
    assert_eq!(issued.redeem().await, Ok(false));
}
