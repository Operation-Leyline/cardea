//! The single-use ticket between [`begin_provider_sign_in`] and Cognito's
//! custom challenge.
//!
//! [`begin_provider_sign_in`]: super::begin_provider_sign_in

use cardea_core::{Directory, Error, Provider};
use tabulary::{FailureKind, WriteError};

use super::{
    TICKET_LIFETIME_SECONDS, TicketKey, TicketKeySource, load_key, random_value, well_formed,
};
use crate::{
    directory::AwsDirectory,
    methods::row::Identity,
    record::{ProviderRow, TicketRow, TicketRowAttrs, TicketRowKey},
};

/// Whom a ticket signs in, and where: all of it is part of the ticket's tag, so
/// a ticket presented for anyone or anywhere else names no row.
#[derive(Clone, Copy)]
pub(crate) struct Binding<'a> {
    pub username: &'a str,
    pub user_id: &'a str,
    pub client_id: &'a str,
}

impl Binding<'_> {
    fn tag(&self, directory: &AwsDirectory, key: &TicketKey, ticket: &str) -> String {
        key.tag(&[
            "cardea.sign-in-ticket.v1",
            directory.pool(),
            self.username,
            self.user_id,
            self.client_id,
            ticket,
        ])
    }
}

/// A new ticket for `binding`, proved by the provider identity, and when it
/// expires. The ticket is returned only once its row is written.
pub(super) async fn mint(
    directory: &AwsDirectory,
    key: &TicketKey,
    binding: Binding<'_>,
    provider: Provider,
    subject: &str,
    now: u64,
) -> Result<(String, u64), Error> {
    let ticket = random_value();
    let expires_at = now + TICKET_LIFETIME_SECONDS;
    let row = TicketRow {
        tag: binding.tag(directory, key, &ticket),
        user_id: binding.user_id.to_owned(),
        client_id: binding.client_id.to_owned(),
        provider: ProviderRow::provider_name(provider),
        subject: subject.to_owned(),
        deadline: expires_at,
        expires_at,
    };
    let request = directory
        .rows()?
        .put(&row)
        .expect_new()
        .build()
        .map_err(|_| Error::Invalid)?;
    request
        .decode(request.apply(directory.dynamodb().put_item()).send().await)
        .map_err(|_| Error::Unavailable)?;
    Ok((ticket, expires_at))
}

/// Whether `ticket` signs `binding` in at `now`, spending it if so. It does
/// when
///
/// 1. it is a ticket by shape, and its tag under the key, with this pool,
///    username, user and app client, names a row;
/// 2. that row names the same user and app client and has not expired;
/// 3. one delete, conditional on all three again, removes the row, so of any
///    number of callers one succeeds; and
/// 4. the provider identity that proved the person is still bound to that user,
///    with no unlink of it under way.
pub(crate) async fn redeem(
    directory: &AwsDirectory,
    keys: &(impl TicketKeySource + ?Sized),
    binding: Binding<'_>,
    ticket: &str,
    now: u64,
) -> Result<bool, Error> {
    if !well_formed(ticket) {
        return Ok(false);
    }
    let key = load_key(keys).await?;
    let tag = binding.tag(directory, &key, ticket);
    let row_key = || TicketRowKey::new(tag.clone()).map_err(|_| Error::Invalid);
    let row = match directory.row::<TicketRow>(row_key()?).await {
        Ok(Some(row)) => row,
        // A ticket nobody can read signs nobody in.
        Ok(None) | Err(Error::Conflict) => return Ok(false),
        Err(error) => return Err(error),
    };
    if row.user_id != binding.user_id || row.client_id != binding.client_id || row.deadline <= now {
        return Ok(false);
    }
    let request = directory
        .rows()?
        .delete(row_key()?)
        .condition(
            TicketRowAttrs::USER_ID
                .eq(binding.user_id.to_owned())
                .and(TicketRowAttrs::CLIENT_ID.eq(binding.client_id.to_owned()))
                .and(TicketRowAttrs::DEADLINE.gt(now)),
        )
        .build()
        .map_err(|_| Error::Invalid)?;
    match request.decode(
        request
            .apply(directory.dynamodb().delete_item())
            .send()
            .await,
    ) {
        Ok(_) => {}
        Err(WriteError::Refused { failure, .. })
            if failure.kind == FailureKind::ConditionFailed =>
        {
            return Ok(false);
        }
        Err(_) => return Err(Error::Unavailable),
    }
    still_bound(directory, &row).await
}

/// Whether the identity `row` was proved by may still sign its user in: an
/// unlink since the ticket was made ends it.
async fn still_bound(directory: &AwsDirectory, row: &TicketRow) -> Result<bool, Error> {
    let Some(provider) = Provider::from_cognito_name(&row.provider) else {
        return Ok(false);
    };
    let Some(bound) = directory.provider(provider, &row.subject).await? else {
        return Ok(false);
    };
    if bound.user_id != row.user_id {
        return Ok(false);
    }
    let identity = Identity {
        provider,
        subject: row.subject.clone(),
    };
    Ok(!directory
        .methods_row(&bound)
        .await?
        .is_some_and(|list| list.is_removing(&identity)))
}
