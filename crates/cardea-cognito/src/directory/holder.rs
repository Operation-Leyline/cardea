//! Who holds a mailbox, for a reader that only needs the user.

use aws_sdk_dynamodb::Client as Dynamo;
use tabulary::{MultiTable, Projection, ReadConsistency, ReadError};

use super::email_key;
use crate::record::{EmailRow, EmailRowAttrs, IdentityTable};

/// What a holder read selects from a mailbox's row: only the user it
/// belongs to, so an owner record this reader never needs cannot fail it.
#[derive(Debug, Projection)]
#[tabulary(record = EmailRow)]
struct Holder {
    #[tabulary(attribute = EmailRowAttrs::USER_ID)]
    user_id: Option<String>,
}

/// Why the holder of a mailbox could not be read.
#[derive(Debug, thiserror::Error)]
pub enum HolderReadError {
    /// The read failed.
    #[error("the identities table could not be read")]
    Read(#[source] Box<ReadError<aws_sdk_dynamodb::operation::get_item::GetItemError>>),
    /// The request could not be built.
    #[error("the identities table name or key is invalid: {0}")]
    Request(#[source] tabulary::BuildError),
}

/// The product user holding `email`'s mailbox, as `client`'s replica of the
/// directory `table` has it: `None` for an address nobody signed up with, or
/// one that does not normalize and so was never anyone's.
pub async fn mailbox_holder(
    client: &Dynamo,
    table: &str,
    email: &str,
) -> Result<Option<String>, HolderReadError> {
    let Ok(key) = email_key(email) else {
        return Ok(None);
    };
    let request = MultiTable::<IdentityTable>::new(table)
        .and_then(|rows| {
            rows.get(key, ReadConsistency::Eventual)
                .select::<Holder>()
                .build()
        })
        .map_err(HolderReadError::Request)?;
    let read = request
        .decode(request.apply(client.get_item()).send().await)
        .map_err(|error| HolderReadError::Read(Box::new(error)))?;
    Ok(read.item.and_then(|holder| holder.user_id))
}
