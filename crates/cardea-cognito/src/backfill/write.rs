//! The backfill's only writes: new rows, each on the condition that its key is
//! free, and identities appended to a list, on the condition that it has not
//! changed.

use aws_sdk_dynamodb::error::ProvideErrorMetadata;
use cardea_core::Error;
use tabulary::{FailureKind, MemberOf, WriteError};

use super::{BackfillError, RowCounts, survey::Missing};
use crate::{
    directory::AwsDirectory,
    methods::row::Identity,
    record::{IdentityTable, ProviderRow, ReadyRow, ReadyRowKey},
};

/// The directory version an open table holds.
const VERSION: i64 = 1;

impl AwsDirectory {
    /// Whether the directory is open. A marker of another version is an error,
    /// not a closed directory.
    pub(super) async fn is_open(&self) -> Result<bool, BackfillError> {
        let key = ReadyRowKey::new().map_err(|_| Error::Invalid)?;
        match self.row::<ReadyRow>(key).await {
            Ok(None) => Ok(false),
            Ok(Some(ready)) if ready.version == VERSION => Ok(true),
            Ok(Some(_)) | Err(Error::Conflict) => Err(BackfillError::UnknownMarker),
            Err(error) => Err(error.into()),
        }
    }

    /// Write `SYSTEM#READY`.
    pub(super) async fn open(&self) -> Result<(), BackfillError> {
        self.create(&ReadyRow { version: VERSION }).await?;
        if self.is_open().await? {
            Ok(())
        } else {
            Err(BackfillError::Write("the marker is absent".into()))
        }
    }

    /// Write each row whose key is still free, and count those written. A key
    /// taken, or a list changed, meanwhile is left for the second pass to
    /// judge.
    pub(super) async fn write_missing(&self, rows: &[Missing]) -> Result<RowCounts, BackfillError> {
        let mut written = RowCounts::default();
        for row in rows {
            let created = match row {
                Missing::Claim(row) => self.create(row).await?,
                Missing::Binding(row) => self.create(row).await?,
                Missing::Unlisted(identity, row) => self.append(identity, row).await?,
                Missing::List(row) => self.create(row).await?,
            };
            if created {
                written.add(row.kind());
            }
        }
        Ok(written)
    }

    /// Create `binding` and put its identity on the user's list in one
    /// transaction, as a link does. No entry already there is touched. `false`
    /// when nothing was written.
    async fn append(
        &self,
        identity: &Identity,
        binding: &ProviderRow,
    ) -> Result<bool, BackfillError> {
        let Some(mut list) = self.methods_row(&binding.record).await? else {
            return Ok(false);
        };
        let version = list.version;
        list.entry(identity);
        Ok(self
            .replace_methods_row_binding(version, list, binding)
            .await?)
    }

    /// Put `row` unless its key holds one: `false` when it does.
    async fn create<R: MemberOf<IdentityTable>>(&self, row: &R) -> Result<bool, BackfillError> {
        let request = self
            .rows()?
            .put(row)
            .expect_new()
            .build()
            .map_err(|_| Error::Invalid)?;
        let sent = request.apply(self.dynamodb().put_item()).send().await;
        let code = sent
            .as_ref()
            .err()
            .and_then(|error| error.code())
            .unwrap_or("no answer")
            .to_owned();
        match request.decode(sent) {
            Ok(_) => Ok(true),
            Err(WriteError::Refused { failure, .. })
                if failure.kind == FailureKind::ConditionFailed =>
            {
                Ok(false)
            }
            Err(_) => Err(BackfillError::Write(code)),
        }
    }
}
