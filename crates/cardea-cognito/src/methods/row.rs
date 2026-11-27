//! Reading a user's identity list and writing it back on the condition that
//! nothing else wrote it meanwhile.

use cardea_core::{Error, Provider, User};
use tabulary::WriteError;

use crate::{
    TransactError,
    directory::AwsDirectory,
    record::{LinkedIdentity, MethodsRow, MethodsRowAttrs, MethodsRowKey, ProviderRow},
    transact,
};

/// How often a change is tried while others keep winning.
pub(crate) const ATTEMPTS: u32 = 4;

/// An identity, named as the list names it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub provider: Provider,
    pub subject: String,
}

impl MethodsRow {
    /// The list of a user who has none yet.
    pub(crate) fn empty(user: &User) -> Self {
        Self {
            user_id: user.user_id.clone(),
            version: 0,
            identities: Vec::new(),
            erasing_mailboxes: None,
        }
    }

    fn position(&self, identity: &Identity) -> Option<usize> {
        let provider = ProviderRow::provider_name(identity.provider);
        self.identities
            .iter()
            .position(|i| i.provider == provider && i.subject == identity.subject)
    }

    pub(crate) fn find(&self, identity: &Identity) -> Option<&LinkedIdentity> {
        self.position(identity).map(|at| &self.identities[at])
    }

    /// The entry for `identity`, added without an address if absent.
    pub(crate) fn entry(&mut self, identity: &Identity) -> &mut LinkedIdentity {
        let at = self.position(identity).unwrap_or_else(|| {
            self.identities.push(LinkedIdentity {
                provider: ProviderRow::provider_name(identity.provider),
                subject: identity.subject.clone(),
                email: None,
                removing: false,
            });
            self.identities.len() - 1
        });
        &mut self.identities[at]
    }

    /// Whether an unlink of `identity` is unfinished.
    pub(crate) fn is_removing(&self, identity: &Identity) -> bool {
        self.find(identity).is_some_and(|entry| entry.removing)
    }
}

impl AwsDirectory {
    /// `user`'s identity list, read consistently.
    pub(crate) async fn methods_row(&self, user: &User) -> Result<Option<MethodsRow>, Error> {
        let key = MethodsRowKey::new(user.user_id.clone()).map_err(|_| Error::Invalid)?;
        self.row(key).await
    }

    /// Replace the list `read` (version 0: there was none) with `next`.
    /// `false` when another write came first and nothing changed.
    pub(crate) async fn replace_methods_row(
        &self,
        read: i64,
        mut next: MethodsRow,
    ) -> Result<bool, Error> {
        next.version = read + 1;
        let put = self.rows()?.put(&next);
        let put = if read == 0 {
            put.expect_new()
        } else {
            put.condition(MethodsRowAttrs::VERSION.eq(read))
        };
        let request = put.build().map_err(|_| Error::Invalid)?;
        match request.decode(request.apply(self.dynamodb().put_item()).send().await) {
            Ok(_) => Ok(true),
            Err(WriteError::Refused { failure, .. })
                if matches!(
                    failure.kind,
                    tabulary::FailureKind::ConditionFailed
                        | tabulary::FailureKind::TransactionConflict
                ) =>
            {
                Ok(false)
            }
            // It may have landed. Every change here can be repeated.
            Err(_) => Err(Error::Unavailable),
        }
    }

    /// [`AwsDirectory::replace_methods_row`] and the creation of `binding`, as
    /// one transaction. The inner error is a transaction refused or not
    /// answered.
    pub(crate) async fn replace_methods_row_binding(
        &self,
        read: i64,
        mut next: MethodsRow,
        binding: &ProviderRow,
    ) -> Result<Result<(), TransactError>, Error> {
        next.version = read + 1;
        let rows = self.rows()?;
        let put = rows.put(&next);
        let put = if read == 0 {
            put.expect_new()
        } else {
            put.condition(MethodsRowAttrs::VERSION.eq(read))
        };
        let list = put.into_tx().map_err(|_| Error::Invalid)?;
        let binding = rows
            .put(binding)
            .expect_new()
            .into_tx()
            .map_err(|_| Error::Invalid)?;
        let items = vec![list.input().clone(), binding.input().clone()];
        Ok(transact(self.dynamodb(), items).await)
    }
}
