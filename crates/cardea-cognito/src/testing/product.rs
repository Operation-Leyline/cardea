//! A product that keeps its accounts in memory but commits the guard for real.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use aws_sdk_dynamodb::{Client, types::TransactWriteItem};
use cardea_core::User;

use crate::{
    mail::{MailDelivery, MailMessage, MessageKind, Template},
    transact,
    triggers::{Claims, NewAccount, Product, ProductError},
};

pub(crate) struct FakeProduct {
    ddb: Client,
    /// The accounts provisioned, in order.
    pub accounts: Mutex<Vec<NewAccount>>,
    /// Fail the next provision before it writes.
    pub fail_provision: AtomicBool,
    /// Fail the next provision after it committed, as a lost race looks.
    pub lose_provision: AtomicBool,
    pub claims: Claims,
}

impl FakeProduct {
    pub fn new(ddb: Client) -> Self {
        Self {
            ddb,
            accounts: Mutex::default(),
            fail_provision: AtomicBool::new(false),
            lose_provision: AtomicBool::new(false),
            claims: Claims::default(),
        }
    }
}

#[async_trait]
impl Product for FakeProduct {
    async fn is_provisioned(&self, account: &NewAccount) -> Result<bool, ProductError> {
        let accounts = self.accounts.lock().unwrap();
        Ok(accounts.iter().any(|a| a.user_id == account.user_id))
    }

    async fn provision(
        &self,
        account: &NewAccount,
        guard: TransactWriteItem,
    ) -> Result<(), ProductError> {
        if self.fail_provision.swap(false, Ordering::SeqCst) {
            return Err(ProductError::new("account tables are unavailable"));
        }
        transact(&self.ddb, vec![guard])
            .await
            .map_err(ProductError::new)?;
        self.accounts.lock().unwrap().push(account.clone());
        if self.lose_provision.swap(false, Ordering::SeqCst) {
            return Err(ProductError::new("answer lost"));
        }
        Ok(())
    }

    async fn token_claims(&self, _user: &User) -> Result<Claims, ProductError> {
        Ok(self.claims.clone())
    }
}

/// What a delivery received: kind, recipient, code and delivery key.
pub(crate) type Sent = (MessageKind, String, Option<String>, String);

/// Records what it is asked to send.
#[derive(Clone, Default)]
pub(crate) struct Outbox {
    pub sent: Arc<Mutex<Vec<Sent>>>,
    /// Report no template for any message.
    pub no_templates: bool,
}

#[async_trait]
impl MailDelivery for Outbox {
    fn template(&self, kind: MessageKind) -> Result<Template, ProductError> {
        if self.no_templates {
            return Err(ProductError::new("no template"));
        }
        Ok(Template {
            id: kind.name().into(),
            version: 1,
        })
    }

    async fn deliver(&self, message: MailMessage<'_>) -> Result<(), ProductError> {
        self.sent.lock().unwrap().push((
            message.kind,
            message.recipient.into(),
            message.code.map(|code| code.expose().into()),
            message.delivery_key.into(),
        ));
        Ok(())
    }
}
