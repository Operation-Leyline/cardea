//! What a product supplies to the trigger handler.

use std::collections::BTreeMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::types::TransactWriteItem;
use cardea_core::User;
use serde_json::{Map, Value};

use crate::mail::MailDelivery;

/// A confirmed account the product may not have seen before.
#[derive(Clone)]
pub struct NewAccount {
    /// The Cognito `sub`: the product's permanent user id.
    pub user_id: String,
    /// The Cognito username.
    pub username: String,
    /// The account's email address, as the pool holds it.
    pub email: String,
    /// The `name` attribute, or the address's local part when there is none.
    pub display_name: String,
    /// Whether the pool marks the address verified.
    pub email_verified: bool,
    /// True only when a person has just confirmed their own signup with a
    /// verified address: the moment to queue a welcome. Password resets,
    /// sign-ins and repairs are false.
    pub confirmed_signup: bool,
    /// Every user attribute the event carried.
    pub attributes: Map<String, Value>,
}

/// Claims to add to a token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims(pub BTreeMap<String, String>);

/// A product hook failed. Cognito quotes a trigger's error text to the person,
/// so the message must be safe to show them.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProductError(Box<dyn std::error::Error + Send + Sync>);

impl ProductError {
    /// An error from another error or a message.
    pub fn new(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(cause.into())
    }
}

/// The product's side of the trigger handler.
#[async_trait]
pub trait Product: Send + Sync {
    /// Whether the product already holds this account. Read it consistently:
    /// it is asked again after a failed [`Product::provision`] to see whether
    /// a concurrent trigger won.
    async fn is_provisioned(&self, account: &NewAccount) -> Result<bool, ProductError>;

    /// First sight of a confirmed account. Must be idempotent, and must put
    /// `guard` in the same DynamoDB transaction as its own writes: the guard
    /// is the condition that no other Cognito user owns this mailbox.
    /// [`crate::transact`] sends such a transaction.
    async fn provision(
        &self,
        account: &NewAccount,
        guard: TransactWriteItem,
    ) -> Result<(), ProductError>;

    /// Claims to add to tokens. Default: none.
    async fn token_claims(&self, _user: &User) -> Result<Claims, ProductError> {
        Ok(Claims::default())
    }

    /// Delivers Cognito's messages for a pool with a custom email sender.
    /// `None` keeps Cognito's own sender, and no budget applies.
    fn mail(&self) -> Option<&dyn MailDelivery> {
        None
    }
}
