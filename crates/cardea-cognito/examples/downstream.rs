//! Every way a product serves Cardea's Lambdas, built as a crate of its own at
//! the default recursion limit. A product must not need to raise it, so this
//! must keep compiling on the workspace's `rust-version`. Nothing runs it.

use async_trait::async_trait;
use cardea_cognito::aws_sdk_dynamodb::types::TransactWriteItem;
use cardea_cognito::mail::{self, MailDelivery, MailMessage};
use cardea_cognito::triggers::{self, NewAccount, Product, ProductError, TriggerHandler};
use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::Value;
use std::sync::Arc;
use tracing::Instrument;

struct Probe;

#[async_trait]
impl Product for Probe {
    async fn is_provisioned(&self, _account: &NewAccount) -> Result<bool, ProductError> {
        Ok(true)
    }

    async fn provision(
        &self,
        _account: &NewAccount,
        _guard: TransactWriteItem,
    ) -> Result<(), ProductError> {
        Ok(())
    }
}

#[async_trait]
impl MailDelivery for Probe {
    async fn deliver(&self, _message: MailMessage<'_>) -> Result<(), ProductError> {
        Ok(())
    }
}

/// A product that wraps each invocation in a tracing span of its own.
async fn wrapped() -> Result<(), lambda_runtime::Error> {
    let handler = Arc::new(TriggerHandler::new(Probe).await);
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let handler = Arc::clone(&handler);
        let span = tracing::info_span!("trigger");
        async move {
            handler
                .invoke(event.payload, &event.context.request_id)
                .await
        }
        .instrument(span)
    }))
    .await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), lambda_runtime::Error> {
    match std::env::args().nth(1).as_deref() {
        Some("wrapped") => wrapped().await,
        Some("mail") => mail::serve(Probe).await,
        Some("triggers") => triggers::serve(Probe).await,
        _ => {
            // The blocking forms start a runtime of their own.
            std::thread::spawn(|| triggers::run(Probe).and(mail::run(Probe)))
                .join()
                .map_err(|_| "the function panicked")?
        }
    }
}
