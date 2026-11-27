//! Running the handler as a Lambda function.

use std::sync::Arc;

use aws_config::SdkConfig;
use lambda_runtime::{LambdaEvent, service_fn};
use serde_json::Value;

use super::{Product, TriggerError, handle};
use crate::directory::{AwsDirectory, config};

/// What a failed invocation, or a function that could not start, reports.
type Failure = lambda_runtime::Error;

/// A product and the configuration it is served under. Use it to wrap each
/// invocation in the product's own tracing; otherwise call [`run`].
pub struct TriggerHandler<P> {
    product: P,
    config: SdkConfig,
    /// Built for the first mail event and kept, so that the budget key is read
    /// once.
    #[cfg(feature = "email-sender")]
    sender: tokio::sync::OnceCell<crate::mail::EmailSender>,
}

impl<P: Product> TriggerHandler<P> {
    /// Load the AWS configuration once for every invocation.
    pub async fn new(product: P) -> Self {
        Self {
            product,
            config: config::load().await,
            #[cfg(feature = "email-sender")]
            sender: tokio::sync::OnceCell::new(),
        }
    }

    /// Answer one event. `request_id` is the Lambda invocation's.
    ///
    /// The directory table comes from `IDENTITIES_TABLE` and the pool from the
    /// event. A custom email sender event needs neither: it goes to
    /// [`Product::mail`].
    pub async fn invoke(&self, payload: Value, request_id: &str) -> Result<Value, Failure> {
        if payload["triggerSource"]
            .as_str()
            .is_some_and(|source| source.starts_with("CustomEmailSender_"))
        {
            return self.send_mail(&payload, request_id).await;
        }
        let pool = payload["userPoolId"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(TriggerError::MissingField("user pool"))?;
        let directory = AwsDirectory::from_env_with(&self.config, pool.into())?;
        Ok(handle(&directory, &self.product, payload).await?)
    }

    #[cfg(feature = "email-sender")]
    async fn send_mail(&self, payload: &Value, request_id: &str) -> Result<Value, Failure> {
        let delivery = self
            .product
            .mail()
            .ok_or("the product delivers no Cognito mail")?;
        // Reading the environment here keeps it unneeded in a function that
        // never receives mail events.
        let sender = self
            .sender
            .get_or_try_init(crate::mail::EmailSender::from_env)
            .await?;
        Ok(sender.send(delivery, payload, request_id).await?)
    }

    #[cfg(not(feature = "email-sender"))]
    async fn send_mail(&self, _payload: &Value, _request_id: &str) -> Result<Value, Failure> {
        Err("built without the email-sender feature".into())
    }
}

/// [`run`] on a Tokio runtime the caller already has.
pub async fn serve<P: Product>(product: P) -> Result<(), Failure> {
    let handler = Arc::new(TriggerHandler::new(product).await);
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let handler = Arc::clone(&handler);
        async move {
            handler
                .invoke(event.payload, &event.context.request_id)
                .await
        }
    }))
    .await
}

/// Serve the product's triggers until Lambda stops the function. This is the
/// whole of a product's `main`; it fails only when the function cannot run.
pub fn run<P: Product>(product: P) -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(product))
}

#[cfg(all(test, feature = "email-sender"))]
mod tests;
