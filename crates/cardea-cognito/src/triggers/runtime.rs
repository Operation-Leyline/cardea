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
/// invocation in the product's own tracing, or to give the mail budget's key a
/// source of the product's own; otherwise call [`run`].
pub struct TriggerHandler<P> {
    product: P,
    config: SdkConfig,
    /// Where mail events get the budget key; none means the secret
    /// `MAIL_BUDGET_KEY_SECRET` names, read once.
    #[cfg(feature = "email-sender")]
    key_source: Option<Arc<dyn crate::mail::BudgetKeySource>>,
    /// Built for the first mail event and kept, with whatever key it holds.
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
            key_source: None,
            #[cfg(feature = "email-sender")]
            sender: tokio::sync::OnceCell::new(),
        }
    }

    /// Take the mail budget key from `source`, asked for every mail event,
    /// rather than from the secret `MAIL_BUDGET_KEY_SECRET` names, which is
    /// then not read. [`crate::mail`] has an example.
    #[cfg(feature = "email-sender")]
    pub fn with_budget_key_source(
        mut self,
        source: impl crate::mail::BudgetKeySource + 'static,
    ) -> Self {
        self.key_source = Some(Arc::new(source));
        self.sender = tokio::sync::OnceCell::new();
        self
    }

    /// Serve events with this handler until Lambda stops the function.
    pub async fn serve(self) -> Result<(), Failure> {
        let handler = Arc::new(self);
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
            .sender(crate::mail::environment, crate::mail::defaults)
            .await?;
        Ok(sender.send(delivery, payload, request_id).await?)
    }

    /// The function's one sender, built on first use from the variables
    /// `variable` answers with and the configuration `config` loads.
    #[cfg(feature = "email-sender")]
    async fn sender<C: Future<Output = SdkConfig>>(
        &self,
        variable: impl Fn(&str) -> Option<String>,
        config: impl FnOnce() -> C,
    ) -> Result<&crate::mail::EmailSender, crate::mail::MailError> {
        self.sender
            .get_or_try_init(|| async move {
                let config = config().await;
                crate::mail::EmailSender::configured(variable, &config, self.key_source.clone())
                    .await
            })
            .await
    }

    #[cfg(not(feature = "email-sender"))]
    async fn send_mail(&self, _payload: &Value, _request_id: &str) -> Result<Value, Failure> {
        Err("built without the email-sender feature".into())
    }
}

/// [`run`] on a Tokio runtime the caller already has.
pub async fn serve<P: Product>(product: P) -> Result<(), Failure> {
    TriggerHandler::new(product).await.serve().await
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
