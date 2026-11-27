//! Every way a product serves Cardea's Lambdas, built as a crate of its own at
//! the default recursion limit. A product must not need to raise it, so this
//! must keep compiling on the workspace's `rust-version`. Nothing runs it.

use async_trait::async_trait;
use cardea_cognito::aws_sdk_dynamodb::types::TransactWriteItem;
use cardea_cognito::directory::AwsDirectory;
use cardea_cognito::link::ProviderClients;
use cardea_cognito::mail::{self, MailDelivery, MailMessage};
use cardea_cognito::native::{
    NativeSignIn, SecretsManagerTicketKey, begin_provider_sign_in, create_sign_in_nonce,
};
use cardea_cognito::proof::JwtVerifier;
use cardea_cognito::triggers::{self, NewAccount, Product, ProductError, TriggerHandler};
use cardea_core::Provider;
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

/// The public half of native sign-in, as a product's API runs it: on a task of
/// its own, inside a span.
async fn native(directory: AwsDirectory, native: NativeSignIn, verifier: JwtVerifier) {
    let task = tokio::spawn(
        async move {
            let nonce = create_sign_in_nonce(&directory, &native, Provider::Google).await?;
            let google = Provider::Google;
            begin_provider_sign_in(&directory, &verifier, &native, google, &nonce.nonce, "app")
                .await
        }
        .instrument(tracing::info_span!("sign-in")),
    );
    let _ = task.await;
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), lambda_runtime::Error> {
    match std::env::args().nth(1).as_deref() {
        Some("wrapped") => wrapped().await,
        Some("mail") => mail::serve(Probe).await,
        Some("triggers") => triggers::serve(Probe).await,
        Some("native") => {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let directory = AwsDirectory::from_env_with(&config, "pool".into())?;
            let keys = SecretsManagerTicketKey::from_env(&config)?;
            let sign_in = NativeSignIn::new(ProviderClients::new(), ["app"], keys);
            native(directory, sign_in, JwtVerifier::new()?).await;
            Ok(())
        }
        _ => {
            // The blocking forms start a runtime of their own.
            std::thread::spawn(|| triggers::run(Probe).and(mail::run(Probe)))
                .join()
                .map_err(|_| "the function panicked")?
        }
    }
}
