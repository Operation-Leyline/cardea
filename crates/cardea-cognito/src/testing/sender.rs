//! What configuring an email sender needs: variables, a Secrets Manager on
//! loopback, and a key source of a product's own.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_secretsmanager::config::{Credentials, SharedCredentialsProvider};
use axum::{Json, Router, body::Bytes, routing::post};
use serde_json::{Value, json};

use super::loopback::{self, Loopback};
use crate::mail::{BudgetKey, BudgetKeySource, KeyError};

pub(crate) const SECRET: &str = "product/mail-budget-key";
pub(crate) const EMAIL_KEY: &str =
    "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000";

/// The environment of a sender with everything set.
pub(crate) fn variable(name: &str) -> Option<String> {
    let value = match name {
        "MAIL_BUDGET_TABLE" => "budget-table",
        "MAIL_BUDGET_KEY_SECRET" => SECRET,
        "COGNITO_EMAIL_KEY_ARN" => EMAIL_KEY,
        _ => return None,
    };
    Some(value.into())
}

/// A Secrets Manager holding a key, which remembers what was asked.
pub(crate) struct SecretStore {
    asked: Arc<Mutex<Vec<Value>>>,
    server: Loopback,
}

impl SecretStore {
    pub async fn serve() -> Self {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&asked);
        let server = loopback::serve(Router::new().route(
            "/",
            post(move |body: Bytes| async move {
                seen.lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                Json(json!({"SecretString": "01".repeat(32)}))
            }),
        ))
        .await;
        Self { asked, server }
    }

    /// A configuration whose clients all come here.
    pub fn config(&self) -> SdkConfig {
        SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                "local", "local", None, None, "test",
            )))
            .endpoint_url(self.server.endpoint())
            .build()
    }

    pub fn asked(&self) -> Vec<Value> {
        self.asked.lock().unwrap().clone()
    }
}

/// A key source that counts how often it is asked.
#[derive(Clone, Default)]
pub(crate) struct Counted(Arc<AtomicUsize>);

impl Counted {
    pub fn reads(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl BudgetKeySource for Counted {
    async fn load(&self) -> Result<BudgetKey, KeyError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        BudgetKey::from_secret(&"01".repeat(32))
    }
}
