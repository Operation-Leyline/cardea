//! A product's native sign-in over the fixture: its app clients, its ticket key
//! and the two public steps, run with the real token checks.

use aws_sdk_dynamodb::types::AttributeValue;
use cardea_core::Provider;

use super::{
    Fixture,
    accounts::clients,
    provider::{token, verifier},
};
use crate::{
    OperationError,
    native::{NativeSignIn, SignInTicket, TicketKey, begin_provider_sign_in, create_sign_in_nonce},
};

/// The app clients allowed to sign in natively.
pub(crate) const WEB: &str = "web-app-client";
pub(crate) const ANDROID: &str = "android-app-client";

/// A ticket key spelled by one repeated byte.
pub(crate) fn ticket_key(byte: &str) -> TicketKey {
    TicketKey::from_secret(&byte.repeat(32)).unwrap()
}

/// Every provider configured, both app clients allowed.
pub(crate) fn native() -> NativeSignIn {
    NativeSignIn::new(clients(), [WEB, ANDROID], ticket_key("a1"))
}

impl Fixture {
    /// A freshly issued Google sign-in nonce.
    pub async fn nonce(&self) -> String {
        create_sign_in_nonce(&self.directory, &native(), Provider::Google)
            .await
            .unwrap()
            .nonce
    }

    /// Begin a sign-in with `id_token` on `app_client`.
    pub async fn begin(
        &self,
        id_token: &str,
        app_client: &str,
    ) -> Result<SignInTicket, OperationError> {
        begin_provider_sign_in(
            &self.directory,
            &verifier(),
            &native(),
            Provider::Google,
            id_token,
            app_client,
        )
        .await
    }

    /// A whole first half for Google's `subject` at `email`, on the web client.
    pub async fn google_ticket(
        &self,
        subject: &str,
        email: &str,
    ) -> Result<SignInTicket, OperationError> {
        let nonce = self.nonce().await;
        self.begin(&token(Provider::Google, &nonce, subject, email), WEB)
            .await
    }

    /// Every row whose key starts with `prefix`.
    pub async fn rows_under(&self, prefix: &str) -> Vec<super::ddb::Item> {
        self.directory
            .dynamodb()
            .scan()
            .table_name(self.directory.table())
            .consistent_read(true)
            .send()
            .await
            .unwrap()
            .items
            .unwrap_or_default()
            .into_iter()
            .filter(|item| {
                matches!(&item["identityKey"], AttributeValue::S(key) if key.starts_with(prefix))
            })
            .collect()
    }
}
