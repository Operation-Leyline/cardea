//! Cognito passes an AWS Encryption SDK envelope, never a raw KMS ciphertext.

use std::collections::HashMap;

use async_trait::async_trait;
use aws_esdk::{
    material_providers::{
        client::Client as Providers,
        types::{
            EsdkCommitmentPolicy, keyring::KeyringRef,
            material_providers_config::MaterialProvidersConfig,
        },
    },
    types::aws_encryption_sdk_config::AwsEncryptionSdkConfig,
};

use super::{CodeDecryptor, MailError};

/// Decrypts Cognito's codes with the pool's custom sender KMS key.
pub struct KmsDecryptor {
    keyring: KeyringRef,
}

impl KmsDecryptor {
    /// A decryptor for the key `key_arn`.
    pub async fn new(kms: aws_sdk_kms::Client, key_arn: String) -> Result<Self, MailError> {
        let failed = |_| MailError::Configuration("the keyring could not be initialized");
        let providers = Providers::from_conf(
            MaterialProvidersConfig::builder()
                .build()
                .map_err(|_| MailError::Configuration("material providers"))?,
        )
        .map_err(|_| MailError::Configuration("material providers"))?;
        let keyring = providers
            .create_aws_kms_keyring()
            .kms_key_id(key_arn)
            .kms_client(kms)
            .send()
            .await
            .map_err(failed)?;
        Ok(Self { keyring })
    }
}

/// The plaintext of `ciphertext`, which must have been encrypted for `pool`.
async fn open(ciphertext: Vec<u8>, keyring: KeyringRef, pool: &str) -> Result<String, MailError> {
    // Cognito can issue non-committing messages.
    let config = AwsEncryptionSdkConfig::builder()
        .commitment_policy(EsdkCommitmentPolicy::RequireEncryptAllowDecrypt)
        .max_encrypted_data_keys(5)
        .build()
        .map_err(|_| MailError::Decryption)?;
    let esdk = aws_esdk::client::Client::from_conf(config).map_err(|_| MailError::Decryption)?;
    let decrypted = esdk
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(keyring)
        .encryption_context(HashMap::from([("userpool-id".into(), pool.into())]))
        .send()
        .await
        .map_err(|_| MailError::Decryption)?;
    let plaintext = decrypted.plaintext.ok_or(MailError::Decryption)?;
    Ok(std::str::from_utf8(plaintext.as_ref())
        .map_err(|_| MailError::Decryption)?
        .to_owned())
}

#[async_trait]
impl CodeDecryptor for KmsDecryptor {
    async fn decrypt(&self, ciphertext: Vec<u8>, pool: &str) -> Result<String, MailError> {
        open(ciphertext, self.keyring.clone(), pool).await
    }
}

#[cfg(test)]
mod tests;
