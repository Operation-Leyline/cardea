use aws_esdk::material_providers::types::{AesWrappingAlg, EsdkAlgorithmSuiteId};

use super::*;

#[tokio::test]
async fn decrypts_esdk_envelopes_and_rejects_wrong_pool_and_tampering() {
    let providers =
        Providers::from_conf(MaterialProvidersConfig::builder().build().unwrap()).unwrap();
    let keyring = providers
        .create_raw_aes_keyring()
        .key_name("test")
        .key_namespace("test")
        .wrapping_key(vec![7_u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await
        .unwrap();
    // Cognito can issue non-committing messages, unlike the ESDK's default policy.
    let encryptor = aws_esdk::client::Client::from_conf(
        AwsEncryptionSdkConfig::builder()
            .commitment_policy(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt)
            .build()
            .unwrap(),
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt()
        .keyring(keyring.clone())
        .plaintext(b"012345".to_vec())
        .algorithm_suite_id(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .encryption_context(HashMap::from([("userpool-id".into(), "test-pool".into())]))
        .send()
        .await
        .unwrap();
    let bytes = encrypted.ciphertext.unwrap().into_inner();
    assert_eq!(
        open(bytes.clone(), keyring.clone(), "test-pool")
            .await
            .unwrap(),
        "012345"
    );
    assert!(
        open(bytes.clone(), keyring.clone(), "other-pool")
            .await
            .is_err()
    );
    let mut corrupt = bytes;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(open(corrupt, keyring, "test-pool").await.is_err());
}
