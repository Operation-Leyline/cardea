use super::*;

/// A key spelled as a secret holds it: `bytes`, then zeroes up to 32. HMAC
/// pads a short key with zeroes itself, so a published vector with a shorter key
/// has the same answer under the padded one.
fn padded(bytes: &[u8]) -> BudgetKey {
    let mut key = [0; KEY_BYTES];
    key[..bytes.len()].copy_from_slice(bytes);
    BudgetKey::from_secret(&hex::encode(key)).unwrap()
}

/// RFC 4231, test cases 1 to 4: the HMAC-SHA-256 answers.
#[test]
fn matches_the_published_hmac_sha_256_vectors() {
    let counting: Vec<u8> = (1..=25).collect();
    for (key, data, expected) in [
        (
            &[0x0b; 20][..],
            &b"Hi There"[..],
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            &[0xaa; 20],
            &[0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            &counting,
            &[0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
    ] {
        assert_eq!(hex::encode(padded(key).mac(data)), expected);
    }
}

/// What a row key holds, computed independently of this crate.
#[test]
fn a_tag_is_the_hmac_of_the_name_in_lower_case_hex() {
    let key = padded(&std::array::from_fn::<u8, 32, _>(|n| n as u8));
    assert_eq!(
        key.tag("victim@gmail.com"),
        "4c4b53e6b24e1861941d9e538a46a468e2cee07fefe4ff0a96ff5f771e686c82"
    );
    assert_eq!(
        key.tag("cognito:example"),
        "980953fdda416d7586096d59bc2ba5e5725b8d773a618c7e8b3699293e5bd615"
    );
}

#[test]
fn a_secret_is_64_hexadecimal_characters() {
    let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let key = BudgetKey::from_secret(hex).unwrap();
    assert_eq!(key.0, std::array::from_fn(|n| n as u8));
    // A trailing newline from a file, or capitals, spell the same key.
    for same in [format!("{hex}\n"), hex.to_uppercase()] {
        assert_eq!(BudgetKey::from_secret(&same).unwrap().0, key.0);
    }
}

#[test]
fn anything_else_is_not_a_key() {
    for text in [
        String::new(),
        "a".repeat(63),
        "a".repeat(62),
        "a".repeat(66),
        "g".repeat(64),
        // 32 bytes in base64, which is not the format.
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
        format!("{{\"key\":\"{}\"}}", "a".repeat(64)),
    ] {
        assert!(
            matches!(BudgetKey::from_secret(&text), Err(KeyError::Format)),
            "{text:?}"
        );
    }
}

#[test]
fn a_key_never_prints() {
    assert_eq!(format!("{:?}", padded(b"secret")), "<redacted>");
}
