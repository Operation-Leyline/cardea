use super::*;
use serde::Deserialize;

/// The delivery address keeps its tag and dots; only the person key folds.
#[test]
fn the_delivery_address_is_only_trimmed_and_lowercased() {
    assert_eq!(
        normalize_email(" Foo.Bar+tag@Example.com ").unwrap(),
        "foo.bar+tag@example.com"
    );
    for email in ["", "@x", "a@", "a@b@c", "a b@c", "a\n@c"] {
        assert!(normalize_email(email).is_err());
    }
    let long = format!("{}@example.com", "a".repeat(320));
    assert_eq!(normalize_email(&long), Err(Error::Invalid));
}

#[derive(Deserialize)]
struct Vectors {
    folds: Vec<(String, String)>,
    invalid: Vec<String>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../testdata/person_keys.json")).unwrap()
}

#[test]
fn every_alias_spelling_of_a_mailbox_folds_to_one_person_key() {
    let vectors = vectors();
    for (spelling, key) in &vectors.folds {
        assert_eq!(&person_key(spelling).unwrap(), key, "{spelling}");
        // Folding is idempotent: a key is its own key.
        assert_eq!(&person_key(key).unwrap(), key, "{key}");
    }
    for spelling in &vectors.invalid {
        assert_eq!(person_key(spelling), Err(Error::Invalid), "{spelling:?}");
    }
}

#[test]
fn different_mailboxes_stay_different_people() {
    for (a, b) in [
        ("first.last@example.com", "firstlast@example.com"),
        ("owner@gmail.com", "owner@example.com"),
        ("owner@gmail.com", "owner2@gmail.com"),
        ("owner+a@example.com", "other+a@example.com"),
    ] {
        assert_ne!(person_key(a).unwrap(), person_key(b).unwrap(), "{a} {b}");
        assert!(!same_mailbox(a, b), "{a} {b}");
    }
    assert!(same_mailbox("o.wner+a@gmail.com", "owner@googlemail.com"));
    assert!(!same_mailbox("not an address", "not an address"));
}

/// A tag fold alone proves nothing about who reads the mail outside Gmail.
#[test]
fn one_inbox_is_the_same_address_or_two_gmail_spellings() {
    assert!(same_inbox("Owner@Example.com", "owner@example.com"));
    assert!(same_inbox("o.wner+a@gmail.com", "owner@googlemail.com"));
    assert!(!same_inbox("owner@example.com", "owner+a@example.com"));
    assert!(!same_inbox("owner@gmail.com", "other@gmail.com"));
    assert!(!same_inbox("not an address", "not an address"));
}
