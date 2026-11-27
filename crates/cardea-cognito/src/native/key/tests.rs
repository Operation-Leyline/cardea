use super::*;

fn key(byte: &str) -> TicketKey {
    TicketKey::from_secret(&byte.repeat(32)).unwrap()
}

#[test]
fn a_secret_is_exactly_64_hexadecimal_characters() {
    assert!(TicketKey::from_secret(&format!(" {}\n", "aB".repeat(32))).is_ok());
    for text in ["", "ab", &"a".repeat(63), &"a".repeat(66), &"g".repeat(64)] {
        assert!(matches!(
            TicketKey::from_secret(text),
            Err(TicketKeyError::Format)
        ));
    }
}

#[test]
fn a_key_never_prints() {
    assert_eq!(format!("{:?}", key("ab")), "<redacted>");
}

#[test]
fn a_tag_depends_on_the_key_and_on_where_each_part_ends() {
    let tag = key("00").tag(&["a", "bc"]);
    assert_eq!(tag.len(), 64);
    assert_eq!(tag, key("00").tag(&["a", "bc"]));
    assert_ne!(tag, key("01").tag(&["a", "bc"]));
    assert_ne!(tag, key("00").tag(&["ab", "c"]));
    assert_ne!(tag, key("00").tag(&["a\",\"bc"]));
}
